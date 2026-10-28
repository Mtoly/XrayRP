package limiter

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The proxy controls connectivity to a real Redis server without stopping or
// modifying that server. Faults affect only this test's client connections.
type redisFaultProxy struct {
	listener    net.Listener
	target      string
	mode        atomic.Int32 // 0 forwarding, 1 disconnect, 2 accept but never respond
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	workers     sync.WaitGroup
}

func newRedisFaultProxy(t *testing.T) *redisFaultProxy {
	t.Helper()
	if os.Getenv("XRAYRP_RUN_REDIS_INTEGRATION") != "1" {
		t.Skip("set XRAYRP_RUN_REDIS_INTEGRATION=1 to use real Redis")
	}
	target := os.Getenv("XRAYRP_REDIS_ADDR")
	if target == "" {
		target = "127.0.0.1:16379"
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &redisFaultProxy{listener: listener, target: target, connections: make(map[net.Conn]struct{})}
	proxy.workers.Add(1)
	go func() {
		defer proxy.workers.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			proxy.mu.Lock()
			proxy.connections[client] = struct{}{}
			proxy.mu.Unlock()
			proxy.workers.Add(1)
			go proxy.forward(client)
		}
	}()
	t.Cleanup(func() {
		_ = proxy.listener.Close()
		proxy.setMode(1)
		proxy.workers.Wait()
	})
	return proxy
}

func (p *redisFaultProxy) forward(client net.Conn) {
	defer p.workers.Done()
	defer func() {
		_ = client.Close()
		p.mu.Lock()
		delete(p.connections, client)
		p.mu.Unlock()
	}()
	switch p.mode.Load() {
	case 1:
		return
	case 2:
		_, _ = io.Copy(io.Discard, client)
		return
	}
	server, err := net.DialTimeout("tcp", p.target, time.Second)
	if err != nil {
		return
	}
	defer server.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(server, client)
		_ = server.Close()
		close(done)
	}()
	_, _ = io.Copy(client, server)
	_ = client.Close()
	<-done
}

func (p *redisFaultProxy) setMode(mode int32) {
	p.mode.Store(mode)
	p.mu.Lock()
	for connection := range p.connections {
		_ = connection.Close()
	}
	p.mu.Unlock()
}

func TestRedisIntegrationOutageTimeoutAndRecovery(t *testing.T) {
	for _, failure := range []string{"open", "closed"} {
		t.Run(failure, func(t *testing.T) {
			proxy := newRedisFaultProxy(t)
			config := &GlobalDeviceLimitConfig{Enable: true, Mode: "strict", FailMode: failure,
				RedisAddr: proxy.listener.Addr().String(), Namespace: t.Name() + "-" + strconv.FormatInt(time.Now().UnixNano(), 36), Timeout: 1, Expiry: 3}
			manager, err := NewGlobalAdmission(config, "", "")
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			manager.SetUsers(map[int]int{71: 1})
			original, err := manager.Acquire(context.Background(), 71, "192.0.2.1", 1)
			if err != nil {
				t.Fatalf("healthy Redis: %v", err)
			}
			if err := original.Commit(); err != nil {
				t.Fatal(err)
			}
			defer original.Close()
			for _, mode := range []int32{1, 2} {
				proxy.setMode(mode)
				start := time.Now()
				same, err := manager.Acquire(context.Background(), 71, "192.0.2.1", 1)
				if elapsed := time.Since(start); elapsed > 2*time.Second {
					t.Fatalf("fault request blocked %s", elapsed)
				}
				if failure == "closed" {
					if !errors.Is(err, ErrGlobalAdmissionUnavailable) {
						t.Fatalf("closed accepted unverified same-IP connection: %v", err)
					}
				} else {
					if err != nil || same == nil {
						t.Fatalf("open lost local existing IP: %v", err)
					}
					if err := same.Commit(); err != nil {
						t.Fatal(err)
					}
					_ = same.Close()
					if other, err := manager.Acquire(context.Background(), 71, "192.0.2.2", 1); !errors.Is(err, ErrGlobalAdmissionQuota) {
						_ = other.Close()
						t.Fatalf("open bypassed local quota: %v", err)
					}
				}
				if !manager.StatusSnapshot().Degraded {
					t.Fatal("outage not reported degraded")
				}
			}
			proxy.setMode(0)
			deadline := time.Now().Add(10 * time.Second)
			for manager.StatusSnapshot().Degraded {
				if time.Now().After(deadline) {
					t.Fatal("Redis recovered but live holder never reacquired")
				}
				time.Sleep(50 * time.Millisecond)
			}
			if !original.GlobalConfirmed() {
				t.Fatal("original idle connection lost reservation after recovery")
			}
			other, err := manager.Acquire(context.Background(), 71, "192.0.2.2", 1)
			_ = other.Close()
			if !errors.Is(err, ErrGlobalAdmissionQuota) {
				t.Fatalf("recovery lost existing quota: %v", err)
			}
		})
	}
}
