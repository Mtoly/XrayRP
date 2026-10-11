package singboxregistry

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func TestAnyTLSInboundAppliesUserUpdatesWhileRunning(t *testing.T) {
	echoAddr := startEchoServer(t)
	listenAddr := netip.MustParseAddr("127.0.0.1")
	port := freeTCPPort(t)
	instance, err := box.New(box.Options{
		Context: WithFullRegistry(context.Background()),
		Options: option.Options{
			Log: &option.LogOptions{Disabled: true},
			Inbounds: []option.Inbound{{
				Type: C.TypeAnyTLS,
				Tag:  "anytls-in",
				Options: &option.AnyTLSInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     (*badoption.Addr)(&listenAddr),
						ListenPort: port,
					},
					Users: []option.AnyTLSUser{{Name: "old-user", Password: "old-password"}},
				},
			}},
			Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		},
	})
	if err != nil {
		t.Fatalf("box.New() error = %v", err)
	}
	if err := instance.Start(); err != nil {
		t.Fatalf("box.Start() error = %v", err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Errorf("box.Close() error = %v", err)
		}
	})
	registered, _ := instance.Inbound().Get("anytls-in")
	inbound, ok := registered.(*AnyTLSInbound)
	if !ok {
		t.Fatalf("registered AnyTLS inbound = %T, want *AnyTLSInbound", registered)
	}
	serverAddr := net.JoinHostPort(listenAddr.String(), strconv.Itoa(int(port)))

	if err := anyTLSEcho(serverAddr, "new-password", echoAddr); err == nil {
		t.Fatal("new user connected before the user update")
	}
	if err := inbound.UpdateUsers([]option.AnyTLSUser{{Name: "new-user", Password: "new-password"}}); err != nil {
		t.Fatalf("UpdateUsers() error = %v", err)
	}
	if err := anyTLSEcho(serverAddr, "new-password", echoAddr); err != nil {
		t.Fatalf("new user after update: %v", err)
	}
	if err := anyTLSEcho(serverAddr, "old-password", echoAddr); err == nil {
		t.Fatal("removed user still connected after the user update")
	}
}

func anyTLSEcho(serverAddr, password, echoAddr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := anytls.NewClient(ctx, anytls.ClientConfig{
		Password: password,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", serverAddr)
		},
		Logger: logger.NOP(),
	})
	if err != nil {
		return err
	}
	conn, err := client.CreateProxy(ctx, M.ParseSocksaddr(echoAddr))
	if err != nil {
		return err
	}
	defer conn.Close()
	return echoRoundTrip(conn)
}

func echoRoundTrip(conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if string(reply) != "ping" {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}
