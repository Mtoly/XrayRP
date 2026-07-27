package tuic

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/service/controller"
)

func TestConnCounterWriteReturnsLimiterFailureBeforeNetworkWrite(t *testing.T) {
	closeErr := errors.New("close failed")
	connection := &limiterTestConn{closeErr: closeErr}
	counter := &connCounter{
		Conn:    connection,
		svc:     limiterTestService(),
		user:    "user",
		limiter: rate.NewLimiter(1, 0),
	}

	n, err := counter.Write([]byte("blocked"))
	if err == nil {
		t.Fatal("Write() error = nil, want limiter failure")
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("Write() error = %v, want joined close error %v", err, closeErr)
	}
	if n != 0 || connection.writeCalls != 0 {
		t.Fatalf("Write() = (%d, %v), network writes = %d; want admission before I/O", n, err, connection.writeCalls)
	}
	if !connection.closed {
		t.Fatal("Write() limiter failure did not close the connection")
	}
}

func TestConnCounterReadReturnsLimiterFailureWithoutDeliveringBytes(t *testing.T) {
	connection := &limiterTestConn{readData: []byte("blocked")}
	counter := &connCounter{
		Conn:    connection,
		svc:     limiterTestService(),
		user:    "user",
		limiter: rate.NewLimiter(1, 0),
	}

	buffer := make([]byte, 16)
	n, err := counter.Read(buffer)
	if err == nil {
		t.Fatal("Read() error = nil, want limiter failure")
	}
	if n != 0 {
		t.Fatalf("Read() bytes = %d, want 0 after admission failure", n)
	}
	if !connection.closed {
		t.Fatal("Read() limiter failure did not close the connection")
	}
}

func TestLimiterFailureUsesWrapperCloseCleanup(t *testing.T) {
	const host = "192.0.2.1"

	t.Run("stream", func(t *testing.T) {
		service := limiterTestService()
		service.onlineIPs["user"] = map[string]struct{}{host: {}}
		service.ipLastActive["user"] = map[string]time.Time{host: time.Now()}
		connection := &limiterTestConn{remoteAddr: limiterTestAddr(host + ":1234")}
		counter := &connCounter{
			Conn:    connection,
			svc:     service,
			user:    "user",
			limiter: rate.NewLimiter(1, 0),
		}

		_, _ = counter.Write([]byte("blocked"))
		assertLimiterCloseCleanup(t, service, host)
	})

	t.Run("packet", func(t *testing.T) {
		service := limiterTestService()
		service.onlineIPs["user"] = map[string]struct{}{host: {}}
		service.ipLastActive["user"] = map[string]time.Time{host: time.Now()}
		counter := &packetConnCounter{
			PacketConn: &limiterTestPacketConn{},
			svc:        service,
			user:       "user",
			host:       host,
			limiter:    rate.NewLimiter(1, 0),
		}
		buffer := buf.As([]byte("blocked"))
		defer buffer.Release()

		_ = counter.WritePacket(buffer, M.ParseSocksaddr("example.com:443"))
		assertLimiterCloseCleanup(t, service, host)
	})
}

func TestConnCounterHonorsCanceledAdmissionContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	limiter := rate.NewLimiter(1, 1)
	if !limiter.Allow() {
		t.Fatal("failed to consume initial limiter token")
	}
	cancel()
	connection := &limiterTestConn{}
	counter := &connCounter{
		Conn:    connection,
		svc:     limiterTestService(),
		user:    "user",
		ctx:     ctx,
		limiter: limiter,
	}

	if _, err := counter.Write([]byte("blocked")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Write() error = %v, want context.Canceled", err)
	}
	if connection.writeCalls != 0 {
		t.Fatalf("canceled Write() network writes = %d, want 0", connection.writeCalls)
	}
}

func TestTrackerAppliesDeviceAdmissionBeforeTraffic(t *testing.T) {
	service := limiterTestService()
	service.users["user"] = userRecord{UID: 17, DeviceLimit: 1}
	service.onlineIPs["user"] = map[string]struct{}{"192.0.2.1": {}}
	connection := &limiterTestConn{}

	tracked := (&tuicTracker{svc: service}).RoutedConnection(
		context.Background(),
		connection,
		adapter.InboundContext{
			User:   "user",
			Source: M.ParseSocksaddr("192.0.2.2:1234"),
		},
		nil,
		nil,
	)
	counter, ok := tracked.(*connCounter)
	if !ok || !counter.blocked {
		t.Fatalf("RoutedConnection() = %#v, want blocked connCounter", tracked)
	}
	if !connection.closed {
		t.Fatal("device admission rejection did not close the connection")
	}
}

func TestConnCounterConcurrentTrafficAccounting(t *testing.T) {
	const operations = 64
	service := limiterTestService()
	limiter := rate.NewLimiter(rate.Inf, 1)
	errs := make(chan error, operations)
	var workers sync.WaitGroup
	workers.Add(operations)

	for i := 0; i < operations; i++ {
		read := i%2 == 0
		go func() {
			defer workers.Done()
			connection := &limiterTestConn{readData: []byte{1}}
			counter := &connCounter{
				Conn:    connection,
				svc:     service,
				user:    "user",
				ctx:     context.Background(),
				limiter: limiter,
			}
			if read {
				_, err := counter.Read(make([]byte, 1))
				errs <- err
				return
			}
			_, err := counter.Write([]byte{1})
			errs <- err
		}()
	}

	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent I/O error = %v", err)
		}
	}
	service.mu.RLock()
	traffic := *service.traffic["user"]
	service.mu.RUnlock()
	if traffic.Upload != operations/2 || traffic.Download != operations/2 {
		t.Fatalf("traffic = %#v, want upload/download %d", traffic, operations/2)
	}
}

func TestRoutedPacketConnectionAttachesConfiguredLimiter(t *testing.T) {
	service := limiterTestService()
	configured := rate.NewLimiter(rate.Inf, 1)
	service.rateLimiters["user"] = configured
	connection := &limiterTestPacketConn{}

	tracked := (&tuicTracker{svc: service}).RoutedPacketConnection(
		context.Background(),
		connection,
		adapter.InboundContext{User: "user"},
		nil,
		nil,
	)
	counter, ok := tracked.(*packetConnCounter)
	if !ok {
		t.Fatalf("RoutedPacketConnection() = %T, want *packetConnCounter", tracked)
	}
	if counter.limiter != configured {
		t.Fatalf("attached limiter = %p, want configured %p", counter.limiter, configured)
	}
}

func TestPacketConnCounterReturnsLimiterFailures(t *testing.T) {
	t.Run("write", func(t *testing.T) {
		connection := &limiterTestPacketConn{}
		counter := &packetConnCounter{
			PacketConn: connection,
			svc:        limiterTestService(),
			user:       "user",
			limiter:    rate.NewLimiter(1, 0),
		}
		buffer := buf.As([]byte("blocked"))
		defer buffer.Release()

		err := counter.WritePacket(buffer, M.ParseSocksaddr("example.com:443"))
		if err == nil {
			t.Fatal("WritePacket() error = nil, want limiter failure")
		}
		if connection.writeCalls != 0 {
			t.Fatalf("WritePacket() network writes = %d, want 0", connection.writeCalls)
		}
		if !connection.closed {
			t.Fatal("WritePacket() limiter failure did not close the connection")
		}
	})

	t.Run("read", func(t *testing.T) {
		connection := &limiterTestPacketConn{readData: []byte("blocked")}
		counter := &packetConnCounter{
			PacketConn: connection,
			svc:        limiterTestService(),
			user:       "user",
			limiter:    rate.NewLimiter(1, 0),
		}
		buffer := buf.New()
		defer buffer.Release()

		if _, err := counter.ReadPacket(buffer); err == nil {
			t.Fatal("ReadPacket() error = nil, want limiter failure")
		}
		if buffer.Len() != 0 {
			t.Fatalf("ReadPacket() retained %d bytes after admission failure", buffer.Len())
		}
		if !connection.closed {
			t.Fatal("ReadPacket() limiter failure did not close the connection")
		}
	})
}

func limiterTestService() *TuicService {
	service := New(&configurablePanelClient{}, &controller.Config{})
	service.users = map[string]userRecord{"user": {UID: 17}}
	service.traffic = make(map[string]*userTraffic)
	service.onlineIPs = make(map[string]map[string]struct{})
	service.ipLastActive = make(map[string]map[string]time.Time)
	service.rateLimiters = make(map[string]*rate.Limiter)
	return service
}

func assertLimiterCloseCleanup(t *testing.T, service *TuicService, host string) {
	t.Helper()
	service.mu.RLock()
	_, online := service.onlineIPs["user"][host]
	_, active := service.ipLastActive["user"][host]
	service.mu.RUnlock()
	if online || active {
		t.Fatalf("limiter failure retained device state: online=%v active=%v", online, active)
	}
}

type limiterTestConn struct {
	readData   []byte
	writeCalls int
	closed     bool
	closeErr   error
	remoteAddr net.Addr
}

func (c *limiterTestConn) Read(p []byte) (int, error) {
	n := copy(p, c.readData)
	c.readData = c.readData[n:]
	return n, nil
}

func (c *limiterTestConn) Write(p []byte) (int, error) {
	c.writeCalls++
	return len(p), nil
}

func (c *limiterTestConn) Close() error {
	c.closed = true
	return c.closeErr
}

func (c *limiterTestConn) LocalAddr() net.Addr { return limiterTestAddr("local") }
func (c *limiterTestConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return limiterTestAddr("remote")
}
func (c *limiterTestConn) SetDeadline(time.Time) error      { return nil }
func (c *limiterTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *limiterTestConn) SetWriteDeadline(time.Time) error { return nil }

type limiterTestPacketConn struct {
	readData   []byte
	writeCalls int
	closed     bool
}

func (c *limiterTestPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	_, _ = buffer.Write(c.readData)
	c.readData = nil
	return M.ParseSocksaddr("example.com:443"), nil
}

func (c *limiterTestPacketConn) WritePacket(*buf.Buffer, M.Socksaddr) error {
	c.writeCalls++
	return nil
}

func (c *limiterTestPacketConn) Close() error                     { c.closed = true; return nil }
func (c *limiterTestPacketConn) LocalAddr() net.Addr              { return limiterTestAddr("local") }
func (c *limiterTestPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *limiterTestPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *limiterTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

type limiterTestAddr string

func (a limiterTestAddr) Network() string { return "test" }
func (a limiterTestAddr) String() string  { return string(a) }
