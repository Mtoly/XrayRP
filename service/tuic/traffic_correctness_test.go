package tuic

import (
	"context"
	"math"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestTrafficAccountingSaturatesAtMaxInt64(t *testing.T) {
	service := limiterTestService()
	service.traffic["user"] = &userTraffic{
		Upload:   math.MaxInt64 - 1,
		Download: math.MaxInt64 - 1,
	}

	readCounter := &connCounter{
		Conn: &limiterTestConn{
			readData:   []byte{1, 2},
			remoteAddr: limiterTestAddr("192.0.2.1:1234"),
		},
		svc:  service,
		user: "user",
		ctx:  context.Background(),
	}
	if _, err := readCounter.Read(make([]byte, 2)); err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	writeCounter := &connCounter{
		Conn: &limiterTestConn{
			remoteAddr: limiterTestAddr("192.0.2.1:1234"),
		},
		svc:  service,
		user: "user",
		ctx:  context.Background(),
	}
	if _, err := writeCounter.Write([]byte{1, 2}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	service.mu.RLock()
	traffic := *service.traffic["user"]
	service.mu.RUnlock()
	if traffic.Upload != math.MaxInt64 || traffic.Download != math.MaxInt64 {
		t.Fatalf("traffic = %#v, want saturated counters", traffic)
	}
}

func TestCollectAndRestorePreserveNewTraffic(t *testing.T) {
	service := limiterTestService()
	service.traffic["user"] = &userTraffic{Upload: 10, Download: 20}

	_, _, snapshot := service.collectUsage()
	counter := &connCounter{
		Conn: &limiterTestConn{
			remoteAddr: limiterTestAddr("192.0.2.1:1234"),
		},
		svc:  service,
		user: "user",
		ctx:  context.Background(),
	}
	if _, err := counter.Write([]byte{1}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	service.restoreTraffic(snapshot)

	service.mu.RLock()
	traffic := *service.traffic["user"]
	service.mu.RUnlock()
	if traffic.Upload != 10 || traffic.Download != 21 {
		t.Fatalf("traffic after restore = %#v, want upload=10 download=21", traffic)
	}
}

func TestRestoreTrafficSaturatesAtMaxInt64(t *testing.T) {
	service := limiterTestService()
	service.traffic["user"] = &userTraffic{
		Upload:   math.MaxInt64 - 1,
		Download: math.MaxInt64 - 1,
	}

	_, _, snapshot := service.collectUsage()
	service.traffic["user"] = &userTraffic{Upload: 2, Download: 2}
	service.restoreTraffic(snapshot)

	service.mu.RLock()
	traffic := *service.traffic["user"]
	service.mu.RUnlock()
	if traffic.Upload != math.MaxInt64 || traffic.Download != math.MaxInt64 {
		t.Fatalf("restored traffic = %#v, want saturated counters", traffic)
	}
}

func TestPacketConnCounterAccountsTrafficAndOnlineIP(t *testing.T) {
	const host = "192.0.2.1"
	service := limiterTestService()
	service.traffic["user"] = &userTraffic{}
	connection := &limiterTestPacketConn{readData: []byte("up")}
	counter := &packetConnCounter{
		PacketConn: connection,
		svc:        service,
		user:       "user",
		host:       host,
		ctx:        context.Background(),
	}

	readBuffer := buf.New()
	defer readBuffer.Release()
	if _, err := counter.ReadPacket(readBuffer); err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	writeBuffer := buf.As([]byte("down"))
	defer writeBuffer.Release()
	if err := counter.WritePacket(writeBuffer, M.ParseSocksaddr("example.com:443")); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}

	service.mu.RLock()
	traffic := *service.traffic["user"]
	_, online := service.onlineIPs["user"][host]
	service.mu.RUnlock()
	if traffic.Upload != 2 || traffic.Download != 4 || !online {
		t.Fatalf("packet traffic = %#v online=%v, want upload=2 download=4 online=true", traffic, online)
	}
}
