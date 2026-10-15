package tuic

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/Mtoly/XrayRP/api"
)

func TestDeviceAdmissionSurvivesUsageReports(t *testing.T) {
	for _, packet := range []bool{false, true} {
		name := "stream"
		if packet {
			name = "packet"
		}
		t.Run(name, func(t *testing.T) {
			svc := limiterTestService()
			svc.users["user"] = userRecord{UID: 17, DeviceLimit: 1}
			first := trackDeviceTestConnection(svc, "192.0.2.1", packet)
			defer first.Close()
			for cycle := 0; cycle < 3; cycle++ {
				_, online, _ := svc.collectUsage()
				if len(online) != 1 || online[0].IP != "192.0.2.1" {
					t.Fatalf("cycle %d online = %v, want connected IP", cycle, online)
				}
				second := trackDeviceTestConnection(svc, "192.0.2.2", packet)
				if !second.isBlocked() {
					t.Fatalf("cycle %d admitted a second device after reporting", cycle)
				}
				_ = second.Close()
			}
			_ = first.Close()
			next := trackDeviceTestConnection(svc, "192.0.2.2", packet)
			defer next.Close()
			if next.isBlocked() {
				t.Fatal("last connection close did not release device")
			}
		})
	}
}

func TestDeviceAdmissionRetainsOtherConnectionsOnClose(t *testing.T) {
	svc := limiterTestService()
	svc.users["user"] = userRecord{UID: 17, DeviceLimit: 1}
	stream := trackDeviceTestConnection(svc, "192.0.2.1", false)
	packet := trackDeviceTestConnection(svc, "192.0.2.1", true)
	defer packet.Close()
	_ = stream.Close()
	_ = stream.Close()
	other := trackDeviceTestConnection(svc, "192.0.2.2", false)
	defer other.Close()
	if !other.isBlocked() {
		t.Fatal("closing one connection released another connection's device")
	}
	_ = packet.Close()
	next := trackDeviceTestConnection(svc, "192.0.2.2", true)
	defer next.Close()
	if next.isBlocked() {
		t.Fatal("last close did not release device")
	}
}

func TestOldConnectionCloseDoesNotReleaseReaddedUser(t *testing.T) {
	svc := limiterTestService()
	svc.box = &fakeRuntimeInstance{events: &lifecycleEvents{}}
	users := []api.UserInfo{{UID: 17, UUID: "user", DeviceLimit: 1}}
	if err := svc.syncUsers(&users); err != nil {
		t.Fatal(err)
	}
	old := trackDeviceTestConnection(svc, "192.0.2.1", false)
	empty := []api.UserInfo{}
	if err := svc.syncUsers(&empty); err != nil {
		t.Fatal(err)
	}
	_, online, _ := svc.collectUsage()
	if len(online) != 0 {
		t.Fatal("removed user reported online")
	}
	removed := trackDeviceTestConnection(svc, "192.0.2.1", false)
	if !removed.isBlocked() {
		t.Fatal("removed user opened a new connection")
	}
	_ = removed.Close()
	if err := svc.syncUsers(&users); err != nil {
		t.Fatal(err)
	}
	second := trackDeviceTestConnection(svc, "192.0.2.2", false)
	defer second.Close()
	if !second.isBlocked() {
		t.Fatal("readded user lost still-open connection reservation")
	}
	current := trackDeviceTestConnection(svc, "192.0.2.1", false)
	defer current.Close()
	_ = old.Close()
	other := trackDeviceTestConnection(svc, "192.0.2.2", false)
	defer other.Close()
	if !other.isBlocked() {
		t.Fatal("old connection released readded user's device")
	}
}

func TestRejectedConnectionCloseDoesNotReleaseDevice(t *testing.T) {
	svc := limiterTestService()
	svc.users["user"] = userRecord{UID: 17, DeviceLimit: 1}
	current := trackDeviceTestConnection(svc, "192.0.2.1", false)
	defer current.Close()
	if err := svc.rules.UpdateRule("", []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile(`blocked`)}}); err != nil {
		t.Fatal(err)
	}
	blocked := (&tuicTracker{svc: svc}).RoutedConnection(context.Background(), &limiterTestConn{}, adapter.InboundContext{
		User: "user", Source: M.ParseSocksaddr("192.0.2.1:1234"), Domain: "blocked.example",
	}, nil, nil).(*connCounter)
	if !blocked.blocked {
		t.Fatal("audit did not reject connection")
	}
	_ = blocked.Close()
	other := trackDeviceTestConnection(svc, "192.0.2.2", false)
	defer other.Close()
	if !other.isBlocked() {
		t.Fatal("rejected connection released an admitted device")
	}
}

func TestDeviceAdmissionUserSyncCommitAndFailure(t *testing.T) {
	svc := limiterTestService()
	fake := &fakeRuntimeInstance{events: &lifecycleEvents{}}
	svc.box = fake
	users := []api.UserInfo{{UID: 17, UUID: "user", DeviceLimit: 1}}
	if err := svc.syncUsers(&users); err != nil {
		t.Fatal(err)
	}
	current := trackDeviceTestConnection(svc, "192.0.2.1", false)
	defer current.Close()
	fake.updateUsersErr = errors.New("rejected update")
	empty := []api.UserInfo{}
	if err := svc.syncUsers(&empty); !errors.Is(err, fake.updateUsersErr) {
		t.Fatalf("sync error = %v", err)
	}
	other := trackDeviceTestConnection(svc, "192.0.2.2", false)
	defer other.Close()
	if !other.isBlocked() {
		t.Fatal("failed user update discarded device ownership")
	}
	fake.updateUsersErr = nil
	if err := svc.syncUsers(&users); err != nil {
		t.Fatal(err)
	}
	_ = current.Close()
	next := trackDeviceTestConnection(svc, "192.0.2.2", false)
	defer next.Close()
	if next.isBlocked() {
		t.Fatal("unchanged user update lost connection close ownership")
	}
	if err := svc.syncUsers(&empty); err != nil {
		t.Fatal(err)
	}
	svc.recordTraffic("user", 1, 0, "192.0.2.2")
	_, online, _ := svc.collectUsage()
	if len(online) != 0 {
		t.Fatal("removed user reported online")
	}
	_ = next.Close()
	svc.recordTraffic("user", 1, 0, "192.0.2.2")
	if len(svc.connections) != 0 || len(svc.onlineIPs) != 0 {
		t.Fatal("late traffic recreated released device state")
	}
}

func TestDeviceAdmissionRuntimeCloseRetainsOwnershipUntilSuccess(t *testing.T) {
	svc := limiterTestService()
	svc.users["user"] = userRecord{UID: 17, DeviceLimit: 1}
	conn := trackDeviceTestConnection(svc, "192.0.2.1", false)
	fake := &fakeRuntimeInstance{events: &lifecycleEvents{}, closeErr: errors.New("close failed")}
	svc.box = fake
	svc.state = stateRunning
	if err := svc.Close(); !errors.Is(err, fake.closeErr) {
		t.Fatalf("Close() = %v", err)
	}
	if len(svc.connections["user"]) != 1 {
		t.Fatal("failed runtime close discarded connection ownership")
	}
	fake.closeErr = nil
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	if len(svc.connections) != 0 || len(svc.onlineIPs) != 0 {
		t.Fatal("successful runtime close retained device state")
	}
	_ = conn.Close()
	if len(svc.connections) != 0 {
		t.Fatal("late connection close recreated stopped runtime state")
	}
}

func TestDeviceAdmissionConcurrentCloseAndReports(t *testing.T) {
	svc := limiterTestService()
	svc.users["user"] = userRecord{UID: 17, DeviceLimit: 1}
	const count = 16
	connections := make([]deviceTestConnection, count)
	for i := range connections {
		connections[i] = trackDeviceTestConnection(svc, "192.0.2.1", i%2 == 0)
	}
	var wg sync.WaitGroup
	for _, conn := range connections {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 3 {
				svc.collectUsage()
				_ = conn.Close()
			}
		}()
	}
	wg.Wait()
	if len(svc.connections) != 0 || len(svc.onlineIPs) != 0 || len(svc.ipLastActive) != 0 {
		t.Fatal("concurrent closes retained device state")
	}
}

type deviceTestConnection struct {
	close   func() error
	blocked bool
}

func (c deviceTestConnection) Close() error    { return c.close() }
func (c deviceTestConnection) isBlocked() bool { return c.blocked }
func trackDeviceTestConnection(svc *TuicService, host string, packet bool) deviceTestConnection {
	metadata := adapter.InboundContext{User: "user", Source: M.ParseSocksaddr(host + ":1234")}
	tracker := &tuicTracker{svc: svc}
	if packet {
		conn := tracker.RoutedPacketConnection(context.Background(), &limiterTestPacketConn{}, metadata, nil, nil).(*packetConnCounter)
		return deviceTestConnection{close: conn.Close, blocked: conn.blocked}
	}
	conn := tracker.RoutedConnection(context.Background(), &limiterTestConn{remoteAddr: limiterTestAddr(host + ":1234")}, metadata, nil, nil).(*connCounter)
	return deviceTestConnection{close: conn.Close, blocked: conn.blocked}
}
