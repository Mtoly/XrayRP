package limiter

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestRedisIntegrationXrayNodeReplacementRetainsIdleLease(t *testing.T) {
	config := redisIntegrationConfig(t, "")
	config.Expiry = 3
	config.RuntimeOwner = "node-owner"
	owner := New()
	defer owner.Close()
	users := []api.UserInfo{{UID: 17, DeviceLimit: 1}}
	if err := owner.AddInboundLimiter("old", 0, &users, config); err != nil {
		t.Fatal(err)
	}
	read, uplink := pipe.New(pipe.WithSizeLimit(1024))
	downlink, write := pipe.New(pipe.WithSizeLimit(1024))
	defer uplink.Close()
	defer downlink.Interrupt()
	reader, writer, reject := owner.AdmitContext(context.Background(), "old", "old||17", "192.0.2.1", read, write)
	if reject {
		t.Fatal("first connection rejected")
	}
	defer reader.(*leasedReader).Interrupt()
	defer writer.(*leasedWriter).Close()
	if err := owner.AddInboundLimiter("replacement", 0, &users, config); err != nil {
		t.Fatal(err)
	}
	if err := owner.DeleteInboundLimiter("old"); err != nil {
		t.Fatal(err)
	}

	// Advance through a complete expiry interval while the original link stays
	// open and idle. A replacement must keep its connection-owned renewal.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_, _, rejected := owner.GetUserBucket("replacement", "replacement||17", "192.0.2.2")
		if !rejected {
			t.Fatal("node replacement lost old idle connection's quota")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := owner.UpdateGlobalDevices("replacement", map[int][]string{17: {"192.0.2.2"}}); err != nil {
		t.Fatal(err)
	}
	if err := owner.SyncAliveList("replacement", map[int][]string{17: {"192.0.2.2"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, rejected := owner.GetUserBucket("replacement", "replacement||17", "192.0.2.2"); !rejected {
		t.Fatal("panel snapshot overrode Redis quota")
	}
	if online, err := owner.GetOnlineDevice("replacement"); err != nil || len(*online) != 1 || (*online)[0].IP != "192.0.2.1" {
		t.Fatalf("idle active connection reporting = %v, %v", online, err)
	}
}

func TestRedisIntegrationRefusalDoesNotOccupyLocalSlot(t *testing.T) {
	if os.Getenv("XRAYRP_RUN_REDIS_INTEGRATION") != "1" {
		t.Skip("real Redis integration disabled")
	}
	config := redisIntegrationConfig(t, "")
	first := New()
	second := New()
	defer first.Close()
	defer second.Close()
	users := []api.UserInfo{{UID: 18, DeviceLimit: 1}}
	if err := first.AddInboundLimiter("first", 0, &users, config); err != nil {
		t.Fatal(err)
	}
	if err := second.AddInboundLimiter("second", 0, &users, config); err != nil {
		t.Fatal(err)
	}
	if _, _, reject := first.GetUserBucket("first", "first||18", "192.0.2.1"); reject {
		t.Fatal("first denied")
	}
	if _, _, reject := second.GetUserBucket("second", "second||18", "192.0.2.2"); !reject {
		t.Fatal("third-party quota ignored")
	}
	if online, err := second.GetOnlineDevice("second"); err != nil || len(*online) != 0 {
		t.Fatalf("Redis denial left local occupancy: %v, %v", online, err)
	}
}
