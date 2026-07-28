package limiter

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
)

func TestSyncAliveListReplacesTheCompletePanelSnapshot(t *testing.T) {
	l := New()
	users := []api.UserInfo{
		{UID: 1, Email: "one@example.com"},
		{UID: 2, Email: "two@example.com"},
	}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter failed: %v", err)
	}
	if _, _, rejected := l.getUserBucket("inbound", "inbound|one@example.com|1", "192.0.2.1"); rejected {
		t.Fatal("expected first user IP to be accepted")
	}
	if _, _, rejected := l.getUserBucket("inbound", "inbound|two@example.com|2", "192.0.2.2"); rejected {
		t.Fatal("expected second user IP to be accepted")
	}

	if err := l.SyncAliveList("inbound", map[int][]string{1: {"198.51.100.1"}}); err != nil {
		t.Fatalf("SyncAliveList failed: %v", err)
	}

	online, err := l.GetOnlineDevice("inbound")
	if err != nil {
		t.Fatalf("GetOnlineDevice failed: %v", err)
	}
	sort.Slice(*online, func(i, j int) bool {
		if (*online)[i].UID != (*online)[j].UID {
			return (*online)[i].UID < (*online)[j].UID
		}
		return (*online)[i].IP < (*online)[j].IP
	})
	want := []api.OnlineUser{{UID: 1, IP: "198.51.100.1"}}
	if !reflect.DeepEqual(*online, want) {
		t.Fatalf("online devices = %#v, want %#v", *online, want)
	}
}

func TestSyncAliveListEmptySnapshotClearsAllOnlineDevices(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.com"}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter failed: %v", err)
	}
	if _, _, rejected := l.getUserBucket("inbound", "inbound|one@example.com|1", "192.0.2.1"); rejected {
		t.Fatal("expected user IP to be accepted")
	}

	if err := l.SyncAliveList("inbound", map[int][]string{}); err != nil {
		t.Fatalf("SyncAliveList failed: %v", err)
	}

	online, err := l.GetOnlineDevice("inbound")
	if err != nil {
		t.Fatalf("GetOnlineDevice failed: %v", err)
	}
	if len(*online) != 0 {
		t.Fatalf("online devices = %#v, want empty", *online)
	}
}

func TestSyncAliveListRefreshesPanelConfirmedIPs(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.com"}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter failed: %v", err)
	}
	userKey := "inbound|one@example.com|1"
	ip := "192.0.2.1"
	if _, _, rejected := l.getUserBucket("inbound", userKey, ip); rejected {
		t.Fatal("expected user IP to be accepted")
	}

	value, ok := l.inboundInfo.Load("inbound")
	if !ok {
		t.Fatal("expected inbound limiter state")
	}
	entryValue, ok := value.(*inboundState).onlineUsers.Load(userKey)
	if !ok {
		t.Fatal("expected online user entry")
	}
	entry := entryValue.(*userOnlineEntry)
	entry.ips.Store(ip, connIP{UID: 1, LastSeen: time.Now().Unix() - ipTTL - 1})

	if err := l.SyncAliveList("inbound", map[int][]string{1: {ip}}); err != nil {
		t.Fatalf("SyncAliveList failed: %v", err)
	}

	online, err := l.GetOnlineDevice("inbound")
	if err != nil {
		t.Fatalf("GetOnlineDevice failed: %v", err)
	}
	want := []api.OnlineUser{{UID: 1, IP: ip}}
	if !reflect.DeepEqual(*online, want) {
		t.Fatalf("online devices = %#v, want %#v", *online, want)
	}
}

func TestSyncAliveListSeedsKnownUsersBeforeTheirFirstLocalConnection(t *testing.T) {
	l := New()
	users := []api.UserInfo{{
		UID:         1,
		Email:       "one@example.com",
		DeviceLimit: 1,
	}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter failed: %v", err)
	}

	panelIP := "192.0.2.1"
	if err := l.SyncAliveList("inbound", map[int][]string{1: {panelIP}}); err != nil {
		t.Fatalf("SyncAliveList failed: %v", err)
	}

	online, err := l.GetOnlineDevice("inbound")
	if err != nil {
		t.Fatalf("GetOnlineDevice failed: %v", err)
	}
	want := []api.OnlineUser{{UID: 1, IP: panelIP}}
	if !reflect.DeepEqual(*online, want) {
		t.Fatalf("online devices = %#v, want %#v", *online, want)
	}

	userKey := "inbound|one@example.com|1"
	if _, _, rejected := l.getUserBucket("inbound", userKey, "198.51.100.1"); !rejected {
		t.Fatal("expected panel-confirmed device to consume the only device slot")
	}
}

func TestSyncAliveListUsesOwnedUIDWhenUserIdentityContainsSeparator(t *testing.T) {
	l := New()
	users := []api.UserInfo{{
		UID:   42,
		Email: "quoted|local@example.test",
	}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}

	userKey := "inbound|quoted|local@example.test|42"
	if _, _, rejected := l.Admit("inbound", userKey, "192.0.2.1", nil, nil); rejected {
		t.Fatal("initial user device was rejected")
	}
	if err := l.SyncAliveList("inbound", map[int][]string{42: {"198.51.100.1"}}); err != nil {
		t.Fatalf("SyncAliveList() error = %v", err)
	}

	online, err := l.GetOnlineDevice("inbound")
	if err != nil {
		t.Fatalf("GetOnlineDevice() error = %v", err)
	}
	want := []api.OnlineUser{{UID: 42, IP: "198.51.100.1"}}
	if !reflect.DeepEqual(*online, want) {
		t.Fatalf("online devices = %#v, want %#v", *online, want)
	}
}
