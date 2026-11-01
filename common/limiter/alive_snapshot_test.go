package limiter

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
)

func TestSyncAliveSnapshotCountAdmissionUsesPairedPanelCount(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 2}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}

	userKey := "inbound|one@example.test|1"
	localIP := "192.0.2.1"
	if _, _, rejected := l.Admit("inbound", userKey, localIP, nil, nil); rejected {
		t.Fatal("initial local IP was rejected")
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 2}},
		map[int][]string{1: {localIP}},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}

	if _, _, rejected := l.Admit("inbound", userKey, localIP, nil, nil); rejected {
		t.Fatal("tracked local IP was rejected at the panel limit")
	}
	if _, _, rejected := l.Admit("inbound", userKey, "198.51.100.1", nil, nil); !rejected {
		t.Fatal("new local IP was admitted even though the paired panel count filled the limit")
	}
}

func TestSyncAliveSnapshotCountAllowsOnlyRemainingLocalHeadroom(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 3}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 2}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}

	userKey := "inbound|one@example.test|1"
	for _, ip := range []string{"192.0.2.1", "192.0.2.1"} {
		if _, _, rejected := l.Admit("inbound", userKey, ip, nil, nil); rejected {
			t.Fatalf("Admit(%s) was rejected before local headroom was exhausted", ip)
		}
	}
	if _, _, rejected := l.Admit("inbound", userKey, "198.51.100.1", nil, nil); !rejected {
		t.Fatal("a second distinct local IP was admitted with only one slot remaining")
	}
}

func TestSyncAliveSnapshotAliasesShareCountHeadroomAtomically(t *testing.T) {
	l := New()
	users := []api.UserInfo{
		{UID: 1, Email: "one@example.test", DeviceLimit: 3},
		{UID: 1, Email: "alias@example.test", DeviceLimit: 3},
	}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 2}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}

	userKeys := []string{
		"inbound|one@example.test|1",
		"inbound|alias@example.test|1",
	}
	ips := []string{
		"192.0.2.10",
		"192.0.2.11",
		"192.0.2.12",
		"192.0.2.13",
	}
	ready := make(chan struct{}, len(ips))
	start := make(chan struct{})
	var wait sync.WaitGroup
	var admitted atomic.Int32
	for index, ip := range ips {
		index, ip := index, ip
		wait.Add(1)
		go func() {
			defer wait.Done()
			ready <- struct{}{}
			<-start
			if _, _, rejected := l.Admit("inbound", userKeys[index%len(userKeys)], ip, nil, nil); !rejected {
				admitted.Add(1)
			}
		}()
	}
	for range ips {
		<-ready
	}
	close(start)
	wait.Wait()

	if got := admitted.Load(); got != 1 {
		t.Fatalf("admitted concurrent aliases = %d, want exactly 1", got)
	}
}

func TestSyncAliveSnapshotAliasReusesLocalIPSlotAtFullPanelCount(t *testing.T) {
	l := New()
	users := []api.UserInfo{
		{UID: 1, Email: "one@example.test", DeviceLimit: 1},
		{UID: 1, Email: "alias@example.test", DeviceLimit: 1},
	}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	localIP := "192.0.2.1"
	if _, _, rejected := l.Admit("inbound", "inbound|one@example.test|1", localIP, nil, nil); rejected {
		t.Fatal("initial local IP was rejected")
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{1: {localIP}},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}

	if _, _, rejected := l.Admit("inbound", "inbound|alias@example.test|1", localIP, nil, nil); rejected {
		t.Fatal("another credential alias for the same UID did not reuse the local IP slot")
	}
	if _, _, rejected := l.Admit("inbound", "inbound|alias@example.test|1", "198.51.100.1", nil, nil); !rejected {
		t.Fatal("another credential alias admitted a new IP past the shared count limit")
	}
}

func TestSyncAliveSnapshotPairKeepsInFlightLocalAdmissionPending(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 3}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	userKey := "inbound|one@example.test|1"
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{1: {"192.0.2.1"}},
	); err != nil {
		t.Fatalf("first SyncAliveSnapshot() error = %v", err)
	}
	if _, _, rejected := l.Admit("inbound", userKey, "198.51.100.1", nil, nil); rejected {
		t.Fatal("in-flight local admission was rejected")
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 2}},
		map[int][]string{1: {"192.0.2.1"}},
	); err != nil {
		t.Fatalf("paired SyncAliveSnapshot() error = %v", err)
	}

	if _, _, rejected := l.Admit("inbound", userKey, "203.0.113.1", nil, nil); !rejected {
		t.Fatal("in-flight local admission was lost when its older report was paired")
	}
}

func TestSyncAliveSnapshotFailurePreservesCountAcrossOnlineExpiry(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 2}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}
	userKey := "inbound|one@example.test|1"
	if _, _, rejected := l.Admit("inbound", userKey, "192.0.2.1", nil, nil); rejected {
		t.Fatal("pending local admission was rejected")
	}
	value, _ := l.InboundInfo.Load("inbound")
	entryValue, _ := value.(*inboundState).UserOnlineIP.Load(userKey)
	entryValue.(*userOnlineEntry).ips.Store(
		"192.0.2.1",
		connIP{UID: 1, LastSeen: time.Now().Unix() - ipTTL - 1, Local: true},
	)
	if _, err := l.GetOnlineDevice("inbound"); err != nil {
		t.Fatalf("GetOnlineDevice() error = %v", err)
	}

	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 0}},
		nil,
	); err != nil {
		t.Fatalf("unpaired SyncAliveSnapshot() error = %v", err)
	}
	if _, _, rejected := l.Admit("inbound", userKey, "198.51.100.1", nil, nil); !rejected {
		t.Fatal("unpaired count snapshot released capacity after online expiry")
	}
}

func TestSyncAliveSnapshotUnpairedCountDoesNotActivateAdmission(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		nil,
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}
	if _, _, rejected := l.Admit("inbound", "inbound|one@example.test|1", "192.0.2.1", nil, nil); rejected {
		t.Fatal("an unpaired count snapshot activated admission without a successful report receipt")
	}
}

func TestSyncAliveSnapshotValidPairReconcilesExpiredPendingIP(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 3}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("initial SyncAliveSnapshot() error = %v", err)
	}
	userKey := "inbound|one@example.test|1"
	for _, ip := range []string{"192.0.2.1", "198.51.100.1"} {
		if _, _, rejected := l.Admit("inbound", userKey, ip, nil, nil); rejected {
			t.Fatalf("Admit(%s) was rejected", ip)
		}
	}
	value, _ := l.InboundInfo.Load("inbound")
	entryValue, _ := value.(*inboundState).UserOnlineIP.Load(userKey)
	entry := entryValue.(*userOnlineEntry)
	entry.mu.Lock()
	entry.ips.Range(func(ip, _ interface{}) bool {
		stale := connIP{UID: 1, LastSeen: time.Now().Unix() - ipTTL - 1, Local: true}
		entry.ips.Store(ip, stale)
		return true
	})
	entry.mu.Unlock()

	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("recovery SyncAliveSnapshot() error = %v", err)
	}
	if _, _, rejected := l.Admit("inbound", userKey, "203.0.113.1", nil, nil); rejected {
		t.Fatal("expired pending record was not reconciled by a valid pair")
	}
	if _, _, rejected := l.Admit("inbound", userKey, "203.0.113.2", nil, nil); rejected {
		t.Fatal("reconciled pending record did not release its stale capacity")
	}
	if _, _, rejected := l.Admit("inbound", userKey, "203.0.113.3", nil, nil); !rejected {
		t.Fatal("reconciled count and pending state admitted beyond the limit")
	}
}

func TestSyncAliveSnapshotCountDoesNotTrustPanelSeededIPAsLocal(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	panelIP := "192.0.2.1"
	if err := l.SyncAliveList("inbound", map[int][]string{1: {panelIP}}); err != nil {
		t.Fatalf("SyncAliveList() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}
	online, err := l.GetOnlineDevice("inbound")
	if err != nil {
		t.Fatalf("GetOnlineDevice() error = %v", err)
	}
	if len(*online) != 0 {
		t.Fatalf("count mode retained a panel-only seed as a local observation: %#v", *online)
	}

	if _, _, rejected := l.Admit("inbound", "inbound|one@example.test|1", panelIP, nil, nil); !rejected {
		t.Fatal("panel-only seed bypassed a full count-mode quota as a local IP")
	}
}

func TestSyncAliveSnapshotPairedEmptyReplacesPanelPortionOnly(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 2}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	userKey := "inbound|one@example.test|1"
	if _, _, rejected := l.Admit("inbound", userKey, "192.0.2.1", nil, nil); rejected {
		t.Fatal("local admission was rejected")
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}

	if _, _, rejected := l.Admit("inbound", userKey, "192.0.2.1", nil, nil); rejected {
		t.Fatal("typed empty snapshot discarded a genuine local observation")
	}
	if _, _, rejected := l.Admit("inbound", userKey, "198.51.100.1", nil, nil); rejected {
		t.Fatal("typed empty snapshot failed to preserve pending local headroom accounting")
	}
	if _, _, rejected := l.Admit("inbound", userKey, "203.0.113.1", nil, nil); !rejected {
		t.Fatal("preserved pending local state admitted beyond the limit")
	}
}

func TestSyncAliveSnapshotExplicitIPsSwitchCountUIDToListMode(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("count SyncAliveSnapshot() error = %v", err)
	}
	userKey := "inbound|one@example.test|1"
	if _, _, rejected := l.Admit("inbound", userKey, "192.0.2.1", nil, nil); !rejected {
		t.Fatal("count mode admitted a new local IP at the limit")
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{IPs: map[int][]string{1: {"198.51.100.1"}}},
		nil,
	); err != nil {
		t.Fatalf("list SyncAliveSnapshot() error = %v", err)
	}
	if _, _, rejected := l.Admit("inbound", userKey, "198.51.100.1", nil, nil); rejected {
		t.Fatal("explicit list snapshot did not switch the UID back to list mode")
	}
}

func TestSyncAliveSnapshotMixedUIDModesDoNotClearEachOther(t *testing.T) {
	l := New()
	users := []api.UserInfo{
		{UID: 1, Email: "one@example.test", DeviceLimit: 2},
		{UID: 2, Email: "two@example.test", DeviceLimit: 1},
	}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{
			IPs:    map[int][]string{2: {"198.51.100.2"}},
			Counts: map[int]int{1: 2},
		},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}

	if _, _, rejected := l.Admit("inbound", "inbound|one@example.test|1", "192.0.2.1", nil, nil); !rejected {
		t.Fatal("count-mode UID bypassed its full panel count")
	}
	if _, _, rejected := l.Admit("inbound", "inbound|two@example.test|2", "198.51.100.2", nil, nil); rejected {
		t.Fatal("list-mode UID lost its panel-seeded IP in a mixed snapshot")
	}
	if _, _, rejected := l.Admit("inbound", "inbound|two@example.test|2", "203.0.113.2", nil, nil); !rejected {
		t.Fatal("list-mode UID admitted a second IP at its limit")
	}
}

func TestSyncAliveSnapshotRetainsUIDCountAcrossCredentialReplacement(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "old@example.test", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}

	replacement := []api.UserInfo{{UID: 1, Email: "new@example.test", DeviceLimit: 1}}
	if err := l.ReplaceInboundUsers("inbound", &replacement); err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}
	if _, _, rejected := l.Admit("inbound", "inbound|new@example.test|1", "192.0.2.1", nil, nil); !rejected {
		t.Fatal("credential replacement reset the UID's occupied count quota")
	}
}

func TestSyncAliveSnapshotDoesNotInheritCountToDifferentUID(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}

	replacement := []api.UserInfo{{UID: 2, Email: "two@example.test", DeviceLimit: 1}}
	if err := l.ReplaceInboundUsers("inbound", &replacement); err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}
	if _, _, rejected := l.Admit("inbound", "inbound|two@example.test|2", "192.0.2.2", nil, nil); rejected {
		t.Fatal("a different UID inherited the removed user's occupied count quota")
	}
}

func TestSyncAliveSnapshotRetainsCountWhenOneAliasIsRemoved(t *testing.T) {
	l := New()
	users := []api.UserInfo{
		{UID: 1, Email: "removed@example.test", DeviceLimit: 1},
		{UID: 1, Email: "retained@example.test", DeviceLimit: 1},
	}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}

	replacement := []api.UserInfo{{UID: 1, Email: "retained@example.test", DeviceLimit: 1}}
	if err := l.ReplaceInboundUsers("inbound", &replacement); err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}
	if _, _, rejected := l.Admit("inbound", "inbound|retained@example.test|1", "192.0.2.1", nil, nil); !rejected {
		t.Fatal("removing one alias reset the retained UID's occupied count quota")
	}
}

func TestAddInboundLimiterRetainsUIDCount(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("initial AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("replacement AddInboundLimiter() error = %v", err)
	}
	if _, _, rejected := l.Admit("inbound", "inbound|one@example.test|1", "192.0.2.1", nil, nil); !rejected {
		t.Fatal("same-tag inbound replacement reset the UID's occupied count quota")
	}
}

func TestSyncAliveSnapshotPairedOmissionZerosEstablishedCount(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 2}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 2}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("initial SyncAliveSnapshot() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{},
		map[int][]string{},
	); err != nil {
		t.Fatalf("empty SyncAliveSnapshot() error = %v", err)
	}

	if _, _, rejected := l.Admit("inbound", "inbound|one@example.test|1", "192.0.2.1", nil, nil); rejected {
		t.Fatal("paired full snapshot omission did not reset the established count to zero")
	}
}

func TestSyncAliveSnapshotFreshWebSocketPrecedesCountAdmission(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 0}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}
	if err := l.UpdateGlobalDevices("inbound", map[int][]string{1: {"192.0.2.1"}}); err != nil {
		t.Fatalf("UpdateGlobalDevices() error = %v", err)
	}

	if _, _, rejected := l.Admit("inbound", "inbound|one@example.test|1", "198.51.100.1", nil, nil); !rejected {
		t.Fatal("count admission overrode a fresh WebSocket full-device decision")
	}
}

func TestSyncAliveSnapshotTracksAdmissionWhileFreshWebSocketIsAuthoritative(t *testing.T) {
	base := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	current := base
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 2}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	value, _ := l.InboundInfo.Load("inbound")
	globalDevices := value.(*inboundState).GlobalDevices
	globalDevices.ttl = time.Second
	globalDevices.now = func() time.Time { return current }

	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}
	if err := l.UpdateGlobalDevices("inbound", map[int][]string{1: {"192.0.2.1"}}); err != nil {
		t.Fatalf("UpdateGlobalDevices() error = %v", err)
	}
	userKey := "inbound|one@example.test|1"
	if _, _, rejected := l.Admit("inbound", userKey, "198.51.100.1", nil, nil); rejected {
		t.Fatal("fresh WebSocket rejected locally admissible IP")
	}

	current = base.Add(2 * time.Second)
	if _, _, rejected := l.Admit("inbound", userKey, "203.0.113.1", nil, nil); !rejected {
		t.Fatal("admission made while WebSocket was authoritative was lost from count mode")
	}
}

func TestSyncAliveSnapshotDrainKeepsAdmissionAfterReportPending(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 3}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 1}},
		map[int][]string{1: {"192.0.2.1"}},
	); err != nil {
		t.Fatalf("initial SyncAliveSnapshot() error = %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	drainStarted := make(chan struct{})
	admitDone := make(chan struct{})
	syncDone := make(chan error, 1)
	l.onAdmissionEntered = func() {
		close(entered)
		<-release
	}
	l.onAdmissionDrainStarted = func() {
		close(drainStarted)
	}
	userKey := "inbound|one@example.test|1"
	go func() {
		defer close(admitDone)
		_, _, _ = l.Admit("inbound", userKey, "198.51.100.1", nil, nil)
	}()
	<-entered
	go func() {
		syncDone <- l.SyncAliveSnapshot(
			"inbound",
			&api.AliveSnapshot{Counts: map[int]int{1: 2}},
			map[int][]string{1: {"192.0.2.1"}},
		)
	}()
	<-drainStarted
	close(release)
	<-admitDone
	if err := <-syncDone; err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}
	l.onAdmissionEntered = nil
	l.onAdmissionDrainStarted = nil

	if _, _, rejected := l.Admit("inbound", userKey, "203.0.113.1", nil, nil); !rejected {
		t.Fatal("admission completed while synchronization drained was lost from pending state")
	}
}

func TestRestoreInboundLimiterStateKeepsLiveUIDCount(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 2}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	snapshot, err := l.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}

	replacement := []api.UserInfo{{UID: 1, Email: "new@example.test", DeviceLimit: 2}}
	if err := l.ReplaceInboundUsers("inbound", &replacement); err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{1: 2}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}
	if err := l.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}
	if _, _, rejected := l.Admit("inbound", "inbound|one@example.test|1", "192.0.2.1", nil, nil); !rejected {
		t.Fatal("configuration restore discarded count state updated after the snapshot")
	}
}

func TestRestoreInboundLimiterStateDropsCandidateOnlyUIDCount(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "one@example.test", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	snapshot, err := l.SnapshotInboundLimiterState("inbound")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState() error = %v", err)
	}

	replacement := []api.UserInfo{{UID: 2, Email: "two@example.test", DeviceLimit: 1}}
	if err := l.ReplaceInboundUsers("inbound", &replacement); err != nil {
		t.Fatalf("ReplaceInboundUsers() error = %v", err)
	}
	if err := l.SyncAliveSnapshot(
		"inbound",
		&api.AliveSnapshot{Counts: map[int]int{2: 1}},
		map[int][]string{},
	); err != nil {
		t.Fatalf("SyncAliveSnapshot() error = %v", err)
	}
	if err := l.RestoreInboundLimiterState("inbound", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState() error = %v", err)
	}
	if _, _, rejected := l.Admit("inbound", "inbound|two@example.test|2", "192.0.2.2", nil, nil); !rejected {
		t.Fatal("restore retained a candidate-only user")
	}
	if _, _, rejected := l.Admit("inbound", "inbound|one@example.test|1", "192.0.2.1", nil, nil); rejected {
		t.Fatal("candidate-only count state displaced the restored UID")
	}
}
