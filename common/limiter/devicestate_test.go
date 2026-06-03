package limiter

import (
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"golang.org/x/time/rate"
)

func TestGlobalDeviceStateRejectsThirdIPWhenFresh(t *testing.T) {
	base := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	state := &globalDeviceState{
		ttl: defaultGlobalDeviceTTL,
		now: func() time.Time { return base },
	}

	state.Replace(map[int][]string{1: []string{"192.0.2.1", "198.51.100.1"}})

	if !state.ShouldReject(1, "203.0.113.1", 2, nil) {
		t.Fatal("expected fresh global device state to reject third IP when device limit is 2")
	}
}

func TestGlobalDeviceStateAllowsExistingGlobalIP(t *testing.T) {
	base := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	state := &globalDeviceState{
		ttl: defaultGlobalDeviceTTL,
		now: func() time.Time { return base },
	}

	state.Replace(map[int][]string{1: []string{"192.0.2.1", "198.51.100.1"}})

	if state.ShouldReject(1, "198.51.100.1", 2, nil) {
		t.Fatal("expected existing global IP to be allowed")
	}
}

func TestGlobalDeviceStateAllowsExistingGlobalIPWhenLocalSortsFirst(t *testing.T) {
	base := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	state := &globalDeviceState{
		ttl: defaultGlobalDeviceTTL,
		now: func() time.Time { return base },
	}

	state.Replace(map[int][]string{1: []string{"203.0.113.2"}})

	reject, fresh := state.ShouldRejectFresh(1, "203.0.113.2", 1, []string{"192.0.2.1"})
	if !fresh {
		t.Fatal("expected global device state to be fresh")
	}
	if reject {
		t.Fatal("expected existing globally-known candidate to be allowed even when local IP sorts first")
	}
}

func TestGlobalDeviceStateStaleFallsBackToLocalOnly(t *testing.T) {
	base := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	current := base
	state := &globalDeviceState{
		ttl: defaultGlobalDeviceTTL,
		now: func() time.Time { return current },
	}

	state.Replace(map[int][]string{1: []string{"192.0.2.1", "198.51.100.1"}})
	current = base.Add(defaultGlobalDeviceTTL + time.Second)

	if state.Fresh() {
		t.Fatal("expected global device state to be stale")
	}
	if state.ShouldReject(1, "203.0.113.1", 2, nil) {
		t.Fatal("expected stale global device state not to reject so caller can fall back to local-only")
	}
}

func TestGlobalDeviceStateClearRemovesGlobalRejections(t *testing.T) {
	base := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	state := &globalDeviceState{
		ttl: defaultGlobalDeviceTTL,
		now: func() time.Time { return base },
	}

	state.Replace(map[int][]string{1: []string{"192.0.2.1", "198.51.100.1"}})
	if !state.ShouldReject(1, "203.0.113.1", 2, nil) {
		t.Fatal("expected global state to reject third IP before Clear")
	}

	state.Clear()

	if state.Fresh() {
		t.Fatal("expected cleared global state not to be fresh")
	}
	if state.ShouldReject(1, "203.0.113.1", 2, nil) {
		t.Fatal("expected Clear to remove global rejection")
	}
}

func TestGlobalDeviceStateDeviceLimitLTEZeroDoesNotReject(t *testing.T) {
	base := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	state := &globalDeviceState{
		ttl: defaultGlobalDeviceTTL,
		now: func() time.Time { return base },
	}

	state.Replace(map[int][]string{1: []string{"192.0.2.1", "198.51.100.1"}})

	if state.ShouldReject(1, "203.0.113.1", 0, nil) {
		t.Fatal("expected zero device limit not to reject")
	}
	if state.ShouldReject(1, "203.0.113.1", -1, nil) {
		t.Fatal("expected negative device limit not to reject")
	}
}

func TestGlobalDeviceStateDeterministicAdmissionUsesCombinedIPs(t *testing.T) {
	base := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	state := &globalDeviceState{
		ttl: defaultGlobalDeviceTTL,
		now: func() time.Time { return base },
	}

	state.Replace(map[int][]string{1: []string{"198.51.100.1"}})

	if state.ShouldReject(1, "192.0.2.1", 2, []string{"203.0.113.1"}) {
		t.Fatal("expected candidate in first two sorted combined IPs to be allowed")
	}
	if !state.ShouldReject(1, "203.0.113.2", 2, []string{"192.0.2.1"}) {
		t.Fatal("expected candidate outside first two sorted combined IPs to be rejected")
	}
}

func TestGlobalDeviceStateReplaceNormalizesAndCopiesInput(t *testing.T) {
	base := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	state := &globalDeviceState{
		ttl: defaultGlobalDeviceTTL,
		now: func() time.Time { return base },
	}
	devices := map[int][]string{
		1: []string{" 192.0.2.1 ", "\t198.51.100.1\n", "192.0.2.1", "", "   "},
		2: []string{"\t", "\n"},
	}

	state.Replace(devices)
	devices[1][0] = "203.0.113.1"
	devices[1] = append(devices[1], "203.0.113.2")
	devices[2] = []string{"203.0.113.3"}

	state.mu.RLock()
	storedSet := state.devices[1]
	_, blankOnlyUIDStored := state.devices[2]
	stored := make([]string, 0, len(storedSet))
	for ip := range storedSet {
		stored = append(stored, ip)
	}
	state.mu.RUnlock()

	sort.Strings(stored)
	want := []string{"192.0.2.1", "198.51.100.1"}
	if !reflect.DeepEqual(stored, want) {
		t.Fatalf("stored IPs = %v, want %v", stored, want)
	}
	if blankOnlyUIDStored {
		t.Fatal("expected whitespace-only IP entries to be skipped")
	}
}

func TestLimiterUsesFreshGlobalAdmissionWithoutLocalOnlyRejection(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", DeviceLimit: 2}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter failed: %v", err)
	}

	userKey := "inbound|user@example.com|1"
	if _, _, rejected := l.GetUserBucket("inbound", userKey, "203.0.113.1"); rejected {
		t.Fatal("expected first local IP to be allowed")
	}
	if _, _, rejected := l.GetUserBucket("inbound", userKey, "203.0.113.2"); rejected {
		t.Fatal("expected second local IP to be allowed")
	}
	if err := l.UpdateGlobalDevices("inbound", map[int][]string{1: []string{"198.51.100.1"}}); err != nil {
		t.Fatalf("UpdateGlobalDevices failed: %v", err)
	}

	if _, _, rejected := l.GetUserBucket("inbound", userKey, "192.0.2.1"); rejected {
		t.Fatal("expected fresh global deterministic admission to allow candidate without old local-only rejection")
	}

	value, ok := l.InboundInfo.Load("inbound")
	if !ok {
		t.Fatal("expected inbound to exist")
	}
	entryValue, ok := value.(*InboundInfo).UserOnlineIP.Load(userKey)
	if !ok || !entryValue.(*userOnlineEntry).hasIP("192.0.2.1") {
		t.Fatal("expected globally admitted IP to be recorded locally")
	}
}

func TestLimiterSerializesConcurrentFreshGlobalAdmission(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", DeviceLimit: 2}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter failed: %v", err)
	}

	userKey := "inbound|user@example.com|1"
	if _, _, rejected := l.GetUserBucket("inbound", userKey, "192.0.2.1"); rejected {
		t.Fatal("expected initial local IP to be allowed")
	}
	if err := l.UpdateGlobalDevices("inbound", map[int][]string{1: []string{"203.0.113.200"}}); err != nil {
		t.Fatalf("UpdateGlobalDevices failed: %v", err)
	}

	candidates := []string{
		"198.51.100.30",
		"203.0.113.201",
		"198.51.100.20",
		"203.0.113.202",
		"198.51.100.10",
	}
	ready := make(chan struct{}, len(candidates))
	start := make(chan struct{})
	var wg sync.WaitGroup
	var rejectedCount int32
	for _, candidate := range candidates {
		candidate := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			if _, _, rejected := l.GetUserBucket("inbound", userKey, candidate); rejected {
				atomic.AddInt32(&rejectedCount, 1)
			}
		}()
	}
	for range candidates {
		<-ready
	}
	close(start)
	wg.Wait()

	rejected := int(atomic.LoadInt32(&rejectedCount))
	if rejected == 0 {
		t.Fatal("expected at least one concurrent candidate to be rejected")
	}
	if rejected == len(candidates) {
		t.Fatal("expected at least one concurrent candidate to be admitted")
	}

	value, ok := l.InboundInfo.Load("inbound")
	if !ok {
		t.Fatal("expected inbound to exist")
	}
	entryValue, ok := value.(*InboundInfo).UserOnlineIP.Load(userKey)
	if !ok {
		t.Fatal("expected user online entry to exist")
	}
	entry := entryValue.(*userOnlineEntry)
	if remaining := entry.cleanStale(ipTTL); remaining > int32(users[0].DeviceLimit) {
		t.Fatalf("online device count = %d, want at most %d", remaining, users[0].DeviceLimit)
	}
	got := entry.snapshotIPs()
	sort.Strings(got)
	want := []string{"192.0.2.1", "198.51.100.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("local IP snapshot = %v, want %v", got, want)
	}
}

func TestLimiterFallsBackToLocalAdmissionWhenGlobalStateIsStale(t *testing.T) {
	base := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	current := base
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter failed: %v", err)
	}

	value, ok := l.InboundInfo.Load("inbound")
	if !ok {
		t.Fatal("expected inbound to exist")
	}
	globalDevices := value.(*InboundInfo).GlobalDevices
	globalDevices.ttl = time.Second
	globalDevices.now = func() time.Time { return current }

	userKey := "inbound|user@example.com|1"
	if _, _, rejected := l.GetUserBucket("inbound", userKey, "192.0.2.1"); rejected {
		t.Fatal("expected first local IP to be allowed")
	}
	if err := l.UpdateGlobalDevices("inbound", map[int][]string{1: []string{"203.0.113.1"}}); err != nil {
		t.Fatalf("UpdateGlobalDevices failed: %v", err)
	}

	current = base.Add(2 * time.Second)
	if _, _, rejected := l.GetUserBucket("inbound", userKey, "198.51.100.1"); !rejected {
		t.Fatal("expected stale global state to fall back to local-only admission and reject at local limit")
	}
}

func TestLimiterFallsBackToLocalAdmissionWhenGlobalStateIsCleared(t *testing.T) {
	l := New()
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", DeviceLimit: 1}}
	if err := l.AddInboundLimiter("inbound", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter failed: %v", err)
	}

	userKey := "inbound|user@example.com|1"
	if _, _, rejected := l.GetUserBucket("inbound", userKey, "192.0.2.1"); rejected {
		t.Fatal("expected first local IP to be allowed")
	}
	if err := l.UpdateGlobalDevices("inbound", map[int][]string{1: []string{"203.0.113.1"}}); err != nil {
		t.Fatalf("UpdateGlobalDevices failed: %v", err)
	}
	if err := l.ClearGlobalDevices("inbound"); err != nil {
		t.Fatalf("ClearGlobalDevices failed: %v", err)
	}

	if _, _, rejected := l.GetUserBucket("inbound", userKey, "198.51.100.1"); !rejected {
		t.Fatal("expected cleared global state to fall back to local-only admission and reject at local limit")
	}
}

func TestLimiterSnapshotRestoreInboundLimiterState(t *testing.T) {
	l := New()
	users := []api.UserInfo{{
		UID:         1,
		Email:       "u@example.com",
		SpeedLimit:  100,
		DeviceLimit: 1,
	}}
	if err := l.AddInboundLimiter("tag", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter failed: %v", err)
	}

	userKey := "tag|u@example.com|1"
	if bucket, speedLimited, rejected := l.GetUserBucket("tag", userKey, "192.0.2.1"); rejected || !speedLimited || bucket == nil {
		t.Fatalf("expected initial user bucket, speedLimited=%v rejected=%v bucket=%v", speedLimited, rejected, bucket)
	}

	value, ok := l.InboundInfo.Load("tag")
	if !ok {
		t.Fatal("expected inbound to exist")
	}
	originalInboundInfo := value.(*InboundInfo)
	originalUserInfo := originalInboundInfo.UserInfo
	originalBucketHub := originalInboundInfo.BucketHub
	originalUserOnlineIP := originalInboundInfo.UserOnlineIP
	originalGlobalDevices := originalInboundInfo.GlobalDevices
	originalGlobalLimit := originalInboundInfo.GlobalLimit

	if err := l.UpdateGlobalDevices("tag", map[int][]string{1: []string{"203.0.113.7"}}); err != nil {
		t.Fatalf("UpdateGlobalDevices failed: %v", err)
	}
	if !originalGlobalDevices.ShouldReject(1, "203.0.113.8", 1, nil) {
		t.Fatal("expected global device state to reject a second IP before restore")
	}

	snapshot, err := l.SnapshotInboundLimiterState("tag")
	if err != nil {
		t.Fatalf("SnapshotInboundLimiterState failed: %v", err)
	}

	updatedUsers := []api.UserInfo{{
		UID:         1,
		Email:       "u@example.com",
		SpeedLimit:  200,
		DeviceLimit: 2,
	}}
	if err := l.UpdateInboundLimiter("tag", &updatedUsers); err != nil {
		t.Fatalf("UpdateInboundLimiter failed: %v", err)
	}

	if err := l.RestoreInboundLimiterState("tag", snapshot); err != nil {
		t.Fatalf("RestoreInboundLimiterState failed: %v", err)
	}

	value, ok = l.InboundInfo.Load("tag")
	if !ok {
		t.Fatal("expected inbound to exist")
	}
	inboundInfo := value.(*InboundInfo)
	if inboundInfo == originalInboundInfo {
		t.Fatal("expected restore to publish a replacement inbound info")
	}
	if inboundInfo.UserInfo == originalUserInfo {
		t.Fatal("expected restore to replace UserInfo with a fresh map")
	}
	if inboundInfo.BucketHub == originalBucketHub {
		t.Fatal("expected restore to replace BucketHub with a fresh map")
	}
	if inboundInfo.UserOnlineIP != originalUserOnlineIP {
		t.Fatal("expected restore to preserve UserOnlineIP state")
	}
	if inboundInfo.GlobalDevices != originalGlobalDevices {
		t.Fatal("expected restore to preserve GlobalDevices state")
	}
	if inboundInfo.GlobalLimit != originalGlobalLimit {
		t.Fatal("expected restore to preserve GlobalLimit state")
	}
	entryValue, ok := inboundInfo.UserOnlineIP.Load(userKey)
	if !ok || !entryValue.(*userOnlineEntry).hasIP("192.0.2.1") {
		t.Fatal("expected restore to preserve existing online IP state")
	}
	if !inboundInfo.GlobalDevices.ShouldReject(1, "203.0.113.8", 1, nil) {
		t.Fatal("expected restore to preserve global device state")
	}

	restoredValue, ok := inboundInfo.UserInfo.Load(userKey)
	if !ok {
		t.Fatalf("expected restored user info for key %s", userKey)
	}
	restored := restoredValue.(UserInfo)
	if restored.SpeedLimit != 100 || restored.DeviceLimit != 1 {
		t.Fatalf("restored user info = %#v, want SpeedLimit=100 DeviceLimit=1", restored)
	}

	bucketValue, ok := inboundInfo.BucketHub.Load(userKey)
	if !ok {
		t.Fatalf("expected restored bucket for key %s", userKey)
	}
	restoredBucket := bucketValue.(*rate.Limiter)
	if restoredBucket.Limit() != rate.Limit(100) || restoredBucket.Burst() != 100 {
		t.Fatalf("restored bucket limit=%v burst=%d, want limit=100 burst=100", restoredBucket.Limit(), restoredBucket.Burst())
	}
}
