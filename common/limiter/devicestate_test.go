package limiter

import (
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
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

func TestGlobalDeviceStateReplaceCopiesInput(t *testing.T) {
	base := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	state := &globalDeviceState{
		ttl: defaultGlobalDeviceTTL,
		now: func() time.Time { return base },
	}
	devices := map[int][]string{1: []string{"192.0.2.1", "198.51.100.1"}}

	state.Replace(devices)
	devices[1][0] = "203.0.113.1"
	devices[1] = append(devices[1], "203.0.113.2")
	devices[2] = []string{"203.0.113.3"}

	if state.ShouldReject(1, "192.0.2.1", 2, nil) {
		t.Fatal("expected original copied IP to remain allowed after caller mutates input")
	}
	if !state.ShouldReject(1, "203.0.113.1", 2, nil) {
		t.Fatal("expected mutated caller IP not to affect copied state")
	}
	if state.ShouldReject(2, "203.0.113.3", 1, nil) {
		t.Fatal("expected new caller map entry after Replace not to affect copied state")
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
