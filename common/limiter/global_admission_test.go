package limiter

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// disabledConfig returns an enabled baseline config that never reaches Redis
// for tests that only exercise local policy and status behavior.
func localAdmissionConfig(namespace string) *GlobalDeviceLimitConfig {
	prefix := defaultGlobalIPv6Prefix
	return &GlobalDeviceLimitConfig{
		Enable:     true,
		RedisAddr:  "127.0.0.1:1", // guaranteed unreachable; used only for outage tests
		Timeout:    1,
		Expiry:     minGlobalAdmissionExpiry,
		Namespace:  namespace,
		IPv6Prefix: &prefix,
	}
}

func TestNewGlobalAdmissionDisabledReturnsNil(t *testing.T) {
	for _, config := range []*GlobalDeviceLimitConfig{nil, {Enable: false}, {}} {
		admission, err := NewGlobalAdmission(config, "NewV2board", "https://panel.example.test")
		if err != nil || admission != nil {
			t.Fatalf("NewGlobalAdmission(%+v) = %v, %v; want nil, nil", config, admission, err)
		}
	}
}

func TestNormalizeGlobalIP(t *testing.T) {
	prefix64 := 64
	prefix0 := 0
	prefix48 := 48
	prefix128 := 128
	tests := []struct {
		name    string
		ip      string
		prefix  *int
		want    string
		wantErr bool
	}{
		{name: "ipv4", ip: " 192.0.2.10 ", want: "192.0.2.10"},
		{name: "ipv4 mapped", ip: "::ffff:192.0.2.10", want: "192.0.2.10"},
		{name: "ipv6 default 64", ip: "2001:db8:1:2:3:4:5:6", want: "2001:db8:1:2::"},
		{name: "ipv6 explicit 64", ip: "2001:db8::1", prefix: &prefix64, want: "2001:db8::"},
		{name: "ipv6 explicit 48", ip: "2001:db8:1:2::9", prefix: &prefix48, want: "2001:db8:1::"},
		{name: "ipv6 prefix 0 means full", ip: "2001:db8::1", prefix: &prefix0, want: "2001:db8::1"},
		{name: "ipv6 prefix 128", ip: "2001:db8::1", prefix: &prefix128, want: "2001:db8::1"},
		{name: "mapped ipv6 prefix ignored", ip: "::ffff:192.0.2.10", prefix: &prefix48, want: "192.0.2.10"},
		{name: "empty", ip: "   ", wantErr: true},
		{name: "invalid", ip: "not-an-ip", wantErr: true},
		{name: "zone rejected", ip: "fe80::1%eth0", wantErr: true},
		{name: "prefix below range", ip: "2001:db8::1", prefix: intPtr(-1), wantErr: true},
		{name: "prefix above range", ip: "2001:db8::1", prefix: intPtr(129), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeGlobalIP(test.ip, test.prefix)
			if test.wantErr {
				if err == nil {
					t.Fatalf("NormalizeGlobalIP(%q, %v) = %q, nil; want error", test.ip, test.prefix, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeGlobalIP(%q, %v) error = %v", test.ip, test.prefix, err)
			}
			if got != test.want {
				t.Fatalf("NormalizeGlobalIP(%q, %v) = %q, want %q", test.ip, test.prefix, got, test.want)
			}
		})
	}
}

func intPtr(value int) *int { return &value }

func TestValidateGlobalDeviceLimitConfig(t *testing.T) {
	strictForwarded := &GlobalDeviceLimitConfig{
		Enable:               true,
		Timeout:              5,
		Expiry:               60,
		Namespace:            "validation",
		Mode:                 "strict",
		StrictClientIPSource: "forwarded",
	}
	tests := []struct {
		name      string
		config    *GlobalDeviceLimitConfig
		forwarded bool
		wantErr   bool
	}{
		{name: "nil", config: nil},
		{name: "disabled ignores invalid", config: &GlobalDeviceLimitConfig{Enable: false, Expiry: -5}},
		{name: "defaults", config: &GlobalDeviceLimitConfig{Enable: true, Namespace: "ok"}},
		{name: "strict explicit forwarded", config: strictForwarded, forwarded: true},
		{name: "strict without forwarded config", config: &GlobalDeviceLimitConfig{Enable: true, Namespace: "ok", Mode: "strict"}},
		{name: "strict forwarded unacknowledged", config: &GlobalDeviceLimitConfig{Enable: true, Namespace: "ok", Mode: "strict"}, forwarded: true, wantErr: true},
		{name: "strict direct ack with forwarded", config: &GlobalDeviceLimitConfig{Enable: true, Namespace: "ok", Mode: "strict", StrictClientIPSource: "peer"}, forwarded: true, wantErr: true},
		{name: "bad mode", config: &GlobalDeviceLimitConfig{Enable: true, Namespace: "ok", Mode: "eventual"}, wantErr: true},
		{name: "bad fail mode", config: &GlobalDeviceLimitConfig{Enable: true, Namespace: "ok", FailMode: "deny"}, wantErr: true},
		{name: "bad source", config: &GlobalDeviceLimitConfig{Enable: true, Namespace: "ok", StrictClientIPSource: "header"}, wantErr: true},
		{name: "negative expiry", config: &GlobalDeviceLimitConfig{Enable: true, Namespace: "ok", Expiry: -1}, wantErr: true},
		{name: "too small expiry", config: &GlobalDeviceLimitConfig{Enable: true, Namespace: "ok", Expiry: minGlobalAdmissionExpiry - 1}, wantErr: true},
		{name: "negative timeout", config: &GlobalDeviceLimitConfig{Enable: true, Namespace: "ok", Timeout: -1}, wantErr: true},
		{name: "negative prefix", config: &GlobalDeviceLimitConfig{Enable: true, Namespace: "ok", IPv6Prefix: intPtr(-1)}, wantErr: true},
		{name: "prefix above range", config: &GlobalDeviceLimitConfig{Enable: true, Namespace: "ok", IPv6Prefix: intPtr(129)}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateGlobalDeviceLimitConfig(test.config, test.forwarded)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateGlobalDeviceLimitConfig(%+v, %v) error = %v, wantErr %v", test.config, test.forwarded, err, test.wantErr)
			}
		})
	}
}

func TestGlobalAdmissionNamespaceIsStableAndSecretFree(t *testing.T) {
	config := &GlobalDeviceLimitConfig{Enable: true, RedisUsername: "redis-user", RedisPassword: "redis-{{PASSWORD_f4vxj2s0}}"}
	first, err := globalAdmissionNamespace(config, "NewV2board", "HTTPS://Panel.Example.Test/")
	if err != nil {
		t.Fatalf("globalAdmissionNamespace() error = %v", err)
	}
	alias, err := globalAdmissionNamespace(config, "V2board", "https://panel.example.test")
	if err != nil {
		t.Fatalf("globalAdmissionNamespace(alias) error = %v", err)
	}
	if alias != first {
		t.Fatalf("canonical panel aliases differ: %q vs %q", alias, first)
	}
	if len(first) != globalAdmissionNamespaceLength {
		t.Fatalf("namespace length = %d, want %d", len(first), globalAdmissionNamespaceLength)
	}
	if strings.Contains(first, "panel") || strings.Contains(first, "redis") {
		t.Fatalf("namespace leaks identity or credentials: %q", first)
	}

	otherHost, err := globalAdmissionNamespace(config, "NewV2board", "https://other.example.test")
	if err != nil {
		t.Fatalf("globalAdmissionNamespace(other host) error = %v", err)
	}
	if otherHost == first {
		t.Fatal("different API hosts produced the same namespace")
	}

	overrideConfig := &GlobalDeviceLimitConfig{Enable: true, Namespace: "opted-in-namespace"}
	override, err := globalAdmissionNamespace(overrideConfig, "", "")
	if err != nil {
		t.Fatalf("globalAdmissionNamespace(override) error = %v", err)
	}
	if override == first || strings.Contains(override, "opted-in-namespace") {
		t.Fatalf("override namespace is not hashed independently: %q", override)
	}

	if _, err := globalAdmissionNamespace(&GlobalDeviceLimitConfig{Enable: true}, "NewV2board", ""); err == nil {
		t.Fatal("missing API host and namespace accepted")
	}
	if _, err := globalAdmissionNamespace(&GlobalDeviceLimitConfig{Enable: true}, "", "https://panel.example.test"); err == nil {
		t.Fatal("missing panel type and namespace accepted")
	}
	if _, err := globalAdmissionNamespace(&GlobalDeviceLimitConfig{Enable: true}, "NewV2board", "ftp://panel.example.test"); err == nil {
		t.Fatal("non-HTTP API host accepted")
	}
}

func TestGlobalAdmissionNilReceiverIsSafe(t *testing.T) {
	var admission *GlobalAdmission
	lease, err := admission.Acquire(context.Background(), 1, "192.0.2.1", 1)
	if err != nil || lease != nil {
		t.Fatalf("nil Acquire() = %v, %v; want nil, nil", lease, err)
	}
	if err := lease.Commit(); err != nil {
		t.Fatalf("nil lease Commit() = %v", err)
	}
	if err := lease.Abort(); err != nil {
		t.Fatalf("nil lease Abort() = %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("nil lease Close() = %v", err)
	}
	if lease.GlobalConfirmed() {
		t.Fatal("nil lease GlobalConfirmed() = true")
	}
	if status := admission.StatusSnapshot(); status.Degraded || status.Reason != "" {
		t.Fatalf("nil admission StatusSnapshot() = %+v", status)
	}
	if live := admission.LiveIPs(); live != nil {
		t.Fatalf("nil admission LiveIPs() = %v", live)
	}
	admission.UpdateLimit(1, 2)
	admission.SetUsers(map[int]int{1: 2})
	if err := admission.Close(); err != nil {
		t.Fatalf("nil admission Close() = %v", err)
	}
}

func TestGlobalAdmissionRejectsInvalidIPAndClosedManager(t *testing.T) {
	admission, err := NewGlobalAdmission(localAdmissionConfig("closed-manager"), "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })

	if _, err := admission.Acquire(context.Background(), 1, "not-an-ip", 1); err == nil {
		t.Fatal("Acquire() accepted an invalid source IP")
	}
	if err := admission.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	// A closed manager is a lifecycle condition: even FailMode=open must not
	// silently accept new connections with a nil lease.
	for _, failMode := range []string{"", "closed"} {
		config := localAdmissionConfig("closed-manager-" + failMode)
		config.FailMode = failMode
		other, err := NewGlobalAdmission(config, "", "")
		if err != nil {
			t.Fatalf("NewGlobalAdmission(%q) error = %v", failMode, err)
		}
		if err := other.Close(); err != nil {
			t.Fatalf("Close(%q) = %v", failMode, err)
		}
		if _, err := other.Acquire(context.Background(), 1, "192.0.2.1", 1); !errors.Is(err, ErrGlobalAdmissionUnavailable) {
			t.Fatalf("Acquire() on closed manager (%q) error = %v, want ErrGlobalAdmissionUnavailable", failMode, err)
		}
	}
}

func TestGlobalAdmissionHonorsCanceledContext(t *testing.T) {
	admission, err := NewGlobalAdmission(localAdmissionConfig("canceled-context"), "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := admission.Acquire(ctx, 1, "192.0.2.1", 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire() with canceled context error = %v, want context.Canceled", err)
	}
}

func TestGlobalAdmissionFailClosedRejectsOnOutage(t *testing.T) {
	config := localAdmissionConfig("fail-closed")
	config.FailMode = "closed"
	admission, err := NewGlobalAdmission(config, "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })

	if _, err := admission.Acquire(context.Background(), 1, "192.0.2.1", 1); !errors.Is(err, ErrGlobalAdmissionUnavailable) {
		t.Fatalf("Acquire() error = %v, want ErrGlobalAdmissionUnavailable", err)
	}
	if !admission.StatusSnapshot().Degraded {
		t.Fatal("FailMode=closed outage did not report degraded")
	}
}

func TestGlobalAdmissionFailOpenKeepsLocalQuota(t *testing.T) {
	config := localAdmissionConfig("fail-open")
	admission, err := NewGlobalAdmission(config, "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })
	admission.SetUsers(map[int]int{1: 1})

	first, err := admission.Acquire(context.Background(), 1, "192.0.2.1", 1)
	if err != nil || first == nil {
		t.Fatalf("Acquire(first IP) = %v, %v; want local lease", first, err)
	}
	if first.GlobalConfirmed() {
		t.Fatal("fail-open lease claimed a confirmed Redis reservation")
	}
	if err := first.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if !admission.StatusSnapshot().Degraded {
		t.Fatal("fail-open local lease did not report degraded")
	}
	if _, err := admission.Acquire(context.Background(), 1, "192.0.2.2", 1); !errors.Is(err, ErrGlobalAdmissionQuota) {
		t.Fatalf("Acquire(second IP) error = %v, want ErrGlobalAdmissionQuota", err)
	}
	// The same normalized IP is not a new device.
	again, err := admission.Acquire(context.Background(), 1, "192.0.2.1", 1)
	if err != nil || again == nil {
		t.Fatalf("Acquire(same IP) = %v, %v; want local lease", again, err)
	}
	if err := again.Abort(); err != nil {
		t.Fatalf("Abort(same IP) = %v", err)
	}

	if live := admission.LiveIPs(); len(live[1]) != 1 || live[1][0] != "192.0.2.1" {
		t.Fatalf("LiveIPs() = %#v, want 192.0.2.1", live)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if live := admission.LiveIPs(); len(live) != 0 {
		t.Fatalf("LiveIPs() after close = %#v, want empty", live)
	}
}

func TestGlobalAdmissionDegradedLatchRequiresAllHolders(t *testing.T) {
	admission, err := NewGlobalAdmission(localAdmissionConfig("degraded-latch"), "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })

	admission.recordBackendFailure()
	if status := admission.StatusSnapshot(); !status.Degraded || status.Reason == "" {
		t.Fatalf("Status() after failure = %+v, want degraded with reason", status)
	}
	admission.recordBackendSuccess()
	if admission.StatusSnapshot().Degraded {
		t.Fatal("StatusSnapshot() stayed degraded with no lost holders")
	}

	key := globalAdmissionHolderKey{uid: 7, ip: "192.0.2.7"}
	admission.mu.Lock()
	admission.holders[key] = &globalAdmissionHolder{uid: 7, ip: "192.0.2.7", live: 1, lost: true}
	admission.mu.Unlock()

	admission.recordBackendFailure()
	admission.recordBackendSuccess()
	if !admission.StatusSnapshot().Degraded {
		t.Fatal("degraded latch cleared while a live holder is still lost")
	}

	admission.mu.Lock()
	admission.holders[key].lost = false
	admission.mu.Unlock()
	admission.recordBackendSuccess()
	if admission.StatusSnapshot().Degraded {
		t.Fatal("degraded latch did not clear after the last holder recovered")
	}
}

func TestGlobalAdmissionLeaseStateMachineIsIdempotent(t *testing.T) {
	admission, err := NewGlobalAdmission(localAdmissionConfig("lease-state"), "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })
	admission.SetUsers(map[int]int{1: 2})

	lease, err := admission.Acquire(context.Background(), 1, "192.0.2.1", 2)
	if err != nil || lease == nil {
		t.Fatalf("Acquire() = %v, %v", lease, err)
	}
	if err := lease.Commit(); err != nil {
		t.Fatalf("Commit() = %v", err)
	}
	if err := lease.Commit(); err != nil {
		t.Fatalf("second Commit() = %v", err)
	}
	if err := lease.Abort(); err != nil {
		t.Fatalf("Abort() after Commit() = %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
	if live := admission.LiveIPs(); len(live) != 0 {
		t.Fatalf("LiveIPs() = %#v, want empty", live)
	}
}

func TestGlobalAdmissionConcurrentLocalQuotaIsAtomic(t *testing.T) {
	admission, err := NewGlobalAdmission(localAdmissionConfig("local-race"), "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })
	admission.SetUsers(map[int]int{1: 1})

	const attempts = 8
	var admitted sync.WaitGroup
	admitted.Add(attempts)
	leases := make([]*GlobalLease, attempts)
	errorsByIndex := make([]error, attempts)
	for index := 0; index < attempts; index++ {
		go func(index int) {
			defer admitted.Done()
			// Distinct IPs contend for the single local slot.
			lease, err := admission.Acquire(context.Background(), 1, "198.51.100."+itoa(index+1), 1)
			leases[index], errorsByIndex[index] = lease, err
			if lease != nil {
				_ = lease.Commit()
			}
		}(index)
	}
	admitted.Wait()

	allowed := 0
	for index := 0; index < attempts; index++ {
		if errorsByIndex[index] == nil {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("local quota admitted %d of %d distinct IPs, want 1", allowed, attempts)
	}
	for _, lease := range leases {
		if lease != nil {
			_ = lease.Close()
		}
	}
}

func itoa(value int) string {
	return strconv.Itoa(value)
}

func TestGlobalAdmissionPolicyMinimumIgnoresZero(t *testing.T) {
	admission, err := NewGlobalAdmission(localAdmissionConfig("policy-minimum"), "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })

	admission.SetUsers(map[int]int{1: 0, 2: 2})
	admission.mu.Lock()
	zeroPolicy := admission.localEffectiveLimitLocked(1, 5)
	positivePolicy := admission.localEffectiveLimitLocked(2, 5)
	unknownPolicy := admission.localEffectiveLimitLocked(3, 4)
	admission.mu.Unlock()
	// A zero registration must not remove or override the caller's limit, and
	// it must never act as "unlimited".
	if zeroPolicy != 5 {
		t.Fatalf("localEffectiveLimitLocked(zero policy) = %d, want caller limit 5", zeroPolicy)
	}
	if positivePolicy != 2 {
		t.Fatalf("localEffectiveLimitLocked(positive policy) = %d, want 2", positivePolicy)
	}
	if unknownPolicy != 4 {
		t.Fatalf("localEffectiveLimitLocked(unknown policy) = %d, want caller limit 4", unknownPolicy)
	}
}

func TestGlobalAdmissionStatusIsCredentialFree(t *testing.T) {
	config := localAdmissionConfig("status-redaction")
	config.RedisUsername = "status-user"
	config.RedisPassword = "status-{{PASSWORD_7j5q2d8m}}"
	admission, err := NewGlobalAdmission(config, "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })
	admission.recordBackendFailure()

	status := admission.StatusSnapshot()
	if !status.Degraded {
		t.Fatal("StatusSnapshot() did not report degraded")
	}
	rendered := status.Reason
	if strings.Contains(rendered, "status-user") || strings.Contains(rendered, "{{PASSWORD_7j5q2d8m}}") {
		t.Fatalf("StatusSnapshot() reason leaked credentials: %q", rendered)
	}
	if strings.Contains(rendered, "192.0.2") {
		t.Fatalf("StatusSnapshot() reason leaked addresses: %q", rendered)
	}
}

func TestGlobalAdmissionLeaseDoesNotCommitAfterClose(t *testing.T) {
	admission, err := NewGlobalAdmission(localAdmissionConfig("late-commit"), "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	admission.SetUsers(map[int]int{1: 1})
	lease, err := admission.Acquire(context.Background(), 1, "192.0.2.1", 1)
	if err != nil || lease == nil {
		t.Fatalf("Acquire() = %v, %v", lease, err)
	}
	if err := admission.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if err := lease.Commit(); !errors.Is(err, ErrGlobalAdmissionUnavailable) {
		t.Fatalf("Commit() after Close() error = %v, want ErrGlobalAdmissionUnavailable", err)
	}
	_ = lease.Close()
}

func TestGlobalAdmissionRenewWorkerStopsOnClose(t *testing.T) {
	admission, err := NewGlobalAdmission(localAdmissionConfig("worker-stop"), "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = admission.Close()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not join the renewal worker")
	}
	_ = admission.Close()
}

func TestGlobalAdmissionRenewalRoundMarksUnreachedHoldersLost(t *testing.T) {
	admission, err := NewGlobalAdmission(localAdmissionConfig("renew-round"), "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })

	key := globalAdmissionHolderKey{uid: 31, ip: "192.0.2.31"}
	admission.mu.Lock()
	admission.holders[key] = &globalAdmissionHolder{uid: 31, ip: "192.0.2.31", live: 1, reserved: true}
	admission.mu.Unlock()

	// An already-expired round deadline must not leave holders silently
	// "healthy": they are marked lost and retried next tick.
	roundCtx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, snapshot := range admission.holderSnapshot() {
		if roundCtx.Err() != nil {
			admission.markHolderLost(snapshot)
			continue
		}
		admission.renewHolder(roundCtx, snapshot)
	}
	if status := admission.StatusSnapshot(); !status.Degraded {
		t.Fatalf("unreached holder did not degrade status: %+v", status)
	}
}

func TestGlobalAdmissionFailOpenSameIPDoesNotLeakSlots(t *testing.T) {
	admission, err := NewGlobalAdmission(localAdmissionConfig("fail-open-same-ip"), "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })
	admission.SetUsers(map[int]int{41: 1})

	first, err := admission.Acquire(context.Background(), 41, "2001:db8::1", 1)
	if err != nil || first == nil {
		t.Fatalf("Acquire(first) = %v, %v", first, err)
	}
	_ = first.Commit()

	// Same /64 through a different address is one device, not two.
	second, err := admission.Acquire(context.Background(), 41, "2001:db8::2", 1)
	if err != nil || second == nil {
		t.Fatalf("Acquire(same /64) = %v, %v; want allowed", second, err)
	}
	_ = second.Commit()

	if live := admission.LiveIPs(); len(live[41]) != 1 || live[41][0] != "2001:db8::" {
		t.Fatalf("LiveIPs() = %#v, want the single normalized /64", live)
	}
	if _, err := admission.Acquire(context.Background(), 41, "2001:db8:0:1::1", 1); !errors.Is(err, ErrGlobalAdmissionQuota) {
		t.Fatalf("different /64 error = %v, want quota", err)
	}

	_ = first.Close()
	// The second connection still holds the shared holder after the first close.
	if live := admission.LiveIPs(); len(live[41]) != 1 {
		t.Fatalf("LiveIPs() after one close = %#v, want the shared holder retained", live)
	}
	_ = second.Close()
	if live := admission.LiveIPs(); len(live) != 0 {
		t.Fatalf("LiveIPs() after last close = %#v, want empty", live)
	}
}

func TestGlobalAdmissionPolicyStaleLatchKeepsDegraded(t *testing.T) {
	admission, err := NewGlobalAdmission(localAdmissionConfig("policy-stale"), "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })
	admission.SetUsers(map[int]int{61: 2})

	// A policy publish failure must be visible on its own.
	admission.markPoliciesStale()
	status := admission.StatusSnapshot()
	if !status.Degraded || status.Reason != "policy registration stale" {
		t.Fatalf("StatusSnapshot() after stale policy = %+v, want policy registration stale", status)
	}

	// A successful holder renewal must NOT clear an unpublished policy view.
	admission.recordBackendFailure()
	admission.recordBackendSuccess()
	if !admission.StatusSnapshot().Degraded {
		t.Fatal("holder success cleared a stale policy view")
	}

	// Even with the backend marked healthy, the stale policy keeps it degraded.
	admission.mu.Lock()
	admission.backendFailed = false
	admission.mu.Unlock()
	if status := admission.StatusSnapshot(); !status.Degraded || status.Reason != "policy registration stale" {
		t.Fatalf("stale policy no longer reported: %+v", status)
	}

	// Only a successful publish clears it.
	admission.mu.Lock()
	admission.policiesStale = false
	admission.mu.Unlock()
	admission.recordBackendSuccess()
	if status := admission.StatusSnapshot(); status.Degraded {
		t.Fatalf("StatusSnapshot() stayed degraded after publish: %+v", status)
	}
}

func TestGlobalAdmissionCallerCancelIsPromptAtBoundaries(t *testing.T) {
	// Hold the per-key semaphore so a second Acquire for the same uid/IP blocks
	// in the wait, where cancellation must be honored immediately.
	admission, err := NewGlobalAdmission(localAdmissionConfig("caller-cancel-queue"), "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })

	lock := admission.keyLock(63, "192.0.2.63")
	lock <- struct{}{}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := admission.Acquire(ctx, 63, "192.0.2.63", 1)
		result <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancelledAt := time.Now()
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Acquire() error = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(cancelledAt); elapsed > time.Second {
			t.Fatalf("cancellation honored after %s, want prompt", elapsed)
		}
	case <-time.After(5 * time.Second):
		<-lock
		t.Fatal("Acquire() ignored caller cancellation while queued")
	}
	<-lock
}

// TestGlobalAdmissionInFlightCommandIsBoundedByTimeout documents the real
// guarantee: the classic go-redis path sets its socket deadline from
// ctx.Deadline() and does not watch ctx.Done() during a blocking read, so a
// cancellation that arrives while one command is in flight is honored after
// that command returns, at worst Timeout. It must still be reported as the
// caller's error and must not degrade backend status.
func TestGlobalAdmissionInFlightCommandIsBoundedByTimeout(t *testing.T) {
	if os.Getenv("XRAYRP_RUN_REDIS_INTEGRATION") == "1" {
		t.Skip("covered by real-Redis integration runs")
	}
	// A listener that never accepts: dial succeeds from the backlog, the reply
	// read blocks until the client's deadline.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	config := localAdmissionConfig("caller-cancel-inflight")
	config.RedisAddr = listener.Addr().String()
	config.Timeout = 2
	admission, err := NewGlobalAdmission(config, "", "")
	if err != nil {
		t.Fatalf("NewGlobalAdmission() error = %v", err)
	}
	t.Cleanup(func() { _ = admission.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := admission.Acquire(ctx, 64, "192.0.2.64", 1)
		result <- err
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Acquire() error = %v, want context.Canceled", err)
		}
		// Bounded by Timeout, and prompt relative to the 30s+ a real hang would
		// take. Allow scheduling slack.
		if elapsed := time.Since(start); elapsed > time.Duration(config.Timeout)*time.Second+3*time.Second {
			t.Fatalf("Acquire() took %s, want bounded by Timeout (%ds)", elapsed, config.Timeout)
		}
	case <-time.After(time.Duration(config.Timeout)*time.Second + 10*time.Second):
		t.Fatal("Acquire() never returned after caller cancellation")
	}

	if status := admission.StatusSnapshot(); status.Degraded {
		t.Fatalf("caller cancellation marked the backend degraded: %+v", status)
	}
}
