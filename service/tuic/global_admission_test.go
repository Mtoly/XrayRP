package tuic

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	commonlimiter "github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/service/controller"
	"golang.org/x/time/rate"
)

type fakeAdmissionAcquire struct {
	uid   int
	ip    string
	limit int
	lease *fakeAdmissionLease
	err   error
}

type fakeAdmissionLease struct {
	mu         sync.Mutex
	commits    int
	aborts     int
	closes     int
	commitErr  error
	abortErr   error
	closeErr   error
	committed  bool
	aborted    bool
	closeCalls []int
}

func (l *fakeAdmissionLease) Commit() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.commits++
	l.committed = true
	return l.commitErr
}

func (l *fakeAdmissionLease) Abort() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.aborts++
	l.aborted = true
	return l.abortErr
}

func (l *fakeAdmissionLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closes++
	return l.closeErr
}

func (l *fakeAdmissionLease) counts() (commits, aborts, closes int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.commits, l.aborts, l.closes
}

type fakeGlobalAdmission struct {
	mu          sync.Mutex
	acquires    []fakeAdmissionAcquire
	users       map[int]int
	setUsers    []map[int]int
	closed      int
	closeErr    error
	status      commonlimiter.GlobalAdmissionStatus
	nextLease   *fakeAdmissionLease
	acquireErrs []error
}

func (f *fakeGlobalAdmission) Acquire(_ context.Context, uid int, ip string, limit int) (globalLease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acquires = append(f.acquires, fakeAdmissionAcquire{uid: uid, ip: ip, limit: limit, lease: f.nextLease})
	if len(f.acquireErrs) > 0 {
		err := f.acquireErrs[0]
		f.acquireErrs = f.acquireErrs[1:]
		return nil, err
	}
	if f.nextLease == nil {
		return nil, nil
	}
	return f.nextLease, nil
}

func (f *fakeGlobalAdmission) SetUsers(limits map[int]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users = limits
	copied := make(map[int]int, len(limits))
	for uid, limit := range limits {
		copied[uid] = limit
	}
	f.setUsers = append(f.setUsers, copied)
}

func (f *fakeGlobalAdmission) StatusSnapshot() commonlimiter.GlobalAdmissionStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeGlobalAdmission) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return f.closeErr
}

func (f *fakeGlobalAdmission) acquireCalls() []fakeAdmissionAcquire {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeAdmissionAcquire(nil), f.acquires...)
}

func globalAdmissionTestService(t *testing.T, admission globalAdmission, limits map[string]int) *TuicService {
	t.Helper()
	svc := New(&configurablePanelClient{}, &controller.Config{})
	svc.globalAdmission = admission
	svc.users = make(map[string]userRecord)
	svc.traffic = make(map[string]*userTraffic)
	svc.onlineIPs = make(map[string]map[string]struct{})
	svc.ipLastActive = make(map[string]map[string]time.Time)
	svc.rateLimiters = make(map[string]*rate.Limiter)
	for key, limit := range limits {
		svc.users[key] = userRecord{UID: 17, DeviceLimit: limit}
	}
	return svc
}

func TestGlobalAdmissionAcquiresByUIDAndCommitsPerConnection(t *testing.T) {
	leaseOne := &fakeAdmissionLease{}
	leaseTwo := &fakeAdmissionLease{}
	admission := &fakeGlobalAdmission{nextLease: leaseOne}
	svc := globalAdmissionTestService(t, admission, map[string]int{"user": 2})

	device, lease, admitted := svc.allowConnection(context.Background(), "user", "192.0.2.1")
	if !admitted || lease == nil || device == nil {
		t.Fatalf("allowConnection() = (%v, %v, %v), want admitted", device, lease, admitted)
	}
	if commits, _, _ := leaseOne.counts(); commits != 1 {
		t.Fatalf("lease commits = %d, want 1", commits)
	}
	calls := admission.acquireCalls()
	if len(calls) != 1 || calls[0].uid != 17 || calls[0].limit != 2 {
		t.Fatalf("Acquire calls = %#v, want uid 17 limit 2", calls)
	}

	admission.mu.Lock()
	admission.nextLease = leaseTwo
	admission.mu.Unlock()
	deviceTwo, leaseTwoResult, admitted := svc.allowConnection(context.Background(), "user", "192.0.2.1")
	if !admitted || leaseTwoResult == nil {
		t.Fatal("second connection from the same IP was rejected")
	}
	if deviceTwo != device || leaseTwoResult == lease {
		t.Fatal("second connection did not share the local reservation with its own lease")
	}
	svc.mu.RLock()
	count := device.count
	svc.mu.RUnlock()
	if count != 2 {
		t.Fatalf("local reservation count = %d, want 2", count)
	}

	if err := lease.Close(); err != nil {
		t.Fatalf("first lease Close() = %v", err)
	}
	if _, _, closes := leaseOne.counts(); closes != 1 {
		t.Fatalf("first lease closes = %d, want 1", closes)
	}
	svc.mu.RLock()
	_, stillOnline := svc.onlineIPs["user"]["192.0.2.1"]
	svc.mu.RUnlock()
	if !stillOnline {
		t.Fatal("closing one of two connections released the shared local slot")
	}
	svc.releaseConnection("user", "192.0.2.1", device)
	svc.releaseConnection("user", "192.0.2.1", device)
	svc.mu.RLock()
	_, retained := svc.onlineIPs["user"]["192.0.2.1"]
	svc.mu.RUnlock()
	if retained {
		t.Fatal("last local release retained the shared slot")
	}
}

func TestGlobalAdmissionRejectionLeavesNoLocalState(t *testing.T) {
	quotaErr := commonlimiter.ErrGlobalAdmissionQuota
	admission := &fakeGlobalAdmission{acquireErrs: []error{quotaErr}}
	svc := globalAdmissionTestService(t, admission, map[string]int{"user": 1})

	device, lease, admitted := svc.allowConnection(context.Background(), "user", "192.0.2.1")
	if admitted || device != nil || lease != nil {
		t.Fatalf("allowConnection() = (%v, %v, %v), want rejection", device, lease, admitted)
	}
	svc.mu.RLock()
	connections := len(svc.connections)
	ips := len(svc.onlineIPs)
	svc.mu.RUnlock()
	if connections != 0 || ips != 0 {
		t.Fatalf("rejection leaked local state: connections=%d ips=%d", connections, ips)
	}
}

func TestGlobalAdmissionCommitFailureReleasesLocalSlot(t *testing.T) {
	commitErr := errors.New("quota lost at commit")
	lease := &fakeAdmissionLease{commitErr: commitErr}
	admission := &fakeGlobalAdmission{nextLease: lease}
	svc := globalAdmissionTestService(t, admission, map[string]int{"user": 1})

	device, returned, admitted := svc.allowConnection(context.Background(), "user", "192.0.2.1")
	if admitted || device != nil || returned != nil {
		t.Fatalf("allowConnection() = (%v, %v, %v), want rejection", device, returned, admitted)
	}
	svc.mu.RLock()
	connections := len(svc.connections)
	ips := len(svc.onlineIPs)
	svc.mu.RUnlock()
	if connections != 0 || ips != 0 {
		t.Fatalf("commit failure leaked local state: connections=%d ips=%d", connections, ips)
	}
	if _, _, closes := lease.counts(); closes != 1 {
		t.Fatalf("commit failure lease closes = %d, want renewal stopped once", closes)
	}
}

func TestGlobalAdmissionBypassesLocalCapacityButKeepsReporting(t *testing.T) {
	leaseOne := &fakeAdmissionLease{}
	admission := &fakeGlobalAdmission{nextLease: leaseOne}
	svc := globalAdmissionTestService(t, admission, map[string]int{"user": 1})

	if _, lease, admitted := svc.allowConnection(context.Background(), "user", "192.0.2.1"); !admitted || lease == nil {
		t.Fatal("first IP rejected")
	}
	// A second distinct IP exceeds the local DeviceLimit=1, but the shared
	// manager owns capacity, so it must be admitted and still reported.
	admission.mu.Lock()
	admission.nextLease = &fakeAdmissionLease{}
	admission.mu.Unlock()
	if _, lease, admitted := svc.allowConnection(context.Background(), "user", "192.0.2.2"); !admitted || lease == nil {
		t.Fatal("global mode rejected a second IP using stale local capacity")
	}
	_, online, _ := svc.collectUsage()
	if len(online) != 2 {
		t.Fatalf("online users = %d, want 2 reported IPs", len(online))
	}
}

func TestSyncUsersPublishesUIDDeviceLimitsToGlobalAdmission(t *testing.T) {
	admission := &fakeGlobalAdmission{}
	svc := globalAdmissionTestService(t, admission, nil)
	svc.box = &fakeRuntimeInstance{events: &lifecycleEvents{}}
	users := []api.UserInfo{
		{UID: 11, UUID: "uuid-a", Passwd: "pass-a", DeviceLimit: 3},
		{UID: 12, UUID: "uuid-b", DeviceLimit: 0},
	}
	if err := svc.syncUsers(&users); err != nil {
		t.Fatalf("syncUsers() error = %v", err)
	}
	admission.mu.Lock()
	limits := admission.users
	admission.mu.Unlock()
	if len(limits) != 2 || limits[11] != 3 || limits[12] != 0 {
		t.Fatalf("SetUsers limits = %#v, want {11:3, 12:0}", limits)
	}
}

func TestCloseStopsConnectionLeaseAndManager(t *testing.T) {
	lease := &fakeAdmissionLease{}
	admission := &fakeGlobalAdmission{nextLease: lease}
	svc := globalAdmissionTestService(t, admission, map[string]int{"user": 1})
	svc.box = &fakeRuntimeInstance{events: &lifecycleEvents{}}
	svc.state = stateRunning
	conn := trackDeviceTestConnection(svc, "192.0.2.1", false)
	svc.mu.Lock()
	stored := svc.connections["user"]["192.0.2.1"]
	svc.mu.Unlock()
	if stored == nil {
		t.Fatal("connection did not create a reservation")
	}

	if err := svc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	admission.mu.Lock()
	closed := admission.closed
	admission.mu.Unlock()
	if closed == 0 {
		t.Fatal("service close did not release the admission manager")
	}
	if svc.globalAdmission != nil {
		t.Fatal("service retained the admission manager after close")
	}
	// The connection still owns its lease object. Closing it after the
	// manager stopped is local cleanup only and must stay idempotent.
	if err := conn.Close(); err != nil {
		t.Fatalf("late connection Close() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("repeated connection Close() error = %v", err)
	}
	if _, _, closes := lease.counts(); closes != 1 {
		t.Fatalf("lease closes = %d, want one idempotent stop", closes)
	}
}

func TestObservabilityReportsGlobalDeviceDegraded(t *testing.T) {
	admission := &fakeGlobalAdmission{status: commonlimiter.GlobalAdmissionStatus{Degraded: true, Reason: "redis unavailable"}}
	svc := globalAdmissionTestService(t, admission, nil)
	svc.state = stateRunning
	if !svc.ObservabilitySnapshot().GlobalDeviceDegraded {
		t.Fatal("degraded admission was not surfaced in the runtime snapshot")
	}
	admission.mu.Lock()
	admission.status = commonlimiter.GlobalAdmissionStatus{}
	admission.mu.Unlock()
	if svc.ObservabilitySnapshot().GlobalDeviceDegraded {
		t.Fatal("healthy admission reported degraded")
	}
}

func TestBuildGlobalAdmissionIdentityRequirements(t *testing.T) {
	t.Run("disabled returns nil", func(t *testing.T) {
		svc := New(&configurablePanelClient{}, &controller.Config{})
		admission, err := svc.buildGlobalAdmission(api.ClientInfo{APIHost: "https://panel.example"})
		if err != nil || admission != nil {
			t.Fatalf("buildGlobalAdmission() = (%v, %v), want (nil, nil)", admission, err)
		}
	})

	t.Run("missing identity fails", func(t *testing.T) {
		svc := New(&configurablePanelClient{}, &controller.Config{
			GlobalDeviceLimitConfig: &commonlimiter.GlobalDeviceLimitConfig{Enable: true},
		})
		if _, err := svc.buildGlobalAdmission(api.ClientInfo{}); err == nil {
			t.Fatal("enabled admission without panel identity succeeded")
		}
	})
}

func TestStartPublishesGlobalAdmissionBeforeRuntimeCanAccept(t *testing.T) {
	events := &lifecycleEvents{}
	admission := &fakeGlobalAdmission{}
	svc := newStartTestService(events, &fakeRuntimeInstance{events: events})
	svc.config.GlobalDeviceLimitConfig = &commonlimiter.GlobalDeviceLimitConfig{Enable: true}
	svc.admissionFactory = func(api.ClientInfo) (globalAdmission, error) { return admission, nil }
	var managerAtRuntimeStart globalAdmission
	svc.startRuntime = func(runtimeInstance) error {
		svc.mu.RLock()
		managerAtRuntimeStart = svc.globalAdmission
		svc.mu.RUnlock()
		return nil
	}

	if err := svc.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer svc.Close()
	if managerAtRuntimeStart != admission {
		t.Fatal("runtime could accept connections before the global manager was published")
	}
	admission.mu.Lock()
	setUsersCalls := len(admission.setUsers)
	admission.mu.Unlock()
	if setUsersCalls == 0 {
		t.Fatal("startup user snapshot was not registered with the global manager")
	}
}

func TestStartFailureReleasesUnpublishedGlobalAdmission(t *testing.T) {
	events := &lifecycleEvents{}
	closeErr := errors.New("close failed")
	admission := &fakeGlobalAdmission{}
	svc := newStartTestService(events, &fakeRuntimeInstance{events: events})
	svc.config.GlobalDeviceLimitConfig = &commonlimiter.GlobalDeviceLimitConfig{Enable: true}
	svc.admissionFactory = func(api.ClientInfo) (globalAdmission, error) { return admission, nil }
	svc.startRuntime = func(runtimeInstance) error { return errors.New("runtime start failed") }
	svc.closeRuntime = func(runtimeInstance) error { return closeErr }

	err := svc.Start()
	if !errors.Is(err, closeErr) {
		t.Fatalf("Start() error = %v, want cleanup failure %v", err, closeErr)
	}
	svc.mu.RLock()
	manager := svc.globalAdmission
	svc.mu.RUnlock()
	admission.mu.Lock()
	closed := admission.closed
	admission.mu.Unlock()
	// StartCleanupFailed keeps runtime ownership, so the manager stays
	// installed for the still-live runtime and Close releases it.
	if manager != admission || closed != 0 {
		t.Fatalf("failed start with retained runtime dropped manager: manager=%v closed=%d", manager, closed)
	}
	svc.closeRuntime = func(runtimeInstance) error { return nil }
	if err := svc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	admission.mu.Lock()
	closed = admission.closed
	admission.mu.Unlock()
	if closed == 0 {
		t.Fatal("Close() after retained runtime did not release the manager")
	}
}

func TestStartFailureSurfacesGlobalAdmissionCloseError(t *testing.T) {
	events := &lifecycleEvents{}
	closeErr := errors.New("admission close failed")
	admission := &fakeGlobalAdmission{closeErr: closeErr}
	svc := newStartTestService(events, &fakeRuntimeInstance{events: events})
	svc.config.GlobalDeviceLimitConfig = &commonlimiter.GlobalDeviceLimitConfig{Enable: true}
	svc.admissionFactory = func(api.ClientInfo) (globalAdmission, error) { return admission, nil }
	userErr := errors.New("user list failed")
	svc.apiClient.(*configurablePanelClient).userListErr = userErr

	err := svc.Start()
	if !errors.Is(err, userErr) {
		t.Fatalf("Start() error = %v, want user list failure", err)
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("Start() error = %v, want joined admission close failure", err)
	}
	admission.mu.Lock()
	closed := admission.closed
	admission.mu.Unlock()
	if closed == 0 {
		t.Fatal("failed start did not close the unpublished manager")
	}
}

// mutatingAdmission changes the published user policy during Acquire to model
// a concurrent snapshot replacement.
type mutatingAdmission struct {
	*fakeGlobalAdmission
	onAcquire func()
}

func (m *mutatingAdmission) Acquire(ctx context.Context, uid int, ip string, limit int) (globalLease, error) {
	if m.onAcquire != nil {
		m.onAcquire()
	}
	return m.fakeGlobalAdmission.Acquire(ctx, uid, ip, limit)
}

func TestGlobalAdmissionAbortsWhenPolicyChangesDuringAcquire(t *testing.T) {
	lease := &fakeAdmissionLease{}
	base := &fakeGlobalAdmission{nextLease: lease}
	svc := globalAdmissionTestService(t, base, map[string]int{"user": 1})
	admission := &mutatingAdmission{fakeGlobalAdmission: base}
	admission.onAcquire = func() {
		svc.mu.Lock()
		svc.applyUserStateLocked(userState{
			users:        map[string]userRecord{"user": {UID: 17, DeviceLimit: 5}},
			traffic:      make(map[string]*userTraffic),
			onlineIPs:    make(map[string]map[string]struct{}),
			ipLastActive: make(map[string]map[string]time.Time),
			rateLimiters: make(map[string]*rate.Limiter),
		})
		svc.mu.Unlock()
	}
	svc.mu.Lock()
	svc.globalAdmission = admission
	svc.mu.Unlock()

	device, returned, admitted := svc.allowConnection(context.Background(), "user", "192.0.2.1")
	if admitted || device != nil || returned != nil {
		t.Fatalf("allowConnection() = (%v, %v, %v), want rejection after policy replacement", device, returned, admitted)
	}
	if _, aborts, _ := lease.counts(); aborts != 1 {
		t.Fatalf("lease aborts = %d, want the tentative hold cancelled", aborts)
	}
	svc.mu.RLock()
	connections := len(svc.connections)
	svc.mu.RUnlock()
	if connections != 0 {
		t.Fatal("policy replacement leaked a local reservation")
	}
}
