package hysteria2

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/apernet/hysteria/core/v2/server"
	"golang.org/x/time/rate"

	"github.com/Mtoly/XrayRP/api"
	commonlimiter "github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/service/controller"
)

type fakeGlobalLease struct {
	mu        sync.Mutex
	commits   int
	aborts    int
	closes    int
	commitErr error
}

func (l *fakeGlobalLease) Commit() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.commits++
	return l.commitErr
}

func (l *fakeGlobalLease) Abort() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.aborts++
	return nil
}

func (l *fakeGlobalLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closes++
	return nil
}

func (l *fakeGlobalLease) counts() (commits, aborts, closes int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.commits, l.aborts, l.closes
}

type fakeGlobalAdmission struct {
	mu       sync.Mutex
	acquire  func(ctx context.Context, uid int, ip string, limit int) (globalLease, error)
	users    map[int]int
	setCalls int
	closed   int
	degraded bool
	acquires []acquireCall
}

type acquireCall struct {
	uid   int
	ip    string
	limit int
}

func (a *fakeGlobalAdmission) Acquire(ctx context.Context, uid int, ip string, limit int) (globalLease, error) {
	a.mu.Lock()
	a.acquires = append(a.acquires, acquireCall{uid: uid, ip: ip, limit: limit})
	acquire := a.acquire
	a.mu.Unlock()
	if acquire != nil {
		return acquire(ctx, uid, ip, limit)
	}
	return &fakeGlobalLease{}, nil
}

func (a *fakeGlobalAdmission) SetUsers(limits map[int]int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.users = make(map[int]int, len(limits))
	for uid, limit := range limits {
		a.users[uid] = limit
	}
	a.setCalls++
}

func (a *fakeGlobalAdmission) Degraded() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.degraded
}

func (a *fakeGlobalAdmission) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed++
	return nil
}

func (a *fakeGlobalAdmission) calls() []acquireCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]acquireCall(nil), a.acquires...)
}

func (a *fakeGlobalAdmission) snapshotUsers() map[int]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	copied := make(map[int]int, len(a.users))
	for uid, limit := range a.users {
		copied[uid] = limit
	}
	return copied
}

func (a *fakeGlobalAdmission) closeCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}

type globalTestService struct {
	svc       *Hysteria2Service
	admission *fakeGlobalAdmission
}

func newGlobalTestService(t *testing.T) *globalTestService {
	t.Helper()
	admission := &fakeGlobalAdmission{}
	svc := New(&configurablePanelClient{}, &controller.Config{
		GlobalDeviceLimitConfig: &commonlimiter.GlobalDeviceLimitConfig{Enable: true},
	})
	svc.admissionFactory = func(api.ClientInfo) (globalAdmission, error) { return admission, nil }
	svc.users = map[string]userRecord{
		"credential-a": {UID: 17, DeviceLimit: 2},
		"credential-b": {UID: 18, DeviceLimit: 1},
	}
	svc.traffic = make(map[string]*userTraffic)
	svc.rateLimiters = make(map[string]*rate.Limiter)
	svc.globalAdmission = admission
	return &globalTestService{svc: svc, admission: admission}
}

func (g *globalTestService) authenticate(t *testing.T, credential, ip string) (string, bool) {
	t.Helper()
	host := &net.UDPAddr{IP: net.ParseIP(ip), Port: 5000}
	ok, id := (&hyAuthenticator{svc: g.svc}).Authenticate(host, credential, 0)
	return id, ok
}

func TestGlobalAuthReturnsDistinctOpaqueSessionIDs(t *testing.T) {
	g := newGlobalTestService(t)
	first, ok := g.authenticate(t, "credential-a", "192.0.2.1")
	if !ok || first == "" {
		t.Fatalf("first Authenticate() = (%q, %v), want accepted session", first, ok)
	}
	second, ok := g.authenticate(t, "credential-a", "192.0.2.1")
	if !ok || second == "" {
		t.Fatalf("second Authenticate() = (%q, %v), want accepted session", second, ok)
	}
	if first == second {
		t.Fatal("same credential and IP produced one session id; connections would not be distinct")
	}
	if first == "credential-a" || second == "credential-a" {
		t.Fatal("opaque session id equals the credential")
	}

	calls := g.admission.calls()
	if len(calls) != 2 || calls[0].uid != 17 || calls[0].ip != "192.0.2.1" || calls[0].limit != 2 {
		t.Fatalf("Acquire calls = %#v", calls)
	}
	g.svc.mu.RLock()
	sessions := len(g.svc.sessions)
	g.svc.mu.RUnlock()
	if sessions != 2 {
		t.Fatalf("tracked sessions = %d, want 2", sessions)
	}
}

func TestGlobalAuthCommitsLeaseAndCloseOneKeepsIP(t *testing.T) {
	g := newGlobalTestService(t)
	var leases []*fakeGlobalLease
	var leaseMu sync.Mutex
	g.admission.acquire = func(context.Context, int, string, int) (globalLease, error) {
		lease := &fakeGlobalLease{}
		leaseMu.Lock()
		leases = append(leases, lease)
		leaseMu.Unlock()
		return lease, nil
	}

	first, _ := g.authenticate(t, "credential-a", "192.0.2.1")
	second, _ := g.authenticate(t, "credential-a", "192.0.2.1")
	if len(leases) != 2 {
		t.Fatalf("acquired leases = %d, want 2", len(leases))
	}
	for i, lease := range leases {
		if commits, _, _ := lease.counts(); commits != 1 {
			t.Fatalf("lease %d commits = %d, want 1", i, commits)
		}
	}

	// Disconnecting one of two same-IP connections must keep the other's slot.
	(&hyEventLogger{svc: g.svc}).Disconnect(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000}, first, nil)
	if commits, _, closes := leases[0].counts(); closes != 1 {
		t.Fatalf("closed session lease closes = %d commit = %d, want one close", closes, commits)
	}
	g.svc.mu.RLock()
	_, stillOnline := g.svc.onlineIPs["credential-a"]["192.0.2.1"]
	_, remaining := g.svc.sessions[second]
	g.svc.mu.RUnlock()
	if !stillOnline {
		t.Fatal("online IP removed while another same-IP session is still live")
	}
	if !remaining {
		t.Fatal("remaining session was removed by the other connection's disconnect")
	}

	(&hyEventLogger{svc: g.svc}).Disconnect(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000}, second, nil)
	g.svc.mu.RLock()
	_, stillOnline = g.svc.onlineIPs["credential-a"]["192.0.2.1"]
	g.svc.mu.RUnlock()
	if stillOnline {
		t.Fatal("online IP retained after the last same-IP session closed")
	}
	if commits, _, closes := leases[1].counts(); closes != 1 {
		t.Fatalf("second lease closes = %d commit = %d, want one close", closes, commits)
	}
}

func TestGlobalAuthQuotaRejectionLeavesNoLocalOccupancy(t *testing.T) {
	g := newGlobalTestService(t)
	g.admission.acquire = func(context.Context, int, string, int) (globalLease, error) {
		return nil, commonlimiter.ErrGlobalAdmissionQuota
	}

	session, ok := g.authenticate(t, "credential-a", "192.0.2.1")
	if ok || session != "" {
		t.Fatalf("Authenticate() = (%q, %v), want rejection", session, ok)
	}
	g.svc.mu.RLock()
	ipCount := len(g.svc.onlineIPs)
	activeCount := len(g.svc.ipLastActive)
	sessionCount := len(g.svc.sessions)
	g.svc.mu.RUnlock()
	if ipCount != 0 || activeCount != 0 || sessionCount != 0 {
		t.Fatalf("rejected admission left local state: online=%d active=%d sessions=%d", ipCount, activeCount, sessionCount)
	}
}

func TestGlobalAuthAbortsLeaseWhenPolicyGenerationChanges(t *testing.T) {
	g := newGlobalTestService(t)
	lease := &fakeGlobalLease{}
	g.admission.acquire = func(context.Context, int, string, int) (globalLease, error) {
		// Simulate a user snapshot update landing while Redis is in flight.
		g.svc.mu.Lock()
		g.svc.users = map[string]userRecord{"credential-a": {UID: 17, DeviceLimit: 1}}
		g.svc.userGeneration++
		g.svc.mu.Unlock()
		return lease, nil
	}

	session, ok := g.authenticate(t, "credential-a", "192.0.2.1")
	if ok || session != "" {
		t.Fatalf("Authenticate() = (%q, %v), want stale-policy rejection", session, ok)
	}
	if commits, aborts, closes := lease.counts(); aborts != 1 || commits != 0 || closes != 0 {
		t.Fatalf("stale lease counts = commits:%d aborts:%d closes:%d, want one abort only", commits, aborts, closes)
	}
	g.svc.mu.RLock()
	sessionCount := len(g.svc.sessions)
	g.svc.mu.RUnlock()
	if sessionCount != 0 {
		t.Fatalf("stale admission created %d sessions", sessionCount)
	}
}

func TestGlobalAuthAbortsLeaseWhenPolicyChangesBeforeCommit(t *testing.T) {
	g := newGlobalTestService(t)
	lease := &fakeGlobalLease{commitErr: commonlimiter.ErrGlobalAdmissionQuota}
	g.admission.acquire = func(context.Context, int, string, int) (globalLease, error) {
		return lease, nil
	}

	session, ok := g.authenticate(t, "credential-a", "192.0.2.1")
	if ok || session != "" {
		t.Fatalf("Authenticate() = (%q, %v), want commit rejection", session, ok)
	}
	if _, _, closes := lease.counts(); closes != 1 {
		t.Fatalf("failed commit lease closes = %d, want cleanup close", closes)
	}
	g.svc.mu.RLock()
	defer g.svc.mu.RUnlock()
	if len(g.svc.sessions) != 0 || len(g.svc.onlineIPs) != 0 {
		t.Fatalf("failed commit left local state: sessions=%d online=%d", len(g.svc.sessions), len(g.svc.onlineIPs))
	}
}

func TestGlobalAuthRejectsUnavailableBackend(t *testing.T) {
	g := newGlobalTestService(t)
	g.admission.acquire = func(context.Context, int, string, int) (globalLease, error) {
		return nil, commonlimiter.ErrGlobalAdmissionUnavailable
	}

	if session, ok := g.authenticate(t, "credential-a", "192.0.2.1"); ok || session != "" {
		t.Fatalf("Authenticate() = (%q, %v), want closed-failure rejection", session, ok)
	}
}

func TestGlobalAuthIdleSessionKeepsLeaseAndOnlineIP(t *testing.T) {
	g := newGlobalTestService(t)
	lease := &fakeGlobalLease{}
	g.admission.acquire = func(context.Context, int, string, int) (globalLease, error) {
		return lease, nil
	}
	session, ok := g.authenticate(t, "credential-a", "198.51.100.7")
	if !ok {
		t.Fatal("Authenticate() rejected the initial connection")
	}

	// No traffic or request callbacks: the session is idle but still live.
	_, online, _ := g.svc.collectUsage()
	if len(online) != 1 || online[0].UID != 17 || online[0].IP != "198.51.100.7" {
		t.Fatalf("idle online users = %#v, want the idle session IP", online)
	}
	if _, _, closes := lease.counts(); closes != 0 {
		t.Fatalf("idle lease closes = %d, want renewal to continue", closes)
	}

	(&hyEventLogger{svc: g.svc}).Disconnect(&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 5000}, session, nil)
	if _, _, closes := lease.counts(); closes != 1 {
		t.Fatalf("idle session lease closes = %d, want 1", closes)
	}
	_, online, _ = g.svc.collectUsage()
	if len(online) != 0 {
		t.Fatalf("online users after idle disconnect = %#v, want none", online)
	}
}

func TestGlobalAuthFailOpenWithoutLeaseKeepsLocalLimit(t *testing.T) {
	g := newGlobalTestService(t)
	g.admission.acquire = func(context.Context, int, string, int) (globalLease, error) {
		// FailMode=open returns no error and no lease when Redis is unverifiable.
		return nil, nil
	}
	g.svc.users = map[string]userRecord{"credential-a": {UID: 17, DeviceLimit: 1}}

	if _, ok := g.authenticate(t, "credential-a", "192.0.2.1"); !ok {
		t.Fatal("fail-open admission rejected the first source IP")
	}
	if _, ok := g.authenticate(t, "credential-a", "198.51.100.1"); ok {
		t.Fatal("fail-open admission bypassed the local device limit")
	}
}

func TestGlobalOnlineStateStopsRenewalBeforeDisconnect(t *testing.T) {
	g := newGlobalTestService(t)
	lease := &fakeGlobalLease{}
	g.admission.acquire = func(context.Context, int, string, int) (globalLease, error) {
		return lease, nil
	}
	session, ok := g.authenticate(t, "credential-a", "192.0.2.1")
	if !ok {
		t.Fatal("Authenticate() rejected the connection")
	}

	// The core reports online=false, then Disconnect. Renewal must stop at the
	// first callback, while the later callback still resolves the UID.
	(&hyTrafficLogger{svc: g.svc}).LogOnlineState(session, false)
	if _, _, closes := lease.counts(); closes != 1 {
		t.Fatalf("lease closes after LogOnlineState(false) = %d, want 1", closes)
	}
	if user, _, ok := g.svc.lookupUser(session); !ok || user.UID != 17 {
		t.Fatal("Disconnect could no longer resolve the session identity")
	}
	(&hyEventLogger{svc: g.svc}).Disconnect(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000}, session, nil)

	// A delayed duplicate callback must not double-close or re-add state.
	(&hyTrafficLogger{svc: g.svc}).LogOnlineState(session, false)
	(&hyEventLogger{svc: g.svc}).Disconnect(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000}, session, nil)
	if _, _, closes := lease.counts(); closes != 1 {
		t.Fatalf("lease closes after repeated callbacks = %d, want 1", closes)
	}
	g.svc.mu.RLock()
	sessionCount := len(g.svc.sessions)
	g.svc.mu.RUnlock()
	if sessionCount != 0 {
		t.Fatalf("repeated callbacks retained %d sessions", sessionCount)
	}
}

func TestGlobalTrafficAndAuditResolveSessionIdentity(t *testing.T) {
	g := newGlobalTestService(t)
	session, ok := g.authenticate(t, "credential-a", "192.0.2.1")
	if !ok {
		t.Fatal("Authenticate() rejected the initial connection")
	}

	(&hyTrafficLogger{svc: g.svc}).LogTraffic(session, 5, 7)
	g.svc.mu.RLock()
	counter := g.svc.traffic["credential-a"]
	g.svc.mu.RUnlock()
	if counter == nil || counter.Upload != 5 || counter.Download != 7 {
		t.Fatalf("session traffic %#v, want user traffic counters", counter)
	}

	users, _, _ := g.svc.collectUsage()
	if len(users) != 1 || users[0].UID != 17 {
		t.Fatalf("reported traffic = %#v, want UID 17", users)
	}
}

func TestGlobalSetUsersPublishesAllKnownUsers(t *testing.T) {
	g := newGlobalTestService(t)
	users := []api.UserInfo{
		{UID: 17, UUID: "credential-a", DeviceLimit: 3},
		{UID: 18, Passwd: "credential-b", DeviceLimit: 1},
		{UID: 19, UUID: "credential-c", DeviceLimit: 0},
	}
	g.svc.syncUsersFor(&users, nil)

	limits := g.admission.snapshotUsers()
	if len(limits) != 3 || limits[17] != 3 || limits[18] != 1 {
		t.Fatalf("published limits = %#v, want all known users including idle ones", limits)
	}
	if _, ok := limits[19]; !ok {
		t.Fatal("zero-limit user was not registered")
	}
}

func TestLocalAuthUnchangedWithoutGlobalAdmission(t *testing.T) {
	svc := New(&configurablePanelClient{}, &controller.Config{})
	svc.users = map[string]userRecord{"credential-a": {UID: 17, DeviceLimit: 1}}
	svc.traffic = make(map[string]*userTraffic)

	ok, id := (&hyAuthenticator{svc: svc}).Authenticate(
		&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000}, "credential-a", 0)
	if !ok || id != "credential-a" {
		t.Fatalf("local Authenticate() = (%q, %v), want credential id", id, ok)
	}
	svc.mu.RLock()
	_, online := svc.onlineIPs["credential-a"]["192.0.2.1"]
	sessions := len(svc.sessions)
	svc.mu.RUnlock()
	if !online || sessions != 0 {
		t.Fatalf("local mode tracking: online=%v sessions=%d, want local IP and no sessions", online, sessions)
	}

	if ok, _ := (&hyAuthenticator{svc: svc}).Authenticate(
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5000}, "credential-a", 0); ok {
		t.Fatal("local device limit was not enforced for a new IP")
	}
	if ok, _ := (&hyAuthenticator{svc: svc}).Authenticate(
		&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5001}, "credential-a", 0); !ok {
		t.Fatal("local mode rejected a repeat IP connection")
	}
}

func TestGlobalCloseStopsLeasesAndManagerWithoutDeleting(t *testing.T) {
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events, serveBlock: make(chan struct{}), serving: make(chan struct{})}
	svc := newStartTestService(events, runtime)
	svc.apiClient.(*configurablePanelClient).users = []api.UserInfo{{UID: 17, UUID: "credential-a", DeviceLimit: 2}}
	admission := &fakeGlobalAdmission{}
	lease := &fakeGlobalLease{}
	admission.acquire = func(context.Context, int, string, int) (globalLease, error) {
		return lease, nil
	}
	svc.admissionFactory = func(api.ClientInfo) (globalAdmission, error) { return admission, nil }
	if err := svc.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if ok, _ := (&hyAuthenticator{svc: svc}).Authenticate(
		&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000}, "credential-a", 0); !ok {
		t.Fatal("Authenticate() rejected the connection")
	}

	if err := svc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, _, closes := lease.counts(); closes != 1 {
		t.Fatalf("leased session closes after Close = %d, want 1", closes)
	}
	if admission.closeCount() != 1 {
		t.Fatalf("admission Close calls = %d, want 1", admission.closeCount())
	}
	svc.mu.RLock()
	sessionCount := len(svc.sessions)
	current := svc.globalAdmission
	svc.mu.RUnlock()
	if sessionCount != 0 || current != nil {
		t.Fatalf("Close retained sessions=%d admission=%v", sessionCount, current)
	}
}
func TestGlobalStartFailureClosesAdmissionManager(t *testing.T) {
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events}
	svc := newStartTestService(events, runtime)
	svc.serverConfigFactory = func(*Hysteria2Service, serverBuildSpec) (*server.Config, error) {
		return nil, errors.New("config build failed")
	}
	admission := &fakeGlobalAdmission{}
	svc.admissionFactory = func(api.ClientInfo) (globalAdmission, error) { return admission, nil }

	if err := svc.Start(); err == nil {
		t.Fatal("Start() succeeded, want build failure")
	}
	if admission.closeCount() != 1 {
		t.Fatalf("admission Close calls = %d, want 1 after failed start", admission.closeCount())
	}
	svc.mu.RLock()
	current := svc.globalAdmission
	svc.mu.RUnlock()
	if current != nil {
		t.Fatal("failed start published the admission manager")
	}
}

func TestObservabilitySnapshotReportsGlobalDeviceDegraded(t *testing.T) {
	g := newGlobalTestService(t)
	g.admission.degraded = true
	snapshot := g.svc.ObservabilitySnapshot()
	if !snapshot.GlobalDeviceDegraded {
		t.Fatal("GlobalDeviceDegraded = false, want degraded manager state")
	}
}
