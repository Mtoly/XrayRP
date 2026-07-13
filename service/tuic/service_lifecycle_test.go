package tuic

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service/controller"
	"github.com/sagernet/sing-box/option"
	"golang.org/x/time/rate"
)

type lifecycleEvents struct {
	mu     sync.Mutex
	events []string
}

func (e *lifecycleEvents) add(event string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *lifecycleEvents) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.events...)
}

func waitForEvents(t *testing.T, events *lifecycleEvents, want []string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := events.snapshot(); reflect.DeepEqual(got, want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("events = %v, want %v", events.snapshot(), want)
}

type fakeRuntimeInstance struct {
	events     *lifecycleEvents
	startErr   error
	closeErr   error
	startBlock <-chan struct{}
	started    chan<- struct{}
}

func (f *fakeRuntimeInstance) Start() error {
	f.events.add("start")
	if f.started != nil {
		close(f.started)
	}
	if f.startBlock != nil {
		<-f.startBlock
	}
	if f.startErr == nil {
		f.events.add("ready")
	}
	return f.startErr
}

func (f *fakeRuntimeInstance) Close() error {
	f.events.add("stop")
	f.events.add("close")
	return f.closeErr
}

func TestRuntimeLifecycleSeamCompiles(t *testing.T) {
	var runtime runtimeInstance = &fakeRuntimeInstance{events: &lifecycleEvents{}}
	var factory runtimeFactory = func(*TuicService) (runtimeInstance, string, error) {
		return runtime, "test-inbound", nil
	}

	service := &TuicService{runtimeFactory: factory}
	if service.runtimeFactory == nil {
		t.Fatal("runtime factory seam is nil")
	}
}

func TestBuildRuntimeRecordsBuildAndReturnsFactoryError(t *testing.T) {
	wantErr := errors.New("build failed")
	events := &lifecycleEvents{}
	service := &TuicService{
		runtimeFactory: func(*TuicService) (runtimeInstance, string, error) {
			events.add("build")
			return nil, "", wantErr
		},
	}

	_, _, err := service.buildRuntime()
	if !errors.Is(err, wantErr) {
		t.Fatalf("buildRuntime() error = %v, want %v", err, wantErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build"}) {
		t.Fatalf("events = %v, want [build]", got)
	}
}

func TestBuildRuntimeReturnsInjectedFake(t *testing.T) {
	events := &lifecycleEvents{}
	wantRuntime := &fakeRuntimeInstance{events: events}
	service := &TuicService{
		runtimeFactory: func(*TuicService) (runtimeInstance, string, error) {
			events.add("build")
			return wantRuntime, "test-inbound", nil
		},
	}

	gotRuntime, gotTag, err := service.buildRuntime()
	if err != nil {
		t.Fatalf("buildRuntime() error = %v", err)
	}
	if gotRuntime != wantRuntime {
		t.Fatalf("buildRuntime() runtime = %T, want injected fake", gotRuntime)
	}
	if gotTag != "test-inbound" {
		t.Fatalf("buildRuntime() tag = %q, want test-inbound", gotTag)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build"}) {
		t.Fatalf("events = %v, want [build]", got)
	}
}

func TestNewInstallsDefaultsWithoutSharingFactoryState(t *testing.T) {
	client := tuicPanelClientContractStub{}
	first := New(client, &controller.Config{})
	second := New(client, &controller.Config{})

	if first.runtimeFactory == nil || first.startRuntime == nil || first.closeRuntime == nil {
		t.Fatal("New() did not install lifecycle defaults")
	}
	first.runtimeFactory = func(*TuicService) (runtimeInstance, string, error) {
		return &fakeRuntimeInstance{events: &lifecycleEvents{}}, "test-inbound", nil
	}
	first.startRuntime = func(runtimeInstance) error { return errors.New("test start") }
	first.closeRuntime = func(runtimeInstance) error { return errors.New("test close") }
	if reflect.ValueOf(second.runtimeFactory).Pointer() != reflect.ValueOf(defaultRuntimeFactory).Pointer() {
		t.Fatal("overriding one service factory changed another New() instance")
	}
	if reflect.ValueOf(second.startRuntime).Pointer() != reflect.ValueOf(defaultStartRuntime).Pointer() {
		t.Fatal("overriding one start helper changed another New() instance")
	}
	if reflect.ValueOf(second.closeRuntime).Pointer() != reflect.ValueOf(defaultCloseRuntime).Pointer() {
		t.Fatal("overriding one close helper changed another New() instance")
	}
}

func TestRuntimeFakeSupportsControlledStartAndClose(t *testing.T) {
	events := &lifecycleEvents{}
	startBlock := make(chan struct{})
	started := make(chan struct{})
	runtime := &fakeRuntimeInstance{
		events:     events,
		startBlock: startBlock,
		started:    started,
	}

	startDone := make(chan error, 1)
	go func() {
		startDone <- runtime.Start()
		events.add("join")
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Start did not reach controlled block")
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"start"}) {
		t.Fatalf("events before release = %v, want [start]", got)
	}

	close(startBlock)
	if err := <-startDone; err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForEvents(t, events, []string{"start", "ready", "join"})
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"start", "ready", "join", "stop", "close"}) {
		t.Fatalf("events = %v, want [start ready join stop close]", got)
	}
}

func TestRuntimeFakeInjectsStartAndCloseErrors(t *testing.T) {
	startErr := errors.New("start failed")
	closeErr := errors.New("close failed")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeInstance{
		events:   events,
		startErr: startErr,
		closeErr: closeErr,
	}

	if err := runtime.Start(); !errors.Is(err, startErr) {
		t.Fatalf("Start() error = %v, want %v", err, startErr)
	}
	if err := runtime.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close() error = %v, want %v", err, closeErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"start", "stop", "close"}) {
		t.Fatalf("events = %v, want [start stop close]", got)
	}
}

type configurablePanelClient struct {
	nodeInfo      *api.NodeInfo
	nodeInfoErr   error
	users         []api.UserInfo
	userListErr   error
	rules         []api.DetectRule
	nodeRuleErr   error
	nodeRuleCalls int
}

func (c *configurablePanelClient) Describe() api.ClientInfo { return api.ClientInfo{NodeID: 8} }
func (c *configurablePanelClient) GetNodeInfo() (*api.NodeInfo, error) {
	return c.nodeInfo, c.nodeInfoErr
}
func (c *configurablePanelClient) GetUserList() (*[]api.UserInfo, error) {
	return &c.users, c.userListErr
}
func (c *configurablePanelClient) GetNodeRule() (*[]api.DetectRule, error) {
	c.nodeRuleCalls++
	return &c.rules, c.nodeRuleErr
}
func (*configurablePanelClient) ReportNodeStatus(*api.NodeStatus) error        { return nil }
func (*configurablePanelClient) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (*configurablePanelClient) ReportUserTraffic(*[]api.UserTraffic) error    { return nil }
func (*configurablePanelClient) ReportIllegal(*[]api.DetectResult) error       { return nil }

type fakePeriodicTask struct {
	tag      string
	events   *lifecycleEvents
	startErr error
	closeErr error
}

func (t *fakePeriodicTask) Start() error { t.events.add("task-start:" + t.tag); return t.startErr }
func (t *fakePeriodicTask) Close() error { t.events.add("task-close:" + t.tag); return t.closeErr }

func newStartTestService(events *lifecycleEvents, runtime *fakeRuntimeInstance) *TuicService {
	client := &configurablePanelClient{
		nodeInfo: &api.NodeInfo{NodeType: "Tuic", NodeID: 8, Port: 8443, TuicConfig: &api.TuicConfig{}},
	}
	service := New(client, &controller.Config{
		ListenIP:       "127.0.0.1",
		UpdatePeriodic: 60,
		DisableGetRule: true,
		CertConfig:     &mylego.CertConfig{},
	})
	service.runtimeFactory = func(*TuicService) (runtimeInstance, string, error) {
		events.add("build")
		return runtime, "test-inbound", nil
	}
	service.taskFactory = func(tag string, _ time.Duration, _ func() error) lifecycleTask {
		return &fakePeriodicTask{tag: tag, events: events}
	}
	return service
}

func TestStartBuildsRuntimeWithIncomingTag(t *testing.T) {
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeInstance{events: events})
	service.inboundTag = "stale-inbound"
	service.tag = "stale-tag"
	service.runtimeFactory = func(service *TuicService) (runtimeInstance, string, error) {
		events.add("build")
		if service.tag != "Tuic_127.0.0.1_8443_8" {
			t.Fatalf("runtime build tag = %q, want incoming tag", service.tag)
		}
		if service.inboundTag != "Tuic_127.0.0.1_8443_8" {
			t.Fatalf("runtime build inbound tag = %q, want incoming tag", service.inboundTag)
		}
		return &fakeRuntimeInstance{events: events}, service.inboundTag, nil
	}

	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if service.inboundTag != "Tuic_127.0.0.1_8443_8" {
		t.Fatalf("published inbound tag = %q, want incoming tag", service.inboundTag)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestStartBuildFailureDoesNotPublishRuntime(t *testing.T) {
	wantErr := errors.New("build failed")
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeInstance{events: events})
	service.runtimeFactory = func(*TuicService) (runtimeInstance, string, error) {
		events.add("build")
		return nil, "", wantErr
	}

	err := service.Start()
	if !errors.Is(err, wantErr) {
		t.Fatalf("Start() error = %v, want %v", err, wantErr)
	}
	if service.box != nil || service.nodeInfo != nil || service.tasks != nil || service.tag != "" || !service.startAt.IsZero() {
		t.Fatalf("failed Start published state: box=%v nodeInfo=%v tasks=%v tag=%q startAt=%v", service.box, service.nodeInfo, service.tasks, service.tag, service.startAt)
	}
	if service.state != stateFailed || !errors.Is(service.runtimeErr, wantErr) {
		t.Fatalf("state/error = %v/%v, want failed/%v", service.state, service.runtimeErr, wantErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build"}) {
		t.Fatalf("events = %v, want [build]", got)
	}
}

func TestStartUserListFailureDoesNotBuildRuntime(t *testing.T) {
	wantErr := errors.New("user list failed")
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeInstance{events: events})
	service.apiClient.(*configurablePanelClient).userListErr = wantErr

	err := service.Start()
	if !errors.Is(err, wantErr) {
		t.Fatalf("Start() error = %v, want %v", err, wantErr)
	}
	if got := events.snapshot(); len(got) != 0 {
		t.Fatalf("events = %v, want no runtime or task work", got)
	}
	if service.nodeInfo != nil || service.box != nil || service.tasks != nil || service.tag != "" || !service.startAt.IsZero() {
		t.Fatalf("panel failure published state: nodeInfo=%v box=%v tasks=%v tag=%q startAt=%v", service.nodeInfo, service.box, service.tasks, service.tag, service.startAt)
	}
}

func TestStartRuntimeFailureCleansRuntimeAndSkipsTasks(t *testing.T) {
	startErr := errors.New("start failed")
	closeErr := errors.New("close failed")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeInstance{events: events, startErr: startErr, closeErr: closeErr}
	service := newStartTestService(events, runtime)

	err := service.Start()
	if !errors.Is(err, startErr) || !errors.Is(err, closeErr) {
		t.Fatalf("Start() error = %v, want joined start and close errors", err)
	}
	if service.box != nil || service.nodeInfo != nil || service.tasks != nil {
		t.Fatalf("failed Start published runtime state: box=%v nodeInfo=%v tasks=%v", service.box, service.nodeInfo, service.tasks)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build", "start", "stop", "close"}) {
		t.Fatalf("events = %v, want [build start stop close]", got)
	}
}

func TestStartTaskFailureCleansStartedTasksInReverseThenRuntime(t *testing.T) {
	taskErr := errors.New("task start failed")
	closeErr := errors.New("runtime close failed")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeInstance{events: events, closeErr: closeErr}
	service := newStartTestService(events, runtime)
	created := 0
	service.taskFactory = func(tag string, _ time.Duration, _ func() error) lifecycleTask {
		created++
		return &fakePeriodicTask{tag: tag, events: events, startErr: map[bool]error{true: taskErr}[created == 2]}
	}

	err := service.Start()
	if !errors.Is(err, taskErr) || !errors.Is(err, closeErr) {
		t.Fatalf("Start() error = %v, want joined task and runtime close errors", err)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{
		"build", "start", "ready", "task-start:Tuic_127.0.0.1_8443_8", "task-start:node monitor",
		"task-close:node monitor", "task-close:Tuic_127.0.0.1_8443_8", "stop", "close",
	}) {
		t.Fatalf("events = %v, want reverse task cleanup then runtime cleanup", got)
	}
	if service.tasks != nil || service.box != nil || service.nodeInfo != nil {
		t.Fatalf("failed Start published state: tasks=%v box=%v nodeInfo=%v", service.tasks, service.box, service.nodeInfo)
	}
}

func TestStartFailureRestoresUserStateAndDefersRules(t *testing.T) {
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeInstance{events: events})
	service.config.DisableGetRule = false
	client := service.apiClient.(*configurablePanelClient)
	client.users = []api.UserInfo{{UUID: "old-user", SpeedLimit: 20}, {UUID: "new-user", SpeedLimit: 10}}
	client.rules = []api.DetectRule{{ID: 1}}
	oldLimiter := rate.NewLimiter(10, 10)
	service.users["old-user"] = userRecord{UID: 1}
	service.authUsers = []option.TUICUser{{Name: "old-user", UUID: "old-user", Password: "old-user"}}
	service.rateLimiters = map[string]*rate.Limiter{"old-user": oldLimiter}
	service.runtimeFactory = func(*TuicService) (runtimeInstance, string, error) {
		return nil, "", errors.New("build failed")
	}

	if err := service.Start(); err == nil {
		t.Fatal("Start() error = nil, want build failure")
	}
	if _, ok := service.users["old-user"]; !ok || len(service.users) != 1 {
		t.Fatalf("users after failed Start = %v, want original users", service.users)
	}
	if len(service.authUsers) != 1 || service.authUsers[0].Name != "old-user" {
		t.Fatalf("authUsers after failed Start = %v, want original users", service.authUsers)
	}
	if limiter, ok := service.rateLimiters["old-user"]; !ok || len(service.rateLimiters) != 1 || limiter != oldLimiter {
		t.Fatalf("rateLimiters after failed Start = %v, want original map", service.rateLimiters)
	}
	if got := oldLimiter.Limit(); got != 10 {
		t.Fatalf("original limiter mutated during failed Start: limit=%v, want 10", got)
	}
	if client.nodeRuleCalls != 0 {
		t.Fatalf("GetNodeRule calls = %d, want deferred until successful startup", client.nodeRuleCalls)
	}
}

func TestCloseWhileStartingIsRejectedWithoutClosingService(t *testing.T) {
	events := &lifecycleEvents{}
	release := make(chan struct{})
	entered := make(chan struct{})
	runtime := &fakeRuntimeInstance{events: events, startBlock: release, started: entered}
	service := newStartTestService(events, runtime)
	done := make(chan error, 1)
	go func() { done <- service.Start() }()
	<-entered
	if err := service.Close(); err == nil {
		t.Fatal("Close() error = nil, want starting-state rejection")
	}
	if service.closed || service.state != stateStarting {
		t.Fatalf("Close() changed starting lifecycle: closed=%v state=%v", service.closed, service.state)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Start() error = %v", err)
	}
}

func TestCloseAfterFailedStartTransitionsToStopped(t *testing.T) {
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeInstance{events: events})
	service.apiClient.(*configurablePanelClient).userListErr = errors.New("users failed")
	if err := service.Start(); err == nil {
		t.Fatal("Start() error = nil, want failure")
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if service.state != stateStopped || !service.closed {
		t.Fatalf("state/closed after Close = %v/%v, want stopped/true", service.state, service.closed)
	}
}

func TestStartPublishesUserStateOnSuccess(t *testing.T) {
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeInstance{events: events})
	service.apiClient.(*configurablePanelClient).users = []api.UserInfo{{UUID: "new-user", SpeedLimit: 10}}
	service.users["old-user"] = userRecord{UID: 1}
	service.authUsers = []option.TUICUser{{Name: "old-user", UUID: "old-user", Password: "old-user"}}

	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, ok := service.users["new-user"]; !ok || len(service.users) != 1 {
		t.Fatalf("users after successful Start = %v, want new users", service.users)
	}
	if len(service.authUsers) != 1 || service.authUsers[0].Name != "new-user" {
		t.Fatalf("authUsers after successful Start = %v, want new auth users", service.authUsers)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestStartPublishesOnlyAfterRuntimeAndTasksAreReady(t *testing.T) {
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeInstance{events: events})

	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if service.state != stateRunning || service.runtimeErr != nil || service.box == nil || service.nodeInfo == nil || service.tasks == nil || service.tag == "" || service.startAt.IsZero() {
		t.Fatalf("successful Start did not publish running state: state=%v err=%v box=%v nodeInfo=%v tasks=%v tag=%q startAt=%v", service.state, service.runtimeErr, service.box, service.nodeInfo, service.tasks, service.tag, service.startAt)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build", "start", "ready", "task-start:Tuic_127.0.0.1_8443_8", "task-start:node monitor"}) {
		t.Fatalf("events = %v, want synchronous runtime readiness before tasks", got)
	}
}

func TestStartTwiceWhileStartingIsRejected(t *testing.T) {
	events := &lifecycleEvents{}
	release := make(chan struct{})
	entered := make(chan struct{})
	runtime := &fakeRuntimeInstance{events: events, startBlock: release, started: entered}
	service := newStartTestService(events, runtime)
	firstDone := make(chan error, 1)
	go func() { firstDone <- service.Start() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first Start() did not enter runtime start")
	}
	if err := service.Start(); err == nil {
		t.Fatal("concurrent Start() error = nil, want starting-state rejection")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
}

func TestStartTwiceAndStartAfterCloseAreRejected(t *testing.T) {
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeInstance{events: events})
	if err := service.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	if err := service.Start(); err == nil {
		t.Fatal("second Start() error = nil, want rejection")
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if service.state != stateStopped {
		t.Fatalf("state after Close = %v, want stopped", service.state)
	}
	if err := service.Start(); err == nil {
		t.Fatal("Start() after Close error = nil, want rejection")
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{
		"build", "start", "ready", "task-start:Tuic_127.0.0.1_8443_8", "task-start:node monitor",
		"task-close:node monitor", "task-close:Tuic_127.0.0.1_8443_8", "stop", "close",
	}) {
		t.Fatalf("events = %v, unexpected restart work", got)
	}
}

func TestRuntimeHelpersPropagateErrorsAndControlledBlocking(t *testing.T) {
	startErr := errors.New("start failed")
	closeErr := errors.New("close failed")
	events := &lifecycleEvents{}
	release := make(chan struct{})
	entered := make(chan struct{})
	runtime := &fakeRuntimeInstance{
		events:     events,
		startErr:   startErr,
		closeErr:   closeErr,
		startBlock: release,
		started:    entered,
	}
	service := &TuicService{
		startRuntime: defaultStartRuntime,
		closeRuntime: defaultCloseRuntime,
	}

	startDone := make(chan error, 1)
	go func() {
		startDone <- service.startRuntime(runtime)
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("startRuntime did not reach controlled block")
	}
	select {
	case err := <-startDone:
		t.Fatalf("startRuntime returned before release: %v", err)
	default:
	}

	close(release)
	if err := <-startDone; !errors.Is(err, startErr) {
		t.Fatalf("startRuntime() error = %v, want %v", err, startErr)
	}
	if err := service.closeRuntime(runtime); !errors.Is(err, closeErr) {
		t.Fatalf("closeRuntime() error = %v, want %v", err, closeErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"start", "stop", "close"}) {
		t.Fatalf("events = %v, want [start stop close]", got)
	}
}
