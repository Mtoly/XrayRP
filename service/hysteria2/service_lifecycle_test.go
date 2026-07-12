package hysteria2

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/server"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service/controller"
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

func waitForState(t *testing.T, service *Hysteria2Service, want lifecycleState) error {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		service.lifecycleMu.Lock()
		state, runtimeErr := service.state, service.runtimeErr
		service.lifecycleMu.Unlock()
		if state == want {
			return runtimeErr
		}
		time.Sleep(time.Millisecond)
	}
	service.lifecycleMu.Lock()
	defer service.lifecycleMu.Unlock()
	t.Fatalf("state = %v, want %v", service.state, want)
	return nil
}

type fakeRuntimeServer struct {
	events      *lifecycleEvents
	serveErr    error
	closeErr    error
	serveBlock  chan struct{}
	serving     chan struct{}
	serveExited chan struct{}
	serveOnce   sync.Once
	exitOnce    sync.Once
}

func (f *fakeRuntimeServer) Serve() error {
	f.events.add("serve")
	if f.serving != nil {
		f.serveOnce.Do(func() { close(f.serving) })
	}
	if f.serveBlock != nil {
		<-f.serveBlock
	}
	if f.serveExited != nil {
		f.exitOnce.Do(func() { close(f.serveExited) })
	}
	return f.serveErr
}

func (f *fakeRuntimeServer) Close() error {
	f.events.add("stop")
	if f.serveBlock != nil {
		select {
		case <-f.serveBlock:
		default:
			close(f.serveBlock)
		}
	}
	if f.serveExited != nil {
		<-f.serveExited
	}
	f.events.add("close")
	return f.closeErr
}

func TestRuntimeLifecycleSeamCompiles(t *testing.T) {
	var runtime runtimeServer = &fakeRuntimeServer{events: &lifecycleEvents{}}
	var configFactory serverConfigFactory = func(*Hysteria2Service) (*server.Config, error) {
		return &server.Config{}, nil
	}
	var factory runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		return runtime, nil
	}

	service := &Hysteria2Service{
		serverConfigFactory:  configFactory,
		runtimeServerFactory: factory,
	}
	if service.serverConfigFactory == nil || service.runtimeServerFactory == nil {
		t.Fatal("runtime factory seams are nil")
	}
}

func TestBuildRuntimeServerRecordsBuildOrder(t *testing.T) {
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events}
	service := &Hysteria2Service{
		serverConfigFactory: func(*Hysteria2Service) (*server.Config, error) {
			events.add("build-config")
			return &server.Config{}, nil
		},
		runtimeServerFactory: func(*server.Config) (runtimeServer, error) {
			events.add("build-server")
			return runtime, nil
		},
	}

	gotRuntime, err := service.buildRuntimeServer()
	if err != nil {
		t.Fatalf("buildRuntimeServer() error = %v", err)
	}
	if gotRuntime != runtime {
		t.Fatalf("buildRuntimeServer() runtime = %T, want fake runtime", gotRuntime)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build-config", "build-server"}) {
		t.Fatalf("events = %v, want [build-config build-server]", got)
	}
}

func TestBuildRuntimeServerStopsAfterConfigError(t *testing.T) {
	wantErr := errors.New("config failed")
	events := &lifecycleEvents{}
	service := &Hysteria2Service{
		serverConfigFactory: func(*Hysteria2Service) (*server.Config, error) {
			events.add("build-config")
			return nil, wantErr
		},
		runtimeServerFactory: func(*server.Config) (runtimeServer, error) {
			events.add("build-server")
			return nil, nil
		},
	}

	_, err := service.buildRuntimeServer()
	if !errors.Is(err, wantErr) {
		t.Fatalf("buildRuntimeServer() error = %v, want %v", err, wantErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build-config"}) {
		t.Fatalf("events = %v, want [build-config]", got)
	}
}

func TestBuildRuntimeServerReturnsInjectedFakeAndFactoryError(t *testing.T) {
	wantErr := errors.New("server failed")
	events := &lifecycleEvents{}
	wantRuntime := &fakeRuntimeServer{events: events}
	service := &Hysteria2Service{
		serverConfigFactory: func(*Hysteria2Service) (*server.Config, error) {
			events.add("build-config")
			return &server.Config{}, nil
		},
		runtimeServerFactory: func(*server.Config) (runtimeServer, error) {
			events.add("build-server")
			return nil, wantErr
		},
	}

	if _, err := service.buildRuntimeServer(); !errors.Is(err, wantErr) {
		t.Fatalf("buildRuntimeServer() error = %v, want %v", err, wantErr)
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		events.add("build-server")
		return wantRuntime, nil
	}
	gotRuntime, err := service.buildRuntimeServer()
	if err != nil {
		t.Fatalf("buildRuntimeServer() error = %v", err)
	}
	if gotRuntime != wantRuntime {
		t.Fatalf("buildRuntimeServer() runtime = %T, want injected fake", gotRuntime)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build-config", "build-server", "build-config", "build-server"}) {
		t.Fatalf("events = %v, want two ordered builds", got)
	}
}

func TestNewInstallsDefaultsWithoutSharingFactoryState(t *testing.T) {
	client := hysteria2PanelClientContractStub{}
	first := New(client, &controller.Config{})
	second := New(client, &controller.Config{})

	if first.serverConfigFactory == nil || first.runtimeServerFactory == nil || first.serveRuntime == nil || first.closeRuntime == nil {
		t.Fatal("New() did not install lifecycle defaults")
	}
	first.runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		return &fakeRuntimeServer{events: &lifecycleEvents{}}, nil
	}
	first.serveRuntime = func(runtimeServer) error { return errors.New("test serve") }
	first.closeRuntime = func(runtimeServer) error { return errors.New("test close") }
	if reflect.ValueOf(second.runtimeServerFactory).Pointer() != reflect.ValueOf(defaultRuntimeServerFactory).Pointer() {
		t.Fatal("overriding one service factory changed another New() instance")
	}
	if reflect.ValueOf(second.serveRuntime).Pointer() != reflect.ValueOf(defaultServeRuntime).Pointer() {
		t.Fatal("overriding one serve helper changed another New() instance")
	}
	if reflect.ValueOf(second.closeRuntime).Pointer() != reflect.ValueOf(defaultCloseRuntime).Pointer() {
		t.Fatal("overriding one close helper changed another New() instance")
	}
}

func TestRuntimeServerFakeSupportsControlledServeAndClose(t *testing.T) {
	events := &lifecycleEvents{}
	serveBlock := make(chan struct{})
	serving := make(chan struct{})
	runtime := &fakeRuntimeServer{
		events:     events,
		serveBlock: serveBlock,
		serving:    serving,
	}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- runtime.Serve()
		events.add("join")
	}()

	select {
	case <-serving:
	case <-time.After(time.Second):
		t.Fatal("Serve did not reach controlled block")
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"serve"}) {
		t.Fatalf("events before release = %v, want [serve]", got)
	}

	close(serveBlock)
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	waitForEvents(t, events, []string{"serve", "join"})
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"serve", "join", "stop", "close"}) {
		t.Fatalf("events = %v, want [serve join stop close]", got)
	}
}

func TestRuntimeServerFakeInjectsServeAndCloseErrors(t *testing.T) {
	serveErr := errors.New("serve failed")
	closeErr := errors.New("close failed")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{
		events:   events,
		serveErr: serveErr,
		closeErr: closeErr,
	}

	if err := runtime.Serve(); !errors.Is(err, serveErr) {
		t.Fatalf("Serve() error = %v, want %v", err, serveErr)
	}
	if err := runtime.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close() error = %v, want %v", err, closeErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"serve", "stop", "close"}) {
		t.Fatalf("events = %v, want [serve stop close]", got)
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

func (c *configurablePanelClient) Describe() api.ClientInfo { return api.ClientInfo{NodeID: 9} }
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

func newStartTestService(events *lifecycleEvents, runtime *fakeRuntimeServer) *Hysteria2Service {
	client := &configurablePanelClient{
		nodeInfo: &api.NodeInfo{NodeType: "Hysteria2", NodeID: 9, Port: 9443, Hysteria2Config: &api.Hysteria2Config{}},
	}
	service := New(client, &controller.Config{
		ListenIP:       "127.0.0.1",
		UpdatePeriodic: 60,
		DisableGetRule: true,
		CertConfig:     &mylego.CertConfig{},
	})
	service.serverConfigFactory = func(*Hysteria2Service) (*server.Config, error) {
		events.add("build-config")
		return &server.Config{}, nil
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		events.add("build-server")
		return runtime, nil
	}
	service.taskFactory = func(tag string, _ time.Duration, _ func() error) lifecycleTask {
		return &fakePeriodicTask{tag: tag, events: events}
	}
	service.serveHandshake = func(start func(), _ <-chan struct{}, result <-chan error) error {
		start()
		select {
		case err := <-result:
			return err
		case <-runtime.servingSignal():
			return nil
		}
	}
	return service
}

func (f *fakeRuntimeServer) servingSignal() <-chan struct{} {
	if f.serving != nil {
		return f.serving
	}
	ready := make(chan struct{})
	close(ready)
	return ready
}

func TestStartBuildFailureDoesNotPublishRuntime(t *testing.T) {
	wantErr := errors.New("build failed")
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeServer{events: events})
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		events.add("build-server")
		return nil, wantErr
	}

	err := service.Start()
	if !errors.Is(err, wantErr) {
		t.Fatalf("Start() error = %v, want %v", err, wantErr)
	}
	if service.server != nil || service.nodeInfo != nil || service.tasks != nil || service.tag != "" || !service.startAt.IsZero() {
		t.Fatalf("failed Start published state: server=%v nodeInfo=%v tasks=%v tag=%q startAt=%v", service.server, service.nodeInfo, service.tasks, service.tag, service.startAt)
	}
	if service.state != stateFailed || !errors.Is(service.runtimeErr, wantErr) {
		t.Fatalf("state/error = %v/%v, want failed/%v", service.state, service.runtimeErr, wantErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build-config", "build-server"}) {
		t.Fatalf("events = %v, want [build-config build-server]", got)
	}
}

func TestStartUserListFailureDoesNotBuildRuntime(t *testing.T) {
	wantErr := errors.New("user list failed")
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeServer{events: events})
	service.apiClient.(*configurablePanelClient).userListErr = wantErr

	err := service.Start()
	if !errors.Is(err, wantErr) {
		t.Fatalf("Start() error = %v, want %v", err, wantErr)
	}
	if got := events.snapshot(); len(got) != 0 {
		t.Fatalf("events = %v, want no runtime or task work", got)
	}
	if service.nodeInfo != nil || service.server != nil || service.tasks != nil || service.tag != "" || !service.startAt.IsZero() {
		t.Fatalf("panel failure published state: nodeInfo=%v server=%v tasks=%v tag=%q startAt=%v", service.nodeInfo, service.server, service.tasks, service.tag, service.startAt)
	}
}

func TestStartImmediateServeFailureCleansRuntimeAndSkipsTasks(t *testing.T) {
	serveErr := errors.New("serve failed")
	closeErr := errors.New("close failed")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events, serveErr: serveErr, closeErr: closeErr}
	service := newStartTestService(events, runtime)
	service.serveHandshake = func(start func(), _ <-chan struct{}, result <-chan error) error {
		start()
		return <-result
	}

	err := service.Start()
	if !errors.Is(err, serveErr) || !errors.Is(err, closeErr) {
		t.Fatalf("Start() error = %v, want joined serve and close errors", err)
	}
	if service.server != nil || service.nodeInfo != nil || service.tasks != nil {
		t.Fatalf("failed Start published runtime state: server=%v nodeInfo=%v tasks=%v", service.server, service.nodeInfo, service.tasks)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build-config", "build-server", "serve", "stop", "close"}) {
		t.Fatalf("events = %v, want immediate serve failure cleanup", got)
	}
}

func TestDefaultServeHandshakeWaitsUntilServeReachesCallPoint(t *testing.T) {
	started := make(chan struct{})
	result := make(chan error, 1)
	startReturned := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		done <- defaultServeHandshake(func() { close(startReturned) }, started, result)
	}()
	<-startReturned
	select {
	case err := <-done:
		t.Fatalf("defaultServeHandshake returned before started closed: %v", err)
	default:
	}
	close(started)
	if err := <-done; err != nil {
		t.Fatalf("defaultServeHandshake() error = %v", err)
	}
}

func TestStartUsesConfiguredHandshakeForImmediateServeFailure(t *testing.T) {
	serveErr := errors.New("serve failed immediately")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events, serveErr: serveErr}
	service := newStartTestService(events, runtime)
	service.serveHandshake = nil
	startCalled := make(chan struct{})
	service.serveRuntime = func(runtimeServer) error {
		close(startCalled)
		return serveErr
	}
	service.serveHandshake = func(start func(), _ <-chan struct{}, result <-chan error) error {
		start()
		<-startCalled
		return <-result
	}

	err := service.Start()
	if !errors.Is(err, serveErr) {
		t.Fatalf("Start() error = %v, want immediate Serve error %v", err, serveErr)
	}
	if service.server != nil || service.tasks != nil {
		t.Fatalf("immediate Serve failure published runtime: server=%v tasks=%v", service.server, service.tasks)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build-config", "build-server", "stop", "close"}) {
		t.Fatalf("events = %v, want build then cleanup", got)
	}
}

func TestStartTaskFailureCleansStartedTasksInReverseThenRuntime(t *testing.T) {
	taskErr := errors.New("task start failed")
	closeErr := errors.New("runtime close failed")
	events := &lifecycleEvents{}
	serving := make(chan struct{})
	runtime := &fakeRuntimeServer{events: events, serveBlock: make(chan struct{}), serving: serving, serveExited: make(chan struct{}), closeErr: closeErr}
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
		"build-config", "build-server", "serve", "task-start:Hysteria2_127.0.0.1_9443_9", "task-start:node monitor",
		"task-close:node monitor", "task-close:Hysteria2_127.0.0.1_9443_9", "stop", "close",
	}) {
		t.Fatalf("events = %v, want reverse task cleanup then runtime cleanup", got)
	}
	if service.tasks != nil || service.server != nil || service.nodeInfo != nil {
		t.Fatalf("failed Start published state: tasks=%v server=%v nodeInfo=%v", service.tasks, service.server, service.nodeInfo)
	}
	select {
	case <-runtime.serveExited:
	default:
		t.Fatal("Serve goroutine did not exit after partial cleanup closed runtime")
	}
}

func TestStartFailureRestoresUserStateAndDefersRules(t *testing.T) {
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeServer{events: events})
	service.config.DisableGetRule = false
	client := service.apiClient.(*configurablePanelClient)
	client.users = []api.UserInfo{{UUID: "old-user", SpeedLimit: 20}, {UUID: "new-user", SpeedLimit: 10}}
	client.rules = []api.DetectRule{{ID: 1}}
	oldLimiter := rate.NewLimiter(10, 10)
	service.users["old-user"] = userRecord{UID: 1}
	service.rateLimiters = map[string]*rate.Limiter{"old-user": oldLimiter}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		return nil, errors.New("build failed")
	}

	if err := service.Start(); err == nil {
		t.Fatal("Start() error = nil, want build failure")
	}
	if _, ok := service.users["old-user"]; !ok || len(service.users) != 1 {
		t.Fatalf("users after failed Start = %v, want original users", service.users)
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
	service := newStartTestService(events, &fakeRuntimeServer{events: events})
	service.serverConfigFactory = func(*Hysteria2Service) (*server.Config, error) {
		close(entered)
		<-release
		return nil, errors.New("build failed")
	}
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
	<-done
}

func TestCloseAfterFailedStartTransitionsToStopped(t *testing.T) {
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeServer{events: events})
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
	serving := make(chan struct{})
	runtime := &fakeRuntimeServer{events: events, serveBlock: make(chan struct{}), serving: serving}
	service := newStartTestService(events, runtime)
	service.apiClient.(*configurablePanelClient).users = []api.UserInfo{{UUID: "new-user", SpeedLimit: 10}}
	service.users["old-user"] = userRecord{UID: 1}

	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, ok := service.users["new-user"]; !ok || len(service.users) != 1 {
		t.Fatalf("users after successful Start = %v, want new users", service.users)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestServeFailureAfterReadinessIsRecorded(t *testing.T) {
	serveErr := errors.New("serve stopped")
	events := &lifecycleEvents{}
	release := make(chan struct{})
	serving := make(chan struct{})
	runtime := &fakeRuntimeServer{events: events, serveErr: serveErr, serveBlock: release, serving: serving}
	service := newStartTestService(events, runtime)

	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	service.lifecycleMu.Lock()
	state, runtimeErr := service.state, service.runtimeErr
	service.lifecycleMu.Unlock()
	if state != stateRunning || runtimeErr != nil || service.server == nil || service.nodeInfo == nil || len(service.tasks) != 2 || service.tag == "" || service.startAt.IsZero() {
		t.Fatalf("state/error after readiness = %v/%v, want running/nil", state, runtimeErr)
	}
	close(release)
	if runtimeErr := waitForState(t, service, stateFailed); !errors.Is(runtimeErr, serveErr) {
		t.Fatalf("runtime error after Serve exit = %v, want %v", runtimeErr, serveErr)
	}
}

func TestStartPublishesOnlyAfterRuntimeAndTasksAreReady(t *testing.T) {
	events := &lifecycleEvents{}
	serving := make(chan struct{})
	runtime := &fakeRuntimeServer{events: events, serveBlock: make(chan struct{}), serving: serving}
	service := newStartTestService(events, runtime)

	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	service.lifecycleMu.Lock()
	state, runtimeErr := service.state, service.runtimeErr
	service.lifecycleMu.Unlock()
	if state != stateRunning || runtimeErr != nil {
		t.Fatalf("successful Start did not publish running state: state=%v err=%v server=%v nodeInfo=%v tasks=%d tag=%q startAt=%v", state, runtimeErr, service.server, service.nodeInfo, len(service.tasks), service.tag, service.startAt)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build-config", "build-server", "serve", "task-start:Hysteria2_127.0.0.1_9443_9", "task-start:node monitor"}) {
		t.Fatalf("events = %v, want Serve started before tasks", got)
	}
}

func TestStartTwiceWhileStartingIsRejected(t *testing.T) {
	events := &lifecycleEvents{}
	serving := make(chan struct{})
	runtime := &fakeRuntimeServer{events: events, serveBlock: make(chan struct{}), serving: serving}
	service := newStartTestService(events, runtime)
	releaseHandshake := make(chan struct{})
	enteredHandshake := make(chan struct{})
	service.serveHandshake = func(start func(), _ <-chan struct{}, result <-chan error) error {
		start()
		<-serving
		close(enteredHandshake)
		<-releaseHandshake
		return nil
	}
	firstDone := make(chan error, 1)
	go func() { firstDone <- service.Start() }()
	select {
	case <-enteredHandshake:
	case <-time.After(time.Second):
		t.Fatal("first Start() did not enter Serve handshake")
	}
	if err := service.Start(); err == nil {
		t.Fatal("concurrent Start() error = nil, want starting-state rejection")
	}
	close(releaseHandshake)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestStartTwiceAndStartAfterCloseAreRejected(t *testing.T) {
	events := &lifecycleEvents{}
	serving := make(chan struct{})
	runtime := &fakeRuntimeServer{events: events, serveBlock: make(chan struct{}), serving: serving}
	service := newStartTestService(events, runtime)
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
		"build-config", "build-server", "serve", "task-start:Hysteria2_127.0.0.1_9443_9", "task-start:node monitor",
		"task-close:node monitor", "task-close:Hysteria2_127.0.0.1_9443_9", "stop", "close",
	}) {
		t.Fatalf("events = %v, unexpected restart work", got)
	}
}

func TestRuntimeHelpersPropagateErrorsAndControlledBlocking(t *testing.T) {
	serveErr := errors.New("serve failed")
	closeErr := errors.New("close failed")
	events := &lifecycleEvents{}
	release := make(chan struct{})
	entered := make(chan struct{})
	runtime := &fakeRuntimeServer{
		events:     events,
		serveErr:   serveErr,
		closeErr:   closeErr,
		serveBlock: release,
		serving:    entered,
	}
	service := &Hysteria2Service{
		serveRuntime: defaultServeRuntime,
		closeRuntime: defaultCloseRuntime,
	}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- service.serveRuntime(runtime)
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("serveRuntime did not reach controlled block")
	}
	select {
	case err := <-serveDone:
		t.Fatalf("serveRuntime returned before release: %v", err)
	default:
	}

	close(release)
	if err := <-serveDone; !errors.Is(err, serveErr) {
		t.Fatalf("serveRuntime() error = %v, want %v", err, serveErr)
	}
	if err := service.closeRuntime(runtime); !errors.Is(err, closeErr) {
		t.Fatalf("closeRuntime() error = %v, want %v", err, closeErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"serve", "stop", "close"}) {
		t.Fatalf("events = %v, want [serve stop close]", got)
	}
}
