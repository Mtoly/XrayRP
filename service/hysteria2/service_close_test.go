package hysteria2

import (
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	xcommon "github.com/Mtoly/XrayRP/common"
)

type stagedPeriodicTask struct {
	tag        string
	events     *lifecycleEvents
	startBlock <-chan struct{}
	startErr   error
	stopErr    error
	waitErr    error
}

func (t *stagedPeriodicTask) Start() error {
	if t.events != nil {
		t.events.add("task-start:" + t.tag)
	}
	if t.startBlock != nil {
		<-t.startBlock
	}
	return t.startErr
}
func (t *stagedPeriodicTask) Stop() error {
	if t.events != nil {
		t.events.add("task-stop:" + t.tag)
	}
	return t.stopErr
}
func (t *stagedPeriodicTask) Wait() error {
	if t.events != nil {
		t.events.add("task-wait:" + t.tag)
	}
	return t.waitErr
}
func (t *stagedPeriodicTask) Close() error { return errors.Join(t.Stop(), t.Wait()) }

type recordingManagedPeriodic struct {
	tag    string
	events *lifecycleEvents
	task   *xcommon.ManagedPeriodic
}

func (t *recordingManagedPeriodic) Start() error { return t.task.Start() }
func (t *recordingManagedPeriodic) Stop() error {
	t.events.add("task-stop:" + t.tag)
	return t.task.Stop()
}
func (t *recordingManagedPeriodic) Wait() error {
	t.events.add("task-wait:" + t.tag)
	return t.task.Wait()
}
func (t *recordingManagedPeriodic) Close() error { return errors.Join(t.Stop(), t.Wait()) }

func TestCloseBeforeStartAndCloseTwiceAreNoOps(t *testing.T) {
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeServer{events: events})

	if err := service.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if got := events.snapshot(); len(got) != 0 {
		t.Fatalf("events = %v, want no startup or cleanup work", got)
	}
}

func TestCloseAfterStartIsSequentiallyIdempotent(t *testing.T) {
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events, serveBlock: make(chan struct{}), serving: make(chan struct{})}
	service := newStartTestService(events, runtime)
	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	first := events.snapshot()
	if err := service.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, first) {
		t.Fatalf("second Close() events = %v, want unchanged %v", got, first)
	}
}

func TestStartOwnsPortHopRuleInstallationBeforePublishingRunning(t *testing.T) {
	originalApply := applyPortHopRules
	defer func() { applyPortHopRules = originalApply }()

	applyEntered := make(chan struct{})
	releaseApply := make(chan struct{})
	applyPortHopRules = func([]portHopRule, *log.Entry) error {
		close(applyEntered)
		<-releaseApply
		return nil
	}

	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{
		events:     events,
		serveBlock: make(chan struct{}),
		serving:    make(chan struct{}),
	}
	service := newStartTestService(events, runtime)
	nodeInfo := service.apiClient.(*configurablePanelClient).nodeInfo
	nodeInfo.Hysteria2Config.PortHopEnabled = true
	nodeInfo.Hysteria2Config.PortHopPorts = "9444"

	startDone := make(chan error, 1)
	go func() { startDone <- service.Start() }()
	<-applyEntered

	closeDone := make(chan error, 1)
	go func() { closeDone <- service.Close() }()
	select {
	case err := <-closeDone:
		close(releaseApply)
		if err == nil {
			t.Fatal("Close() error = nil during startup-owned port-hop installation")
		}
	case <-time.After(20 * time.Millisecond):
		close(releaseApply)
		<-startDone
		t.Fatal("Close() blocked instead of rejecting startup-owned port-hop installation")
	}

	if err := <-startDone; err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close() after Start error = %v", err)
	}
}

func TestStartRecordsInstalledPortHopRulesForCloseOwnership(t *testing.T) {
	originalApply, originalDelete := applyPortHopRules, deletePortHopRules
	t.Cleanup(func() {
		applyPortHopRules = originalApply
		deletePortHopRules = originalDelete
	})
	applyPortHopRules = func([]portHopRule, *log.Entry) error { return nil }
	deleted := make(chan []portHopRule, 1)
	deletePortHopRules = func(rules []portHopRule, _ *log.Entry) error {
		deleted <- append([]portHopRule(nil), rules...)
		return nil
	}

	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events, serveBlock: make(chan struct{}), serving: make(chan struct{})}
	service := newStartTestService(events, runtime)
	nodeInfo := service.apiClient.(*configurablePanelClient).nodeInfo
	nodeInfo.Hysteria2Config.PortHopEnabled = true
	nodeInfo.Hysteria2Config.PortHopPorts = "9444-9445"

	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	wantRules := buildPortHopRulesFromNode(nodeInfo)
	if !reflect.DeepEqual(service.portHopRules, wantRules) {
		t.Fatalf("installed port-hop ownership = %v, want %v", service.portHopRules, wantRules)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := <-deleted; !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("Close() deleted rules = %v, want %v", got, wantRules)
	}
}

func TestStartPortHopFailureCleansRuntimeAndDoesNotPublishOwnership(t *testing.T) {
	applyErr := errors.New("port-hop apply failed")
	originalApply, originalDelete := applyPortHopRules, deletePortHopRules
	t.Cleanup(func() {
		applyPortHopRules = originalApply
		deletePortHopRules = originalDelete
	})
	applyPortHopRules = func([]portHopRule, *log.Entry) error { return applyErr }
	deletePortHopRules = func([]portHopRule, *log.Entry) error { return nil }

	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events, serveBlock: make(chan struct{}), serving: make(chan struct{})}
	service := newStartTestService(events, runtime)
	nodeInfo := service.apiClient.(*configurablePanelClient).nodeInfo
	nodeInfo.Hysteria2Config.PortHopEnabled = true
	nodeInfo.Hysteria2Config.PortHopPorts = "9444-9445"

	err := service.Start()
	if !errors.Is(err, applyErr) {
		t.Fatalf("Start() error = %v, want %v", err, applyErr)
	}
	if service.state != stateFailed || service.server != nil || service.nodeInfo != nil || len(service.portHopRules) != 0 {
		t.Fatalf("failed port-hop Start published state: state=%v server=%v node=%v rules=%v", service.state, service.server, service.nodeInfo, service.portHopRules)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{
		"build-config", "build-server", "serve",
		"task-start:Hysteria2_127.0.0.1_9443_9", "task-start:node monitor",
		"task-close:node monitor", "task-close:Hysteria2_127.0.0.1_9443_9",
		"stop", "close",
	}) {
		t.Fatalf("cleanup events = %v", got)
	}
}

func TestCloseWaitsForRunningPeriodicCallback(t *testing.T) {
	events := &lifecycleEvents{}
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	var calls atomic.Int32
	var startedOnce atomic.Bool
	task := defaultTaskFactory("blocking", time.Millisecond, func() error {
		if calls.Add(1) == 1 {
			return nil
		}
		if startedOnce.CompareAndSwap(false, true) {
			close(callbackStarted)
		}
		<-releaseCallback
		events.add("task-exit")
		return nil
	})
	if err := task.Start(); err != nil {
		t.Fatalf("task Start() error = %v", err)
	}
	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("periodic callback did not start")
	}

	service := &Hysteria2Service{
		state:        stateRunning,
		server:       &fakeRuntimeServer{events: events},
		closeRuntime: defaultCloseRuntime,
		tasks:        []periodicTask{{tag: "blocking", task: task}},
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- service.Close() }()

	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before callback exit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"stop", "close"}) {
		t.Fatalf("events before callback release = %v, want runtime closed before wait", got)
	}
	close(releaseCallback)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestCloseWaitsForServeAndWatcherGoroutines(t *testing.T) {
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events}
	service := newStartTestService(events, runtime)
	serveStarted := make(chan struct{})
	releaseServe := make(chan struct{})
	closeRequested := make(chan struct{})
	service.serveRuntime = func(runtimeServer) error {
		close(serveStarted)
		<-releaseServe
		return errors.New("server closed")
	}
	service.closeRuntime = func(runtimeServer) error {
		close(closeRequested)
		return nil
	}
	service.serveHandshake = func(start func(), _ <-chan struct{}, _ <-chan error) error {
		start()
		<-serveStarted
		return nil
	}

	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- service.Close() }()
	select {
	case <-closeRequested:
	case <-time.After(time.Second):
		t.Fatal("Close() did not close runtime")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before Serve exit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseServe)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if service.state != stateStopped || service.runtimeErr != nil {
		t.Fatalf("state/error after normal Close = %v/%v, want stopped/nil", service.state, service.runtimeErr)
	}
}

func TestCloseWaitsForServeAndWatcherGoroutinesWhenRuntimeCloseFails(t *testing.T) {
	closeErr := errors.New("runtime close failed")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events}
	service := newStartTestService(events, runtime)
	serveStarted := make(chan struct{})
	releaseServe := make(chan struct{})
	closeRequested := make(chan struct{})
	service.serveRuntime = func(runtimeServer) error {
		close(serveStarted)
		<-releaseServe
		return errors.New("server closed")
	}
	service.closeRuntime = func(runtimeServer) error {
		close(closeRequested)
		close(releaseServe)
		return closeErr
	}
	service.serveHandshake = func(start func(), _ <-chan struct{}, _ <-chan error) error {
		start()
		<-serveStarted
		return nil
	}

	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := service.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close() error = %v, want %v", err, closeErr)
	}
	select {
	case <-closeRequested:
	default:
		t.Fatal("Close() did not call runtime close")
	}
	if service.state != stateStopped || service.runtimeErr != nil {
		t.Fatalf("state/error after Close = %v/%v, want stopped/nil", service.state, service.runtimeErr)
	}
}

func TestCloseJoinsTaskAndRuntimeErrors(t *testing.T) {
	stopErr := errors.New("task stop failed")
	waitErr := errors.New("task wait failed")
	runtimeErr := errors.New("runtime close failed")
	events := &lifecycleEvents{}
	service := &Hysteria2Service{
		state:        stateRunning,
		server:       &fakeRuntimeServer{events: events, closeErr: runtimeErr},
		closeRuntime: defaultCloseRuntime,
		tasks: []periodicTask{{tag: "failing", task: &stagedPeriodicTask{
			tag: "failing", events: events, stopErr: stopErr, waitErr: waitErr,
		}}},
	}

	err := service.Close()
	if !errors.Is(err, stopErr) || !errors.Is(err, waitErr) || !errors.Is(err, runtimeErr) {
		t.Fatalf("Close() error = %v, want task stop, task wait, and runtime close errors", err)
	}
}

func TestStartHandshakeFailureWaitsForServeExit(t *testing.T) {
	handshakeErr := errors.New("handshake failed")
	closeErr := errors.New("runtime close failed")
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeServer{events: events})
	serveStarted := make(chan struct{})
	serveReleased := make(chan struct{})
	allowServeExit := make(chan struct{})
	closeCalled := make(chan struct{})
	defer func() {
		select {
		case <-allowServeExit:
		default:
			close(allowServeExit)
		}
	}()
	service.serveRuntime = func(runtimeServer) error {
		close(serveStarted)
		<-serveReleased
		<-allowServeExit
		events.add("serve-exit")
		return nil
	}
	service.serveHandshake = func(start func(), _ <-chan struct{}, _ <-chan error) error {
		start()
		<-serveStarted
		return handshakeErr
	}
	service.closeRuntime = func(runtimeServer) error {
		events.add("runtime-close")
		close(closeCalled)
		close(serveReleased)
		return closeErr
	}

	startDone := make(chan error, 1)
	go func() { startDone <- service.Start() }()
	select {
	case <-closeCalled:
	case <-time.After(time.Second):
		t.Fatal("Start() did not close runtime after handshake failure")
	}
	select {
	case err := <-startDone:
		t.Fatalf("Start() returned before Serve exited: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(allowServeExit)
	err := <-startDone
	if !errors.Is(err, handshakeErr) || !errors.Is(err, closeErr) {
		t.Fatalf("Start() error = %v, want handshake and close errors", err)
	}
}

func TestStartTaskFailureStopsTasksClosesRuntimeWaitsForServeThenTasks(t *testing.T) {
	taskStartErr := errors.New("task start failed")
	taskStopErr := errors.New("task stop failed")
	taskWaitErr := errors.New("task wait failed")
	callbackErr := errors.New("callback failed")
	runtimeCloseErr := errors.New("runtime close failed")
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeServer{events: events})
	runtimeClosed := make(chan struct{})
	callbackStarted := make(chan struct{})
	serveStarted := make(chan struct{})
	serveReleased := make(chan struct{})
	allowServeExit := make(chan struct{})
	defer func() {
		for _, ch := range []chan struct{}{runtimeClosed, serveReleased, allowServeExit} {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
	}()
	service.serveRuntime = func(runtimeServer) error {
		close(serveStarted)
		<-serveReleased
		<-allowServeExit
		events.add("serve-exit")
		return nil
	}
	service.serveHandshake = func(start func(), _ <-chan struct{}, _ <-chan error) error {
		start()
		<-serveStarted
		return nil
	}
	service.closeRuntime = func(runtimeServer) error {
		events.add("runtime-close")
		select {
		case <-runtimeClosed:
		default:
			close(runtimeClosed)
		}
		select {
		case <-serveReleased:
		default:
			close(serveReleased)
		}
		return runtimeCloseErr
	}
	created := 0
	calls := 0
	service.taskFactory = func(tag string, _ time.Duration, _ func() error) lifecycleTask {
		created++
		if created == 1 {
			managed := &xcommon.ManagedPeriodic{
				Interval: time.Nanosecond,
				Execute: func() error {
					calls++
					if calls == 1 {
						events.add("callback-initial")
						return nil
					}
					events.add("callback-start")
					close(callbackStarted)
					<-runtimeClosed
					events.add("callback-exit")
					return callbackErr
				},
			}
			return &recordingManagedPeriodic{tag: tag, events: events, task: managed}
		}
		return &stagedPeriodicTask{
			tag: tag, events: events, startBlock: callbackStarted,
			startErr: taskStartErr, stopErr: taskStopErr, waitErr: taskWaitErr,
		}
	}

	startDone := make(chan error, 1)
	go func() { startDone <- service.Start() }()
	select {
	case <-runtimeClosed:
	case <-time.After(time.Second):
		t.Fatal("Start() did not reach runtime cleanup")
	}
	select {
	case err := <-startDone:
		t.Fatalf("Start() returned before Serve exited: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(allowServeExit)
	err := <-startDone
	for _, wantErr := range []error{taskStartErr, taskStopErr, taskWaitErr, callbackErr, runtimeCloseErr} {
		if !errors.Is(err, wantErr) {
			t.Fatalf("Start() error = %v, want joined %v", err, wantErr)
		}
	}

	got := events.snapshot()
	index := func(event string) int {
		for i, gotEvent := range got {
			if gotEvent == event {
				return i
			}
		}
		return -1
	}
	ordered := []string{
		"task-stop:node monitor",
		"task-stop:Hysteria2_127.0.0.1_9443_9",
		"runtime-close",
		"serve-exit",
		"task-wait:node monitor",
		"task-wait:Hysteria2_127.0.0.1_9443_9",
	}
	for i := 1; i < len(ordered); i++ {
		if index(ordered[i-1]) < 0 || index(ordered[i-1]) >= index(ordered[i]) {
			t.Fatalf("events = %v, want ordered phases %v", got, ordered)
		}
	}
	if index("runtime-close") >= index("callback-exit") {
		t.Fatalf("events = %v, want runtime close before callback exit", got)
	}
}
