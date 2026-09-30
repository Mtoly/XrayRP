package controller

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
)

// splitStopJoinPeriodic exposes Stop and Wait separately so tests can observe
// whether shutdown signals every producer before it joins any producer.
type splitStopJoinPeriodic struct {
	stopEntered chan struct{}
	releaseStop chan struct{}
	waitEntered chan struct{}
	releaseWait chan struct{}
	onStop      func()
	onWait      func()
	stopCalls   atomic.Int32
	waitCalls   atomic.Int32
	stopOnce    sync.Once
	waitOnce    sync.Once
}

func (*splitStopJoinPeriodic) Start() error { return nil }

func (p *splitStopJoinPeriodic) Stop() error {
	p.stopCalls.Add(1)
	if p.onStop != nil {
		p.onStop()
	}
	if p.stopEntered != nil {
		p.stopOnce.Do(func() { close(p.stopEntered) })
	}
	if p.releaseStop != nil {
		<-p.releaseStop
	}
	return nil
}

func (p *splitStopJoinPeriodic) Wait() error {
	p.waitCalls.Add(1)
	if p.onWait != nil {
		p.onWait()
	}
	if p.waitEntered != nil {
		p.waitOnce.Do(func() { close(p.waitEntered) })
	}
	if p.releaseWait != nil {
		<-p.releaseWait
	}
	return nil
}

func (p *splitStopJoinPeriodic) Close() error {
	return errors.Join(p.Stop(), p.Wait())
}

// contextLifecyclePeriodic honours the shutdown context in WaitContext, which
// mirrors the production runners and lets a Close attempt return on its
// deadline without pretending the producer exited.
type contextLifecyclePeriodic struct {
	stopEntered chan struct{}
	waitEntered chan struct{}
	releaseWait chan struct{}
	stopCalls   atomic.Int32
	waitCalls   atomic.Int32
	stopOnce    sync.Once
	waitOnce    sync.Once
}

func (*contextLifecyclePeriodic) Start() error { return nil }

func (p *contextLifecyclePeriodic) StopContext(context.Context) error {
	p.stopCalls.Add(1)
	p.stopOnce.Do(func() { close(p.stopEntered) })
	return nil
}

func (p *contextLifecyclePeriodic) WaitContext(ctx context.Context) error {
	p.waitCalls.Add(1)
	p.waitOnce.Do(func() { close(p.waitEntered) })
	select {
	case <-p.releaseWait:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *contextLifecyclePeriodic) Stop() error {
	return p.StopContext(context.Background())
}

func (p *contextLifecyclePeriodic) Wait() error {
	return p.WaitContext(context.Background())
}

func (p *contextLifecyclePeriodic) Close() error {
	return errors.Join(p.Stop(), p.Wait())
}

func (p *contextLifecyclePeriodic) CloseContext(ctx context.Context) error {
	return errors.Join(p.StopContext(ctx), p.WaitContext(ctx))
}

func waitForPeriodicShutdownSignal(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func assertNoPeriodicShutdownSignal(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s happened before all producers were signalled to stop", description)
	default:
	}
}

func periodicShutdownTagListed(err error, tag string) bool {
	var shutdownErr interface{ PendingTags() []string }
	if !errors.As(err, &shutdownErr) {
		return false
	}
	for _, pending := range shutdownErr.PendingTags() {
		if pending == tag {
			return true
		}
	}
	return false
}

func TestControllerClosePeriodicTasksSignalsEveryProducerBeforeJoining(t *testing.T) {
	releasedStop := make(chan struct{})
	close(releasedStop)
	releasedWait := make(chan struct{})
	close(releasedWait)

	blocker := &splitStopJoinPeriodic{
		stopEntered: make(chan struct{}),
		releaseStop: make(chan struct{}),
		waitEntered: make(chan struct{}),
		releaseWait: releasedWait,
	}
	second := &splitStopJoinPeriodic{
		stopEntered: make(chan struct{}),
		releaseStop: releasedStop,
		waitEntered: make(chan struct{}),
		releaseWait: releasedWait,
	}
	third := &splitStopJoinPeriodic{
		stopEntered: make(chan struct{}),
		releaseStop: releasedStop,
		waitEntered: make(chan struct{}),
		releaseWait: releasedWait,
	}
	controller := &Controller{
		tasks: []periodicTask{
			{tag: periodicTaskNodeMonitor, Periodic: blocker},
			{tag: periodicTaskUserMonitor, Periodic: second},
			{tag: periodicTaskCertMonitor, Periodic: third},
		},
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- controller.closePeriodicTasks() }()

	waitForPeriodicShutdownSignal(t, blocker.stopEntered, "first producer stop")
	// The first producer is still blocked inside Stop. Every other producer
	// must already have received its stop signal, and no producer may be
	// joined yet.
	waitForPeriodicShutdownSignal(t, second.stopEntered, "second producer stop")
	waitForPeriodicShutdownSignal(t, third.stopEntered, "third producer stop")
	assertNoPeriodicShutdownSignal(t, blocker.waitEntered, "first producer join")
	assertNoPeriodicShutdownSignal(t, second.waitEntered, "second producer join")

	close(blocker.releaseStop)
	if err := <-closeDone; err != nil {
		t.Fatalf("closePeriodicTasks() error = %v", err)
	}
	if got := blocker.waitCalls.Load(); got != 1 {
		t.Fatalf("first producer join calls = %d, want 1", got)
	}
}

func TestControllerClosePeriodicTasksRetriesJoinWithoutRestartingProducers(t *testing.T) {
	runner := &contextLifecyclePeriodic{
		stopEntered: make(chan struct{}),
		waitEntered: make(chan struct{}),
		releaseWait: make(chan struct{}),
	}
	controller := &Controller{
		tasks: []periodicTask{
			{tag: periodicTaskCertMonitor, Periodic: runner},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	closeDone := make(chan error, 1)
	go func() { closeDone <- controller.closePeriodicTasksContext(ctx) }()

	waitForPeriodicShutdownSignal(t, runner.waitEntered, "producer join attempt")
	cancel()
	firstErr := <-closeDone
	if !periodicShutdownTagListed(firstErr, periodicTaskCertMonitor) {
		t.Fatalf("first close error = %v, want typed error listing %q", firstErr, periodicTaskCertMonitor)
	}

	close(runner.releaseWait)
	if err := controller.closePeriodicTasksContext(context.Background()); err != nil {
		t.Fatalf("second close error = %v, want a real join", err)
	}
	if got := runner.stopCalls.Load(); got != 1 {
		t.Fatalf("producer stop calls = %d, want stop delivered exactly once", got)
	}
}

func TestControllerCloseRetryJoinsRunnerThatExitsAfterFirstDeadline(t *testing.T) {
	runner := &splitStopJoinPeriodic{
		stopEntered: make(chan struct{}),
		releaseStop: make(chan struct{}),
		waitEntered: make(chan struct{}),
		releaseWait: make(chan struct{}),
	}
	close(runner.releaseStop)
	controller := &Controller{
		tasks: []periodicTask{{tag: periodicTaskNodeMonitor, Periodic: runner}},
	}

	// First Close: the producer is still running when the attempt gives up.
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- controller.closePeriodicTasksContext(firstCtx) }()
	waitForPeriodicShutdownSignal(t, runner.waitEntered, "first producer join")
	cancelFirst()
	firstErr := <-firstDone
	if !periodicShutdownTagListed(firstErr, periodicTaskNodeMonitor) {
		t.Fatalf("first close error = %v, want typed error naming the live producer", firstErr)
	}
	if !errors.Is(firstErr, context.Canceled) {
		t.Fatalf("first close error = %v, want the attempt deadline reported", firstErr)
	}

	// The producer exits only after the first attempt already gave up.
	close(runner.releaseWait)

	// Second Close: it must observe the real exit and release ownership rather
	// than replay the first attempt's deadline error.
	if err := controller.closePeriodicTasksContext(context.Background()); err != nil {
		t.Fatalf("second close error = %v, want the real join result", err)
	}
	if !controller.periodicShutdownCompleted() {
		t.Fatal("periodic shutdown did not complete after the producer exited")
	}
	if err := controller.closePeriodicTasksContext(context.Background()); err != nil {
		t.Fatalf("third close error = %v, want a stable completed result", err)
	}
	if got := runner.stopCalls.Load(); got != 1 {
		t.Fatalf("producer stop calls = %d, want a single stop signal", got)
	}
}
func TestControllerCloseKeepsDependenciesWhilePeriodicProducersRemain(t *testing.T) {
	runner := &splitStopJoinPeriodic{
		stopEntered: make(chan struct{}),
		releaseStop: make(chan struct{}),
		waitEntered: make(chan struct{}),
		releaseWait: make(chan struct{}),
	}
	close(runner.releaseStop)
	ws := &fakeLifecycleWSRuntime{}
	coordinator := &fakeLifecycleCoordinator{}
	var (
		ruleUpdates    int
		limiterDeletes int
		runtimeDeletes int
	)
	hooks := syncApplyHooks{
		runtime: syncApplyRuntimeHooks{
			cleanupTag: func(*api.NodeInfo, string) error {
				runtimeDeletes++
				return nil
			},
		},
		limiter: syncApplyLimiterHooks{
			deleteInbound: func(string) error {
				limiterDeletes++
				return nil
			},
		},
		updateRule: func(string, []api.DetectRule) error {
			ruleUpdates++
			return nil
		},
	}
	controller := &Controller{
		tasks:           []periodicTask{{tag: periodicTaskCertMonitor, Periodic: runner}},
		wsRuntime:       ws,
		syncCoordinator: coordinator,
	}
	ownership := controllerRuntimeOwnership{
		nodeSnapshot:    &api.NodeSnapshot{NodeType: "V2ray", NodeID: 1},
		tag:             "test-tag",
		runtime:         true,
		limiter:         true,
		rules:           true,
		periodic:        true,
		websocket:       true,
		syncCoordinator: true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cleanupDone := make(chan error, 1)
	go func() {
		cleanupDone <- controller.cleanupControllerOwnershipContext(ctx, &ownership, hooks)
	}()

	waitForPeriodicShutdownSignal(t, runner.waitEntered, "producer join attempt")
	cancel()
	err := <-cleanupDone
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cleanup error = %v, want cancellation reported", err)
	}
	if !periodicShutdownTagListed(err, periodicTaskCertMonitor) {
		t.Fatalf("cleanup error = %v, want typed error listing %q", err, periodicTaskCertMonitor)
	}
	if ws.stopped {
		t.Fatal("websocket was stopped while a periodic producer could still use it")
	}
	if coordinator.stopped {
		t.Fatal("sync coordinator was stopped while a periodic producer could still submit into it")
	}
	if ruleUpdates != 0 || limiterDeletes != 0 || runtimeDeletes != 0 {
		t.Fatalf("dependency teardown ran while a periodic producer was alive: rules=%d limiter=%d runtime=%d", ruleUpdates, limiterDeletes, runtimeDeletes)
	}
	if !ownership.periodic || !ownership.websocket || !ownership.syncCoordinator || !ownership.rules || !ownership.limiter || !ownership.runtime {
		t.Fatalf("ownership was released while a periodic producer was alive: %+v", ownership)
	}

	close(runner.releaseWait)
	if err := controller.closePeriodicTasksContext(context.Background()); err != nil {
		t.Fatalf("periodic cleanup error = %v", err)
	}
}

func TestControllerCloseOrdersPeriodicShutdownBeforeDependencies(t *testing.T) {
	var order []string
	releasedStop := make(chan struct{})
	close(releasedStop)
	releasedWait := make(chan struct{})
	close(releasedWait)
	runner := &splitStopJoinPeriodic{
		releaseStop: releasedStop,
		releaseWait: releasedWait,
		onStop:      func() { order = append(order, "periodic-stop") },
		onWait:      func() { order = append(order, "periodic-wait") },
	}
	ws := &fakeLifecycleWSRuntime{order: &order}
	coordinator := &fakeLifecycleCoordinator{order: &order}
	hooks := syncApplyHooks{
		runtime: syncApplyRuntimeHooks{
			cleanupTag: func(*api.NodeInfo, string) error {
				order = append(order, "runtime")
				return nil
			},
		},
		limiter: syncApplyLimiterHooks{
			deleteInbound: func(string) error {
				order = append(order, "limiter")
				return nil
			},
		},
		updateRule: func(string, []api.DetectRule) error {
			order = append(order, "rules")
			return nil
		},
	}
	controller := &Controller{
		tasks:           []periodicTask{{tag: periodicTaskCertMonitor, Periodic: runner}},
		wsRuntime:       ws,
		syncCoordinator: coordinator,
	}
	ownership := controllerRuntimeOwnership{
		nodeSnapshot:    &api.NodeSnapshot{NodeType: "V2ray", NodeID: 1},
		tag:             "test-tag",
		runtime:         true,
		limiter:         true,
		rules:           true,
		periodic:        true,
		websocket:       true,
		syncCoordinator: true,
	}

	if err := controller.cleanupControllerOwnershipContext(context.Background(), &ownership, hooks); err != nil {
		t.Fatalf("cleanup error = %v", err)
	}
	if ownership.hasResources() {
		t.Fatalf("cleanup retained ownership: %+v", ownership)
	}
	want := []string{"periodic-stop", "periodic-wait", "ws", "coordinator", "rules", "limiter", "runtime"}
	if len(order) != len(want) {
		t.Fatalf("teardown order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("teardown order = %v, want %v", order, want)
		}
	}
}

func TestControllerConcurrentCloseStopsAndJoinsEachProducerOnce(t *testing.T) {
	runner := &contextLifecyclePeriodic{
		stopEntered: make(chan struct{}),
		waitEntered: make(chan struct{}),
		releaseWait: make(chan struct{}),
	}
	controller := &Controller{
		tasks: []periodicTask{{tag: periodicTaskCertMonitor, Periodic: runner}},
	}

	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- controller.closePeriodicTasksContext(context.Background()) }()
	waitForPeriodicShutdownSignal(t, runner.waitEntered, "first close join")
	go func() { secondDone <- controller.closePeriodicTasksContext(context.Background()) }()

	close(runner.releaseWait)
	if err := <-firstDone; err != nil {
		t.Fatalf("first close error = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second close error = %v", err)
	}
	// Two concurrent Close calls must hand off the producer's ownership
	// exactly once and observe the same join.
	if got := runner.stopCalls.Load(); got != 1 {
		t.Fatalf("producer stop calls = %d, want a single stop signal", got)
	}
	if got := runner.waitCalls.Load(); got != 1 {
		t.Fatalf("producer join calls = %d, want a single join", got)
	}
}

func TestControllerClosePeriodicTasksClosesRunnersWithoutSeparateJoin(t *testing.T) {
	first := &recordingPeriodic{closeErr: errors.New("first close failed")}
	second := &recordingPeriodic{}
	controller := &Controller{
		tasks: []periodicTask{
			{tag: periodicTaskNodeMonitor, Periodic: first},
			{tag: periodicTaskUserMonitor, Periodic: second},
		},
	}

	err := controller.closePeriodicTasks()
	if err == nil {
		t.Fatal("closePeriodicTasks() error = nil, want the producer close error reported")
	}
	if first.closed != 1 || second.closed != 1 {
		t.Fatalf("producer Close calls = first:%d second:%d, want each producer closed once", first.closed, second.closed)
	}
	if !controller.periodicShutdownCompleted() {
		t.Fatal("periodic shutdown did not complete after closing every producer")
	}
}

func TestControllerCloseRetainsOwnershipUntilPeriodicProducersExit(t *testing.T) {
	runner := &contextLifecyclePeriodic{
		stopEntered: make(chan struct{}),
		waitEntered: make(chan struct{}),
		releaseWait: make(chan struct{}),
	}
	ws := &fakeLifecycleWSRuntime{}
	coordinator := &fakeLifecycleCoordinator{}
	var runtimeDeletes, limiterDeletes, ruleClears atomic.Int32
	hooks := syncApplyHooks{
		runtime: syncApplyRuntimeHooks{
			cleanupTag: func(*api.NodeInfo, string) error {
				runtimeDeletes.Add(1)
				return nil
			},
		},
		limiter: syncApplyLimiterHooks{
			deleteInbound: func(string) error {
				limiterDeletes.Add(1)
				return nil
			},
		},
		updateRule: func(string, []api.DetectRule) error {
			ruleClears.Add(1)
			return nil
		},
	}
	controller := &Controller{
		tasks:           []periodicTask{{tag: periodicTaskCertMonitor, Periodic: runner}},
		wsRuntime:       ws,
		syncCoordinator: coordinator,
		syncApplyHooks:  hooks,
		lifecycleState:  controllerStateRunning,
		ownedRuntime: controllerRuntimeOwnership{
			nodeSnapshot:    &api.NodeSnapshot{NodeType: "V2ray", NodeID: 1},
			tag:             "test-tag",
			runtime:         true,
			limiter:         true,
			rules:           true,
			periodic:        true,
			websocket:       true,
			syncCoordinator: true,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	closeDone := make(chan error, 1)
	go func() {
		ownership, shouldCleanup, err := controller.beginLifecycleClose()
		if err != nil || !shouldCleanup {
			closeDone <- err
			return
		}
		closeErr := controller.cleanupControllerOwnershipContext(ctx, &ownership, hooks)
		controller.finishLifecycleClose(ownership, closeErr)
		closeDone <- closeErr
	}()

	waitForPeriodicShutdownSignal(t, runner.waitEntered, "producer join attempt")
	cancel()
	if err := <-closeDone; err == nil {
		t.Fatal("Close() error = nil, want the incomplete periodic shutdown reported")
	}
	controller.lifecycleMu.Lock()
	state := controller.lifecycleState
	owned := controller.ownedRuntime
	controller.lifecycleMu.Unlock()
	if state != controllerStateFailedOwned {
		t.Fatalf("lifecycle state after incomplete close = %v, want FailedOwned", state)
	}
	if !owned.periodic || !owned.websocket || !owned.syncCoordinator {
		t.Fatalf("ownership released while producers were alive: %+v", owned)
	}
	if ws.stopped || coordinator.stopped {
		t.Fatalf("downstream resources were torn down while producers were alive: ws=%v coordinator=%v", ws.stopped, coordinator.stopped)
	}
	if runtimeDeletes.Load() != 0 || limiterDeletes.Load() != 0 || ruleClears.Load() != 0 {
		t.Fatalf("dependency teardown ran while producers were alive: runtime=%d limiter=%d rules=%d",
			runtimeDeletes.Load(), limiterDeletes.Load(), ruleClears.Load())
	}

	// Once the producer actually exits, the retry must release ownership and
	// tear the dependencies down through the same close path.
	close(runner.releaseWait)
	if err := controller.Close(); err != nil {
		t.Fatalf("Close() retry error = %v", err)
	}
	controller.lifecycleMu.Lock()
	state = controller.lifecycleState
	controller.lifecycleMu.Unlock()
	if state != controllerStateClosed {
		t.Fatalf("lifecycle state after successful retry = %v, want Closed", state)
	}
	if !ws.stopped || !coordinator.stopped {
		t.Fatalf("downstream resources were not torn down after producers exited: ws=%v coordinator=%v", ws.stopped, coordinator.stopped)
	}
	if runtimeDeletes.Load() != 1 || limiterDeletes.Load() != 1 || ruleClears.Load() != 1 {
		t.Fatalf("dependency teardown after retry = runtime:%d limiter:%d rules:%d, want 1/1/1",
			runtimeDeletes.Load(), limiterDeletes.Load(), ruleClears.Load())
	}
}
