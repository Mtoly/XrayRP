package controller

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type coordinatorTestExecutor struct {
	mu               sync.Mutex
	calls            []syncActionType
	active           map[syncActionType]int
	maxActive        map[syncActionType]int
	started          chan syncActionType
	blockedCallIndex map[int]chan struct{}
	results          map[int]error
	canceled         chan int
}

func newCoordinatorTestExecutor() *coordinatorTestExecutor {
	return &coordinatorTestExecutor{
		active:           make(map[syncActionType]int),
		maxActive:        make(map[syncActionType]int),
		started:          make(chan syncActionType, 32),
		blockedCallIndex: make(map[int]chan struct{}),
		results:          make(map[int]error),
		canceled:         make(chan int, 32),
	}
}

func (e *coordinatorTestExecutor) blockCall(index int) chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()

	release := make(chan struct{})
	e.blockedCallIndex[index] = release
	return release
}

func (e *coordinatorTestExecutor) returnError(index int, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.results[index] = err
}

func (e *coordinatorTestExecutor) ExecuteSyncAction(ctx context.Context, action syncAction) error {
	e.mu.Lock()
	callIndex := len(e.calls) + 1
	e.calls = append(e.calls, action.Type)
	e.active[action.Type]++
	if e.active[action.Type] > e.maxActive[action.Type] {
		e.maxActive[action.Type] = e.active[action.Type]
	}
	release := e.blockedCallIndex[callIndex]
	result := e.results[callIndex]
	e.mu.Unlock()

	e.started <- action.Type

	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			e.canceled <- callIndex
			result = ctx.Err()
		}
	}

	e.mu.Lock()
	e.active[action.Type]--
	e.mu.Unlock()
	return result
}

func (e *coordinatorTestExecutor) Calls() []syncActionType {
	e.mu.Lock()
	defer e.mu.Unlock()

	calls := make([]syncActionType, len(e.calls))
	copy(calls, e.calls)
	return calls
}

func (e *coordinatorTestExecutor) MaxActive(actionType syncActionType) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.maxActive[actionType]
}

func waitForCoordinatorAction(t *testing.T, started <-chan syncActionType, want syncActionType) {
	t.Helper()

	select {
	case got := <-started:
		if got != want {
			t.Fatalf("unexpected started action: got %q want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for action %q to start", want)
	}
}

func waitForCoordinatorIdle(t *testing.T, coordinator *syncCoordinator) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		coordinator.WaitIdle()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for coordinator to become idle")
	}
}

func stopCoordinator(t *testing.T, coordinator *syncCoordinator) {
	t.Helper()
	coordinator.Stop()
}

func TestSyncCoordinator_RecordsFailureAndSubsequentRecovery(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	executor.returnError(1, errors.New("first execution failed"))
	state := newSyncExecutionState()
	coordinator := newSyncCoordinatorWithResultHandling(executor, state, nil)
	t.Cleanup(coordinator.Stop)

	first := newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"})
	coordinator.Submit(first)
	waitForCoordinatorIdle(t, coordinator)

	failed := state.Snapshot()
	if failed.Action.Type != first.Type || failed.Action.Source != first.Source || failed.Action.Trigger != first.Metadata.Trigger {
		t.Fatalf("unexpected failed action snapshot: %+v", failed.Action)
	}
	if failed.LastAttemptAt.IsZero() || !failed.LastSuccessAt.IsZero() {
		t.Fatalf("unexpected failure timestamps: attempt=%v success=%v", failed.LastAttemptAt, failed.LastSuccessAt)
	}
	if failed.LastError == nil || failed.ConsecutiveFailures != 1 {
		t.Fatalf("unexpected failure state: error=%v failures=%d", failed.LastError, failed.ConsecutiveFailures)
	}

	second := newSyncAction(syncActionTypeSyncUsers, syncActionSourcePolling, syncActionMetadata{Trigger: syncActionTriggerPollingTick})
	coordinator.Submit(second)
	waitForCoordinatorIdle(t, coordinator)

	recovered := state.Snapshot()
	if recovered.Action.Source != second.Source || recovered.LastSuccessAt.IsZero() {
		t.Fatalf("unexpected recovery snapshot: %+v", recovered)
	}
	if recovered.LastError != nil || recovered.ConsecutiveFailures != 0 {
		t.Fatalf("failure state not cleared after success: error=%v failures=%d", recovered.LastError, recovered.ConsecutiveFailures)
	}
}

func TestSyncCoordinator_CountsConsecutiveFailures(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	executor.returnError(1, errors.New("first failure"))
	executor.returnError(2, errors.New("second failure"))
	state := newSyncExecutionState()
	coordinator := newSyncCoordinatorWithResultHandling(executor, state, nil)
	t.Cleanup(coordinator.Stop)

	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "one"}))
	waitForCoordinatorIdle(t, coordinator)
	coordinator.Submit(newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourceWS, syncActionMetadata{Trigger: "two"}))
	waitForCoordinatorIdle(t, coordinator)

	snapshot := state.Snapshot()
	if snapshot.ConsecutiveFailures != 2 {
		t.Fatalf("unexpected consecutive failure count: got %d want 2", snapshot.ConsecutiveFailures)
	}
	if snapshot.LastError == nil || snapshot.LastError.Error() != "second failure" {
		t.Fatalf("unexpected last error: %v", snapshot.LastError)
	}
}

func TestSyncCoordinator_FailureStillRequeuesDirtyAction(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	executor.returnError(1, errors.New("first failure"))
	releaseFirst := executor.blockCall(1)
	state := newSyncExecutionState()
	coordinator := newSyncCoordinatorWithResultHandling(executor, state, nil)
	t.Cleanup(coordinator.Stop)

	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "first"}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncUsers)
	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourcePolling, syncActionMetadata{Trigger: "dirty"}))
	close(releaseFirst)
	waitForCoordinatorIdle(t, coordinator)

	if got, want := executor.Calls(), []syncActionType{syncActionTypeSyncUsers, syncActionTypeSyncUsers}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected calls after failed dirty action: got %v want %v", got, want)
	}
	if snapshot := state.Snapshot(); snapshot.LastError != nil || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("dirty success did not recover failure state: %+v", snapshot)
	}
}

func TestSyncCoordinator_StopCancelsInflightActionWithoutPublishingLateResult(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	release := executor.blockCall(1)
	state := newSyncExecutionState()
	coordinator := newSyncCoordinatorWithResultHandling(executor, state, nil)
	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "stop_cancel"}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncUsers)

	stopped := make(chan error, 1)
	go func() {
		stopped <- coordinator.StopContext(context.Background())
	}()

	select {
	case call := <-executor.canceled:
		if call != 1 {
			t.Fatalf("canceled call = %d, want 1", call)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inflight action did not observe coordinator cancellation")
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("StopContext() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StopContext did not join the canceled inflight action")
	}
	close(release)
	if snapshot := state.Snapshot(); snapshot.LastAttemptAt.IsZero() == false || snapshot.LastError != nil || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("canceled inflight result was published: %+v", snapshot)
	}
}
func TestSyncCoordinator_ObserverPanicDoesNotBreakCoordinator(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	observed := make(chan syncActionType, 2)
	observerCalls := 0
	coordinator := newSyncCoordinatorWithObserver(executor, func(action syncAction, _ error) {
		observerCalls++
		observed <- action.Type
		if observerCalls == 1 {
			panic("observer failed")
		}
	})

	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{}))
	select {
	case got := <-observed:
		if got != syncActionTypeSyncUsers {
			t.Fatalf("unexpected first observed action: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for panicking observer")
	}
	waitForCoordinatorIdle(t, coordinator)

	coordinator.Submit(newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourceWS, syncActionMetadata{}))
	select {
	case got := <-observed:
		if got != syncActionTypeSyncNodeConfig {
			t.Fatalf("unexpected second observed action: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("coordinator did not continue after observer panic")
	}
	waitForCoordinatorIdle(t, coordinator)

	stopped := make(chan struct{})
	go func() {
		coordinator.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after observer panic")
	}
}

func TestSyncCoordinator_BlockingObserverHonorsStopDeadlineAndCanBeJoined(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	observerEntered := make(chan struct{})
	releaseObserver := make(chan struct{})
	observerReturned := make(chan struct{})
	coordinator := newSyncCoordinatorWithObserver(executor, func(syncAction, error) {
		close(observerEntered)
		<-releaseObserver
		close(observerReturned)
	})

	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncUsers)
	select {
	case <-observerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for observer to block")
	}
	waitForCoordinatorIdle(t, coordinator)

	coordinator.Submit(newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourceWS, syncActionMetadata{}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncNodeConfig)
	waitForCoordinatorIdle(t, coordinator)

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() {
		stopped <- coordinator.StopContext(ctx)
	}()
	select {
	case <-coordinator.done:
	case <-time.After(2 * time.Second):
		t.Fatal("coordinator execution loop did not stop")
	}
	select {
	case err := <-stopped:
		t.Fatalf("StopContext returned before the observer joined: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-stopped:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("StopContext error = %v, want context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StopContext did not honor its cancellation deadline")
	}

	close(releaseObserver)
	select {
	case <-observerReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not return after release")
	}
	if err := coordinator.StopContext(context.Background()); err != nil {
		t.Fatalf("StopContext retry error = %v", err)
	}
}
func TestSyncCoordinator_DedupeQueuedActions(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	releaseFirst := executor.blockCall(1)
	coordinator := newSyncCoordinator(executor)

	coordinator.Submit(newSyncAction(syncActionTypeSyncAliveState, syncActionSourceManual, syncActionMetadata{}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncAliveState)

	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{}))
	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourcePolling, syncActionMetadata{}))

	close(releaseFirst)
	waitForCoordinatorIdle(t, coordinator)

	got := executor.Calls()
	want := []syncActionType{syncActionTypeSyncAliveState, syncActionTypeSyncUsers}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected execution order: got %v want %v", got, want)
	}
	stopCoordinator(t, coordinator)
}

func TestSyncCoordinator_DirtyRequeuesInflightAction(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	releaseFirst := executor.blockCall(1)
	coordinator := newSyncCoordinator(executor)

	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncUsers)

	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourcePolling, syncActionMetadata{}))

	close(releaseFirst)
	waitForCoordinatorIdle(t, coordinator)

	got := executor.Calls()
	want := []syncActionType{syncActionTypeSyncUsers, syncActionTypeSyncUsers}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected execution order: got %v want %v", got, want)
	}
	stopCoordinator(t, coordinator)
}

func TestSyncCoordinator_PrioritizesPendingActionsByPriority(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	releaseFirst := executor.blockCall(1)
	releaseSecond := executor.blockCall(2)
	releaseThird := executor.blockCall(3)
	releaseFourth := executor.blockCall(4)
	coordinator := newSyncCoordinator(executor)

	coordinator.Submit(newSyncAction(syncActionTypeSyncAliveState, syncActionSourceManual, syncActionMetadata{}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncAliveState)

	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{}))
	coordinator.Submit(newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourceWS, syncActionMetadata{}))
	coordinator.Submit(newSyncAction(syncActionTypeSyncRoutesAndOutbounds, syncActionSourceWS, syncActionMetadata{}))

	close(releaseFirst)
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncRoutesAndOutbounds)
	close(releaseSecond)
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncNodeConfig)
	close(releaseThird)
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncUsers)
	close(releaseFourth)

	waitForCoordinatorIdle(t, coordinator)

	got := executor.Calls()
	want := []syncActionType{
		syncActionTypeSyncAliveState,
		syncActionTypeSyncRoutesAndOutbounds,
		syncActionTypeSyncNodeConfig,
		syncActionTypeSyncUsers,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected execution order: got %v want %v", got, want)
	}
	stopCoordinator(t, coordinator)
}

func TestSyncCoordinator_ResyncAllOverridesPendingPartialActions(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	releaseFirst := executor.blockCall(1)
	releaseSecond := executor.blockCall(2)
	coordinator := newSyncCoordinator(executor)

	coordinator.Submit(newSyncAction(syncActionTypeSyncAliveState, syncActionSourceManual, syncActionMetadata{}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncAliveState)

	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{}))
	coordinator.Submit(newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourceWS, syncActionMetadata{}))
	coordinator.Submit(newSyncAction(syncActionTypeResyncAll, syncActionSourceReconnect, syncActionMetadata{}))

	close(releaseFirst)
	waitForCoordinatorAction(t, executor.started, syncActionTypeResyncAll)
	close(releaseSecond)
	waitForCoordinatorIdle(t, coordinator)

	got := executor.Calls()
	want := []syncActionType{syncActionTypeSyncAliveState, syncActionTypeResyncAll}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected execution order: got %v want %v", got, want)
	}
	stopCoordinator(t, coordinator)
}

func TestSyncCoordinator_PendingResyncDoesNotDropSyncDevices(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	releaseFirst := executor.blockCall(1)
	releaseSecond := executor.blockCall(2)
	coordinator := newSyncCoordinator(executor)

	coordinator.Submit(newSyncAction(syncActionTypeResyncAll, syncActionSourceManual, syncActionMetadata{}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeResyncAll)

	coordinator.Submit(newSyncAction(syncActionTypeSyncDevices, syncActionSourceWS, syncActionMetadata{}))

	close(releaseFirst)
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncDevices)
	close(releaseSecond)
	waitForCoordinatorIdle(t, coordinator)

	got := executor.Calls()
	want := []syncActionType{syncActionTypeResyncAll, syncActionTypeSyncDevices}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected execution order: got %v want %v", got, want)
	}
	stopCoordinator(t, coordinator)
}

func TestSyncCoordinator_PendingResyncDoesNotDropClearGlobalDevices(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	releaseFirst := executor.blockCall(1)
	releaseSecond := executor.blockCall(2)
	coordinator := newSyncCoordinator(executor)

	coordinator.Submit(newSyncAction(syncActionTypeResyncAll, syncActionSourceManual, syncActionMetadata{}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeResyncAll)

	coordinator.Submit(newSyncAction(syncActionTypeClearGlobalDevices, syncActionSourceReconnect, syncActionMetadata{}))

	close(releaseFirst)
	waitForCoordinatorAction(t, executor.started, syncActionTypeClearGlobalDevices)
	close(releaseSecond)
	waitForCoordinatorIdle(t, coordinator)

	got := executor.Calls()
	want := []syncActionType{syncActionTypeResyncAll, syncActionTypeClearGlobalDevices}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected execution order: got %v want %v", got, want)
	}
	stopCoordinator(t, coordinator)
}

func TestSyncCoordinator_ResyncAllReplacementPreservesDeviceActions(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	releaseFirst := executor.blockCall(1)
	releaseSecond := executor.blockCall(2)
	releaseThird := executor.blockCall(3)
	coordinator := newSyncCoordinator(executor)

	coordinator.Submit(newSyncAction(syncActionTypeSyncAliveState, syncActionSourceManual, syncActionMetadata{}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncAliveState)

	coordinator.Submit(newSyncAction(syncActionTypeSyncDevices, syncActionSourceWS, syncActionMetadata{}))
	coordinator.Submit(newSyncAction(syncActionTypeResyncAll, syncActionSourceReconnect, syncActionMetadata{}))

	close(releaseFirst)
	waitForCoordinatorAction(t, executor.started, syncActionTypeResyncAll)
	close(releaseSecond)
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncDevices)
	close(releaseThird)
	waitForCoordinatorIdle(t, coordinator)

	got := executor.Calls()
	want := []syncActionType{syncActionTypeSyncAliveState, syncActionTypeResyncAll, syncActionTypeSyncDevices}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected execution order: got %v want %v", got, want)
	}
	stopCoordinator(t, coordinator)
}

func TestSyncCoordinator_DirtyDoesNotRunConcurrentDuplicateActions(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	releaseFirst := executor.blockCall(1)
	coordinator := newSyncCoordinator(executor)

	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncUsers)

	for i := 0; i < 16; i++ {
		coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourcePolling, syncActionMetadata{}))
	}

	close(releaseFirst)
	waitForCoordinatorIdle(t, coordinator)

	got := executor.Calls()
	want := []syncActionType{syncActionTypeSyncUsers, syncActionTypeSyncUsers}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected execution order: got %v want %v", got, want)
	}
	if maxConcurrent := executor.MaxActive(syncActionTypeSyncUsers); maxConcurrent != 1 {
		t.Fatalf("unexpected concurrent sync user actions: got %d want %d", maxConcurrent, 1)
	}
	stopCoordinator(t, coordinator)
}
