package controller

import (
	"context"
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
}

func newCoordinatorTestExecutor() *coordinatorTestExecutor {
	return &coordinatorTestExecutor{
		active:           make(map[syncActionType]int),
		maxActive:        make(map[syncActionType]int),
		started:          make(chan syncActionType, 32),
		blockedCallIndex: make(map[int]chan struct{}),
	}
}

func (e *coordinatorTestExecutor) blockCall(index int) chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()

	release := make(chan struct{})
	e.blockedCallIndex[index] = release
	return release
}

func (e *coordinatorTestExecutor) ExecuteSyncAction(_ context.Context, action syncAction) error {
	e.mu.Lock()
	callIndex := len(e.calls) + 1
	e.calls = append(e.calls, action.Type)
	e.active[action.Type]++
	if e.active[action.Type] > e.maxActive[action.Type] {
		e.maxActive[action.Type] = e.active[action.Type]
	}
	release := e.blockedCallIndex[callIndex]
	e.mu.Unlock()

	e.started <- action.Type

	if release != nil {
		<-release
	}

	e.mu.Lock()
	e.active[action.Type]--
	e.mu.Unlock()
	return nil
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
}

func TestSyncCoordinator_ResyncAllOverridesPendingPartialActions(t *testing.T) {
	executor := newCoordinatorTestExecutor()
	releaseFirst := executor.blockCall(1)
	coordinator := newSyncCoordinator(executor)

	coordinator.Submit(newSyncAction(syncActionTypeSyncAliveState, syncActionSourceManual, syncActionMetadata{}))
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncAliveState)

	coordinator.Submit(newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{}))
	coordinator.Submit(newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourceWS, syncActionMetadata{}))
	coordinator.Submit(newSyncAction(syncActionTypeResyncAll, syncActionSourceReconnect, syncActionMetadata{}))

	close(releaseFirst)
	waitForCoordinatorIdle(t, coordinator)

	got := executor.Calls()
	want := []syncActionType{syncActionTypeSyncAliveState, syncActionTypeResyncAll}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected execution order: got %v want %v", got, want)
	}
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
}
