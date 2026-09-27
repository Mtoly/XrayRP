package controller

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service"
)

func newSyncHealthTestController(apiClient PanelClient) *Controller {
	controller, _ := newTestSyncApplyController(apiClient)
	controller.syncExecutionState = newSyncExecutionState()
	controller.lifecycleState = controllerStateRunning
	return controller
}

func TestExecuteSyncActionPollingSuccessAdvancesHealth(t *testing.T) {
	panel := &fakeSyncApplyAPI{userList: &[]api.UserInfo{}}
	controller := newSyncHealthTestController(panel)
	staleAfter := 30 * time.Second
	initial := time.Now().Add(-2 * staleAfter)
	controller.health.RecordSuccessfulSync(initial)
	if readiness := service.EvaluateReadiness(controller.ObservabilitySnapshot(), time.Now(), staleAfter); readiness.Ready || !slices.Contains(readiness.Reasons, service.ReadinessReasonSyncStale) {
		t.Fatalf("readiness before sync = %#v, want sync_stale", readiness)
	}

	action := newSyncAction(
		syncActionTypeSyncUsers,
		syncActionSourcePolling,
		syncActionMetadata{Trigger: syncActionTriggerPollingTick},
	)
	if err := controller.ExecuteSyncAction(context.Background(), action); err != nil {
		t.Fatalf("ExecuteSyncAction() error = %v", err)
	}

	health := controller.health.Snapshot()
	if !health.LastSuccessfulSync.After(initial) {
		t.Fatalf("LastSuccessfulSync = %v, want after %v", health.LastSuccessfulSync, initial)
	}
	if panel.getUserListCalls != 1 {
		t.Fatalf("panel user fetches = %d, want 1", panel.getUserListCalls)
	}
	if snapshot := controller.ObservabilitySnapshot(); snapshot.Lifecycle != service.RuntimeLifecycleRunning {
		t.Fatalf("controller lifecycle = %q, want running", snapshot.Lifecycle)
	}
	if readiness := service.EvaluateReadiness(controller.ObservabilitySnapshot(), time.Now(), staleAfter); !readiness.Ready {
		t.Fatalf("readiness after successful sync = %#v, want ready", readiness)
	}
}

func TestExecuteSyncActionRepeatedPollingSuccessAdvancesHealth(t *testing.T) {
	panel := &fakeSyncApplyAPI{userList: &[]api.UserInfo{}}
	controller := newSyncHealthTestController(panel)
	initial := time.Now().Add(-time.Minute)
	controller.health.RecordSuccessfulSync(initial)
	previous := initial

	for range 3 {
		before := time.Now()
		if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(
			syncActionTypeSyncUsers,
			syncActionSourcePolling,
			syncActionMetadata{Trigger: syncActionTriggerPollingTick},
		)); err != nil {
			t.Fatalf("ExecuteSyncAction() error = %v", err)
		}
		current := controller.health.Snapshot().LastSuccessfulSync
		if current.Before(before) || current.Before(previous) || !current.After(initial) {
			t.Fatalf("LastSuccessfulSync = %v, want no earlier than call start %v and previous %v, after initial %v", current, before, previous, initial)
		}
		if readiness := service.EvaluateReadiness(controller.ObservabilitySnapshot(), time.Now(), 30*time.Second); !readiness.Ready {
			t.Fatalf("readiness after repeated successful sync = %#v, want ready", readiness)
		}
		previous = current
	}
	if panel.getUserListCalls != 3 {
		t.Fatalf("panel user fetches = %d, want 3", panel.getUserListCalls)
	}
}

func TestSyncCoordinatorRecordsFailureOnceAndRecoveryKeepsHealthFresh(t *testing.T) {
	panelErr := errors.New("panel sync failed")
	panel := &fakeSyncApplyAPI{userList: &[]api.UserInfo{}, userErr: panelErr}
	controller := newSyncHealthTestController(panel)
	staleAfter := 30 * time.Second
	initial := time.Now().Add(-2 * staleAfter)
	controller.health.RecordSuccessfulSync(initial)
	coordinator := newSyncCoordinatorWithResultHandling(controller, controller.syncExecutionState, nil)
	t.Cleanup(coordinator.Stop)

	coordinator.Submit(newSyncAction(
		syncActionTypeSyncUsers,
		syncActionSourcePolling,
		syncActionMetadata{Trigger: syncActionTriggerPollingTick},
	))
	waitForCoordinatorIdle(t, coordinator)

	failedState := controller.syncExecutionSnapshot()
	if failedState.ConsecutiveFailures != 1 {
		t.Fatalf("ConsecutiveFailures = %d, want 1", failedState.ConsecutiveFailures)
	}
	if failedState.LastError == nil {
		t.Fatal("failed sync did not retain internal error state")
	}
	if health := controller.health.Snapshot(); health.LastFailureStage != service.FailureStageSync || !health.LastSuccessfulSync.Equal(initial) {
		t.Fatalf("health after failed sync = %#v, want sync failure without freshness update", health)
	}
	if readiness := service.EvaluateReadiness(controller.ObservabilitySnapshot(), time.Now(), staleAfter); readiness.Ready || !slices.Contains(readiness.Reasons, service.ReadinessReasonSyncStale) {
		t.Fatalf("readiness after failed sync = %#v, want sync_stale", readiness)
	}

	panel.userErr = nil
	coordinator.Submit(newSyncAction(
		syncActionTypeSyncUsers,
		syncActionSourcePolling,
		syncActionMetadata{Trigger: syncActionTriggerPollingTick},
	))
	waitForCoordinatorIdle(t, coordinator)

	recoveredState := controller.syncExecutionSnapshot()
	if recoveredState.ConsecutiveFailures != 0 || recoveredState.LastError != nil {
		t.Fatalf("failure state not cleared after recovery: failures=%d error=%v", recoveredState.ConsecutiveFailures, recoveredState.LastError)
	}
	if health := controller.health.Snapshot(); !health.LastSuccessfulSync.After(initial) {
		t.Fatalf("LastSuccessfulSync = %v, want after %v", health.LastSuccessfulSync, initial)
	}
	if readiness := service.EvaluateReadiness(controller.ObservabilitySnapshot(), time.Now(), staleAfter); !readiness.Ready {
		t.Fatalf("readiness after recovery = %#v, want ready", readiness)
	}
}
