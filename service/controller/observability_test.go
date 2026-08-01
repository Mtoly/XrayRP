package controller

import (
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/service"
)

type observedWSRuntime struct {
	snapshot service.WebSocketSnapshot
}

func (*observedWSRuntime) Start() {}
func (*observedWSRuntime) Stop()  {}

func (r *observedWSRuntime) WebSocketObservabilitySnapshot() service.WebSocketSnapshot {
	return r.snapshot
}

func TestControllerObservabilitySnapshotPreservesOwnedFailureAndBoundedState(t *testing.T) {
	controller := newLifecycleTestController(newFakeControllerAPI(), true)
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	controller.lifecycleState = controllerStateFailedOwned
	controller.ownedRuntime = controllerRuntimeOwnership{runtime: true, websocket: true}
	controller.health.RecordSuccessfulSync(now.Add(-time.Minute))
	controller.health.RecordFailure(service.FailureStageCleanup, now)
	controller.health.SetTrafficBacklog(4)
	controller.setWSRuntime(&observedWSRuntime{snapshot: service.WebSocketSnapshot{
		State:         service.WebSocketDegraded,
		LastFailureAt: now.Add(time.Second),
	}})

	snapshot := controller.ObservabilitySnapshot()
	if snapshot.Kind != service.RuntimeKindController ||
		snapshot.Lifecycle != service.RuntimeLifecycleFailedOwned ||
		!snapshot.CleanupPending ||
		snapshot.TrafficReportBacklog != 4 {
		t.Fatalf("controller snapshot = %#v", snapshot)
	}
	if snapshot.WebSocket != service.WebSocketDegraded ||
		snapshot.LastFailureStage != service.FailureStageWebSocket {
		t.Fatalf("controller websocket snapshot = %#v", snapshot)
	}
}
