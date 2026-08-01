package machine

import (
	"errors"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/service"
)

type observedNodeService struct {
	snapshot service.RuntimeSnapshot
}

func (*observedNodeService) Start() error { return nil }
func (*observedNodeService) Close() error { return nil }

func (s *observedNodeService) ObservabilitySnapshot() service.RuntimeSnapshot {
	return s.snapshot
}

func TestSupervisorObservabilitySnapshotIncludesGenerationAndNodeLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	supervisor := &Supervisor{
		running: map[int]*nodeRuntime{
			7: {
				binding: NodeBinding{NodeID: 7},
				service: &observedNodeService{snapshot: service.RuntimeSnapshot{
					Kind:               service.RuntimeKindController,
					Lifecycle:          service.RuntimeLifecycleRunning,
					LastSuccessfulSync: now,
				}},
				state: nodeRuntimeRunning,
			},
			9: {
				binding: NodeBinding{NodeID: 9},
				service: &observedNodeService{},
				state:   nodeRuntimeFailedOwned,
				failure: errors.New("credential-bearing details must remain internal"),
			},
		},
		topologyGeneration: 11,
		started:            true,
	}
	supervisor.health.RecordSuccessfulSync(now)
	supervisor.health.RecordFailure(service.FailureStageReconcile, now)

	snapshot := supervisor.ObservabilitySnapshot()
	if snapshot.TopologyGeneration != 11 || snapshot.Lifecycle != service.RuntimeLifecycleRunning {
		t.Fatalf("machine snapshot = %#v", snapshot)
	}
	if len(snapshot.Children) != 2 ||
		snapshot.Children[0].NodeID != 7 ||
		snapshot.Children[0].Lifecycle != service.RuntimeLifecycleRunning ||
		snapshot.Children[1].NodeID != 9 ||
		snapshot.Children[1].Lifecycle != service.RuntimeLifecycleFailedOwned ||
		!snapshot.Children[1].CleanupPending {
		t.Fatalf("machine node snapshots = %#v", snapshot.Children)
	}
}

func TestRuntimeServiceObservabilityIncludesSharedWebSocketDegradation(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	supervisor := &Supervisor{running: make(map[int]*nodeRuntime), started: true}
	supervisor.health.RecordSuccessfulSync(now)
	shared := NewSharedWSRuntime(SharedWSRuntimeConfig{})
	shared.degraded = true
	shared.lastFailureAt = now

	snapshot := NewRuntimeService(supervisor, shared).ObservabilitySnapshot()
	if snapshot.WebSocket != service.WebSocketDegraded ||
		snapshot.LastFailureStage != service.FailureStageWebSocket {
		t.Fatalf("machine websocket snapshot = %#v", snapshot)
	}
}
