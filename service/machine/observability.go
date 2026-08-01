package machine

import (
	"sort"

	"github.com/Mtoly/XrayRP/service"
)

func (s *Supervisor) ObservabilitySnapshot() service.RuntimeSnapshot {
	if s == nil {
		return service.RuntimeSnapshot{Kind: service.RuntimeKindMachine, Mode: service.RuntimeModeMachine, Lifecycle: service.RuntimeLifecycleStopped, WebSocket: service.WebSocketDisabled}
	}

	s.mu.Lock()
	generation := s.topologyGeneration
	runtimes := cloneMachineTopology(s.running)
	cleanupPending := s.cleanupPending
	closing := s.closing
	closed := s.closed
	started := s.started
	s.mu.Unlock()

	health := s.health.Snapshot()
	snapshot := service.RuntimeSnapshot{
		Kind:                 service.RuntimeKindMachine,
		Mode:                 service.RuntimeModeMachine,
		Lifecycle:            machineSupervisorLifecycle(started, closing, closed, cleanupPending),
		TopologyGeneration:   generation,
		LastSuccessfulSync:   health.LastSuccessfulSync,
		LastFailureStage:     health.LastFailureStage,
		LastFailureAt:        health.LastFailureAt,
		CleanupPending:       cleanupPending,
		TrafficReportBacklog: health.TrafficBacklog,
		WebSocket:            service.WebSocketDisabled,
	}

	nodeIDs := make([]int, 0, len(runtimes))
	for nodeID := range runtimes {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Ints(nodeIDs)
	for _, nodeID := range nodeIDs {
		runtime := runtimes[nodeID]
		child := service.RuntimeSnapshot{
			Kind:      service.RuntimeKindController,
			NodeID:    nodeID,
			Lifecycle: service.RuntimeLifecycleStopped,
			WebSocket: service.WebSocketDisabled,
		}
		if runtime != nil {
			if provider, ok := runtime.service.(service.RuntimeSnapshotProvider); ok {
				child = provider.ObservabilitySnapshot()
				child.NodeID = nodeID
			}
			child.Lifecycle = machineNodeLifecycle(runtime.state)
			child.CleanupPending = runtime.state == nodeRuntimeFailedOwned || len(runtime.cleanupServices) != 0
			if child.CleanupPending && child.LastFailureStage == service.FailureStageNone {
				child.LastFailureStage = service.FailureStageCleanup
			}
		}
		snapshot.Children = append(snapshot.Children, child)
	}
	return snapshot
}

func (s *RuntimeService) ObservabilitySnapshot() service.RuntimeSnapshot {
	if s == nil || s.supervisor == nil {
		return service.RuntimeSnapshot{Kind: service.RuntimeKindMachine, Mode: service.RuntimeModeMachine, Lifecycle: service.RuntimeLifecycleStopped, WebSocket: service.WebSocketDisabled}
	}
	snapshot := s.supervisor.ObservabilitySnapshot()
	if s.sharedWS != nil {
		ws := s.sharedWS.WebSocketObservabilitySnapshot()
		snapshot.WebSocket = ws.State
		if ws.LastFailureAt.After(snapshot.LastFailureAt) {
			snapshot.LastFailureStage = service.FailureStageWebSocket
			snapshot.LastFailureAt = ws.LastFailureAt
		}
	}
	return snapshot
}

func machineSupervisorLifecycle(started, closing, closed, cleanupPending bool) service.RuntimeLifecycle {
	switch {
	case cleanupPending:
		return service.RuntimeLifecycleFailedOwned
	case closing:
		return service.RuntimeLifecycleStopping
	case closed:
		return service.RuntimeLifecycleClosed
	case started:
		return service.RuntimeLifecycleRunning
	default:
		return service.RuntimeLifecycleStopped
	}
}

func machineNodeLifecycle(state nodeRuntimeLifecycleState) service.RuntimeLifecycle {
	switch state {
	case nodeRuntimeRunning:
		return service.RuntimeLifecycleRunning
	case nodeRuntimeRetiring:
		return service.RuntimeLifecycleRetiring
	case nodeRuntimeFailedOwned:
		return service.RuntimeLifecycleFailedOwned
	default:
		return service.RuntimeLifecycleFailed
	}
}
