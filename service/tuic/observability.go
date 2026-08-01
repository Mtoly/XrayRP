package tuic

import (
	"time"

	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service"
)

func (s *TuicService) ObservabilitySnapshot() service.RuntimeSnapshot {
	if s == nil {
		return service.RuntimeSnapshot{Kind: service.RuntimeKindTUIC, Lifecycle: service.RuntimeLifecycleStopped, WebSocket: service.WebSocketDisabled}
	}

	s.lifecycleMu.Lock()
	state := s.state
	nodeID := s.clientInfo.NodeID
	cleanupPending := state == stateFailed && (s.box != nil || len(s.cleanupRuntimes) != 0 || s.tasks != nil)
	s.lifecycleMu.Unlock()
	if nodeID == 0 && s.apiClient != nil {
		nodeID = s.apiClient.Describe().NodeID
	}
	health := s.health.Snapshot()
	return service.RuntimeSnapshot{
		Kind:                 service.RuntimeKindTUIC,
		NodeID:               nodeID,
		Lifecycle:            specializedObservabilityLifecycle(state, cleanupPending),
		LastSuccessfulSync:   health.LastSuccessfulSync,
		LastFailureStage:     health.LastFailureStage,
		LastFailureAt:        health.LastFailureAt,
		CleanupPending:       cleanupPending,
		TrafficReportBacklog: health.TrafficBacklog,
		CertificateExpiresAt: health.CertificateExpiry,
		WebSocket:            service.WebSocketDisabled,
	}
}

func (s *TuicService) refreshCertificateExpiry() {
	if s == nil || s.config == nil {
		return
	}
	expiry, err := mylego.CertificateExpiry(cloneCertConfig(s.config.CertConfig))
	if err != nil {
		s.health.RecordFailure(service.FailureStageCertificate, time.Now())
		return
	}
	s.health.SetCertificateExpiry(expiry)
}

func specializedObservabilityLifecycle(state lifecycleState, cleanupPending bool) service.RuntimeLifecycle {
	switch state {
	case stateStarting:
		return service.RuntimeLifecycleStarting
	case stateRunning:
		return service.RuntimeLifecycleRunning
	case stateReloading:
		return service.RuntimeLifecycleReloading
	case stateStopping:
		return service.RuntimeLifecycleStopping
	case stateFailed:
		if cleanupPending {
			return service.RuntimeLifecycleFailedOwned
		}
		return service.RuntimeLifecycleFailed
	default:
		return service.RuntimeLifecycleStopped
	}
}
