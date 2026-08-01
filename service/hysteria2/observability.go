package hysteria2

import (
	"time"

	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service"
)

func (h *Hysteria2Service) ObservabilitySnapshot() service.RuntimeSnapshot {
	if h == nil {
		return service.RuntimeSnapshot{Kind: service.RuntimeKindHysteria2, Lifecycle: service.RuntimeLifecycleStopped, WebSocket: service.WebSocketDisabled}
	}

	h.lifecycleMu.Lock()
	state := h.state
	nodeID := h.clientInfo.NodeID
	cleanupPending := state == stateFailed && (h.server != nil || len(h.cleanupRuntimes) != 0 || h.tasks != nil || h.serveDone != nil || h.watcherDone != nil)
	h.lifecycleMu.Unlock()
	if nodeID == 0 && h.apiClient != nil {
		nodeID = h.apiClient.Describe().NodeID
	}
	health := h.health.Snapshot()
	return service.RuntimeSnapshot{
		Kind:                 service.RuntimeKindHysteria2,
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

func (h *Hysteria2Service) refreshCertificateExpiry() {
	if h == nil || h.config == nil {
		return
	}
	expiry, err := mylego.CertificateExpiry(cloneCertConfig(h.config.CertConfig))
	if err != nil {
		h.health.RecordFailure(service.FailureStageCertificate, time.Now())
		return
	}
	h.health.SetCertificateExpiry(expiry)
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
