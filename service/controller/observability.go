package controller

import (
	"time"

	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service"
)

func (c *Controller) ObservabilitySnapshot() service.RuntimeSnapshot {
	if c == nil {
		return service.RuntimeSnapshot{
			Kind:      service.RuntimeKindController,
			Lifecycle: service.RuntimeLifecycleStopped,
			WebSocket: service.WebSocketDisabled,
		}
	}

	c.lifecycleMu.Lock()
	lifecycle := controllerObservabilityLifecycle(c.lifecycleState)
	ownership := c.ownedRuntime
	nodeID := c.clientInfo.NodeID
	c.lifecycleMu.Unlock()
	if nodeID == 0 && c.apiClient != nil {
		nodeID = c.apiClient.Describe().NodeID
	}

	health := c.health.Snapshot()
	snapshot := service.RuntimeSnapshot{
		Kind:                 service.RuntimeKindController,
		NodeID:               nodeID,
		Lifecycle:            lifecycle,
		LastSuccessfulSync:   health.LastSuccessfulSync,
		LastFailureStage:     health.LastFailureStage,
		LastFailureAt:        health.LastFailureAt,
		CleanupPending:       ownership.hasResources() && lifecycle == service.RuntimeLifecycleFailedOwned,
		TrafficReportBacklog: health.TrafficBacklog,
		CertificateExpiresAt: health.CertificateExpiry,
		WebSocket:            service.WebSocketDisabled,
	}
	if c.config != nil && c.config.WebSocketConfig != nil && c.config.WebSocketConfig.Enable {
		snapshot.WebSocket = service.WebSocketDisconnected
		if provider, ok := c.currentWSRuntime().(service.WebSocketSnapshotProvider); ok {
			ws := provider.WebSocketObservabilitySnapshot()
			snapshot.WebSocket = ws.State
			if ws.LastFailureAt.After(snapshot.LastFailureAt) {
				snapshot.LastFailureStage = service.FailureStageWebSocket
				snapshot.LastFailureAt = ws.LastFailureAt
			}
		}
	}
	return snapshot
}

func (c *Controller) currentWSRuntime() wsRuntimeLifecycle {
	if c == nil {
		return nil
	}
	c.wsRuntimeMu.RLock()
	defer c.wsRuntimeMu.RUnlock()
	return c.wsRuntime
}

func (c *Controller) setWSRuntime(runtime wsRuntimeLifecycle) {
	if c == nil {
		return
	}
	c.wsRuntimeMu.Lock()
	c.wsRuntime = runtime
	c.wsRuntimeMu.Unlock()
}

func (c *Controller) refreshCertificateExpiry() {
	if c == nil || c.config == nil {
		return
	}
	certConfig := cloneRuntimeCertConfig(c.config.CertConfig)
	expiry, err := mylego.CertificateExpiry(certConfig)
	if err != nil {
		c.health.RecordFailure(service.FailureStageCertificate, time.Now())
		return
	}
	c.health.SetCertificateExpiry(expiry)
}

func controllerObservabilityLifecycle(state controllerLifecycleState) service.RuntimeLifecycle {
	switch state {
	case controllerStateStarting:
		return service.RuntimeLifecycleStarting
	case controllerStateRunning:
		return service.RuntimeLifecycleRunning
	case controllerStateStopping:
		return service.RuntimeLifecycleStopping
	case controllerStateFailed:
		return service.RuntimeLifecycleFailed
	case controllerStateFailedOwned:
		return service.RuntimeLifecycleFailedOwned
	case controllerStateClosed:
		return service.RuntimeLifecycleClosed
	default:
		return service.RuntimeLifecycleStopped
	}
}
