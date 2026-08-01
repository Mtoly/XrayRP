package panel

import "github.com/Mtoly/XrayRP/service"

func (p *Panel) ObservabilitySnapshot() service.RuntimeSnapshot {
	if p == nil {
		return service.RuntimeSnapshot{Kind: service.RuntimeKindPanel, Lifecycle: service.RuntimeLifecycleStopped, WebSocket: service.WebSocketDisabled}
	}

	published := p.publishedStateSnapshot()
	snapshot := service.RuntimeSnapshot{
		Kind:           service.RuntimeKindPanel,
		Mode:           panelRuntimeMode(p.panelConfig),
		Lifecycle:      panelObservabilityLifecycle(published.lifecycle),
		CleanupPending: published.lifecycle == panelStateFailedOwned,
		WebSocket:      service.WebSocketDisabled,
	}
	if snapshot.CleanupPending {
		snapshot.LastFailureStage = service.FailureStageCleanup
	}
	for _, runtimeService := range published.services {
		if provider, ok := runtimeService.(service.RuntimeSnapshotProvider); ok {
			snapshot.Children = append(snapshot.Children, provider.ObservabilitySnapshot())
			continue
		}
		snapshot.Children = append(snapshot.Children, service.RuntimeSnapshot{
			Kind:      service.RuntimeKindController,
			Lifecycle: service.RuntimeLifecycleRunning,
			WebSocket: service.WebSocketDisabled,
		})
	}
	service.SortRuntimeSnapshots(snapshot.Children)
	return snapshot
}

func panelRuntimeMode(config *Config) service.RuntimeMode {
	if config != nil && config.MachineConfig != nil && config.MachineConfig.Enable {
		return service.RuntimeModeMachine
	}
	return service.RuntimeModeStatic
}

func panelObservabilityLifecycle(state panelLifecycleState) service.RuntimeLifecycle {
	switch state {
	case panelStateStarting:
		return service.RuntimeLifecycleStarting
	case panelStateRunning:
		return service.RuntimeLifecycleRunning
	case panelStateStopping:
		return service.RuntimeLifecycleStopping
	case panelStateFailedOwned:
		return service.RuntimeLifecycleFailedOwned
	default:
		return service.RuntimeLifecycleStopped
	}
}
