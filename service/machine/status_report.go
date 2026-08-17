package machine

import (
	"context"
	"errors"
	"fmt"
)

func materializeMachineStatusSnapshot(collector MachineStatusCollector) machineStatusSnapshot {
	if collector == nil {
		return machineStatusSnapshot{}
	}
	status, err := collector()
	return machineStatusSnapshot{status: status, err: err}
}

func (s *Supervisor) reportMachineStatus() {
	s.reportMachineStatusContext(context.Background())
}

func (s *Supervisor) reportMachineStatusContext(ctx context.Context) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return false
	}
	if s == nil || s.config.MachineStatus.Reporter == nil || s.config.MachineStatus.Collector == nil {
		return false
	}
	snapshot := materializeMachineStatusSnapshot(s.config.MachineStatus.Collector)
	if ctx.Err() != nil {
		return false
	}
	if snapshot.err != nil {
		s.logWarning(fmt.Errorf("collect machine status: %w", snapshot.err))
	}
	var reportErr error
	if contextual, ok := s.config.MachineStatus.Reporter.(ContextMachineStatusReporter); ok {
		reportErr = contextual.ReportMachineStatusContext(ctx, snapshot.status)
	} else if ctx.Err() == nil {
		reportErr = s.config.MachineStatus.Reporter.ReportMachineStatus(snapshot.status)
	}
	if reportErr != nil && !errors.Is(reportErr, context.Canceled) {
		s.logWarning(fmt.Errorf("report machine status: %w", reportErr))
	}
	return ctx.Err() == nil
}
