package machine

import (
	"context"
	"errors"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service"
)

func (s *Supervisor) applyBaseConfigLocked(baseConfig api.BaseConfig) []machineLoopHandoff {
	schedule := materializeMachineRuntimeSchedule(baseConfig, machineRuntimeScheduleOptions{
		currentDiscoveryInterval: s.discoveryInterval,
		minDiscoveryInterval:     s.config.MinDiscoveryInterval,
		currentStatusInterval:    s.statusInterval,
		minStatusInterval:        s.config.MachineStatus.MinStatusInterval,
	})
	var handoffs []machineLoopHandoff
	if schedule.updateDiscovery {
		nextInterval := schedule.discoveryInterval
		s.discoveryInterval = nextInterval

		if (s.cancel != nil || s.done != nil) && !s.closed && !s.closing {
			if s.config.Logger != nil {
				s.config.Logger.Infof("Update machine discovery interval to %s", nextInterval)
			}
			parent := s.runCtx
			if parent == nil {
				parent = context.Background()
			}
			ctx, cancel := context.WithCancel(parent)
			done := make(chan struct{})
			retired := machineLoopOwner{cancel: s.cancel, done: s.done}
			replacement := machineLoopOwner{cancel: cancel, done: done}
			s.cancel = cancel
			s.done = done
			s.retireLoopLocked(retired)
			handoffs = append(handoffs, machineLoopHandoff{
				kind:        machineDiscoveryLoop,
				interval:    nextInterval,
				ctx:         ctx,
				retired:     retired,
				replacement: replacement,
			})
		}
	}

	if schedule.updateStatus {
		if handoff, ok := s.replaceStatusIntervalLocked(schedule.statusInterval); ok {
			handoffs = append(handoffs, handoff)
		}
	}
	return handoffs
}

func (s *Supervisor) retireLoopLocked(loop machineLoopOwner) {
	if loop.done == nil {
		return
	}
	if s.retiredLoops == nil {
		s.retiredLoops = make(map[chan struct{}]machineLoopOwner)
	}
	s.retiredLoops[loop.done] = loop
}

func (s *Supervisor) activateLoopHandoffs(handoffs []machineLoopHandoff) {
	for _, handoff := range handoffs {
		if handoff.retired.cancel != nil {
			handoff.retired.cancel()
		}
		switch handoff.kind {
		case machineDiscoveryLoop:
			go s.run(handoff.ctx, handoff.replacement.done, handoff.interval)
		case machineStatusLoop:
			go s.runStatus(handoff.ctx, handoff.replacement.done, handoff.interval)
		}
	}
}

func (s *Supervisor) joinLoopHandoffs(handoffs []machineLoopHandoff, ownerDone chan struct{}) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultJoinTimeout)
	defer cancel()
	_ = s.joinLoopHandoffsContext(ctx, handoffs, ownerDone)
}

func (s *Supervisor) joinLoopHandoffsContext(ctx context.Context, handoffs []machineLoopHandoff, ownerDone chan struct{}) error {
	var errs []error
	for _, handoff := range handoffs {
		done := handoff.retired.done
		if done == nil || done == ownerDone {
			continue
		}
		if err := s.waitForLoopContext(ctx, done); err != nil {
			errs = append(errs, err)
			continue
		}
		s.forgetRetiredLoop(done)
	}
	return errors.Join(errs...)
}

func (s *Supervisor) waitForLoop(done <-chan struct{}) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultJoinTimeout)
	defer cancel()
	_ = s.waitForLoopContext(ctx, done)
}

func (s *Supervisor) waitForLoopContext(ctx context.Context, done <-chan struct{}) error {
	if done == nil {
		return nil
	}
	if s.waitLoop != nil {
		waitDone := make(chan struct{})
		go func() {
			s.waitLoop(done)
			close(waitDone)
		}()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-waitDone:
			return nil
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (s *Supervisor) forgetRetiredLoop(done chan struct{}) {
	if done == nil {
		return
	}
	s.mu.Lock()
	delete(s.retiredLoops, done)
	s.mu.Unlock()
}

func appendMachineLoopOwner(loops []machineLoopOwner, candidate machineLoopOwner) []machineLoopOwner {
	if candidate.cancel == nil && candidate.done == nil {
		return loops
	}
	if candidate.done != nil {
		for _, loop := range loops {
			if loop.done == candidate.done {
				return loops
			}
		}
	}
	return append(loops, candidate)
}

func materializeMachineRuntimeSchedule(baseConfig api.BaseConfig, options machineRuntimeScheduleOptions) machineRuntimeSchedule {
	schedule := machineRuntimeSchedule{
		discoveryInterval: options.currentDiscoveryInterval,
		statusInterval:    options.currentStatusInterval,
	}
	if baseConfig.PullInterval > 0 {
		nextInterval := normalizeDiscoveryInterval(time.Duration(baseConfig.PullInterval)*time.Second, options.minDiscoveryInterval)
		if nextInterval > 0 && nextInterval != options.currentDiscoveryInterval {
			schedule.discoveryInterval = nextInterval
			schedule.updateDiscovery = true
		}
	}
	if baseConfig.PushInterval > 0 {
		nextInterval := normalizeStatusInterval(time.Duration(baseConfig.PushInterval)*time.Second, options.minStatusInterval)
		schedule.statusInterval = nextInterval
		schedule.updateStatus = nextInterval > 0 && nextInterval != options.currentStatusInterval
	}
	return schedule
}

func (s *Supervisor) run(ctx context.Context, done chan struct{}, interval time.Duration) {
	defer func() {
		close(done)
		s.forgetRetiredLoop(done)
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcileCtx, cancel := service.WithDefaultTimeout(ctx, service.DefaultSyncTimeout)
			err := s.reconcilePeriodicFromContext(reconcileCtx, done)
			cancel()
			if err != nil && !errors.Is(err, context.Canceled) {
				s.logWarning(err)
			}
		}
	}
}

func (s *Supervisor) startStatusLoopLocked(interval time.Duration) {
	if s.config.MachineStatus.Reporter == nil || s.config.MachineStatus.Collector == nil || interval <= 0 || s.closed || s.statusCancel != nil {
		return
	}
	parent := s.runCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	s.statusCancel = cancel
	s.statusDone = done
	go s.runStatus(ctx, done, interval)
}

func (s *Supervisor) replaceStatusIntervalLocked(interval time.Duration) (machineLoopHandoff, bool) {
	if interval <= 0 || interval == s.statusInterval {
		return machineLoopHandoff{}, false
	}
	s.statusInterval = interval
	if (s.statusCancel == nil && s.statusDone == nil) || s.closed || s.closing || s.config.MachineStatus.Reporter == nil || s.config.MachineStatus.Collector == nil {
		return machineLoopHandoff{}, false
	}
	if s.config.Logger != nil {
		s.config.Logger.Infof("Update machine status interval to %s", interval)
	}
	parent := s.runCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	retired := machineLoopOwner{cancel: s.statusCancel, done: s.statusDone}
	replacement := machineLoopOwner{cancel: cancel, done: done}
	s.statusCancel = cancel
	s.statusDone = done
	s.retireLoopLocked(retired)
	return machineLoopHandoff{
		kind:        machineStatusLoop,
		interval:    interval,
		ctx:         ctx,
		retired:     retired,
		replacement: replacement,
	}, true
}

func (s *Supervisor) runStatus(ctx context.Context, done chan struct{}, interval time.Duration) {
	defer func() {
		close(done)
		s.forgetRetiredLoop(done)
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	if !s.reportMachineStatusContext(ctx) {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.reportMachineStatusContext(ctx) {
				return
			}
		}
	}
}
