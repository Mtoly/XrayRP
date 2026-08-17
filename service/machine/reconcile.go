package machine

import (
	"context"
	"errors"
	"fmt"

	"github.com/Mtoly/XrayRP/service"
)

func (s *Supervisor) reconcile(bindings []NodeBinding) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.reconcileContext(ctx, bindings)
}

func (s *Supervisor) reconcileContext(ctx context.Context, bindings []NodeBinding) error {
	transaction, ok := s.planReconcile(bindings)
	if !ok {
		return nil
	}
	result := s.executeReconcileContext(ctx, transaction)
	if err := s.commitReconcile(result); err != nil {
		cleanupCtx, cancel := service.CleanupContext(ctx)
		cleanupErr := s.cleanupUnpublishedRuntimesContext(cleanupCtx, result.started)
		cancel()
		return errors.Join(result.failure, err, cleanupErr)
	}
	return result.failure
}

func (s *Supervisor) planReconcile(bindings []NodeBinding) (machineReconcileTransaction, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || s.cleanupPending {
		return machineReconcileTransaction{}, false
	}

	running := cloneMachineTopology(s.running)
	return machineReconcileTransaction{
		generation: s.topologyGeneration,
		running:    running,
		plan:       materializeMachineReconcilePlan(running, bindings),
	}, true
}

func (s *Supervisor) executeReconcile(transaction machineReconcileTransaction) machineReconcileResult {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.executeReconcileContext(ctx, transaction)
}

func (s *Supervisor) executeReconcileContext(ctx context.Context, transaction machineReconcileTransaction) machineReconcileResult {
	started := make([]*nodeRuntime, 0, len(transaction.plan.bindings))
	var errs []error
	for _, decision := range transaction.plan.missing {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		if decision.runtime == nil {
			delete(transaction.running, decision.nodeID)
			continue
		}
		decision.runtime.missingCount = decision.nextMissingCount
		if !decision.remove {
			continue
		}

		if err := s.closeRuntimeContext(ctx, decision.runtime); err != nil {
			s.logWarning(err)
			errs = append(errs, err)
			transaction.running[decision.nodeID] = decision.runtime
			continue
		}
		delete(transaction.running, decision.nodeID)
	}

	if ctx.Err() == nil {
		for _, decision := range transaction.plan.bindings {
			if err := ctx.Err(); err != nil {
				errs = append(errs, err)
				break
			}
			var nextRuntime *nodeRuntime
			var err error
			switch decision.action {
			case machineReconcileStart:
				nextRuntime, err = s.startRuntimeContext(ctx, decision.binding)
			case machineReconcileKeep:
				decision.runtime.binding = decision.binding
				decision.runtime.missingCount = 0
				decision.runtime.failure = nil
				continue
			case machineReconcileRestart:
				nextRuntime, err = s.restartRuntimeContext(ctx, decision.runtime, decision.binding)
			case machineReconcileRecover:
				nextRuntime, err = s.recoverRuntimeContext(ctx, decision.runtime, decision.binding)
			}

			if nextRuntime != nil {
				transaction.running[decision.binding.NodeID] = nextRuntime
				if nextRuntime != decision.runtime {
					started = append(started, nextRuntime)
				}
			} else {
				delete(transaction.running, decision.binding.NodeID)
			}
			if err != nil {
				s.logWarning(err)
				errs = append(errs, err)
			}
		}
	}

	return machineReconcileResult{
		generation: transaction.generation,
		running:    transaction.running,
		started:    started,
		failure:    errors.Join(errs...),
	}
}

func (s *Supervisor) commitReconcile(result machineReconcileResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Close waits for the operation gate, so reconcile commits the final ownership state first.
	if s.closed || s.cleanupPending {
		return fmt.Errorf("machine supervisor is unavailable")
	}
	if s.topologyGeneration != result.generation {
		return fmt.Errorf(
			"machine topology generation changed during reconcile: got %d, want %d",
			s.topologyGeneration,
			result.generation,
		)
	}

	s.running = result.running
	s.topologyFailure = result.failure
	s.topologyGeneration++
	return nil
}

func (s *Supervisor) topologySnapshot() machineTopologySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return machineTopologySnapshot{
		generation: s.topologyGeneration,
		running:    cloneMachineTopology(s.running),
		failure:    s.topologyFailure,
	}
}

func cloneMachineTopology(running map[int]*nodeRuntime) map[int]*nodeRuntime {
	cloned := make(map[int]*nodeRuntime, len(running))
	for nodeID, runtime := range running {
		if runtime == nil {
			cloned[nodeID] = nil
			continue
		}
		runtimeValue := *runtime
		runtimeValue.cleanupServices = append([]service.Service(nil), runtime.cleanupServices...)
		cloned[nodeID] = &runtimeValue
	}
	return cloned
}

func newNodeRuntime(binding NodeBinding, nodeService service.Service) *nodeRuntime {
	runtime := &nodeRuntime{
		binding: binding,
		service: nodeService,
		state:   nodeRuntimeRetiring,
	}
	if restorer, ok := nodeService.(machineRuntimeRestorer); ok {
		runtime.restorer = restorer
	}
	return runtime
}

func (runtime *nodeRuntime) hasResources() bool {
	return runtime != nil && (runtime.service != nil || len(runtime.cleanupServices) != 0)
}

func (runtime *nodeRuntime) absorbOwnership(other *nodeRuntime) {
	if runtime == nil || other == nil {
		return
	}
	if other.service != nil {
		runtime.cleanupServices = append(runtime.cleanupServices, other.service)
	}
	runtime.cleanupServices = append(runtime.cleanupServices, other.cleanupServices...)
	runtime.state = nodeRuntimeFailedOwned
	runtime.failure = errors.Join(runtime.failure, other.failure)
}

func (s *Supervisor) startRuntime(binding NodeBinding) (*nodeRuntime, error) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return s.startRuntimeContext(ctx, binding)
}

func (s *Supervisor) startRuntimeContext(ctx context.Context, binding NodeBinding) (*nodeRuntime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nodeService, err := s.factory(binding)
	if err != nil {
		return nil, fmt.Errorf("build service for machine node %d: %w", binding.NodeID, err)
	}
	if nodeService == nil {
		return nil, fmt.Errorf("build service for machine node %d: nil service", binding.NodeID)
	}
	return s.startPreparedRuntimeContext(ctx, newNodeRuntime(binding, nodeService), "start service")
}

func (s *Supervisor) startPreparedRuntime(runtime *nodeRuntime, operation string) (*nodeRuntime, error) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return s.startPreparedRuntimeContext(ctx, runtime, operation)
}

func (s *Supervisor) startPreparedRuntimeContext(ctx context.Context, runtime *nodeRuntime, operation string) (*nodeRuntime, error) {
	if runtime == nil || runtime.service == nil {
		return nil, errors.New("machine runtime service is nil")
	}
	if err := service.StartContext(ctx, runtime.service); err != nil {
		startErr := fmt.Errorf("%s for machine node %d: %w", operation, runtime.binding.NodeID, err)
		cleanupCtx, cancel := service.CleanupContext(ctx)
		cleanupErr := s.closeRuntimeContext(cleanupCtx, runtime)
		cancel()
		joined := errors.Join(startErr, cleanupErr)
		if runtime.hasResources() {
			runtime.state = nodeRuntimeFailedOwned
			runtime.failure = joined
			return runtime, joined
		}
		return nil, joined
	}
	runtime.state = nodeRuntimeRunning
	runtime.failure = nil
	runtime.missingCount = 0
	return runtime, nil
}

func (s *Supervisor) restartRuntime(oldRuntime *nodeRuntime, nextBinding NodeBinding) (*nodeRuntime, error) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.restartRuntimeContext(ctx, oldRuntime, nextBinding)
}

func (s *Supervisor) restartRuntimeContext(ctx context.Context, oldRuntime *nodeRuntime, nextBinding NodeBinding) (*nodeRuntime, error) {
	if err := ctx.Err(); err != nil {
		return oldRuntime, err
	}
	nextService, err := s.factory(nextBinding)
	if err != nil {
		return oldRuntime, fmt.Errorf("build replacement service for machine node %d: %w", nextBinding.NodeID, err)
	}
	if nextService == nil {
		return oldRuntime, fmt.Errorf("build replacement service for machine node %d: nil service", nextBinding.NodeID)
	}
	nextRuntime := newNodeRuntime(nextBinding, nextService)

	if closeErr := s.closeRuntimeContext(ctx, oldRuntime); closeErr != nil {
		cleanupCtx, cancel := service.CleanupContext(ctx)
		cleanupErr := s.closeRuntimeContext(cleanupCtx, nextRuntime)
		cancel()
		if nextRuntime.hasResources() {
			oldRuntime.absorbOwnership(nextRuntime)
		}
		joined := errors.Join(
			fmt.Errorf("close old service for machine node %d before restart: %w", oldRuntime.binding.NodeID, closeErr),
			cleanupErr,
		)
		oldRuntime.state = nodeRuntimeFailedOwned
		oldRuntime.failure = joined
		return oldRuntime, joined
	}

	startedRuntime, startErr := s.startPreparedRuntimeContext(ctx, nextRuntime, "start replacement service")
	if startErr == nil {
		return startedRuntime, nil
	}
	if startedRuntime != nil {
		oldRuntime.absorbOwnership(startedRuntime)
		oldRuntime.state = nodeRuntimeFailedOwned
		oldRuntime.failure = startErr
		return oldRuntime, startErr
	}

	cleanupCtx, cancel := service.CleanupContext(ctx)
	rollbackRuntime, rollbackErr := s.rollbackRuntimeContext(cleanupCtx, oldRuntime)
	cancel()
	if rollbackRuntime != nil {
		return rollbackRuntime, errors.Join(startErr, rollbackErr)
	}
	return nil, errors.Join(
		startErr,
		fmt.Errorf("rollback old service for machine node %d: %w", oldRuntime.binding.NodeID, rollbackErr),
	)
}

func (s *Supervisor) recoverRuntime(runtime *nodeRuntime, desiredBinding NodeBinding) (*nodeRuntime, error) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.recoverRuntimeContext(ctx, runtime, desiredBinding)
}

func (s *Supervisor) recoverRuntimeContext(ctx context.Context, runtime *nodeRuntime, desiredBinding NodeBinding) (*nodeRuntime, error) {
	if runtime == nil {
		return s.startRuntimeContext(ctx, desiredBinding)
	}
	if err := s.closeRuntimeContext(ctx, runtime); err != nil {
		return runtime, err
	}
	if runtime.restorer != nil {
		restored, err := s.rollbackRuntimeContext(ctx, runtime)
		if err != nil {
			return restored, fmt.Errorf("restore last-known-good machine node %d: %w", runtime.binding.NodeID, err)
		}
		return restored, nil
	}
	return s.startRuntimeContext(ctx, desiredBinding)
}

func (s *Supervisor) rollbackRuntime(oldRuntime *nodeRuntime) (*nodeRuntime, error) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return s.rollbackRuntimeContext(ctx, oldRuntime)
}

func (s *Supervisor) rollbackRuntimeContext(ctx context.Context, oldRuntime *nodeRuntime) (*nodeRuntime, error) {
	if oldRuntime == nil {
		return nil, errors.New("nil rollback runtime")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var rollbackService service.Service
	var err error
	if oldRuntime.restorer != nil {
		rollbackService, err = oldRuntime.restorer.RestoreMachineRuntime()
	} else {
		rollbackService, err = s.factory(oldRuntime.binding)
	}
	if err != nil {
		return nil, err
	}
	if rollbackService == nil {
		return nil, fmt.Errorf("nil rollback service")
	}
	runtime := newNodeRuntime(oldRuntime.binding, rollbackService)
	if runtime.restorer == nil {
		runtime.restorer = oldRuntime.restorer
	}
	return s.startPreparedRuntimeContext(ctx, runtime, "start rollback service")
}

func (s *Supervisor) closeRuntime(runtime *nodeRuntime) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return s.closeRuntimeContext(ctx, runtime)
}

func (s *Supervisor) closeRuntimeContext(ctx context.Context, runtime *nodeRuntime) error {
	if runtime == nil {
		return nil
	}
	runtime.state = nodeRuntimeRetiring
	var errs []error
	if runtime.service != nil {
		if err := service.CloseContext(ctx, runtime.service); err != nil {
			errs = append(errs, fmt.Errorf("close service for machine node %d: %w", runtime.binding.NodeID, err))
		} else {
			runtime.service = nil
		}
	}

	remaining := make([]service.Service, 0, len(runtime.cleanupServices))
	for _, ownedService := range runtime.cleanupServices {
		if ownedService == nil {
			continue
		}
		if err := service.CloseContext(ctx, ownedService); err != nil {
			remaining = append(remaining, ownedService)
			errs = append(errs, fmt.Errorf("close retained service for machine node %d: %w", runtime.binding.NodeID, err))
		}
	}
	runtime.cleanupServices = remaining
	closeErr := errors.Join(errs...)
	if runtime.hasResources() {
		runtime.state = nodeRuntimeFailedOwned
		runtime.failure = closeErr
		return closeErr
	}
	runtime.failure = nil
	return closeErr
}

func (s *Supervisor) cleanupUnpublishedRuntimes(runtimes []*nodeRuntime) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return s.cleanupUnpublishedRuntimesContext(ctx, runtimes)
}

func (s *Supervisor) cleanupUnpublishedRuntimesContext(ctx context.Context, runtimes []*nodeRuntime) error {
	var errs []error
	for i := len(runtimes) - 1; i >= 0; i-- {
		runtime := runtimes[i]
		if err := s.closeRuntimeContext(ctx, runtime); err != nil {
			errs = append(errs, err)
		}
		if runtime != nil && runtime.hasResources() {
			s.retainUnpublishedOwnership(runtime)
		}
	}
	return errors.Join(errs...)
}

func (s *Supervisor) retainUnpublishedOwnership(runtime *nodeRuntime) {
	if runtime == nil || !runtime.hasResources() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	nodeID := runtime.binding.NodeID
	if current := s.running[nodeID]; current != nil {
		current.absorbOwnership(runtime)
		current.failure = errors.Join(current.failure, runtime.failure)
	} else {
		runtime.state = nodeRuntimeFailedOwned
		s.running[nodeID] = runtime
	}
	s.topologyFailure = errors.Join(s.topologyFailure, runtime.failure)
	s.topologyGeneration++
}
