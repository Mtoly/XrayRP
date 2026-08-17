package machine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/common/serverstatus"
	"github.com/Mtoly/XrayRP/internal/operation"
	"github.com/Mtoly/XrayRP/service"
	log "github.com/sirupsen/logrus"
)

const (
	defaultMachineDiscoveryInterval = 60 * time.Second
	defaultMachineStatusInterval    = 60 * time.Second
	minMachineDiscoveryInterval     = 30 * time.Second
	minMachineStatusInterval        = 10 * time.Second
	removedNodeMissingThreshold     = 2
)

type NodeDiscoverer interface {
	DiscoverMachineNodes() (*api.MachineNodesResponse, error)
}

type ContextNodeDiscoverer interface {
	DiscoverMachineNodesContext(context.Context) (*api.MachineNodesResponse, error)
}

type NodeServiceFactory func(NodeBinding) (service.Service, error)

type MachineStatusReporterConfig struct {
	Reporter          MachineStatusReporter
	Collector         MachineStatusCollector
	StatusInterval    time.Duration
	MinStatusInterval time.Duration
}

type SupervisorConfig struct {
	DiscoveryInterval    time.Duration
	MinDiscoveryInterval time.Duration
	MachineStatus        MachineStatusReporterConfig
	Logger               *log.Entry
	ShowErrorDetails     bool
}

type Supervisor struct {
	config     SupervisorConfig
	discoverer NodeDiscoverer
	factory    NodeServiceFactory

	operationMu           operation.Gate
	operationContextMu    sync.Mutex
	activeOperation       supervisorOperation
	activeOperationSet    bool
	activeOperationCancel context.CancelFunc
	observeOperation      func(supervisorOperation, supervisorOperationPhase)
	mu                    sync.Mutex
	running               map[int]*nodeRuntime
	topologyGeneration    uint64
	topologyFailure       error
	runCtx                context.Context
	runCancel             context.CancelFunc
	cancel                context.CancelFunc
	done                  chan struct{}
	statusCancel          context.CancelFunc
	statusDone            chan struct{}
	retiredLoops          map[chan struct{}]machineLoopOwner
	waitLoop              func(<-chan struct{})
	discoveryInterval     time.Duration
	statusInterval        time.Duration
	started               bool
	cleanupPending        bool
	closing               bool
	closeDone             chan struct{}
	closeErr              error
	closed                bool
	health                service.RuntimeHealthState
}

type supervisorOperation uint8

const (
	supervisorOperationInitial supervisorOperation = iota
	supervisorOperationReconcile
	supervisorOperationClose
)

type supervisorOperationPhase uint8

const (
	supervisorOperationAttempted supervisorOperationPhase = iota
	supervisorOperationEntered
	supervisorOperationExited
)

type nodeRuntime struct {
	binding         NodeBinding
	service         service.Service
	cleanupServices []service.Service
	restorer        machineRuntimeRestorer
	state           nodeRuntimeLifecycleState
	failure         error
	missingCount    int
}

type nodeRuntimeLifecycleState uint8

const (
	nodeRuntimeRunning nodeRuntimeLifecycleState = iota
	nodeRuntimeRetiring
	nodeRuntimeFailedOwned
)

type machineRuntimeRestorer interface {
	RestoreMachineRuntime() (service.Service, error)
}

type discoverySnapshot struct {
	bindings   []NodeBinding
	baseConfig api.BaseConfig
}

type machineTopologySnapshot struct {
	generation uint64
	running    map[int]*nodeRuntime
	failure    error
}

type machineLoopOwner struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type machineLoopKind uint8

const (
	machineDiscoveryLoop machineLoopKind = iota
	machineStatusLoop
)

type machineLoopHandoff struct {
	kind        machineLoopKind
	interval    time.Duration
	ctx         context.Context
	retired     machineLoopOwner
	replacement machineLoopOwner
}

func NewSupervisor(config SupervisorConfig, discoverer NodeDiscoverer, factory NodeServiceFactory) (*Supervisor, error) {
	if discoverer == nil {
		return nil, fmt.Errorf("node discoverer must not be nil")
	}
	if factory == nil {
		return nil, fmt.Errorf("node service factory must not be nil")
	}

	config.DiscoveryInterval = normalizeDiscoveryInterval(config.DiscoveryInterval, config.MinDiscoveryInterval)
	if config.MinDiscoveryInterval <= 0 {
		config.MinDiscoveryInterval = minMachineDiscoveryInterval
	}
	config.MachineStatus.MinStatusInterval = normalizeMinStatusInterval(config.MachineStatus.MinStatusInterval)
	config.MachineStatus.StatusInterval = normalizeStatusInterval(config.MachineStatus.StatusInterval, config.MachineStatus.MinStatusInterval)
	if config.MachineStatus.Collector == nil {
		config.MachineStatus.Collector = serverstatus.GetMachineStatus
	}

	return &Supervisor{
		config:            config,
		discoverer:        discoverer,
		factory:           factory,
		running:           make(map[int]*nodeRuntime),
		retiredLoops:      make(map[chan struct{}]machineLoopOwner),
		discoveryInterval: config.DiscoveryInterval,
		statusInterval:    config.MachineStatus.StatusInterval,
	}, nil
}

func (s *Supervisor) Start() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return s.StartContext(ctx)
}

func (s *Supervisor) StartContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultStartTimeout)
	defer cancel()
	if err := s.startInitialContext(ctx); err != nil {
		s.health.RecordFailure(service.FailureStageStart, time.Now())
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	if s.cancel != nil || s.closed || s.closing || s.cleanupPending {
		s.mu.Unlock()
		return nil
	}

	runCtx, runCancel := context.WithCancel(context.WithoutCancel(ctx))
	discoveryCtx, discoveryCancel := context.WithCancel(runCtx)
	done := make(chan struct{})
	s.runCtx = runCtx
	s.runCancel = runCancel
	s.cancel = discoveryCancel
	s.done = done
	go s.run(discoveryCtx, done, s.discoveryInterval)
	s.startStatusLoopLocked(s.statusInterval)
	topologyFailure := s.topologyFailure
	s.mu.Unlock()
	now := time.Now()
	s.health.RecordSuccessfulSync(now)
	if topologyFailure != nil {
		s.health.RecordFailure(service.FailureStageReconcile, now)
	}
	return nil
}

func (s *Supervisor) Close() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return s.CloseContext(ctx)
}

func (s *Supervisor) CloseContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultCloseTimeout)
	defer cancel()
	s.cancelActiveOperation()
	s.notifyOperation(supervisorOperationClose, supervisorOperationAttempted)

	s.mu.Lock()
	if s.closing {
		done := s.closeDone
		s.mu.Unlock()
		if done != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
			}
		}
		s.mu.Lock()
		closeErr := s.closeErr
		s.mu.Unlock()
		return closeErr
	}
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	s.closeErr = nil
	s.closeDone = make(chan struct{})
	loops := make([]machineLoopOwner, 0, 2+len(s.retiredLoops))
	loops = appendMachineLoopOwner(loops, machineLoopOwner{cancel: s.cancel, done: s.done})
	loops = appendMachineLoopOwner(loops, machineLoopOwner{cancel: s.statusCancel, done: s.statusDone})
	for _, loop := range s.retiredLoops {
		loops = appendMachineLoopOwner(loops, loop)
	}
	runCancel := s.runCancel
	s.runCtx = nil
	s.runCancel = nil
	s.cancel = nil
	s.done = nil
	s.statusCancel = nil
	s.statusDone = nil
	s.retiredLoops = make(map[chan struct{}]machineLoopOwner)
	s.mu.Unlock()

	if runCancel != nil {
		runCancel()
	}
	for _, loop := range loops {
		if loop.cancel != nil {
			loop.cancel()
		}
	}

	var errs []error
	remainingLoops := make([]machineLoopOwner, 0)
	for _, loop := range loops {
		if err := s.waitForLoopContext(ctx, loop.done); err != nil {
			errs = append(errs, fmt.Errorf("join machine loop: %w", err))
			remainingLoops = appendMachineLoopOwner(remainingLoops, loop)
		}
	}

	operationCtx, operationCancel, err := s.beginOperationContext(ctx, supervisorOperationClose)
	if err != nil {
		errs = append(errs, err)
		return s.finishCloseAttempt(nil, remainingLoops, errors.Join(errs...))
	}
	defer operationCancel()
	ctx = operationCtx

	s.mu.Lock()
	runtimes := cloneMachineTopology(s.running)
	s.mu.Unlock()

	remaining := make(map[int]*nodeRuntime)
	for nodeID, runtime := range runtimes {
		if err := s.closeRuntimeContext(ctx, runtime); err != nil {
			errs = append(errs, err)
		}
		if runtime.hasResources() {
			remaining[nodeID] = runtime
		}
	}
	closeErr := errors.Join(errs...)
	s.endOperation(supervisorOperationClose)
	return s.finishCloseAttempt(remaining, remainingLoops, closeErr)
}

func (s *Supervisor) finishCloseAttempt(remaining map[int]*nodeRuntime, remainingLoops []machineLoopOwner, closeErr error) error {
	s.mu.Lock()
	if remaining != nil {
		s.running = remaining
		s.topologyGeneration++
	}
	for _, loop := range remainingLoops {
		s.retireLoopLocked(loop)
	}
	if closeErr != nil {
		s.topologyFailure = closeErr
	}
	s.started = false
	s.cleanupPending = len(s.running) != 0 || len(s.retiredLoops) != 0
	s.closed = !s.cleanupPending
	s.closeErr = closeErr
	closeDone := s.closeDone
	s.closing = false
	s.closeDone = nil
	if closeDone != nil {
		close(closeDone)
	}
	s.mu.Unlock()
	if closeErr != nil {
		stage := service.FailureStageClose
		if len(remaining) != 0 || len(remainingLoops) != 0 {
			stage = service.FailureStageCleanup
		}
		s.health.RecordFailure(stage, time.Now())
	}
	return closeErr
}

func (s *Supervisor) startInitial() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return s.startInitialContext(ctx)
}

func (s *Supervisor) startInitialContext(ctx context.Context) error {
	operationCtx, operationCancel, err := s.beginOperationContext(ctx, supervisorOperationInitial)
	if err != nil {
		return err
	}
	defer operationCancel()
	ctx = operationCtx
	var loopHandoffs []machineLoopHandoff

	s.mu.Lock()
	if s.closed || s.closing {
		s.mu.Unlock()
		s.endOperation(supervisorOperationInitial)
		return fmt.Errorf("machine supervisor is closed")
	}
	if s.cleanupPending {
		failure := s.topologyFailure
		s.mu.Unlock()
		s.endOperation(supervisorOperationInitial)
		return errors.Join(errors.New("machine supervisor cleanup ownership remains"), failure)
	}
	if s.started {
		s.mu.Unlock()
		s.endOperation(supervisorOperationInitial)
		return nil
	}
	generation := s.topologyGeneration
	s.mu.Unlock()

	snapshot, err := s.discoverSnapshotContext(ctx)
	if err != nil {
		s.endOperation(supervisorOperationInitial)
		return err
	}
	if err := ctx.Err(); err != nil {
		s.endOperation(supervisorOperationInitial)
		return err
	}
	bindings := snapshot.bindings

	runtimes := make(map[int]*nodeRuntime, len(bindings))
	started := make([]*nodeRuntime, 0, len(bindings))
	runningCount := 0
	var errs []error
	for _, binding := range bindings {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		runtime, startErr := s.startRuntimeContext(ctx, binding)
		if runtime != nil {
			runtimes[binding.NodeID] = runtime
			started = append(started, runtime)
			if runtime.state == nodeRuntimeRunning {
				runningCount++
			}
		}
		if startErr != nil {
			s.logWarning(startErr)
			errs = append(errs, startErr)
		}
	}

	failure := errors.Join(errs...)
	s.mu.Lock()
	var commitErr error
	switch {
	case ctx.Err() != nil:
		commitErr = ctx.Err()
	case s.closed || s.closing:
		commitErr = fmt.Errorf("machine supervisor is closed")
	case s.topologyGeneration != generation:
		commitErr = fmt.Errorf(
			"machine topology generation changed during initial start: got %d, want %d",
			s.topologyGeneration,
			generation,
		)
	default:
		s.running = runtimes
		s.topologyFailure = failure
		s.topologyGeneration++
		s.started = runningCount > 0 || len(bindings) == 0
		s.cleanupPending = runningCount == 0 && len(runtimes) != 0
		if s.started {
			loopHandoffs = s.applyBaseConfigLocked(snapshot.baseConfig)
		}
	}
	s.mu.Unlock()
	s.endOperation(supervisorOperationInitial)

	if commitErr != nil {
		cleanupCtx, cancel := service.CleanupContext(ctx)
		cleanupErr := s.cleanupUnpublishedRuntimesContext(cleanupCtx, started)
		cancel()
		return errors.Join(commitErr, cleanupErr)
	}
	s.activateLoopHandoffs(loopHandoffs)
	joinErr := s.joinLoopHandoffsContext(ctx, loopHandoffs, nil)
	if len(bindings) > 0 && runningCount == 0 {
		return errors.Join(failure, joinErr)
	}
	return joinErr
}

func (s *Supervisor) reconcilePeriodic() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.reconcilePeriodicFromContext(ctx, nil)
}

func (s *Supervisor) reconcilePeriodicFrom(ownerDone chan struct{}) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.reconcilePeriodicFromContext(ctx, ownerDone)
}

func (s *Supervisor) reconcilePeriodicFromContext(ctx context.Context, ownerDone chan struct{}) error {
	operationCtx, operationCancel, err := s.beginOperationContext(ctx, supervisorOperationReconcile)
	if err != nil {
		return err
	}
	defer operationCancel()
	ctx = operationCtx
	var loopHandoffs []machineLoopHandoff

	s.mu.Lock()
	unavailable := s.closed || s.closing || s.cleanupPending || ownerDone != nil && s.done != ownerDone
	s.mu.Unlock()
	if unavailable {
		s.endOperation(supervisorOperationReconcile)
		return nil
	}

	snapshot, err := s.discoverSnapshotContext(ctx)
	if err != nil {
		s.logWarning(err)
		s.endOperation(supervisorOperationReconcile)
		s.health.RecordFailure(service.FailureStageReconcile, time.Now())
		return err
	}
	if err := ctx.Err(); err != nil {
		s.endOperation(supervisorOperationReconcile)
		return err
	}

	s.mu.Lock()
	if s.closed || s.closing || s.cleanupPending || ownerDone != nil && s.done != ownerDone {
		s.mu.Unlock()
		s.endOperation(supervisorOperationReconcile)
		return nil
	}
	loopHandoffs = s.applyBaseConfigLocked(snapshot.baseConfig)
	s.mu.Unlock()

	reconcileErr := s.reconcileContext(ctx, snapshot.bindings)
	s.endOperation(supervisorOperationReconcile)
	s.activateLoopHandoffs(loopHandoffs)
	resultErr := errors.Join(reconcileErr, s.joinLoopHandoffsContext(ctx, loopHandoffs, ownerDone))
	if resultErr != nil {
		s.health.RecordFailure(service.FailureStageReconcile, time.Now())
	} else {
		s.health.RecordSuccessfulSync(time.Now())
	}
	return resultErr
}

func (s *Supervisor) ReconcileNow() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.ReconcileNowContext(ctx)
}

func (s *Supervisor) ReconcileNowContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultSyncTimeout)
	defer cancel()
	return s.reconcilePeriodicFromContext(ctx, nil)
}

type machineRuntimeScheduleOptions struct {
	currentDiscoveryInterval time.Duration
	minDiscoveryInterval     time.Duration
	currentStatusInterval    time.Duration
	minStatusInterval        time.Duration
}

type machineRuntimeSchedule struct {
	discoveryInterval time.Duration
	statusInterval    time.Duration
	updateDiscovery   bool
	updateStatus      bool
}

type machineStatusSnapshot struct {
	status api.MachineStatus
	err    error
}

func (s *Supervisor) logWarning(err error) {
	if err == nil || s.config.Logger == nil {
		return
	}
	if s.showErrorDetails() {
		s.config.Logger.Warn(err)
		return
	}
	s.config.Logger.Warn("machine supervisor operation failed; error details omitted because they may contain credentials")
}

func (s *Supervisor) showErrorDetails() bool {
	return common.ShowErrorDetails() || s != nil && s.config.ShowErrorDetails
}

func (s *Supervisor) beginOperation(operation supervisorOperation) {
	_, _, _ = s.beginOperationContext(context.Background(), operation)
}

func (s *Supervisor) beginOperationContext(ctx context.Context, operation supervisorOperation) (context.Context, context.CancelFunc, error) {
	s.notifyOperation(operation, supervisorOperationAttempted)
	if err := s.operationMu.Lock(ctx); err != nil {
		return nil, nil, err
	}
	operationCtx, cancel := context.WithCancel(ctx)
	s.operationContextMu.Lock()
	s.activeOperation = operation
	s.activeOperationSet = true
	s.activeOperationCancel = cancel
	s.operationContextMu.Unlock()
	s.notifyOperation(operation, supervisorOperationEntered)
	return operationCtx, cancel, nil
}

func (s *Supervisor) cancelActiveOperation() {
	s.operationContextMu.Lock()
	cancel := s.activeOperationCancel
	active := s.activeOperationSet && s.activeOperation != supervisorOperationClose
	s.operationContextMu.Unlock()
	if active && cancel != nil {
		cancel()
	}
}

func (s *Supervisor) endOperation(operation supervisorOperation) {
	s.operationContextMu.Lock()
	if s.activeOperationSet && s.activeOperation == operation {
		s.activeOperationSet = false
		s.activeOperationCancel = nil
	}
	s.operationContextMu.Unlock()
	s.notifyOperation(operation, supervisorOperationExited)
	s.operationMu.Unlock()
}
func (s *Supervisor) notifyOperation(operation supervisorOperation, phase supervisorOperationPhase) {
	if s.observeOperation != nil {
		s.observeOperation(operation, phase)
	}
}

func normalizeDiscoveryInterval(interval, min time.Duration) time.Duration {
	if min <= 0 {
		min = minMachineDiscoveryInterval
	}
	if interval <= 0 {
		return defaultMachineDiscoveryInterval
	}
	if interval < min {
		return min
	}
	return interval
}

func normalizeMinStatusInterval(min time.Duration) time.Duration {
	if min <= 0 {
		return minMachineStatusInterval
	}
	return min
}

func normalizeStatusInterval(interval, min time.Duration) time.Duration {
	min = normalizeMinStatusInterval(min)
	if interval <= 0 {
		return defaultMachineStatusInterval
	}
	if interval < min {
		return min
	}
	return interval
}
