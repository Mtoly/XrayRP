package machine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
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
	DiscoverMachineNodes() (*newV2board.MachineNodesResponse, error)
}

type ContextNodeDiscoverer interface {
	DiscoverMachineNodesContext(context.Context) (*newV2board.MachineNodesResponse, error)
}

type NewV2boardDiscoverer struct {
	Config newV2board.MachineDiscoveryConfig
}

func (d *NewV2boardDiscoverer) DiscoverMachineNodes() (*newV2board.MachineNodesResponse, error) {
	return newV2board.DiscoverMachineNodes(d.Config)
}

func (d *NewV2boardDiscoverer) DiscoverMachineNodesContext(ctx context.Context) (*newV2board.MachineNodesResponse, error) {
	return newV2board.DiscoverMachineNodesContext(ctx, d.Config)
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

func (s *Supervisor) discoverSnapshot() (discoverySnapshot, error) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.discoverSnapshotContext(ctx)
}

func (s *Supervisor) discoverSnapshotContext(ctx context.Context) (discoverySnapshot, error) {
	var response *newV2board.MachineNodesResponse
	var err error
	if contextual, ok := s.discoverer.(ContextNodeDiscoverer); ok {
		response, err = contextual.DiscoverMachineNodesContext(ctx)
	} else {
		if err := ctx.Err(); err != nil {
			return discoverySnapshot{}, err
		}
		response, err = s.discoverer.DiscoverMachineNodes()
	}
	if err != nil {
		return discoverySnapshot{}, fmt.Errorf("discover machine nodes: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return discoverySnapshot{}, err
	}
	return materializeDiscoverySnapshot(response)
}
func materializeDiscoverySnapshot(response *newV2board.MachineNodesResponse) (discoverySnapshot, error) {
	if response == nil {
		return discoverySnapshot{}, fmt.Errorf("discover machine nodes: empty response")
	}

	bindings, err := NormalizeNodeBindings(response.Nodes)
	if err != nil {
		return discoverySnapshot{}, fmt.Errorf("normalize machine node bindings: %w", err)
	}
	return discoverySnapshot{bindings: bindings, baseConfig: response.BaseConfig}, nil
}

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

type machineReconcileAction int

const (
	machineReconcileStart machineReconcileAction = iota
	machineReconcileKeep
	machineReconcileRestart
	machineReconcileRecover
)

type machineReconcilePlan struct {
	missing  []machineMissingRuntimeDecision
	bindings []machineBindingDecision
}

type machineMissingRuntimeDecision struct {
	nodeID           int
	runtime          *nodeRuntime
	nextMissingCount int
	remove           bool
}

type machineBindingDecision struct {
	action  machineReconcileAction
	binding NodeBinding
	runtime *nodeRuntime
}

type machineReconcileTransaction struct {
	generation uint64
	running    map[int]*nodeRuntime
	plan       machineReconcilePlan
}

type machineReconcileResult struct {
	generation uint64
	running    map[int]*nodeRuntime
	started    []*nodeRuntime
	failure    error
}

func materializeMachineReconcilePlan(running map[int]*nodeRuntime, bindings []NodeBinding) machineReconcilePlan {
	newByID := make(map[int]NodeBinding, len(bindings))
	for _, binding := range bindings {
		newByID[binding.NodeID] = binding
	}

	plan := machineReconcilePlan{
		bindings: make([]machineBindingDecision, 0, len(bindings)),
	}
	for nodeID, runtime := range running {
		if _, exists := newByID[nodeID]; exists {
			continue
		}
		if runtime == nil {
			plan.missing = append(plan.missing, machineMissingRuntimeDecision{nodeID: nodeID, remove: true})
			continue
		}

		nextMissingCount := runtime.missingCount + 1
		plan.missing = append(plan.missing, machineMissingRuntimeDecision{
			nodeID:           nodeID,
			runtime:          runtime,
			nextMissingCount: nextMissingCount,
			remove:           runtime.state != nodeRuntimeRunning || nextMissingCount >= removedNodeMissingThreshold,
		})
	}

	for _, binding := range bindings {
		runtime, exists := running[binding.NodeID]
		if !exists || runtime == nil {
			plan.bindings = append(plan.bindings, machineBindingDecision{action: machineReconcileStart, binding: binding})
			continue
		}
		if runtime.state != nodeRuntimeRunning {
			plan.bindings = append(plan.bindings, machineBindingDecision{action: machineReconcileRecover, binding: binding, runtime: runtime})
			continue
		}
		if runtime.binding.NodeType == binding.NodeType {
			plan.bindings = append(plan.bindings, machineBindingDecision{action: machineReconcileKeep, binding: binding, runtime: runtime})
			continue
		}
		plan.bindings = append(plan.bindings, machineBindingDecision{action: machineReconcileRestart, binding: binding, runtime: runtime})
	}

	return plan
}

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

type machineStatusSnapshot struct {
	status api.MachineStatus
	err    error
}

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
