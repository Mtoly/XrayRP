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

type NewV2boardDiscoverer struct {
	Config newV2board.MachineDiscoveryConfig
}

func (d *NewV2boardDiscoverer) DiscoverMachineNodes() (*newV2board.MachineNodesResponse, error) {
	return newV2board.DiscoverMachineNodes(d.Config)
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

	mu                sync.Mutex
	running           map[int]*nodeRuntime
	cancel            context.CancelFunc
	done              chan struct{}
	statusCancel      context.CancelFunc
	statusDone        chan struct{}
	discoveryInterval time.Duration
	statusInterval    time.Duration
	started           bool
	closed            bool
}

type nodeRuntime struct {
	binding      NodeBinding
	service      service.Service
	missingCount int
}

type discoverySnapshot struct {
	bindings   []NodeBinding
	baseConfig api.BaseConfig
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
		discoveryInterval: config.DiscoveryInterval,
		statusInterval:    config.MachineStatus.StatusInterval,
	}, nil
}

func (s *Supervisor) Start() error {
	if err := s.startInitial(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil || s.closed {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.cancel = cancel
	s.done = done
	go s.run(ctx, done, s.discoveryInterval)
	s.startStatusLoopLocked(s.statusInterval)
	return nil
}

func (s *Supervisor) Close() error {
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	statusCancel := s.statusCancel
	statusDone := s.statusDone
	s.cancel = nil
	s.done = nil
	s.statusCancel = nil
	s.statusDone = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if statusCancel != nil {
		statusCancel()
	}
	if done != nil {
		<-done
	}
	if statusDone != nil {
		<-statusDone
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	for nodeID, runtime := range s.running {
		if err := s.closeRuntime(runtime); err != nil {
			errs = append(errs, err)
		}
		delete(s.running, nodeID)
	}
	s.started = false
	s.closed = true
	return errors.Join(errs...)
}

func (s *Supervisor) startInitial() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("machine supervisor is closed")
	}
	s.mu.Unlock()

	snapshot, err := s.discoverSnapshot()
	if err != nil {
		return err
	}
	bindings := snapshot.bindings

	runtimes := make(map[int]*nodeRuntime, len(bindings))
	started := make([]*nodeRuntime, 0, len(bindings))
	var errs []error
	for _, binding := range bindings {
		runtime, err := s.startRuntime(binding)
		if err != nil {
			s.logWarning(err)
			errs = append(errs, err)
			continue
		}
		runtimes[binding.NodeID] = runtime
		started = append(started, runtime)
	}

	if len(bindings) > 0 && len(runtimes) == 0 {
		return errors.Join(errs...)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.closeRuntimesBestEffort(started)
		return fmt.Errorf("machine supervisor is closed")
	}
	s.running = runtimes
	s.started = true
	s.applyBaseConfigLocked(snapshot.baseConfig)
	return nil
}

func (s *Supervisor) reconcilePeriodic() error {
	snapshot, err := s.discoverSnapshot()
	if err != nil {
		s.logWarning(err)
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}

	s.applyBaseConfigLocked(snapshot.baseConfig)
	return s.reconcile(snapshot.bindings)
}

func (s *Supervisor) ReconcileNow() error {
	return s.reconcilePeriodic()
}

func (s *Supervisor) discoverSnapshot() (discoverySnapshot, error) {
	response, err := s.discoverer.DiscoverMachineNodes()
	if err != nil {
		return discoverySnapshot{}, fmt.Errorf("discover machine nodes: %w", err)
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

func (s *Supervisor) applyBaseConfigLocked(baseConfig api.BaseConfig) {
	schedule := materializeMachineRuntimeSchedule(baseConfig, machineRuntimeScheduleOptions{
		currentDiscoveryInterval: s.discoveryInterval,
		minDiscoveryInterval:     s.config.MinDiscoveryInterval,
		currentStatusInterval:    s.statusInterval,
		minStatusInterval:        s.config.MachineStatus.MinStatusInterval,
	})
	if schedule.updateDiscovery {
		nextInterval := schedule.discoveryInterval
		s.discoveryInterval = nextInterval

		if s.cancel != nil && !s.closed {
			oldCancel := s.cancel
			if s.config.Logger != nil {
				s.config.Logger.Infof("Update machine discovery interval to %s", nextInterval)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			s.cancel = cancel
			s.done = done
			oldCancel()
			go s.run(ctx, done, nextInterval)
		}
	}

	if schedule.updateStatus {
		s.replaceStatusIntervalLocked(schedule.statusInterval)
	}
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

		nextMissingCount := runtime.missingCount + 1
		plan.missing = append(plan.missing, machineMissingRuntimeDecision{
			nodeID:           nodeID,
			runtime:          runtime,
			nextMissingCount: nextMissingCount,
			remove:           nextMissingCount >= removedNodeMissingThreshold,
		})
	}

	for _, binding := range bindings {
		runtime, exists := running[binding.NodeID]
		if !exists {
			plan.bindings = append(plan.bindings, machineBindingDecision{action: machineReconcileStart, binding: binding})
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
	plan := materializeMachineReconcilePlan(s.running, bindings)

	var errs []error
	for _, decision := range plan.missing {
		decision.runtime.missingCount = decision.nextMissingCount
		if !decision.remove {
			continue
		}

		if err := s.closeRuntime(decision.runtime); err != nil {
			s.logWarning(err)
			errs = append(errs, err)
		}
		delete(s.running, decision.nodeID)
	}

	for _, decision := range plan.bindings {
		switch decision.action {
		case machineReconcileStart:
			nextRuntime, err := s.startRuntime(decision.binding)
			if err != nil {
				s.logWarning(err)
				errs = append(errs, err)
				continue
			}
			s.running[decision.binding.NodeID] = nextRuntime
		case machineReconcileKeep:
			decision.runtime.binding = decision.binding
			decision.runtime.missingCount = 0
		case machineReconcileRestart:
			nextRuntime, err := s.restartRuntime(decision.runtime, decision.binding)
			if nextRuntime != nil {
				s.running[decision.binding.NodeID] = nextRuntime
			} else {
				delete(s.running, decision.binding.NodeID)
			}
			if err != nil {
				s.logWarning(err)
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

func (s *Supervisor) startRuntime(binding NodeBinding) (*nodeRuntime, error) {
	nodeService, err := s.factory(binding)
	if err != nil {
		return nil, fmt.Errorf("build service for machine node %d: %w", binding.NodeID, err)
	}
	if nodeService == nil {
		return nil, fmt.Errorf("build service for machine node %d: nil service", binding.NodeID)
	}
	if err := nodeService.Start(); err != nil {
		return nil, fmt.Errorf("start service for machine node %d: %w", binding.NodeID, err)
	}

	return &nodeRuntime{
		binding: binding,
		service: nodeService,
	}, nil
}

func (s *Supervisor) restartRuntime(oldRuntime *nodeRuntime, nextBinding NodeBinding) (*nodeRuntime, error) {
	nextService, err := s.factory(nextBinding)
	if err != nil {
		return oldRuntime, fmt.Errorf("build replacement service for machine node %d: %w", nextBinding.NodeID, err)
	}
	if nextService == nil {
		return oldRuntime, fmt.Errorf("build replacement service for machine node %d: nil service", nextBinding.NodeID)
	}

	if err := s.closeRuntime(oldRuntime); err != nil {
		_ = nextService.Close()
		return oldRuntime, fmt.Errorf("close old service for machine node %d before restart: %w", oldRuntime.binding.NodeID, err)
	}

	if err := nextService.Start(); err == nil {
		return &nodeRuntime{
			binding: nextBinding,
			service: nextService,
		}, nil
	} else {
		_ = nextService.Close()
		rollbackRuntime, rollbackErr := s.rollbackRuntime(oldRuntime)
		if rollbackErr == nil {
			return rollbackRuntime, fmt.Errorf("start replacement service for machine node %d: %w", nextBinding.NodeID, err)
		}
		return nil, errors.Join(
			fmt.Errorf("start replacement service for machine node %d: %w", nextBinding.NodeID, err),
			fmt.Errorf("rollback old service for machine node %d: %w", oldRuntime.binding.NodeID, rollbackErr),
		)
	}
}

func (s *Supervisor) rollbackRuntime(oldRuntime *nodeRuntime) (*nodeRuntime, error) {
	rollbackService, err := s.factory(oldRuntime.binding)
	if err != nil {
		return nil, err
	}
	if rollbackService == nil {
		return nil, fmt.Errorf("nil rollback service")
	}
	if err := rollbackService.Start(); err != nil {
		return nil, err
	}
	return &nodeRuntime{
		binding: oldRuntime.binding,
		service: rollbackService,
	}, nil
}

func (s *Supervisor) closeRuntime(runtime *nodeRuntime) error {
	if runtime == nil || runtime.service == nil {
		return nil
	}
	if err := runtime.service.Close(); err != nil {
		return fmt.Errorf("close service for machine node %d: %w", runtime.binding.NodeID, err)
	}
	return nil
}

func (s *Supervisor) closeRuntimesBestEffort(runtimes []*nodeRuntime) {
	for i := len(runtimes) - 1; i >= 0; i-- {
		_ = s.closeRuntime(runtimes[i])
	}
}

func (s *Supervisor) run(ctx context.Context, done chan struct{}, interval time.Duration) {
	defer close(done)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.reconcilePeriodic(); err != nil {
				s.logWarning(err)
			}
		}
	}
}

func (s *Supervisor) startStatusLoopLocked(interval time.Duration) {
	if s.config.MachineStatus.Reporter == nil || s.config.MachineStatus.Collector == nil || interval <= 0 || s.closed || s.statusCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.statusCancel = cancel
	s.statusDone = done
	go s.runStatus(ctx, done, interval)
}

func (s *Supervisor) replaceStatusIntervalLocked(interval time.Duration) {
	if interval <= 0 || interval == s.statusInterval {
		return
	}
	s.statusInterval = interval
	if s.statusCancel == nil || s.closed || s.config.MachineStatus.Reporter == nil || s.config.MachineStatus.Collector == nil {
		return
	}
	oldCancel := s.statusCancel
	if s.config.Logger != nil {
		s.config.Logger.Infof("Update machine status interval to %s", interval)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.statusCancel = cancel
	s.statusDone = done
	oldCancel()
	go s.runStatus(ctx, done, interval)
}

func (s *Supervisor) runStatus(ctx context.Context, done chan struct{}, interval time.Duration) {
	defer close(done)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	s.reportMachineStatus()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reportMachineStatus()
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
	if s == nil || s.config.MachineStatus.Reporter == nil || s.config.MachineStatus.Collector == nil {
		return
	}
	snapshot := materializeMachineStatusSnapshot(s.config.MachineStatus.Collector)
	if snapshot.err != nil {
		s.logWarning(fmt.Errorf("collect machine status: %w", snapshot.err))
	}
	if err := s.config.MachineStatus.Reporter.ReportMachineStatus(snapshot.status); err != nil {
		s.logWarning(fmt.Errorf("report machine status: %w", err))
	}
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
