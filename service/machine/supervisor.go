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
	"github.com/Mtoly/XrayRP/service"
	log "github.com/sirupsen/logrus"
)

const (
	defaultMachineDiscoveryInterval = 60 * time.Second
	minMachineDiscoveryInterval     = 30 * time.Second
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

type SupervisorConfig struct {
	DiscoveryInterval    time.Duration
	MinDiscoveryInterval time.Duration
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
	discoveryInterval time.Duration
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

	return &Supervisor{
		config:            config,
		discoverer:        discoverer,
		factory:           factory,
		running:           make(map[int]*nodeRuntime),
		discoveryInterval: config.DiscoveryInterval,
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
	return nil
}

func (s *Supervisor) Close() error {
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	s.cancel = nil
	s.done = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
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
	for _, binding := range bindings {
		runtime, err := s.startRuntime(binding)
		if err != nil {
			s.closeRuntimesBestEffort(started)
			return err
		}
		runtimes[binding.NodeID] = runtime
		started = append(started, runtime)
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
	if baseConfig.PullInterval <= 0 {
		return
	}

	nextInterval := normalizeDiscoveryInterval(time.Duration(baseConfig.PullInterval)*time.Second, s.config.MinDiscoveryInterval)
	if nextInterval <= 0 || nextInterval == s.discoveryInterval {
		return
	}
	s.discoveryInterval = nextInterval

	if s.cancel == nil || s.closed {
		return
	}
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

func (s *Supervisor) reconcile(bindings []NodeBinding) error {
	newByID := make(map[int]NodeBinding, len(bindings))
	for _, binding := range bindings {
		newByID[binding.NodeID] = binding
	}

	var errs []error
	for nodeID, runtime := range s.running {
		if _, exists := newByID[nodeID]; exists {
			continue
		}

		runtime.missingCount++
		if runtime.missingCount < removedNodeMissingThreshold {
			continue
		}

		if err := s.closeRuntime(runtime); err != nil {
			s.logWarning(err)
			errs = append(errs, err)
		}
		delete(s.running, nodeID)
	}

	for _, binding := range bindings {
		runtime, exists := s.running[binding.NodeID]
		if !exists {
			nextRuntime, err := s.startRuntime(binding)
			if err != nil {
				s.logWarning(err)
				errs = append(errs, err)
				continue
			}
			s.running[binding.NodeID] = nextRuntime
			continue
		}

		if runtime.binding.NodeType == binding.NodeType {
			runtime.binding = binding
			runtime.missingCount = 0
			continue
		}

		nextRuntime, err := s.restartRuntime(runtime, binding)
		if nextRuntime != nil {
			s.running[binding.NodeID] = nextRuntime
		} else {
			delete(s.running, binding.NodeID)
		}
		if err != nil {
			s.logWarning(err)
			errs = append(errs, err)
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
