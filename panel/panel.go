package panel

import (
	"errors"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/core"

	"github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/service"
)

// Panel Structure
type Panel struct {
	access      sync.Mutex
	publishedMu sync.RWMutex
	published   panelPublishedState
	panelConfig *Config
	lifecycle   panelLifecycleOps
	// Server, Service, and Running are compatibility projections. Internal
	// lifecycle code owns resources through published instead.
	Server  *core.Instance
	Service []service.Service
	Running bool
	logger  *log.Entry
}

type panelLifecycleState uint8

const (
	panelStateStopped panelLifecycleState = iota
	panelStateStarting
	panelStateRunning
	panelStateStopping
)

type panelPublishedState struct {
	lifecycle panelLifecycleState
	server    *core.Instance
	services  []service.Service
}

type panelLifecycleOps struct {
	loadCore           func(*Config) (*core.Instance, error)
	startCore          func(*core.Instance) error
	closeCore          func(*core.Instance) error
	buildRuntimePlan   func(*Config) (runtimeConfigPlan, error)
	buildStaticModules func(*Panel, *core.Instance, runtimeConfigPlan) ([]service.Service, error)
	buildMachineModule func(*Panel, *core.Instance, runtimeConfigPlan) (service.Service, error)
}

func (p *Panel) lifecycleOps() panelLifecycleOps {
	ops := p.lifecycle
	defaults := defaultPanelLifecycleOps()
	if ops.loadCore == nil {
		ops.loadCore = defaults.loadCore
	}
	if ops.startCore == nil {
		ops.startCore = defaults.startCore
	}
	if ops.closeCore == nil {
		ops.closeCore = defaults.closeCore
	}
	if ops.buildRuntimePlan == nil {
		ops.buildRuntimePlan = defaults.buildRuntimePlan
	}
	if ops.buildStaticModules == nil {
		ops.buildStaticModules = defaults.buildStaticModules
	}
	if ops.buildMachineModule == nil {
		ops.buildMachineModule = defaults.buildMachineModule
	}
	return ops
}

func defaultPanelLifecycleOps() panelLifecycleOps {
	coreBuilder := defaultCoreConfigBuilder()
	return panelLifecycleOps{
		loadCore: coreBuilder.Build,
		startCore: func(server *core.Instance) error {
			return server.Start()
		},
		closeCore: func(server *core.Instance) error {
			return server.Close()
		},
		buildRuntimePlan: buildRuntimeConfigPlan,
		buildStaticModules: func(p *Panel, server *core.Instance, plan runtimeConfigPlan) ([]service.Service, error) {
			return p.buildStaticNodeServices(server, plan)
		},
		buildMachineModule: func(p *Panel, server *core.Instance, plan runtimeConfigPlan) (service.Service, error) {
			return p.buildMachineSupervisor(server, plan)
		},
	}
}

func New(panelConfig *Config) *Panel {
	logger := log.WithFields(log.Fields{"module": "panel"})
	p := &Panel{
		panelConfig: panelConfig,
		lifecycle:   defaultPanelLifecycleOps(),
		logger:      logger,
	}
	return p
}

// Start the panel
func (p *Panel) Start() error {
	p.access.Lock()
	defer p.access.Unlock()
	p.logger.Info("Starting panel")
	ops := p.lifecycleOps()
	current := p.publishedStateSnapshot()
	if current.lifecycle == panelStateRunning {
		p.publishState(current.lifecycle, current.server, current.services)
		return nil
	}
	p.publishState(panelStateStarting, nil, nil)

	plan, err := ops.buildRuntimePlan(p.panelConfig)
	if err != nil {
		p.publishState(panelStateStopped, nil, nil)
		return err
	}

	server, err := ops.loadCore(p.panelConfig)
	if err != nil {
		p.publishState(panelStateStopped, nil, nil)
		return fmt.Errorf("failed to load core: %w", err)
	}

	startedServices := make([]service.Service, 0)
	rollback := func(primary error) error {
		errs := []error{primary}
		for i := len(startedServices) - 1; i >= 0; i-- {
			if err := startedServices[i].Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to roll back service: %w", err))
				p.logLifecycleError("Failed to roll back service", err)
			}
		}
		if err := ops.closeCore(server); err != nil {
			errs = append(errs, fmt.Errorf("failed to roll back core: %w", err))
			p.logLifecycleError("Failed to roll back core", err)
		}
		p.publishState(panelStateStopped, nil, nil)
		return errors.Join(errs...)
	}
	if err := ops.startCore(server); err != nil {
		return rollback(fmt.Errorf("failed to start instance: %w", err))
	}

	var services []service.Service
	if plan.mode == runtimeConfigModeMachine {
		supervisor, err := ops.buildMachineModule(p, server, plan)
		if err != nil {
			return rollback(err)
		}
		services = []service.Service{supervisor}
	} else {
		services, err = ops.buildStaticModules(p, server, plan)
		if err != nil {
			return rollback(err)
		}
	}

	for _, s := range services {
		if err := s.Start(); err != nil {
			p.logLifecycleError("Failed to start service", err)
			return rollback(fmt.Errorf("failed to start service: %w", err))
		}
		startedServices = append(startedServices, s)
	}

	p.publishState(panelStateRunning, server, services)
	return nil
}

func (p *Panel) publishState(lifecycle panelLifecycleState, server *core.Instance, services []service.Service) {
	next := panelPublishedState{lifecycle: lifecycle}
	if lifecycle == panelStateRunning {
		next.server = server
		next.services = append([]service.Service(nil), services...)
	}

	p.publishedMu.Lock()
	p.published = next
	p.Server = next.server
	p.Service = append([]service.Service(nil), next.services...)
	p.Running = lifecycle == panelStateRunning
	p.publishedMu.Unlock()
}

func (p *Panel) publishedStateSnapshot() panelPublishedState {
	p.publishedMu.RLock()
	defer p.publishedMu.RUnlock()

	snapshot := p.published
	snapshot.services = append([]service.Service(nil), p.published.services...)
	return snapshot
}

func (p *Panel) logLifecycleError(message string, err error) {
	if common.ShowErrorDetails() {
		p.logger.Errorf("%s: %v", message, err)
		return
	}
	p.logger.Errorf("%s; error details omitted because they may contain credentials", message)
}

func (p *Panel) buildStaticNodeServices(server *core.Instance, plan runtimeConfigPlan) ([]service.Service, error) {
	services := make([]service.Service, 0, len(plan.staticNodes))
	runtimeRegistry := defaultRuntimeServiceRegistry()
	for _, nodePlan := range plan.staticNodes {
		apiConfig := *nodePlan.apiConfig
		apiClient := nodePlan.newAPIClient(&apiConfig)

		controllerConfig, err := nodePlan.materializeControllerConfig()
		if err != nil {
			return nil, err
		}
		materializeRuntimeCertConfig(apiClient, controllerConfig, p.logger)

		runtimeService := runtimeRegistry.build(runtimeServiceConstruction{
			server:           server,
			apiClient:        apiClient,
			controllerConfig: controllerConfig,
			panelType:        nodePlan.panelType,
		}, nodePlan.fallbackNodeType)
		services = append(services, runtimeService)
	}
	return services, nil
}

// Close the panel
func (p *Panel) Close() error {
	p.access.Lock()
	defer p.access.Unlock()

	current := p.publishedStateSnapshot()
	if current.lifecycle == panelStateStopped {
		p.publishState(panelStateStopped, nil, nil)
		return nil
	}
	p.publishState(panelStateStopping, nil, nil)

	services := current.services
	server := current.server
	ops := p.lifecycleOps()

	var errs []error
	for _, s := range services {
		if err := s.Close(); err != nil {
			p.logLifecycleError("Failed to close service", err)
			errs = append(errs, err)
		}
	}

	if server != nil {
		if err := ops.closeCore(server); err != nil {
			p.logLifecycleError("Failed to close core", err)
			errs = append(errs, err)
		}
	}

	p.publishState(panelStateStopped, nil, nil)
	return errors.Join(errs...)
}
