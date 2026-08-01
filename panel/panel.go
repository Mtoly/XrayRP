package panel

import (
	"context"
	"errors"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/core"

	"github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/internal/operation"
	"github.com/Mtoly/XrayRP/service"
)

// Panel Structure
type Panel struct {
	access      operation.Gate
	publishedMu sync.RWMutex
	published   panelPublishedState
	panelConfig *Config
	lifecycle   panelLifecycleOps

	// Server is a compatibility projection of the currently owned core.
	//
	// Deprecated: Use ServerInstance. The returned core is borrowed; callers
	// must not close it or assume ownership.
	Server *core.Instance
	// Service is a compatibility projection of the currently owned services.
	//
	// Deprecated: Use ServicesSnapshot, which returns a cloned slice.
	Service []service.Service
	// Running is a compatibility projection of the panel lifecycle.
	//
	// Deprecated: Use IsRunning.
	Running bool
	logger  *log.Entry
}

type panelLifecycleState uint8

const (
	panelStateStopped panelLifecycleState = iota
	panelStateStarting
	panelStateRunning
	panelStateStopping
	panelStateFailedOwned
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
		buildRuntimePlan: buildValidatedRuntimeConfigPlan,
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
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return p.StartContext(ctx)
}

func (p *Panel) StartContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultStartTimeout)
	defer cancel()
	if err := p.access.Lock(ctx); err != nil {
		return err
	}
	defer p.access.Unlock()
	p.logger.Info("Starting panel")
	ops := p.lifecycleOps()
	current := p.publishedStateSnapshot()
	switch current.lifecycle {
	case panelStateRunning:
		p.publishState(current.lifecycle, current.server, current.services)
		return nil
	case panelStateFailedOwned:
		return errors.New("panel cannot start while cleanup ownership remains")
	case panelStateStarting, panelStateStopping:
		return fmt.Errorf("panel cannot start from lifecycle state %d", current.lifecycle)
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
		cleanupCtx, cleanupCancel := service.CleanupContext(ctx)
		defer cleanupCancel()
		errs := []error{primary}
		remainingServices := make([]service.Service, 0)
		for i := len(startedServices) - 1; i >= 0; i-- {
			if err := service.CloseContext(cleanupCtx, startedServices[i]); err != nil {
				errs = append(errs, fmt.Errorf("failed to roll back service: %w", err))
				remainingServices = append(remainingServices, startedServices[i])
				p.logLifecycleError("Failed to roll back service", err)
			}
		}
		var remainingServer *core.Instance
		if err := ops.closeCore(server); err != nil {
			errs = append(errs, fmt.Errorf("failed to roll back core: %w", err))
			remainingServer = server
			p.logLifecycleError("Failed to roll back core", err)
		}
		if remainingServer != nil || len(remainingServices) != 0 {
			p.publishState(panelStateFailedOwned, remainingServer, remainingServices)
		} else {
			p.publishState(panelStateStopped, nil, nil)
		}
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

	for _, runtimeService := range services {
		if err := service.StartContext(ctx, runtimeService); err != nil {
			startedServices = append(startedServices, runtimeService)
			p.logLifecycleError("Failed to start service", err)
			return rollback(fmt.Errorf("failed to start service: %w", err))
		}
		startedServices = append(startedServices, runtimeService)
	}

	if err := ctx.Err(); err != nil {
		return rollback(err)
	}
	p.publishState(panelStateRunning, server, services)
	return nil
}
func (p *Panel) publishState(lifecycle panelLifecycleState, server *core.Instance, services []service.Service) {
	next := panelPublishedState{lifecycle: lifecycle}
	if lifecycle == panelStateRunning || lifecycle == panelStateStopping || lifecycle == panelStateFailedOwned {
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

// IsRunning reports whether the authoritative panel lifecycle is running.
func (p *Panel) IsRunning() bool {
	if p == nil {
		return false
	}
	return p.publishedStateSnapshot().lifecycle == panelStateRunning
}

// ServerInstance returns the core currently owned by the panel, if any.
// The returned core is borrowed; callers must not close it or assume ownership.
func (p *Panel) ServerInstance() *core.Instance {
	if p == nil {
		return nil
	}
	return p.publishedStateSnapshot().server
}

// ServicesSnapshot returns a cloned slice of services currently owned by the
// panel. The service references are borrowed and must not be closed by callers.
func (p *Panel) ServicesSnapshot() []service.Service {
	if p == nil {
		return nil
	}
	return p.publishedStateSnapshot().services
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
		runtimeService, err := runtimeRegistry.build(runtimeServiceConstruction{
			server:           server,
			apiClient:        apiClient,
			controllerConfig: controllerConfig,
			panelType:        nodePlan.panelType,
		}, nodePlan.fallbackNodeType)
		if err != nil {
			return nil, err
		}
		services = append(services, runtimeService)
	}
	return services, nil
}

// Close the panel
func (p *Panel) Close() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return p.CloseContext(ctx)
}

func (p *Panel) CloseContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultCloseTimeout)
	defer cancel()
	if err := p.access.Lock(ctx); err != nil {
		return err
	}
	defer p.access.Unlock()

	current := p.publishedStateSnapshot()
	if current.lifecycle == panelStateStopped {
		p.publishState(panelStateStopped, nil, nil)
		return nil
	}
	if current.lifecycle == panelStateStarting || current.lifecycle == panelStateStopping {
		return fmt.Errorf("panel cannot close from lifecycle state %d", current.lifecycle)
	}
	p.publishState(panelStateStopping, current.server, current.services)

	ops := p.lifecycleOps()
	remainingServices := make([]service.Service, 0)
	var errs []error
	for _, runtimeService := range current.services {
		if err := service.CloseContext(ctx, runtimeService); err != nil {
			p.logLifecycleError("Failed to close service", err)
			errs = append(errs, err)
			remainingServices = append(remainingServices, runtimeService)
		}
	}

	var remainingServer *core.Instance
	if current.server != nil {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			remainingServer = current.server
		} else if err := ops.closeCore(current.server); err != nil {
			p.logLifecycleError("Failed to close core", err)
			errs = append(errs, err)
			remainingServer = current.server
		}
	}

	if remainingServer != nil || len(remainingServices) != 0 {
		p.publishState(panelStateFailedOwned, remainingServer, remainingServices)
	} else {
		p.publishState(panelStateStopped, nil, nil)
	}
	return errors.Join(errs...)
}
