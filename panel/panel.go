package panel

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/core"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/bunpanel"
	"github.com/Mtoly/XrayRP/api/gov2panel"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/api/pmpanel"
	"github.com/Mtoly/XrayRP/api/proxypanel"
	"github.com/Mtoly/XrayRP/api/sspanel"
	"github.com/Mtoly/XrayRP/api/v2raysocks"
	"github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/anytls"
	"github.com/Mtoly/XrayRP/service/controller"
	"github.com/Mtoly/XrayRP/service/hysteria2"
	"github.com/Mtoly/XrayRP/service/tuic"
)

// Panel Structure
type Panel struct {
	access       sync.Mutex
	serverMutex  sync.RWMutex
	serviceMutex sync.RWMutex
	panelConfig  *Config
	lifecycle    panelLifecycleOps
	state        panelLifecycleState
	Server       *core.Instance
	Service      []service.Service
	Running      bool
	logger       *log.Entry
}

type panelLifecycleState uint8

const (
	panelStateStopped panelLifecycleState = iota
	panelStateStarting
	panelStateRunning
	panelStateStopping
)

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
	if p.state == panelStateRunning {
		p.Running = true
		return nil
	}
	p.state = panelStateStarting
	p.Running = false

	server, err := ops.loadCore(p.panelConfig)
	if err != nil {
		p.state = panelStateStopped
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
		p.clearPublishedState()
		p.state = panelStateStopped
		return errors.Join(errs...)
	}
	if err := ops.startCore(server); err != nil {
		return rollback(fmt.Errorf("failed to start instance: %w", err))
	}

	plan, err := ops.buildRuntimePlan(p.panelConfig)
	if err != nil {
		return rollback(err)
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

	p.serverMutex.Lock()
	p.serviceMutex.Lock()
	p.Server = server
	p.Service = append([]service.Service(nil), services...)
	p.state = panelStateRunning
	p.Running = true
	p.serviceMutex.Unlock()
	p.serverMutex.Unlock()
	return nil
}

func (p *Panel) clearPublishedState() {
	p.serverMutex.Lock()
	p.serviceMutex.Lock()
	p.Server = nil
	p.Service = nil
	p.Running = false
	p.serviceMutex.Unlock()
	p.serverMutex.Unlock()
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
	for _, nodePlan := range plan.staticNodes {
		apiConfig := *nodePlan.apiConfig
		var apiClient runtimePanelClient
		switch nodePlan.panelType {
		case "SSpanel", "SSPanel":
			apiClient = sspanel.New(&apiConfig)
		case "NewV2board", "V2board":
			apiClient = newV2board.New(&apiConfig)
		case "PMpanel":
			apiClient = pmpanel.New(&apiConfig)
		case "Proxypanel":
			apiClient = proxypanel.New(&apiConfig)
		case "V2RaySocks":
			apiClient = v2raysocks.New(&apiConfig)
		case "GoV2Panel":
			apiClient = gov2panel.New(&apiConfig)
		case "BunPanel":
			apiClient = bunpanel.New(&apiConfig)
		default:
			return nil, fmt.Errorf("unsupported panel type: %s", nodePlan.panelType)
		}

		controllerConfig, err := nodePlan.materializeControllerConfig()
		if err != nil {
			return nil, err
		}
		materializeRuntimeCertConfig(apiClient, controllerConfig, p.logger)

		controllerService, err := p.buildNodeServiceWithFallbackNodeType(server, apiClient, controllerConfig, nodePlan.panelType, nodePlan.fallbackNodeType)
		if err != nil {
			return nil, err
		}
		services = append(services, controllerService)
	}
	return services, nil
}

type runtimePanelClient interface {
	Describe() api.ClientInfo
	GetNodeInfo() (*api.NodeInfo, error)
	GetUserList() (*[]api.UserInfo, error)
	GetNodeRule() (*[]api.DetectRule, error)
	ReportNodeStatus(*api.NodeStatus) error
	ReportNodeOnlineUsers(*[]api.OnlineUser) error
	ReportUserTraffic(*[]api.UserTraffic) error
	ReportIllegal(*[]api.DetectResult) error
}

func (p *Panel) buildNodeService(server *core.Instance, apiClient runtimePanelClient, controllerConfig *controller.Config, panelType string) (service.Service, error) {
	return p.buildNodeServiceWithFallbackNodeType(server, apiClient, controllerConfig, panelType, "")
}

func (p *Panel) buildNodeServiceWithFallbackNodeType(server *core.Instance, apiClient runtimePanelClient, controllerConfig *controller.Config, panelType, fallbackNodeType string) (service.Service, error) {
	nodeType := runtimeNodeServiceType(apiClient, fallbackNodeType)
	return p.buildRuntimeNodeService(server, apiClient, controllerConfig, panelType, nodeType)
}

type runtimeNodeServiceKind string

const (
	runtimeNodeServiceController runtimeNodeServiceKind = "controller"
	runtimeNodeServiceHysteria2  runtimeNodeServiceKind = "hysteria2"
	runtimeNodeServiceTuic       runtimeNodeServiceKind = "tuic"
	runtimeNodeServiceAnyTLS     runtimeNodeServiceKind = "anytls"
)

type describer interface {
	Describe() api.ClientInfo
}

func runtimeNodeServiceType(apiClient describer, fallbackNodeType string) string {
	nodeType := apiClient.Describe().NodeType
	if nodeType == "" {
		return fallbackNodeType
	}
	return nodeType
}

func runtimeNodeServiceKindForNodeType(nodeType string) runtimeNodeServiceKind {
	switch {
	case strings.EqualFold(nodeType, "Hysteria2"), strings.EqualFold(nodeType, "Hysteria"):
		return runtimeNodeServiceHysteria2
	case strings.EqualFold(nodeType, "Tuic"):
		return runtimeNodeServiceTuic
	case strings.EqualFold(nodeType, "AnyTLS"):
		return runtimeNodeServiceAnyTLS
	default:
		return runtimeNodeServiceController
	}
}

func (p *Panel) buildRuntimeNodeService(server *core.Instance, apiClient runtimePanelClient, controllerConfig *controller.Config, panelType, nodeType string) (service.Service, error) {
	switch runtimeNodeServiceKindForNodeType(nodeType) {
	case runtimeNodeServiceHysteria2:
		return hysteria2.New(apiClient, controllerConfig), nil
	case runtimeNodeServiceTuic:
		return tuic.New(apiClient, controllerConfig), nil
	case runtimeNodeServiceAnyTLS:
		return anytls.New(apiClient, controllerConfig), nil
	default:
		return controller.New(server, apiClient, controllerConfig, panelType), nil
	}
}

// Close the panel
func (p *Panel) Close() error {
	p.access.Lock()
	defer p.access.Unlock()

	if p.state == panelStateStopped {
		p.clearPublishedState()
		return nil
	}
	p.state = panelStateStopping
	p.Running = false

	p.serviceMutex.RLock()
	services := make([]service.Service, len(p.Service))
	copy(services, p.Service)
	p.serviceMutex.RUnlock()
	ops := p.lifecycleOps()

	var errs []error
	for _, s := range services {
		if err := s.Close(); err != nil {
			p.logLifecycleError("Failed to close service", err)
			errs = append(errs, err)
		}
	}

	p.serviceMutex.Lock()
	p.Service = nil
	p.serviceMutex.Unlock()

	p.serverMutex.Lock()
	server := p.Server
	p.Server = nil
	p.serverMutex.Unlock()
	if server != nil {
		if err := ops.closeCore(server); err != nil {
			p.logLifecycleError("Failed to close core", err)
			errs = append(errs, err)
		}
	}

	p.serverMutex.Lock()
	p.state = panelStateStopped
	p.Running = false
	p.serverMutex.Unlock()
	return errors.Join(errs...)
}
