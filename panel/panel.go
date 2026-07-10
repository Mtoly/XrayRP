package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/r3labs/diff/v2"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/bunpanel"
	"github.com/Mtoly/XrayRP/api/gov2panel"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/api/pmpanel"
	"github.com/Mtoly/XrayRP/api/proxypanel"
	"github.com/Mtoly/XrayRP/api/sspanel"
	"github.com/Mtoly/XrayRP/api/v2raysocks"
	"github.com/Mtoly/XrayRP/app/mydispatcher"
	_ "github.com/Mtoly/XrayRP/cmd/distro/all"
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
	Server       *core.Instance
	Service      []service.Service
	Running      bool
	logger       *log.Entry
}

func New(panelConfig *Config) *Panel {
	logger := log.WithFields(log.Fields{"module": "panel"})
	p := &Panel{
		panelConfig: panelConfig,
		logger:      logger,
	}
	return p
}

func (p *Panel) loadCore(panelConfig *Config) (*core.Instance, error) {
	// Log Config
	coreLogConfig := &conf.LogConfig{}
	logConfig := getDefaultLogConfig()
	if panelConfig.LogConfig != nil {
		if _, err := diff.Merge(logConfig, panelConfig.LogConfig, logConfig); err != nil {
			return nil, fmt.Errorf("read log config failed: %w", err)
		}
	}
	coreLogConfig.LogLevel = logConfig.Level
	coreLogConfig.AccessLog = logConfig.AccessPath
	coreLogConfig.ErrorLog = logConfig.ErrorPath

	// DNS config
	coreDnsConfig := &conf.DNSConfig{}
	if panelConfig.DnsConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.DnsConfigPath); err != nil {
			return nil, fmt.Errorf("failed to read DNS config file at %s: %w", panelConfig.DnsConfigPath, err)
		} else {
			if err = json.Unmarshal(data, coreDnsConfig); err != nil {
				return nil, fmt.Errorf("failed to unmarshal DNS config %s: %w", panelConfig.DnsConfigPath, err)
			}
		}
	}

	// init controller's DNS config
	// for _, config := range p.panelConfig.NodesConfig {
	// 	config.ControllerConfig.DNSConfig = coreDnsConfig
	// }

	dnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to understand DNS config, please check https://xtls.github.io/config/dns.html for help: %w", err)
	}

	// Routing config
	coreRouterConfig := &conf.RouterConfig{}
	if panelConfig.RouteConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.RouteConfigPath); err != nil {
			return nil, fmt.Errorf("failed to read routing config file at %s: %w", panelConfig.RouteConfigPath, err)
		} else {
			if err = json.Unmarshal(data, coreRouterConfig); err != nil {
				return nil, fmt.Errorf("failed to unmarshal routing config %s: %w", panelConfig.RouteConfigPath, err)
			}
		}
	}
	routeConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to understand routing config, please check https://xtls.github.io/config/routing.html for help: %w", err)
	}
	// Custom Inbound config
	var coreCustomInboundConfig []conf.InboundDetourConfig
	if panelConfig.InboundConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.InboundConfigPath); err != nil {
			return nil, fmt.Errorf("failed to read custom inbound config file at %s: %w", panelConfig.InboundConfigPath, err)
		} else {
			if err = json.Unmarshal(data, &coreCustomInboundConfig); err != nil {
				return nil, fmt.Errorf("failed to unmarshal custom inbound config %s: %w", panelConfig.InboundConfigPath, err)
			}
		}
	}
	var inBoundConfig []*core.InboundHandlerConfig
	for _, config := range coreCustomInboundConfig {
		oc, err := config.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to understand inbound config, please check https://xtls.github.io/config/inbound.html for help: %w", err)
		}
		inBoundConfig = append(inBoundConfig, oc)
	}
	// Custom Outbound config
	var coreCustomOutboundConfig []conf.OutboundDetourConfig
	if panelConfig.OutboundConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.OutboundConfigPath); err != nil {
			return nil, fmt.Errorf("failed to read custom outbound config file at %s: %w", panelConfig.OutboundConfigPath, err)
		} else {
			if err = json.Unmarshal(data, &coreCustomOutboundConfig); err != nil {
				return nil, fmt.Errorf("failed to unmarshal custom outbound config %s: %w", panelConfig.OutboundConfigPath, err)
			}
		}
	}
	var outBoundConfig []*core.OutboundHandlerConfig
	for _, config := range coreCustomOutboundConfig {
		oc, err := config.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to understand outbound config, please check https://xtls.github.io/config/outbound.html for help: %w", err)
		}
		outBoundConfig = append(outBoundConfig, oc)
	}
	// Policy config
	levelPolicyConfig, err := parseConnectionConfig(panelConfig.ConnectionConfig)
	if err != nil {
		return nil, err
	}
	corePolicyConfig := &conf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*conf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()
	// Build Core Config
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&mydispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}
	server, err := core.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance: %w", err)
	}

	return server, nil
}

// Start the panel
func (p *Panel) Start() error {
	p.access.Lock()
	defer p.access.Unlock()
	p.logger.Info("Starting panel")
	// Load Core
	server, err := p.loadCore(p.panelConfig)
	if err != nil {
		return fmt.Errorf("failed to load core: %w", err)
	}
	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start instance: %w", err)
	}
	p.serverMutex.Lock()
	p.Server = server
	p.serverMutex.Unlock()

	plan, err := buildRuntimeConfigPlan(p.panelConfig)
	if err != nil {
		return err
	}

	var services []service.Service
	if plan.mode == runtimeConfigModeMachine {
		supervisor, err := p.buildMachineSupervisor(server, plan)
		if err != nil {
			return err
		}
		services = []service.Service{supervisor}
	} else {
		services, err = p.buildStaticNodeServices(server, plan)
		if err != nil {
			return err
		}
	}

	p.serviceMutex.Lock()
	p.Service = append(p.Service, services...)
	p.serviceMutex.Unlock()

	for _, s := range services {
		if err := s.Start(); err != nil {
			if common.ShowErrorDetails() {
				p.logger.Errorf("Failed to start service: %v", err)
			} else {
				p.logger.Error("Failed to start service; error details omitted because they may contain credentials")
			}
			return fmt.Errorf("failed to start service: %w", err)
		}
	}
	p.Running = true
	return nil
}

func (p *Panel) buildStaticNodeServices(server *core.Instance, plan runtimeConfigPlan) ([]service.Service, error) {
	if plan.mode != runtimeConfigModeStatic {
		return nil, fmt.Errorf("static node mode is not enabled")
	}

	services := make([]service.Service, 0, len(plan.staticNodes))
	for _, nodePlan := range plan.staticNodes {
		var apiClient api.API
		switch nodePlan.panelType {
		case "SSpanel", "SSPanel":
			apiClient = sspanel.New(nodePlan.apiConfig)
		case "NewV2board", "V2board":
			apiClient = newV2board.New(nodePlan.apiConfig)
		case "PMpanel":
			apiClient = pmpanel.New(nodePlan.apiConfig)
		case "Proxypanel":
			apiClient = proxypanel.New(nodePlan.apiConfig)
		case "V2RaySocks":
			apiClient = v2raysocks.New(nodePlan.apiConfig)
		case "GoV2Panel":
			apiClient = gov2panel.New(nodePlan.apiConfig)
		case "BunPanel":
			apiClient = bunpanel.New(nodePlan.apiConfig)
		default:
			return nil, fmt.Errorf("unsupported panel type: %s", nodePlan.panelType)
		}

		controllerConfig, err := materializeRuntimeControllerConfig(nodePlan.controllerConfigTemplate, runtimeControllerConfigOptions{
			showErrorDetails: plan.showErrorDetails,
		})
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

func (p *Panel) buildNodeService(server *core.Instance, apiClient api.API, controllerConfig *controller.Config, panelType string) (service.Service, error) {
	return p.buildNodeServiceWithFallbackNodeType(server, apiClient, controllerConfig, panelType, "")
}

func (p *Panel) buildNodeServiceWithFallbackNodeType(server *core.Instance, apiClient api.API, controllerConfig *controller.Config, panelType, fallbackNodeType string) (service.Service, error) {
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

func runtimeNodeServiceType(apiClient api.API, fallbackNodeType string) string {
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

func (p *Panel) buildRuntimeNodeService(server *core.Instance, apiClient api.API, controllerConfig *controller.Config, panelType, nodeType string) (service.Service, error) {
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

	p.serviceMutex.RLock()
	services := make([]service.Service, len(p.Service))
	copy(services, p.Service)
	p.serviceMutex.RUnlock()

	var errs []error
	for _, s := range services {
		if err := s.Close(); err != nil {
			p.logger.Errorf("Failed to close service: %v", err)
			errs = append(errs, err)
		}
	}

	p.serviceMutex.Lock()
	p.Service = nil
	p.serviceMutex.Unlock()

	p.serverMutex.Lock()
	if p.Server != nil {
		if err := p.Server.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	p.serverMutex.Unlock()

	p.Running = false
	return errors.Join(errs...)
}

func parseConnectionConfig(c *ConnectionConfig) (*conf.Policy, error) {
	connectionConfig := getDefaultConnectionConfig()
	if c != nil {
		if _, err := diff.Merge(connectionConfig, c, connectionConfig); err != nil {
			return nil, fmt.Errorf("read connection config failed: %w", err)
		}
	}
	policy := &conf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         &connectionConfig.Handshake,
		ConnectionIdle:    &connectionConfig.ConnIdle,
		UplinkOnly:        &connectionConfig.UplinkOnly,
		DownlinkOnly:      &connectionConfig.DownlinkOnly,
		BufferSize:        &connectionConfig.BufferSize,
	}

	return policy, nil
}
