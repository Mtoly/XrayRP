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
	"github.com/Mtoly/XrayRP/common/mylego"
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
		supervisor, err := p.buildMachineSupervisor(server)
		if err != nil {
			return err
		}
		services = []service.Service{supervisor}
	} else {
		services, err = p.buildStaticNodeServices(server)
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

func (p *Panel) buildStaticNodeServices(server *core.Instance) ([]service.Service, error) {
	plan, err := buildRuntimeConfigPlan(p.panelConfig)
	if err != nil {
		return nil, err
	}
	if plan.mode != runtimeConfigModeStatic {
		return nil, fmt.Errorf("static node mode is not enabled")
	}

	services := make([]service.Service, 0, len(plan.staticNodes))
	for _, nodeConfig := range plan.staticNodes {
		var apiClient api.API
		switch nodeConfig.PanelType {
		case "SSpanel", "SSPanel":
			apiClient = sspanel.New(nodeConfig.ApiConfig)
		case "NewV2board", "V2board":
			apiClient = newV2board.New(nodeConfig.ApiConfig)
		case "PMpanel":
			apiClient = pmpanel.New(nodeConfig.ApiConfig)
		case "Proxypanel":
			apiClient = proxypanel.New(nodeConfig.ApiConfig)
		case "V2RaySocks":
			apiClient = v2raysocks.New(nodeConfig.ApiConfig)
		case "GoV2Panel":
			apiClient = gov2panel.New(nodeConfig.ApiConfig)
		case "BunPanel":
			apiClient = bunpanel.New(nodeConfig.ApiConfig)
		default:
			return nil, fmt.Errorf("unsupported panel type: %s", nodeConfig.PanelType)
		}

		controllerConfig, err := p.buildControllerConfig(nodeConfig.ControllerConfig)
		if err != nil {
			return nil, err
		}
		p.mergePanelCertConfig(apiClient, controllerConfig)

		fallbackNodeType := ""
		if nodeConfig.ApiConfig != nil {
			fallbackNodeType = nodeConfig.ApiConfig.NodeType
		}
		controllerService, err := p.buildNodeServiceWithFallbackNodeType(server, apiClient, controllerConfig, nodeConfig.PanelType, fallbackNodeType)
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
	nodeType := apiClient.Describe().NodeType
	if nodeType == "" {
		nodeType = fallbackNodeType
	}
	switch {
	case strings.EqualFold(nodeType, "Hysteria2"), strings.EqualFold(nodeType, "Hysteria"):
		return hysteria2.New(apiClient, controllerConfig), nil
	case strings.EqualFold(nodeType, "Tuic"):
		return tuic.New(apiClient, controllerConfig), nil
	case strings.EqualFold(nodeType, "AnyTLS"):
		return anytls.New(apiClient, controllerConfig), nil
	default:
		return controller.New(server, apiClient, controllerConfig, panelType), nil
	}
}

func (p *Panel) buildControllerConfig(template *controller.Config) (*controller.Config, error) {
	return materializeRuntimeControllerConfig(template, runtimeControllerConfigOptions{
		showErrorDetails: p.panelConfig.ShowErrorDetails(),
	})
}

func (p *Panel) mergePanelCertConfig(apiClient api.API, controllerConfig *controller.Config) {
	if panelCert, err := apiClient.GetXrayRCertConfig(); err != nil {
		p.logger.Warnf("Failed to get XrayR cert config from panel: %v", err)
	} else if panelCertHasConfig(panelCert) {
		if controllerConfig.CertConfig == nil {
			controllerConfig.CertConfig = &mylego.CertConfig{}
		}
		if err := applyPanelCertConfig(controllerConfig.CertConfig, panelCert); err != nil {
			p.logger.Warnf("Failed to apply XrayR cert config from panel: %v", err)
		}
	}
}

func panelCertHasConfig(panelCert *api.XrayRCertConfig) bool {
	if panelCert == nil {
		return false
	}
	return strings.TrimSpace(panelCert.CertMode) != "" ||
		strings.TrimSpace(panelCert.CertDomain) != "" ||
		strings.TrimSpace(panelCert.CertFile) != "" ||
		strings.TrimSpace(panelCert.KeyFile) != "" ||
		strings.TrimSpace(panelCert.CertContent) != "" ||
		strings.TrimSpace(panelCert.KeyContent) != "" ||
		strings.TrimSpace(panelCert.Provider) != "" ||
		strings.TrimSpace(panelCert.Email) != "" ||
		len(panelCert.DNSEnv) > 0
}

func applyPanelCertConfig(certConfig *mylego.CertConfig, panelCert *api.XrayRCertConfig) error {
	if certConfig == nil {
		return nil
	}
	certMode := strings.ToLower(strings.TrimSpace(panelCert.CertMode))
	if certMode == "" {
		if strings.TrimSpace(panelCert.Provider) == "" && len(panelCert.DNSEnv) == 0 {
			return nil
		}
		certMode = "dns"
	}
	certConfig.CertMode = certMode

	if panelCert.CertDomain != "" {
		certConfig.CertDomain = panelCert.CertDomain
	}
	if panelCert.CertFile != "" {
		certConfig.CertFile = panelCert.CertFile
	}
	if panelCert.KeyFile != "" {
		certConfig.KeyFile = panelCert.KeyFile
	}
	if panelCert.Provider != "" {
		certConfig.Provider = panelCert.Provider
	}
	if panelCert.Email != "" {
		certConfig.Email = panelCert.Email
	}
	if len(panelCert.DNSEnv) > 0 {
		if certConfig.DNSEnv == nil {
			certConfig.DNSEnv = make(map[string]string)
		}
		for k, v := range panelCert.DNSEnv {
			certConfig.DNSEnv[k] = v
		}
	}
	if certMode == "content" {
		certConfig.CertContent = panelCert.CertContent
		certConfig.KeyContent = panelCert.KeyContent
	}
	return nil
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
