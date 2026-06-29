package panel

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/core"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
	"github.com/Mtoly/XrayRP/service/machine"
)

type newV2boardMachineStatusReporter struct {
	config newV2board.MachineDiscoveryConfig
}

func (r *newV2boardMachineStatusReporter) ReportMachineStatus(status api.MachineStatus) error {
	return newV2board.ReportMachineStatus(r.config, status)
}

func machineModeEnabled(config *Config) bool {
	return config != nil && config.MachineConfig != nil && config.MachineConfig.Enable
}

func validateMachineModeConfig(config *Config) error {
	if !machineModeEnabled(config) {
		return nil
	}

	machineConfig := config.MachineConfig
	if len(config.NodesConfig) > 0 {
		return fmt.Errorf("machine mode cannot be enabled with static Nodes config")
	}
	if strings.TrimSpace(machineConfig.ApiHost) == "" {
		return fmt.Errorf("machine mode ApiHost must not be empty")
	}
	if machineConfig.MachineID <= 0 {
		return fmt.Errorf("machine mode MachineID must be greater than 0")
	}
	if strings.TrimSpace(machineConfig.Token) == "" {
		return fmt.Errorf("machine mode Token must not be empty")
	}

	switch panelType := strings.TrimSpace(machineConfig.PanelType); panelType {
	case "":
		return fmt.Errorf("machine mode PanelType must not be empty")
	case "NewV2board", "V2board":
	default:
		return fmt.Errorf("unsupported panel type for machine mode: %s", machineConfig.PanelType)
	}

	if _, err := buildMachineNodeControllerConfig(machineConfig.ControllerConfig); err != nil {
		return err
	}
	return nil
}

func (p *Panel) buildMachineSupervisor(server *core.Instance) (service.Service, error) {
	plan, err := buildRuntimeConfigPlan(p.panelConfig)
	if err != nil {
		return nil, err
	}
	if plan.mode != runtimeConfigModeMachine {
		return nil, fmt.Errorf("machine mode is not enabled")
	}

	mc := plan.machineConfig
	baseControllerConfig, err := buildMachineNodeControllerConfigWithOptions(mc.ControllerConfig, runtimeControllerConfigOptions{
		showErrorDetails: plan.showErrorDetails,
		clone:            true,
	})
	if err != nil {
		return nil, err
	}
	sharedWS, err := buildMachineSharedWSRuntime(mc, baseControllerConfig.WebSocketConfig, p.logger.WithField("service", "machine-websocket"))
	if err != nil {
		return nil, err
	}

	discoveryConfig := newV2board.MachineDiscoveryConfig{
		APIHost:   mc.ApiHost,
		MachineID: mc.MachineID,
		Token:     mc.Token,
		Timeout:   time.Duration(mc.Timeout) * time.Second,
	}
	discoverer := &machine.NewV2boardDiscoverer{Config: discoveryConfig}
	factory := func(binding machine.NodeBinding) (service.Service, error) {
		return p.buildMachineRuntimeNodeService(server, machineRuntimeNodePlan{
			machineConfig:    mc,
			binding:          binding,
			sharedWS:         sharedWS,
			showErrorDetails: plan.showErrorDetails,
		})
	}

	supervisor, err := machine.NewSupervisor(machine.SupervisorConfig{
		DiscoveryInterval: time.Duration(mc.DiscoveryInterval) * time.Second,
		MachineStatus: machine.MachineStatusReporterConfig{
			Reporter: &newV2boardMachineStatusReporter{config: discoveryConfig},
		},
		Logger:           p.logger.WithField("service", "machine-supervisor"),
		ShowErrorDetails: p.panelConfig.ShowErrorDetails(),
	}, discoverer, factory)
	if err != nil {
		return nil, err
	}
	if sharedWS != nil {
		return machine.NewRuntimeService(supervisor, sharedWS), nil
	}
	return supervisor, nil
}

type machineRuntimeNodePlan struct {
	machineConfig         *MachineConfig
	binding               machine.NodeBinding
	sharedWS              *machine.SharedWSRuntime
	showErrorDetails      bool
	newAPIClient          func(*api.Config) api.API
	materializeCertConfig func(api.API, *controller.Config, *log.Entry)
}

type machineRuntimeNode struct {
	apiClient        api.API
	controllerConfig *controller.Config
}

func (plan machineRuntimeNodePlan) useSharedWSRuntime() bool {
	return plan.sharedWS != nil && machineSharedWSSupportedNodeType(plan.binding.NodeType)
}

func (p *Panel) buildMachineRuntimeNodeService(server *core.Instance, plan machineRuntimeNodePlan) (service.Service, error) {
	runtimeNode, err := p.materializeMachineRuntimeNode(plan)
	if err != nil {
		return nil, err
	}

	machineConfig := plan.machineConfig
	if plan.useSharedWSRuntime() {
		controllerService := controller.New(server, runtimeNode.apiClient, runtimeNode.controllerConfig, machineConfig.PanelType)
		controllerService.SetWSEventRuntimeFactory(plan.sharedWS.NewNodeRuntimeFactory(plan.binding.NodeID))
		return controllerService, nil
	}

	return p.buildNodeService(server, runtimeNode.apiClient, runtimeNode.controllerConfig, machineConfig.PanelType)
}

func (p *Panel) materializeMachineRuntimeNode(plan machineRuntimeNodePlan) (*machineRuntimeNode, error) {
	machineConfig := plan.machineConfig
	apiConfig := buildMachineNodeAPIConfig(machineConfig, plan.binding)
	newAPIClient := plan.newAPIClient
	if newAPIClient == nil {
		newAPIClient = func(apiConfig *api.Config) api.API {
			return newV2board.New(apiConfig)
		}
	}
	var apiClient api.API = newAPIClient(apiConfig)
	if plan.sharedWS != nil {
		apiClient = machine.WrapAPIWithReporter(apiClient, plan.binding.NodeID, plan.sharedWS)
	}

	controllerConfig, err := buildMachineNodeControllerConfigWithOptions(machineConfig.ControllerConfig, runtimeControllerConfigOptions{
		showErrorDetails: plan.showErrorDetails,
		clone:            true,
	})
	if err != nil {
		return nil, err
	}
	materializeCertConfig := plan.materializeCertConfig
	if materializeCertConfig == nil {
		materializeCertConfig = materializeRuntimeCertConfig
	}
	materializeCertConfig(apiClient, controllerConfig, p.logger)

	return &machineRuntimeNode{
		apiClient:        apiClient,
		controllerConfig: controllerConfig,
	}, nil
}

func buildMachineNodeAPIConfig(machineConfig *MachineConfig, binding machine.NodeBinding) *api.Config {
	apiConfig := &api.Config{
		NodeID:   binding.NodeID,
		NodeType: binding.NodeType,
	}
	if machineConfig == nil {
		return apiConfig
	}

	apiConfig.APIHost = machineConfig.ApiHost
	apiConfig.Key = machineConfig.Token
	apiConfig.MachineID = machineConfig.MachineID
	apiConfig.Timeout = machineConfig.Timeout
	return apiConfig
}

func buildMachineNodeControllerConfig(template *controller.Config) (*controller.Config, error) {
	return buildMachineNodeControllerConfigWithOptions(template, runtimeControllerConfigOptions{clone: true})
}

func buildMachineNodeControllerConfigWithOptions(template *controller.Config, options runtimeControllerConfigOptions) (*controller.Config, error) {
	options.clone = true
	return materializeRuntimeControllerConfig(template, options)
}

func buildMachineSharedWSRuntime(machineConfig *MachineConfig, wsConfig *controller.WebSocketConfig, logger *log.Entry) (*machine.SharedWSRuntime, error) {
	if machineConfig == nil || wsConfig == nil || !wsConfig.Enable {
		return nil, nil
	}

	endpoint, err := controller.BuildWSEndpoint(&api.WSConfig{
		APIHost:   machineConfig.ApiHost,
		MachineID: machineConfig.MachineID,
		Key:       machineConfig.Token,
	}, wsConfig)
	if err != nil {
		return nil, err
	}

	return machine.NewSharedWSRuntime(machine.SharedWSRuntimeConfig{
		Endpoint:          endpoint,
		HeartbeatInterval: time.Duration(wsConfig.HeartbeatInterval) * time.Second,
		ReconnectBackoff:  time.Duration(wsConfig.ReconnectBackoff) * time.Second,
		ResyncOnReconnect: wsConfig.ResyncOnReconnect,
		Logger:            logger,
	}), nil
}

func machineSharedWSSupportedNodeType(nodeType string) bool {
	switch strings.ToLower(strings.TrimSpace(nodeType)) {
	case "hysteria", "hysteria2", "tuic", "anytls":
		return false
	default:
		return true
	}
}

func cloneControllerConfig(config *controller.Config) (*controller.Config, error) {
	if config == nil {
		return nil, nil
	}

	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	var cloned controller.Config
	if err := json.Unmarshal(data, &cloned); err != nil {
		return nil, err
	}
	return &cloned, nil
}
