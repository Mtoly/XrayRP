package panel

import (
	"fmt"
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

func (plan runtimeConfigPlan) machineDiscoveryConfig() newV2board.MachineDiscoveryConfig {
	if plan.machineConfig == nil {
		return newV2board.MachineDiscoveryConfig{}
	}
	return newV2board.MachineDiscoveryConfig{
		APIHost:   plan.machineConfig.ApiHost,
		MachineID: plan.machineConfig.MachineID,
		Token:     plan.machineConfig.Token,
		Timeout:   time.Duration(plan.machineConfig.Timeout) * time.Second,
	}
}

func (p *Panel) buildMachineSupervisor(server *core.Instance, plan runtimeConfigPlan) (service.Service, error) {
	mc := plan.machineConfig
	baseControllerConfig, err := plan.machineNodeControllerConfig()
	if err != nil {
		return nil, err
	}
	sharedWS := buildMachineSharedWSRuntime(
		baseControllerConfig.WebSocketConfig,
		plan.machineSharedWSEndpoint,
		p.logger.WithField("service", "machine-websocket"),
	)

	discoveryConfig := plan.machineDiscoveryConfig()
	discoverer := &machine.NewV2boardDiscoverer{Config: discoveryConfig}
	factory := func(binding machine.NodeBinding) (service.Service, error) {
		return p.buildMachineRuntimeNodeService(server, machineRuntimeNodePlan{
			binding:  binding,
			sharedWS: sharedWS,
		}, plan)
	}

	supervisor, err := machine.NewSupervisor(machine.SupervisorConfig{
		DiscoveryInterval: time.Duration(mc.DiscoveryInterval) * time.Second,
		MachineStatus: machine.MachineStatusReporterConfig{
			Reporter: &newV2boardMachineStatusReporter{config: discoveryConfig},
		},
		Logger:           p.logger.WithField("service", "machine-supervisor"),
		ShowErrorDetails: plan.showErrorDetails,
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
	binding               machine.NodeBinding
	sharedWS              *machine.SharedWSRuntime
	newAPIClient          func(*api.Config) runtimePanelClient
	materializeCertConfig func(any, *controller.Config, *log.Entry)
}

type machineRuntimeNode struct {
	apiClient        runtimePanelClient
	controllerConfig *controller.Config
}

func (plan machineRuntimeNodePlan) useSharedWSRuntime() bool {
	return plan.sharedWS != nil && defaultRuntimeServiceRegistry().supportsSharedWS(plan.binding.NodeType)
}

func (p *Panel) buildMachineRuntimeNodeService(server *core.Instance, nodePlan machineRuntimeNodePlan, plan runtimeConfigPlan) (service.Service, error) {
	runtimeNode, err := plan.materializeMachineRuntimeNode(nodePlan, p.logger)
	if err != nil {
		return nil, err
	}

	machineConfig := plan.machineConfig
	construction := runtimeServiceConstruction{
		server:           server,
		apiClient:        runtimeNode.apiClient,
		controllerConfig: runtimeNode.controllerConfig,
		panelType:        machineConfig.PanelType,
	}
	if nodePlan.useSharedWSRuntime() {
		construction.wsEventRuntimeFactory = nodePlan.sharedWS.NewNodeRuntimeFactory(nodePlan.binding.NodeID)
	}
	return defaultRuntimeServiceRegistry().build(construction, ""), nil
}

func (plan runtimeConfigPlan) materializeMachineRuntimeNode(nodePlan machineRuntimeNodePlan, logger *log.Entry) (*machineRuntimeNode, error) {
	apiConfig := plan.machineNodeAPIConfig(nodePlan.binding)
	newAPIClient := nodePlan.newAPIClient
	if newAPIClient == nil {
		newAPIClient = plan.machineNewAPIClient
	}
	rawAPIClient := newAPIClient(apiConfig)
	apiClient := rawAPIClient
	if nodePlan.sharedWS != nil {
		wrappedAPIClient, wrapErr := machine.WrapMachineAPIWithReporter(apiClient, nodePlan.binding.NodeID, nodePlan.sharedWS)
		if wrapErr != nil {
			return nil, fmt.Errorf("configure machine runtime node reporter: %w", wrapErr)
		}
		apiClient = wrappedAPIClient
	}

	controllerConfig, err := plan.machineNodeControllerConfig()
	if err != nil {
		return nil, err
	}
	materializeCertConfig := nodePlan.materializeCertConfig
	if materializeCertConfig == nil {
		materializeCertConfig = materializeRuntimeCertConfig
	}
	materializeCertConfig(rawAPIClient, controllerConfig, logger)

	return &machineRuntimeNode{
		apiClient:        apiClient,
		controllerConfig: controllerConfig,
	}, nil
}

func (plan runtimeConfigPlan) machineNodeAPIConfig(binding machine.NodeBinding) *api.Config {
	apiConfig := &api.Config{
		NodeID:   binding.NodeID,
		NodeType: binding.NodeType,
	}
	machineConfig := plan.machineConfig
	if machineConfig == nil {
		return apiConfig
	}

	apiConfig.APIHost = machineConfig.ApiHost
	apiConfig.Key = machineConfig.Token
	apiConfig.MachineID = machineConfig.MachineID
	apiConfig.Timeout = machineConfig.Timeout
	return apiConfig
}

func (plan runtimeConfigPlan) machineNodeControllerConfig() (*controller.Config, error) {
	controllerConfig, err := cloneControllerConfig(plan.machineConfig.ControllerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to clone controller config: %w", err)
	}
	return controllerConfig, nil
}

func buildMachineSharedWSRuntime(wsConfig *controller.WebSocketConfig, endpoint string, logger *log.Entry) *machine.SharedWSRuntime {
	if wsConfig == nil || !wsConfig.Enable {
		return nil
	}
	return machine.NewSharedWSRuntime(machine.SharedWSRuntimeConfig{
		Endpoint:          endpoint,
		HeartbeatInterval: time.Duration(wsConfig.HeartbeatInterval) * time.Second,
		ReconnectBackoff:  time.Duration(wsConfig.ReconnectBackoff) * time.Second,
		ResyncOnReconnect: wsConfig.ResyncOnReconnect,
		Logger:            logger,
	})
}
