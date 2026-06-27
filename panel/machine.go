package panel

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"dario.cat/mergo"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/core"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
	"github.com/Mtoly/XrayRP/service/machine"
)

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
	if err := validateMachineModeConfig(p.panelConfig); err != nil {
		return nil, err
	}
	if !machineModeEnabled(p.panelConfig) {
		return nil, fmt.Errorf("machine mode is not enabled")
	}

	mc := p.panelConfig.MachineConfig
	baseControllerConfig, err := buildMachineNodeControllerConfig(mc.ControllerConfig)
	if err != nil {
		return nil, err
	}
	baseControllerConfig.ShowErrorDetails = p.panelConfig.ShowErrorDetails()
	sharedWS, err := buildMachineSharedWSRuntime(mc, baseControllerConfig.WebSocketConfig, p.logger.WithField("service", "machine-websocket"))
	if err != nil {
		return nil, err
	}

	discoverer := &machine.NewV2boardDiscoverer{
		Config: newV2board.MachineDiscoveryConfig{
			APIHost:   mc.ApiHost,
			MachineID: mc.MachineID,
			Token:     mc.Token,
			Timeout:   time.Duration(mc.Timeout) * time.Second,
		},
	}
	factory := func(binding machine.NodeBinding) (service.Service, error) {
		apiConfig := buildMachineNodeAPIConfig(mc, binding)
		var apiClient api.API = newV2board.New(apiConfig)
		if sharedWS != nil {
			apiClient = machine.WrapAPIWithReporter(apiClient, binding.NodeID, sharedWS)
		}

		controllerConfig, err := buildMachineNodeControllerConfig(mc.ControllerConfig)
		if err != nil {
			return nil, err
		}
		controllerConfig.ShowErrorDetails = p.panelConfig.ShowErrorDetails()
		p.mergePanelCertConfig(apiClient, controllerConfig)

		if sharedWS != nil && machineSharedWSSupportedNodeType(binding.NodeType) {
			controllerService := controller.New(server, apiClient, controllerConfig, mc.PanelType)
			controllerService.SetWSEventRuntimeFactory(sharedWS.NewNodeRuntimeFactory(binding.NodeID))
			return controllerService, nil
		}

		return p.buildNodeService(server, apiClient, controllerConfig, mc.PanelType)
	}

	supervisor, err := machine.NewSupervisor(machine.SupervisorConfig{
		DiscoveryInterval: time.Duration(mc.DiscoveryInterval) * time.Second,
		Logger:            p.logger.WithField("service", "machine-supervisor"),
		ShowErrorDetails:  p.panelConfig.ShowErrorDetails(),
	}, discoverer, factory)
	if err != nil {
		return nil, err
	}
	if sharedWS != nil {
		return machine.NewRuntimeService(supervisor, sharedWS), nil
	}
	return supervisor, nil
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
	controllerConfig := getDefaultControllerConfig()
	if template != nil {
		if err := mergo.Merge(controllerConfig, template, mergo.WithOverride); err != nil {
			return nil, fmt.Errorf("failed to read controller config: %w", err)
		}
	}

	controllerConfig, err := cloneControllerConfig(controllerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to clone controller config: %w", err)
	}
	return controllerConfig, nil
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
