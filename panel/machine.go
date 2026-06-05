package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"dario.cat/mergo"
	"github.com/xtls/xray-core/core"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
	"github.com/Mtoly/XrayRP/service/machine"
)

const machineModeWebSocketUnsupportedMessage = "MachineConfig.ControllerConfig.WebSocketConfig.Enable is not supported in machine mode yet; disable it until shared machine websocket mux is implemented"

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
		apiClient := newV2board.New(apiConfig)
		controllerConfig, err := buildMachineNodeControllerConfig(mc.ControllerConfig)
		if err != nil {
			return nil, err
		}
		p.mergePanelCertConfig(apiClient, controllerConfig)
		return p.buildNodeService(server, apiClient, controllerConfig, mc.PanelType)
	}

	return machine.NewSupervisor(machine.SupervisorConfig{
		DiscoveryInterval: time.Duration(mc.DiscoveryInterval) * time.Second,
		Logger:            p.logger.WithField("service", "machine-supervisor"),
	}, discoverer, factory)
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
	if controllerConfig.WebSocketConfig != nil && controllerConfig.WebSocketConfig.Enable {
		return nil, errors.New(machineModeWebSocketUnsupportedMessage)
	}
	return controllerConfig, nil
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
