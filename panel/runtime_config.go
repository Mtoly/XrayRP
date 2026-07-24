package panel

import (
	"encoding/json"
	"fmt"
	"strings"

	"dario.cat/mergo"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service/controller"
)

type runtimeConfigMode string

const (
	runtimeConfigModeStatic  runtimeConfigMode = "static"
	runtimeConfigModeMachine runtimeConfigMode = "machine"
)

type runtimeConfigPlan struct {
	mode                    runtimeConfigMode
	staticNodes             []staticRuntimeNodePlan
	machineConfig           *MachineConfig
	machineSharedWSEndpoint string
	showErrorDetails        bool
}

type staticRuntimeNodePlan struct {
	panelType                string
	apiConfig                *api.Config
	controllerConfigTemplate *controller.Config
	fallbackNodeType         string
}

func (plan staticRuntimeNodePlan) materializeControllerConfig() (*controller.Config, error) {
	controllerConfig, err := cloneControllerConfig(plan.controllerConfigTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to clone controller config: %w", err)
	}
	return controllerConfig, nil
}

func buildRuntimeConfigPlan(config *Config) (runtimeConfigPlan, error) {
	plan := runtimeConfigPlan{mode: runtimeConfigModeStatic}
	if config == nil {
		return plan, nil
	}

	plan.showErrorDetails = config.ShowErrorDetails()
	if config.MachineConfig != nil && config.MachineConfig.Enable {
		machineConfig, sharedWSEndpoint, err := buildMachineRuntimeConfigPlan(config, plan.showErrorDetails)
		if err != nil {
			return plan, err
		}
		plan.mode = runtimeConfigModeMachine
		plan.machineConfig = machineConfig
		plan.machineSharedWSEndpoint = sharedWSEndpoint
		return plan, nil
	}

	staticNodes, err := buildStaticRuntimeNodePlans(config.NodesConfig, plan.showErrorDetails)
	if err != nil {
		return plan, err
	}
	plan.staticNodes = staticNodes
	return plan, nil
}

func buildStaticRuntimeNodePlans(nodes []*NodesConfig, showErrorDetails bool) ([]staticRuntimeNodePlan, error) {
	plans := make([]staticRuntimeNodePlan, 0, len(nodes))
	for index, node := range nodes {
		if node == nil {
			return nil, fmt.Errorf("static node config at index %d must not be nil", index)
		}
		if err := validateStaticPanelType(node.PanelType); err != nil {
			return nil, err
		}
		if node.ApiConfig == nil {
			return nil, fmt.Errorf("static node API config at index %d must not be nil", index)
		}
		apiConfig := *node.ApiConfig
		controllerConfig, err := buildRuntimeControllerConfig(node.ControllerConfig, showErrorDetails)
		if err != nil {
			return nil, err
		}
		plans = append(plans, staticRuntimeNodePlan{
			panelType:                node.PanelType,
			apiConfig:                &apiConfig,
			controllerConfigTemplate: controllerConfig,
			fallbackNodeType:         apiConfig.NodeType,
		})
	}
	return plans, nil
}

func validateStaticPanelType(panelType string) error {
	switch panelType {
	case "SSpanel", "SSPanel", "NewV2board", "V2board", "PMpanel", "Proxypanel", "V2RaySocks", "GoV2Panel", "BunPanel":
		return nil
	default:
		return fmt.Errorf("unsupported panel type: %s", panelType)
	}
}

func buildMachineRuntimeConfigPlan(config *Config, showErrorDetails bool) (*MachineConfig, string, error) {
	machineConfig := config.MachineConfig
	if len(config.NodesConfig) > 0 {
		return nil, "", fmt.Errorf("machine mode cannot be enabled with static Nodes config")
	}
	if strings.TrimSpace(machineConfig.ApiHost) == "" {
		return nil, "", fmt.Errorf("machine mode ApiHost must not be empty")
	}
	if machineConfig.MachineID <= 0 {
		return nil, "", fmt.Errorf("machine mode MachineID must be greater than 0")
	}
	if strings.TrimSpace(machineConfig.Token) == "" {
		return nil, "", fmt.Errorf("machine mode Token must not be empty")
	}
	switch panelType := strings.TrimSpace(machineConfig.PanelType); panelType {
	case "":
		return nil, "", fmt.Errorf("machine mode PanelType must not be empty")
	case "NewV2board", "V2board":
	default:
		return nil, "", fmt.Errorf("unsupported panel type for machine mode: %s", machineConfig.PanelType)
	}

	controllerConfig, err := buildRuntimeControllerConfig(machineConfig.ControllerConfig, showErrorDetails)
	if err != nil {
		return nil, "", err
	}
	sharedWSEndpoint := ""
	if wsConfig := controllerConfig.WebSocketConfig; wsConfig != nil && wsConfig.Enable {
		endpoint, err := controller.BuildWSEndpoint(&api.WSConfig{
			APIHost:   machineConfig.ApiHost,
			MachineID: machineConfig.MachineID,
			Key:       machineConfig.Token,
		}, wsConfig)
		if err != nil {
			return nil, "", err
		}
		sharedWSEndpoint = endpoint
	}

	snapshot := *machineConfig
	snapshot.ControllerConfig = controllerConfig
	return &snapshot, sharedWSEndpoint, nil
}

func buildRuntimeControllerConfig(template *controller.Config, showErrorDetails bool) (*controller.Config, error) {
	controllerConfig := getDefaultControllerConfig()
	if template != nil {
		if err := mergo.Merge(controllerConfig, template, mergo.WithOverride); err != nil {
			return nil, fmt.Errorf("failed to read controller config: %w", err)
		}
	}
	controllerConfig.ShowErrorDetails = showErrorDetails

	cloned, err := cloneControllerConfig(controllerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to clone controller config: %w", err)
	}
	return cloned, nil
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
