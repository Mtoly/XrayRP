package panel

import (
	"fmt"

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
	mode             runtimeConfigMode
	staticNodes      []staticRuntimeNodePlan
	machineConfig    *MachineConfig
	showErrorDetails bool
}

type staticRuntimeNodePlan struct {
	panelType                string
	apiConfig                *api.Config
	controllerConfigTemplate *controller.Config
	fallbackNodeType         string
}

type runtimeControllerConfigOptions struct {
	showErrorDetails bool
	clone            bool
}

func buildRuntimeConfigPlan(config *Config) (runtimeConfigPlan, error) {
	plan := runtimeConfigPlan{mode: runtimeConfigModeStatic}
	if config == nil {
		return plan, nil
	}

	plan.showErrorDetails = config.ShowErrorDetails()
	if machineModeEnabled(config) {
		if err := validateMachineModeConfig(config); err != nil {
			return plan, err
		}
		plan.mode = runtimeConfigModeMachine
		plan.machineConfig = config.MachineConfig
		return plan, nil
	}

	plan.staticNodes = buildStaticRuntimeNodePlans(config.NodesConfig)
	return plan, nil
}

func buildStaticRuntimeNodePlans(nodes []*NodesConfig) []staticRuntimeNodePlan {
	plans := make([]staticRuntimeNodePlan, 0, len(nodes))
	for _, node := range nodes {
		fallbackNodeType := ""
		if node.ApiConfig != nil {
			fallbackNodeType = node.ApiConfig.NodeType
		}
		plans = append(plans, staticRuntimeNodePlan{
			panelType:                node.PanelType,
			apiConfig:                node.ApiConfig,
			controllerConfigTemplate: node.ControllerConfig,
			fallbackNodeType:         fallbackNodeType,
		})
	}
	return plans
}

func materializeRuntimeControllerConfig(template *controller.Config, options runtimeControllerConfigOptions) (*controller.Config, error) {
	controllerConfig := getDefaultControllerConfig()
	if template != nil {
		if err := mergo.Merge(controllerConfig, template, mergo.WithOverride); err != nil {
			return nil, fmt.Errorf("failed to read controller config: %w", err)
		}
	}
	controllerConfig.ShowErrorDetails = options.showErrorDetails

	if !options.clone {
		return controllerConfig, nil
	}

	cloned, err := cloneControllerConfig(controllerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to clone controller config: %w", err)
	}
	return cloned, nil
}
