package panel

import (
	"encoding/json"
	"errors"
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

var (
	ErrStaticRuntimeConfigEmptyNodes = errors.New("static mode requires at least one Nodes entry")
	ErrRuntimeConfigModeConflict     = errors.New("static Nodes and enabled MachineConfig are mutually exclusive")
	ErrRuntimeConfigModeChange       = errors.New("online runtime mode change is not supported")
)

type runtimeConfigPlan struct {
	mode                    runtimeConfigMode
	staticNodes             []staticRuntimeNodePlan
	machineConfig           *MachineConfig
	machineNewAPIClient     panelClientFactory
	machineSharedWSEndpoint string
	showErrorDetails        bool
}

type staticRuntimeNodePlan struct {
	panelType                string
	apiConfig                *api.Config
	newAPIClient             panelClientFactory
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

func ValidateRuntimeConfig(config *Config) error {
	_, err := buildValidatedRuntimeConfigPlan(config)
	return err
}

func ValidateRuntimeConfigReload(current, candidate *Config) error {
	currentPlan, err := buildValidatedRuntimeConfigPlan(current)
	if err != nil {
		return fmt.Errorf("validate applied runtime config: %w", err)
	}
	candidatePlan, err := buildValidatedRuntimeConfigPlan(candidate)
	if err != nil {
		return fmt.Errorf("validate candidate runtime config: %w", err)
	}
	if currentPlan.mode != candidatePlan.mode {
		return fmt.Errorf("%w: %s to %s", ErrRuntimeConfigModeChange, currentPlan.mode, candidatePlan.mode)
	}
	return nil
}

func buildValidatedRuntimeConfigPlan(config *Config) (runtimeConfigPlan, error) {
	plan, err := buildRuntimeConfigPlan(config)
	if err != nil {
		return plan, err
	}
	if plan.mode == runtimeConfigModeStatic && len(plan.staticNodes) == 0 {
		return plan, ErrStaticRuntimeConfigEmptyNodes
	}
	return plan, nil
}

func buildRuntimeConfigPlan(config *Config) (runtimeConfigPlan, error) {
	plan := runtimeConfigPlan{mode: runtimeConfigModeStatic}
	if config == nil {
		return plan, nil
	}

	plan.showErrorDetails = config.ShowErrorDetails()
	if config.MachineConfig != nil && config.MachineConfig.Enable {
		machineConfig, newAPIClient, sharedWSEndpoint, err := buildMachineRuntimeConfigPlan(config, plan.showErrorDetails)
		if err != nil {
			return plan, err
		}
		plan.mode = runtimeConfigModeMachine
		plan.machineConfig = machineConfig
		plan.machineNewAPIClient = newAPIClient
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
	adapterRegistry := defaultPanelAdapterRegistry()
	for index, node := range nodes {
		if node == nil {
			return nil, fmt.Errorf("static node config at index %d must not be nil", index)
		}
		newAPIClient, err := adapterRegistry.staticFactory(node.PanelType)
		if err != nil {
			return nil, err
		}
		if node.ApiConfig == nil {
			return nil, fmt.Errorf("static node API config at index %d must not be nil", index)
		}
		apiConfig := *node.ApiConfig
		if err := validatePanelAPIHost(apiConfig.APIHost); err != nil {
			return nil, fmt.Errorf("static node API config at index %d: %w", index, err)
		}
		controllerConfig, err := buildRuntimeControllerConfig(node.ControllerConfig, showErrorDetails)
		if err != nil {
			return nil, err
		}
		plans = append(plans, staticRuntimeNodePlan{
			panelType:                node.PanelType,
			apiConfig:                &apiConfig,
			newAPIClient:             newAPIClient,
			controllerConfigTemplate: controllerConfig,
			fallbackNodeType:         apiConfig.NodeType,
		})
	}
	return plans, nil
}

func buildMachineRuntimeConfigPlan(config *Config, showErrorDetails bool) (*MachineConfig, panelClientFactory, string, error) {
	machineConfig := config.MachineConfig
	if len(config.NodesConfig) > 0 {
		return nil, nil, "", fmt.Errorf("%w: machine mode cannot be enabled with static Nodes config", ErrRuntimeConfigModeConflict)
	}
	if strings.TrimSpace(machineConfig.ApiHost) == "" {
		return nil, nil, "", fmt.Errorf("machine mode ApiHost must not be empty")
	}
	if err := validatePanelAPIHost(machineConfig.ApiHost); err != nil {
		return nil, nil, "", fmt.Errorf("machine mode ApiHost: %w", err)
	}
	if machineConfig.MachineID <= 0 {
		return nil, nil, "", fmt.Errorf("machine mode MachineID must be greater than 0")
	}
	if strings.TrimSpace(machineConfig.Token) == "" {
		return nil, nil, "", fmt.Errorf("machine mode Token must not be empty")
	}
	newAPIClient, err := defaultPanelAdapterRegistry().machineFactory(machineConfig.PanelType)
	if err != nil {
		return nil, nil, "", err
	}

	controllerConfig, err := buildRuntimeControllerConfig(machineConfig.ControllerConfig, showErrorDetails)
	if err != nil {
		return nil, nil, "", err
	}
	sharedWSEndpoint := ""
	if wsConfig := controllerConfig.WebSocketConfig; wsConfig != nil && wsConfig.Enable {
		endpoint, err := controller.BuildWSEndpoint(&api.WSConfig{
			APIHost:   machineConfig.ApiHost,
			MachineID: machineConfig.MachineID,
			Key:       machineConfig.Token,
		}, wsConfig)
		if err != nil {
			return nil, nil, "", err
		}
		sharedWSEndpoint = endpoint
	}

	snapshot := *machineConfig
	snapshot.ControllerConfig = controllerConfig
	return &snapshot, newAPIClient, sharedWSEndpoint, nil
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
