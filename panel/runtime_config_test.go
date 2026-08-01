package panel

import (
	"errors"
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/service/controller"
)

func TestBuildRuntimeConfigPlanSelectsStaticNodes(t *testing.T) {
	apiConfig := &api.Config{NodeType: "Hysteria2"}
	controllerTemplate := &controller.Config{UpdatePeriodic: 12}
	nodes := []*NodesConfig{
		{PanelType: "SSPanel", ApiConfig: apiConfig, ControllerConfig: controllerTemplate},
		{PanelType: "NewV2board", ApiConfig: &api.Config{NodeType: "Vless"}},
	}
	config := &Config{
		LogConfig:   &LogConfig{ShowErrorDetails: true},
		NodesConfig: nodes,
	}

	plan, err := buildRuntimeConfigPlan(config)
	if err != nil {
		t.Fatalf("build runtime config plan: %v", err)
	}

	if plan.mode != runtimeConfigModeStatic {
		t.Fatalf("expected static runtime mode, got %q", plan.mode)
	}
	if len(plan.staticNodes) != 2 {
		t.Fatalf("expected two static node plans, got %#v", plan.staticNodes)
	}
	if plan.staticNodes[0].panelType != "SSPanel" ||
		plan.staticNodes[0].apiConfig == apiConfig ||
		plan.staticNodes[0].controllerConfigTemplate == controllerTemplate {
		t.Fatalf("expected first static node plan to own config snapshots, got %#v", plan.staticNodes[0])
	}
	if plan.staticNodes[0].apiConfig.NodeType != apiConfig.NodeType ||
		plan.staticNodes[0].controllerConfigTemplate.UpdatePeriodic != controllerTemplate.UpdatePeriodic {
		t.Fatalf("expected first static node values to be preserved, got %#v", plan.staticNodes[0])
	}
	if plan.staticNodes[0].newAPIClient == nil || plan.staticNodes[1].newAPIClient == nil {
		t.Fatal("expected static node plans to retain validated adapter factories")
	}
	if plan.staticNodes[0].fallbackNodeType != "Hysteria2" {
		t.Fatalf("expected fallback node type Hysteria2, got %q", plan.staticNodes[0].fallbackNodeType)
	}
	if plan.staticNodes[1].panelType != "NewV2board" || plan.staticNodes[1].fallbackNodeType != "Vless" {
		t.Fatalf("expected second static node plan to preserve panel and fallback node type, got %#v", plan.staticNodes[1])
	}
	if plan.machineConfig != nil {
		t.Fatalf("expected no machine config in static plan, got %#v", plan.machineConfig)
	}
	if !plan.showErrorDetails {
		t.Fatal("expected ShowErrorDetails to be carried into runtime plan")
	}
}

func TestBuildRuntimeConfigPlanHandlesNilConfigAsEmptyStaticPlan(t *testing.T) {
	plan, err := buildRuntimeConfigPlan(nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.mode != runtimeConfigModeStatic || len(plan.staticNodes) != 0 || plan.machineConfig != nil || plan.showErrorDetails {
		t.Fatalf("unexpected nil-config plan: %#v", plan)
	}
}

func TestValidateRuntimeConfigAppliesModeSpecificRules(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr error
	}{
		{
			name: "static mode requires nodes",
			config: &Config{
				NodesConfig: nil,
			},
			wantErr: ErrStaticRuntimeConfigEmptyNodes,
		},
		{
			name: "static mode accepts nodes",
			config: &Config{
				NodesConfig: []*NodesConfig{{
					PanelType: "SSPanel",
					ApiConfig: &api.Config{},
				}},
			},
		},
		{
			name:   "machine mode accepts empty nodes",
			config: validMachineModeConfig(),
		},
		{
			name: "machine mode rejects static nodes",
			config: func() *Config {
				config := validMachineModeConfig()
				config.NodesConfig = []*NodesConfig{{
					PanelType: "SSPanel",
					ApiConfig: &api.Config{},
				}}
				return config
			}(),
			wantErr: ErrRuntimeConfigModeConflict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuntimeConfig(tt.config)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateRuntimeConfig() error = %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateRuntimeConfig() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRuntimeConfigReloadRejectsModeChanges(t *testing.T) {
	staticConfig := &Config{
		NodesConfig: []*NodesConfig{{
			PanelType: "SSPanel",
			ApiConfig: &api.Config{},
		}},
	}
	machineConfig := validMachineModeConfig()

	if err := ValidateRuntimeConfigReload(staticConfig, staticConfig); err != nil {
		t.Fatalf("static-to-static validation error = %v", err)
	}
	if err := ValidateRuntimeConfigReload(machineConfig, machineConfig); err != nil {
		t.Fatalf("machine-to-machine validation error = %v", err)
	}
	if err := ValidateRuntimeConfigReload(staticConfig, machineConfig); !errors.Is(err, ErrRuntimeConfigModeChange) {
		t.Fatalf("static-to-machine validation error = %v, want %v", err, ErrRuntimeConfigModeChange)
	}
	if err := ValidateRuntimeConfigReload(machineConfig, staticConfig); !errors.Is(err, ErrRuntimeConfigModeChange) {
		t.Fatalf("machine-to-static validation error = %v, want %v", err, ErrRuntimeConfigModeChange)
	}
}

func TestDefaultPanelLifecycleUsesValidatedRuntimeConfigPlan(t *testing.T) {
	ops := defaultPanelLifecycleOps()
	if _, err := ops.buildRuntimePlan(&Config{}); !errors.Is(err, ErrStaticRuntimeConfigEmptyNodes) {
		t.Fatalf("empty static initial config error = %v, want %v", err, ErrStaticRuntimeConfigEmptyNodes)
	}
	if _, err := ops.buildRuntimePlan(validMachineModeConfig()); err != nil {
		t.Fatalf("machine initial config with empty Nodes error = %v", err)
	}
}

func TestBuildRuntimeConfigPlanRejectsInvalidStaticNodes(t *testing.T) {
	tests := []struct {
		name  string
		nodes []*NodesConfig
		want  string
	}{
		{
			name:  "unsupported panel",
			nodes: []*NodesConfig{{PanelType: "UnsupportedPanel", ApiConfig: &api.Config{}}},
			want:  "unsupported panel type: UnsupportedPanel",
		},
		{
			name:  "nil node",
			nodes: []*NodesConfig{nil},
			want:  "static node config at index 0 must not be nil",
		},
		{
			name:  "nil API config",
			nodes: []*NodesConfig{{PanelType: "SSPanel"}},
			want:  "static node API config at index 0 must not be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildRuntimeConfigPlan(&Config{NodesConfig: tt.nodes})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestBuildRuntimeConfigPlanSnapshotsStaticInputs(t *testing.T) {
	apiConfig := &api.Config{NodeType: "Hysteria2", APIHost: "https://original.example"}
	controllerTemplate := &controller.Config{
		UpdatePeriodic: 12,
		WebSocketConfig: &controller.WebSocketConfig{
			Endpoint: "wss://original.example/ws",
		},
	}
	config := &Config{
		LogConfig: &LogConfig{ShowErrorDetails: true},
		NodesConfig: []*NodesConfig{{
			PanelType:        "SSPanel",
			ApiConfig:        apiConfig,
			ControllerConfig: controllerTemplate,
		}},
	}

	plan, err := buildRuntimeConfigPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	apiConfig.NodeType = "Tuic"
	apiConfig.APIHost = "https://mutated.example"
	controllerTemplate.UpdatePeriodic = 99
	controllerTemplate.WebSocketConfig.Endpoint = "wss://mutated.example/ws"
	config.LogConfig.ShowErrorDetails = false

	nodePlan := plan.staticNodes[0]
	if nodePlan.apiConfig.NodeType != "Hysteria2" || nodePlan.apiConfig.APIHost != "https://original.example" {
		t.Fatalf("static API config changed with source: %#v", nodePlan.apiConfig)
	}
	if nodePlan.controllerConfigTemplate.UpdatePeriodic != 12 ||
		nodePlan.controllerConfigTemplate.WebSocketConfig.Endpoint != "wss://original.example/ws" {
		t.Fatalf("static controller config changed with source: %#v", nodePlan.controllerConfigTemplate)
	}
	if !nodePlan.controllerConfigTemplate.ShowErrorDetails {
		t.Fatal("static controller snapshot lost ShowErrorDetails")
	}
	if nodePlan.fallbackNodeType != "Hysteria2" || !plan.showErrorDetails {
		t.Fatalf("derived static values changed: node=%#v plan=%#v", nodePlan, plan)
	}
}

func TestBuildRuntimeConfigPlanSelectsMachineMode(t *testing.T) {
	config := validMachineModeConfig()
	config.LogConfig = &LogConfig{ShowErrorDetails: true}

	plan, err := buildRuntimeConfigPlan(config)
	if err != nil {
		t.Fatalf("build runtime config plan: %v", err)
	}

	if plan.mode != runtimeConfigModeMachine {
		t.Fatalf("expected machine runtime mode, got %q", plan.mode)
	}
	if plan.machineConfig == config.MachineConfig {
		t.Fatal("expected machine config snapshot to be independently owned")
	}
	if plan.machineNewAPIClient == nil {
		t.Fatal("expected machine plan to retain its validated adapter factory")
	}
	if plan.machineConfig.ApiHost != config.MachineConfig.ApiHost ||
		plan.machineConfig.MachineID != config.MachineConfig.MachineID ||
		plan.machineConfig.Token != config.MachineConfig.Token {
		t.Fatalf("expected machine config values to be preserved, got %#v", plan.machineConfig)
	}
	if len(plan.staticNodes) != 0 {
		t.Fatalf("expected no static nodes in machine plan, got %#v", plan.staticNodes)
	}
	if !plan.showErrorDetails {
		t.Fatal("expected ShowErrorDetails to be carried into runtime plan")
	}
}

func TestBuildRuntimeConfigPlanPreservesRawMachinePanelAlias(t *testing.T) {
	config := validMachineModeConfig()
	config.MachineConfig.PanelType = " V2board "

	plan, err := buildRuntimeConfigPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	if plan.machineConfig.PanelType != " V2board " {
		t.Fatalf("machine PanelType = %q, want raw alias preserved", plan.machineConfig.PanelType)
	}
	if plan.machineNewAPIClient == nil {
		t.Fatal("expected trimmed alias validation to retain a machine adapter factory")
	}
}

func TestBuildRuntimeConfigPlanSnapshotsMachineInputs(t *testing.T) {
	config := validMachineModeConfig()
	config.LogConfig = &LogConfig{ShowErrorDetails: true}
	config.MachineConfig.DiscoveryInterval = 17
	config.MachineConfig.ControllerConfig = &controller.Config{
		UpdatePeriodic: 45,
		WebSocketConfig: &controller.WebSocketConfig{
			Enable:            true,
			HeartbeatInterval: 30,
			ReconnectBackoff:  5,
		},
	}

	plan, err := buildRuntimeConfigPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	config.MachineConfig.ApiHost = "https://mutated.example"
	config.MachineConfig.MachineID = 99
	config.MachineConfig.Token = "mutated-token"
	config.MachineConfig.Timeout = 99
	config.MachineConfig.DiscoveryInterval = 99
	config.MachineConfig.ControllerConfig.UpdatePeriodic = 99
	config.MachineConfig.ControllerConfig.WebSocketConfig.HeartbeatInterval = 99
	config.LogConfig.ShowErrorDetails = false

	if plan.machineConfig.ApiHost != "https://panel.example.com" ||
		plan.machineConfig.MachineID != 7 ||
		plan.machineConfig.Token != "machine-token" ||
		plan.machineConfig.Timeout != 30 ||
		plan.machineConfig.DiscoveryInterval != 17 {
		t.Fatalf("machine config changed with source: %#v", plan.machineConfig)
	}
	if plan.machineConfig.ControllerConfig.UpdatePeriodic != 45 ||
		plan.machineConfig.ControllerConfig.WebSocketConfig.HeartbeatInterval != 30 {
		t.Fatalf("machine controller config changed with source: %#v", plan.machineConfig.ControllerConfig)
	}
	if !plan.machineConfig.ControllerConfig.ShowErrorDetails {
		t.Fatal("machine controller snapshot lost ShowErrorDetails")
	}
	if !plan.showErrorDetails {
		t.Fatal("ShowErrorDetails changed with source")
	}
}

func TestBuildRuntimeConfigPlanRejectsInvalidSharedWebSocketEndpoint(t *testing.T) {
	config := validMachineModeConfig()
	config.MachineConfig.ControllerConfig = &controller.Config{
		WebSocketConfig: &controller.WebSocketConfig{
			Enable:   true,
			Endpoint: "ftp://panel.example/ws",
		},
	}

	_, err := buildRuntimeConfigPlan(config)
	if err == nil || !strings.Contains(err.Error(), "unsupported websocket endpoint scheme") {
		t.Fatalf("error = %v, want shared WebSocket endpoint validation", err)
	}
}

func TestRuntimeConfigPlanMaterializesIndependentControllerConfigs(t *testing.T) {
	template := &controller.Config{
		WebSocketConfig: &controller.WebSocketConfig{HeartbeatInterval: 99},
		GlobalDeviceLimitConfig: &limiter.GlobalDeviceLimitConfig{
			RedisAddr: "127.0.0.1:6379",
		},
	}
	plan, err := buildRuntimeConfigPlan(&Config{
		NodesConfig: []*NodesConfig{{
			PanelType:        "SSPanel",
			ApiConfig:        &api.Config{},
			ControllerConfig: template,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := plan.staticNodes[0].materializeControllerConfig()
	if err != nil {
		t.Fatal(err)
	}
	second, err := plan.staticNodes[0].materializeControllerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || first.WebSocketConfig == second.WebSocketConfig ||
		first.GlobalDeviceLimitConfig == second.GlobalDeviceLimitConfig {
		t.Fatalf("materialized configs share ownership: first=%#v second=%#v", first, second)
	}
	first.WebSocketConfig.HeartbeatInterval = 1
	first.GlobalDeviceLimitConfig.RedisAddr = "10.0.0.1:6379"
	if second.WebSocketConfig.HeartbeatInterval != 99 ||
		second.GlobalDeviceLimitConfig.RedisAddr != "127.0.0.1:6379" {
		t.Fatalf("mutating one materialization changed another: first=%#v second=%#v", first, second)
	}
}

func TestBuildRuntimeConfigPlanPreservesMachineValidation(t *testing.T) {
	config := validMachineModeConfig()
	config.NodesConfig = []*NodesConfig{{PanelType: "SSPanel"}}

	_, err := buildRuntimeConfigPlan(config)
	if err == nil {
		t.Fatal("expected machine/static mode conflict error")
	}
	if !strings.Contains(err.Error(), "static Nodes") {
		t.Fatalf("expected static Nodes error, got %v", err)
	}
}

func TestBuildRuntimeControllerConfigPreservesDefaultsAndOverrides(t *testing.T) {
	template := &controller.Config{
		UpdatePeriodic: 45,
		WebSocketConfig: &controller.WebSocketConfig{
			Enable:            true,
			Endpoint:          "wss://panel.example/ws",
			HeartbeatInterval: 99,
			ReconnectBackoff:  7,
			ResyncOnReconnect: true,
		},
		GlobalDeviceLimitConfig: &limiter.GlobalDeviceLimitConfig{
			Enable:       true,
			RedisNetwork: "tcp",
			RedisAddr:    "127.0.0.1:6379",
			Timeout:      5,
			Expiry:       60,
		},
	}

	cfg, err := buildRuntimeControllerConfig(template, true)
	if err != nil {
		t.Fatalf("materialize controller config: %v", err)
	}

	if cfg.ListenIP != "0.0.0.0" || cfg.SendIP != "0.0.0.0" || cfg.DNSType != "AsIs" {
		t.Fatalf("expected default listen/send/DNS values, got listen=%q send=%q dns=%q", cfg.ListenIP, cfg.SendIP, cfg.DNSType)
	}
	if cfg.UpdatePeriodic != 45 {
		t.Fatalf("expected UpdatePeriodic override 45, got %d", cfg.UpdatePeriodic)
	}
	if cfg.WebSocketConfig == nil {
		t.Fatal("expected WebSocketConfig to be materialized")
	}
	if !cfg.WebSocketConfig.Enable || cfg.WebSocketConfig.Endpoint != "wss://panel.example/ws" || cfg.WebSocketConfig.HeartbeatInterval != 99 || cfg.WebSocketConfig.ReconnectBackoff != 7 || !cfg.WebSocketConfig.ResyncOnReconnect {
		t.Fatalf("unexpected websocket config: %#v", cfg.WebSocketConfig)
	}
	if cfg.GlobalDeviceLimitConfig == nil || !cfg.GlobalDeviceLimitConfig.Enable || cfg.GlobalDeviceLimitConfig.RedisAddr != "127.0.0.1:6379" {
		t.Fatalf("unexpected global device limit config: %#v", cfg.GlobalDeviceLimitConfig)
	}
	if !cfg.ShowErrorDetails {
		t.Fatal("expected ShowErrorDetails to be materialized")
	}
}

func TestBuildRuntimeControllerConfigIsIndependent(t *testing.T) {
	template := &controller.Config{
		WebSocketConfig: &controller.WebSocketConfig{HeartbeatInterval: 99},
		GlobalDeviceLimitConfig: &limiter.GlobalDeviceLimitConfig{
			RedisAddr: "127.0.0.1:6379",
		},
	}

	cfg1, err := buildRuntimeControllerConfig(template, false)
	if err != nil {
		t.Fatalf("materialize first controller config: %v", err)
	}
	cfg2, err := buildRuntimeControllerConfig(template, false)
	if err != nil {
		t.Fatalf("materialize second controller config: %v", err)
	}

	if cfg1 == cfg2 {
		t.Fatal("expected fresh top-level configs")
	}
	if cfg1.WebSocketConfig == nil || cfg2.WebSocketConfig == nil || cfg1.WebSocketConfig == cfg2.WebSocketConfig {
		t.Fatalf("expected independent WebSocketConfig pointers, got cfg1=%p cfg2=%p", cfg1.WebSocketConfig, cfg2.WebSocketConfig)
	}
	if cfg1.GlobalDeviceLimitConfig == nil || cfg2.GlobalDeviceLimitConfig == nil || cfg1.GlobalDeviceLimitConfig == cfg2.GlobalDeviceLimitConfig {
		t.Fatalf("expected independent GlobalDeviceLimitConfig pointers, got cfg1=%p cfg2=%p", cfg1.GlobalDeviceLimitConfig, cfg2.GlobalDeviceLimitConfig)
	}

	cfg1.WebSocketConfig.HeartbeatInterval = 1
	cfg1.GlobalDeviceLimitConfig.RedisAddr = "10.0.0.1:6379"

	if cfg2.WebSocketConfig.HeartbeatInterval != 99 {
		t.Fatalf("mutating cfg1 WebSocketConfig changed cfg2: got %d", cfg2.WebSocketConfig.HeartbeatInterval)
	}
	if cfg2.GlobalDeviceLimitConfig.RedisAddr != "127.0.0.1:6379" {
		t.Fatalf("mutating cfg1 GlobalDeviceLimitConfig changed cfg2: got %q", cfg2.GlobalDeviceLimitConfig.RedisAddr)
	}
}
