package panel

import (
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
	if plan.staticNodes[0].panelType != "SSPanel" || plan.staticNodes[0].apiConfig != apiConfig || plan.staticNodes[0].controllerConfigTemplate != controllerTemplate {
		t.Fatalf("expected first static node plan to preserve node config pointers, got %#v", plan.staticNodes[0])
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

func TestBuildStaticNodeServicesRejectsUnsupportedPanelType(t *testing.T) {
	panel := New(&Config{})
	plan := runtimeConfigPlan{
		mode: runtimeConfigModeStatic,
		staticNodes: []staticRuntimeNodePlan{{
			panelType: "UnsupportedPanel",
		}},
	}

	services, err := panel.buildStaticNodeServices(nil, plan)
	if err == nil {
		t.Fatal("expected unsupported panel type error")
	}
	if services != nil {
		t.Fatalf("expected no services, got %#v", services)
	}
	if !strings.Contains(err.Error(), "unsupported panel type: UnsupportedPanel") {
		t.Fatalf("expected unsupported panel type error, got %v", err)
	}
}

func TestRuntimeNodeServiceTypeUsesFallbackWhenDescribeNodeTypeEmpty(t *testing.T) {
	client := &runtimeNodeServiceTestAPI{clientInfo: api.ClientInfo{NodeType: ""}}

	if got := runtimeNodeServiceType(client, "Hysteria2"); got != "Hysteria2" {
		t.Fatalf("expected fallback node type Hysteria2, got %q", got)
	}
}

func TestRuntimeNodeServiceTypePrefersDescribedNodeType(t *testing.T) {
	client := &runtimeNodeServiceTestAPI{clientInfo: api.ClientInfo{NodeType: "Tuic"}}

	if got := runtimeNodeServiceType(client, "Hysteria2"); got != "Tuic" {
		t.Fatalf("expected described node type Tuic, got %q", got)
	}
}

func TestRuntimeNodeServiceKindForNodeType(t *testing.T) {
	tests := []struct {
		name     string
		nodeType string
		want     runtimeNodeServiceKind
	}{
		{name: "hysteria2", nodeType: "Hysteria2", want: runtimeNodeServiceHysteria2},
		{name: "hysteria alias", nodeType: "Hysteria", want: runtimeNodeServiceHysteria2},
		{name: "hysteria case insensitive", nodeType: "hYsTeRiA2", want: runtimeNodeServiceHysteria2},
		{name: "tuic", nodeType: "Tuic", want: runtimeNodeServiceTuic},
		{name: "tuic case insensitive", nodeType: "tuic", want: runtimeNodeServiceTuic},
		{name: "anytls", nodeType: "AnyTLS", want: runtimeNodeServiceAnyTLS},
		{name: "anytls case insensitive", nodeType: "anytls", want: runtimeNodeServiceAnyTLS},
		{name: "vless falls back", nodeType: "Vless", want: runtimeNodeServiceController},
		{name: "vmess falls back", nodeType: "Vmess", want: runtimeNodeServiceController},
		{name: "trojan falls back", nodeType: "Trojan", want: runtimeNodeServiceController},
		{name: "shadowsocks falls back", nodeType: "Shadowsocks", want: runtimeNodeServiceController},
		{name: "socks falls back", nodeType: "Socks", want: runtimeNodeServiceController},
		{name: "http falls back", nodeType: "HTTP", want: runtimeNodeServiceController},
		{name: "empty falls back", nodeType: "", want: runtimeNodeServiceController},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := runtimeNodeServiceKindForNodeType(test.nodeType); got != test.want {
				t.Fatalf("expected %q, got %q", test.want, got)
			}
		})
	}
}

type runtimeNodeServiceTestAPI struct {
	clientInfo api.ClientInfo
}

func (a *runtimeNodeServiceTestAPI) Describe() api.ClientInfo { return a.clientInfo }

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
	if plan.machineConfig != config.MachineConfig {
		t.Fatalf("expected machine config to be preserved, got %#v", plan.machineConfig)
	}
	if len(plan.staticNodes) != 0 {
		t.Fatalf("expected no static nodes in machine plan, got %#v", plan.staticNodes)
	}
	if !plan.showErrorDetails {
		t.Fatal("expected ShowErrorDetails to be carried into runtime plan")
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

func TestMaterializeRuntimeControllerConfigPreservesDefaultsAndOverrides(t *testing.T) {
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

	cfg, err := materializeRuntimeControllerConfig(template, runtimeControllerConfigOptions{showErrorDetails: true})
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

func TestMaterializeRuntimeControllerConfigCloneOptionIsIndependent(t *testing.T) {
	template := &controller.Config{
		WebSocketConfig: &controller.WebSocketConfig{HeartbeatInterval: 99},
		GlobalDeviceLimitConfig: &limiter.GlobalDeviceLimitConfig{
			RedisAddr: "127.0.0.1:6379",
		},
	}

	cfg1, err := materializeRuntimeControllerConfig(template, runtimeControllerConfigOptions{clone: true})
	if err != nil {
		t.Fatalf("materialize first controller config: %v", err)
	}
	cfg2, err := materializeRuntimeControllerConfig(template, runtimeControllerConfigOptions{clone: true})
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
