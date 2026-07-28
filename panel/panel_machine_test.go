package panel

import (
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service/controller"
	"github.com/Mtoly/XrayRP/service/machine"
)

func TestValidateMachineModeRejectsStaticNodes(t *testing.T) {
	config := validMachineModeConfig()
	config.NodesConfig = []*NodesConfig{{PanelType: "SSPanel"}}

	_, err := buildRuntimeConfigPlan(config)
	if err == nil {
		t.Fatal("expected static Nodes conflict error")
	}
	if !strings.Contains(err.Error(), "static Nodes") {
		t.Fatalf("expected static Nodes error, got %v", err)
	}
}

func TestValidateMachineModeAllowsWebSocketEnabled(t *testing.T) {
	config := validMachineModeConfig()
	config.MachineConfig.ControllerConfig = &controller.Config{
		WebSocketConfig: &controller.WebSocketConfig{Enable: true},
	}

	plan, err := buildRuntimeConfigPlan(config)
	if err != nil {
		t.Fatalf("expected WebSocket config to be valid in machine mode, got %v", err)
	}
	if plan.machineSharedWSEndpoint == "" {
		t.Fatal("expected shared WebSocket endpoint to be resolved during plan construction")
	}
}

func TestBuildMachineSupervisorAllowsWebSocketEnabled(t *testing.T) {
	config := validMachineModeConfig()
	config.MachineConfig.ControllerConfig = &controller.Config{
		WebSocketConfig: &controller.WebSocketConfig{Enable: true},
	}
	panel := New(config)

	plan, err := buildRuntimeConfigPlan(config)
	if err != nil {
		t.Fatalf("build runtime config plan: %v", err)
	}
	service, err := panel.buildMachineSupervisor(nil, plan)
	if err != nil {
		t.Fatalf("expected machine supervisor with shared WebSocket, got %v", err)
	}
	if service == nil {
		t.Fatal("expected machine runtime service")
	}
	if _, ok := service.(*machine.RuntimeService); !ok {
		t.Fatalf("expected machine runtime service, got %T", service)
	}
}

func TestValidateMachineModeRejectsInvalidMachineCredentials(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*MachineConfig)
		want   string
	}{
		{
			name:   "empty ApiHost",
			mutate: func(config *MachineConfig) { config.ApiHost = "" },
			want:   "ApiHost",
		},
		{
			name:   "blank ApiHost",
			mutate: func(config *MachineConfig) { config.ApiHost = " \t\n " },
			want:   "ApiHost",
		},
		{
			name:   "zero MachineID",
			mutate: func(config *MachineConfig) { config.MachineID = 0 },
			want:   "MachineID",
		},
		{
			name:   "negative MachineID",
			mutate: func(config *MachineConfig) { config.MachineID = -1 },
			want:   "MachineID",
		},
		{
			name:   "empty Token",
			mutate: func(config *MachineConfig) { config.Token = "" },
			want:   "Token",
		},
		{
			name:   "blank Token",
			mutate: func(config *MachineConfig) { config.Token = " \t\n " },
			want:   "Token",
		},
		{
			name:   "empty PanelType",
			mutate: func(config *MachineConfig) { config.PanelType = "" },
			want:   "PanelType",
		},
		{
			name:   "unsupported PanelType",
			mutate: func(config *MachineConfig) { config.PanelType = "SSPanel" },
			want:   "unsupported panel type",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validMachineModeConfig()
			test.mutate(config.MachineConfig)

			_, err := buildRuntimeConfigPlan(config)
			if err == nil {
				t.Fatalf("expected error containing %q", test.want)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

func TestBuildMachineDiscoveryConfigPreservesMachineConfigFields(t *testing.T) {
	machineConfig := &MachineConfig{
		Enable:    true,
		PanelType: "NewV2board",
		ApiHost:   " https://panel.example.com ",
		MachineID: 42,
		Token:     " machine-token ",
		Timeout:   31,
	}

	plan, err := buildRuntimeConfigPlan(&Config{MachineConfig: machineConfig})
	if err != nil {
		t.Fatal(err)
	}
	discoveryConfig := plan.machineDiscoveryConfig()
	if discoveryConfig.APIHost != machineConfig.ApiHost {
		t.Fatalf("expected APIHost %q, got %q", machineConfig.ApiHost, discoveryConfig.APIHost)
	}
	if discoveryConfig.MachineID != machineConfig.MachineID {
		t.Fatalf("expected MachineID %d, got %d", machineConfig.MachineID, discoveryConfig.MachineID)
	}
	if discoveryConfig.Token != machineConfig.Token {
		t.Fatalf("expected Token %q, got %q", machineConfig.Token, discoveryConfig.Token)
	}
	if discoveryConfig.Timeout != 31*time.Second {
		t.Fatalf("expected Timeout 31s, got %s", discoveryConfig.Timeout)
	}
}

func TestBuildMachineNodeAPIConfigIncludesMachineID(t *testing.T) {
	machineConfig := &MachineConfig{
		Enable:    true,
		PanelType: "NewV2board",
		ApiHost:   " https://panel.example.com ",
		MachineID: 42,
		Token:     " machine-token ",
		Timeout:   31,
	}
	binding := machine.NodeBinding{
		NodeID:   9,
		NodeType: "VLESS",
	}

	plan, err := buildRuntimeConfigPlan(&Config{MachineConfig: machineConfig})
	if err != nil {
		t.Fatal(err)
	}
	apiConfig := plan.machineNodeAPIConfig(binding)
	if apiConfig == nil {
		t.Fatal("expected api config")
	}
	if apiConfig.APIHost != machineConfig.ApiHost {
		t.Fatalf("expected APIHost %q, got %q", machineConfig.ApiHost, apiConfig.APIHost)
	}
	if apiConfig.NodeID != binding.NodeID {
		t.Fatalf("expected NodeID %d, got %d", binding.NodeID, apiConfig.NodeID)
	}
	if apiConfig.NodeType != binding.NodeType {
		t.Fatalf("expected NodeType %q, got %q", binding.NodeType, apiConfig.NodeType)
	}
	if apiConfig.Key != machineConfig.Token {
		t.Fatalf("expected Key %q, got %q", machineConfig.Token, apiConfig.Key)
	}
	if apiConfig.MachineID != machineConfig.MachineID {
		t.Fatalf("expected MachineID %d, got %d", machineConfig.MachineID, apiConfig.MachineID)
	}
	if apiConfig.Timeout != machineConfig.Timeout {
		t.Fatalf("expected Timeout %d, got %d", machineConfig.Timeout, apiConfig.Timeout)
	}
}

func TestBuildMachineControllerConfigReturnsFreshConfigPerNode(t *testing.T) {
	template := &controller.Config{
		UpdatePeriodic: 45,
		WebSocketConfig: &controller.WebSocketConfig{
			Enable:            false,
			Endpoint:          "wss://panel.example.com/ws",
			HeartbeatInterval: 99,
			ReconnectBackoff:  7,
			ResyncOnReconnect: false,
		},
		GlobalDeviceLimitConfig: &limiter.GlobalDeviceLimitConfig{
			Enable:       true,
			RedisNetwork: "tcp",
			RedisAddr:    "127.0.0.1:6379",
			Timeout:      5,
			Expiry:       60,
		},
	}

	config := validMachineModeConfig()
	config.MachineConfig.ControllerConfig = template
	plan, err := buildRuntimeConfigPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	cfg1, err := plan.machineNodeControllerConfig()
	if err != nil {
		t.Fatalf("build first controller config: %v", err)
	}
	cfg2, err := plan.machineNodeControllerConfig()
	if err != nil {
		t.Fatalf("build second controller config: %v", err)
	}

	if cfg1 == cfg2 {
		t.Fatal("expected fresh top-level controller configs")
	}
	if cfg1.UpdatePeriodic != template.UpdatePeriodic || cfg2.UpdatePeriodic != template.UpdatePeriodic {
		t.Fatalf("expected UpdatePeriodic %d, got %d and %d", template.UpdatePeriodic, cfg1.UpdatePeriodic, cfg2.UpdatePeriodic)
	}
	if cfg1.WebSocketConfig == nil || cfg2.WebSocketConfig == nil {
		t.Fatal("expected WebSocketConfig to be present")
	}
	if cfg1.WebSocketConfig == cfg2.WebSocketConfig {
		t.Fatal("expected independent WebSocketConfig pointers")
	}
	if cfg1.GlobalDeviceLimitConfig == nil || cfg2.GlobalDeviceLimitConfig == nil {
		t.Fatal("expected GlobalDeviceLimitConfig to be present")
	}
	if cfg1.GlobalDeviceLimitConfig == cfg2.GlobalDeviceLimitConfig {
		t.Fatal("expected independent GlobalDeviceLimitConfig pointers")
	}

	cfg1.WebSocketConfig.HeartbeatInterval = 1
	cfg1.GlobalDeviceLimitConfig.RedisAddr = "10.0.0.1:6379"

	if cfg2.WebSocketConfig.HeartbeatInterval != template.WebSocketConfig.HeartbeatInterval {
		t.Fatalf("mutating cfg1 WebSocketConfig changed cfg2: got %d", cfg2.WebSocketConfig.HeartbeatInterval)
	}
	if cfg2.GlobalDeviceLimitConfig.RedisAddr != template.GlobalDeviceLimitConfig.RedisAddr {
		t.Fatalf("mutating cfg1 GlobalDeviceLimitConfig changed cfg2: got %q", cfg2.GlobalDeviceLimitConfig.RedisAddr)
	}
}

func TestApplyPanelCertConfigPreservesContentMode(t *testing.T) {
	certConfig := &mylego.CertConfig{}
	panelCert := &api.XrayRCertConfig{
		CertMode:    "content",
		CertDomain:  "example.com",
		CertContent: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
		KeyContent:  "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
	}

	if err := applyPanelCertConfig(certConfig, panelCert); err != nil {
		t.Fatalf("applyPanelCertConfig returned error: %v", err)
	}
	if certConfig.CertMode != "content" {
		t.Fatalf("expected content mode to be preserved, got %q", certConfig.CertMode)
	}
	if certConfig.CertDomain != panelCert.CertDomain {
		t.Fatalf("expected cert domain %q, got %q", panelCert.CertDomain, certConfig.CertDomain)
	}
	if certConfig.CertContent != panelCert.CertContent || certConfig.KeyContent != panelCert.KeyContent {
		t.Fatalf("expected cert/key content to be preserved, got cert=%q key=%q", certConfig.CertContent, certConfig.KeyContent)
	}
	if certConfig.CertFile != "" || certConfig.KeyFile != "" {
		t.Fatalf("expected content mode not to write file paths in panel layer, got cert=%q key=%q", certConfig.CertFile, certConfig.KeyFile)
	}
}

func TestApplyPanelCertConfigSkipsEmptyLegacyCertConfig(t *testing.T) {
	certConfig := &mylego.CertConfig{}
	panelCert := &api.XrayRCertConfig{}

	if err := applyPanelCertConfig(certConfig, panelCert); err != nil {
		t.Fatalf("applyPanelCertConfig returned error: %v", err)
	}
	if certConfig.CertMode != "" || certConfig.Provider != "" || certConfig.Email != "" || len(certConfig.DNSEnv) != 0 {
		t.Fatalf("expected empty panel cert config to be ignored, got %#v", certConfig)
	}
}

func TestApplyPanelCertConfigUsesDNSOnlyWhenPanelProvidesDNSFields(t *testing.T) {
	certConfig := &mylego.CertConfig{}
	panelCert := &api.XrayRCertConfig{Provider: "cloudflare"}

	if err := applyPanelCertConfig(certConfig, panelCert); err != nil {
		t.Fatalf("applyPanelCertConfig returned error: %v", err)
	}
	if certConfig.CertMode != "dns" || certConfig.Provider != "cloudflare" {
		t.Fatalf("unexpected DNS cert config: %#v", certConfig)
	}
}

func TestMaterializeMachineRuntimeNodeBuildsClientConfigControllerConfigAndCert(t *testing.T) {
	panel := New(&Config{})
	machineConfig := &MachineConfig{
		Enable:    true,
		PanelType: "NewV2board",
		ApiHost:   "https://panel.example.com",
		MachineID: 42,
		Token:     "machine-token",
		Timeout:   31,
		ControllerConfig: &controller.Config{
			UpdatePeriodic: 77,
		},
	}
	binding := machine.NodeBinding{NodeID: 9, NodeType: "Vless"}
	client := &machineRuntimeNodeTestAPI{clientInfo: api.ClientInfo{APIHost: machineConfig.ApiHost, NodeID: binding.NodeID, NodeType: binding.NodeType}}
	var gotAPIConfig *api.Config
	var materializedAPI any
	var materializedControllerConfig *controller.Config
	var materializedLogger *log.Entry

	config := &Config{
		LogConfig:     &LogConfig{ShowErrorDetails: true},
		MachineConfig: machineConfig,
	}
	plan, err := buildRuntimeConfigPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	runtimeNode, err := plan.materializeMachineRuntimeNode(machineRuntimeNodePlan{
		binding: binding,
		newAPIClient: func(config *api.Config) runtimePanelClient {
			gotAPIConfig = config
			return client
		},
		materializeCertConfig: func(apiClient any, controllerConfig *controller.Config, logger *log.Entry) {
			materializedAPI = apiClient
			materializedControllerConfig = controllerConfig
			materializedLogger = logger
			controllerConfig.CertConfig = &mylego.CertConfig{CertMode: "file", CertFile: "/panel/cert.crt", KeyFile: "/panel/cert.key"}
		},
	}, panel.logger)
	if err != nil {
		t.Fatalf("materialize machine runtime node: %v", err)
	}
	if runtimeNode == nil {
		t.Fatal("expected runtime node")
	}
	if gotAPIConfig == nil {
		t.Fatal("expected API config to be passed to client factory")
	}
	if gotAPIConfig.APIHost != machineConfig.ApiHost || gotAPIConfig.Key != machineConfig.Token || gotAPIConfig.MachineID != machineConfig.MachineID || gotAPIConfig.Timeout != machineConfig.Timeout {
		t.Fatalf("unexpected API config: %#v", gotAPIConfig)
	}
	if gotAPIConfig.NodeID != binding.NodeID || gotAPIConfig.NodeType != binding.NodeType {
		t.Fatalf("expected binding fields in API config, got %#v", gotAPIConfig)
	}
	if runtimeNode.apiClient != client || materializedAPI != client {
		t.Fatalf("expected raw API client without shared WS wrapper, got runtime=%T materialized=%T", runtimeNode.apiClient, materializedAPI)
	}
	if runtimeNode.controllerConfig == nil || materializedControllerConfig != runtimeNode.controllerConfig {
		t.Fatal("expected materialized controller config to be used by runtime node")
	}
	if runtimeNode.controllerConfig.UpdatePeriodic != machineConfig.ControllerConfig.UpdatePeriodic {
		t.Fatalf("expected UpdatePeriodic override %d, got %d", machineConfig.ControllerConfig.UpdatePeriodic, runtimeNode.controllerConfig.UpdatePeriodic)
	}
	if !runtimeNode.controllerConfig.ShowErrorDetails {
		t.Fatal("expected ShowErrorDetails to be materialized")
	}
	if runtimeNode.controllerConfig == machineConfig.ControllerConfig {
		t.Fatal("expected controller config to be cloned")
	}
	if runtimeNode.controllerConfig.CertConfig == nil || runtimeNode.controllerConfig.CertConfig.CertFile != "/panel/cert.crt" || runtimeNode.controllerConfig.CertConfig.KeyFile != "/panel/cert.key" {
		t.Fatalf("expected cert materializer to run before service construction, got %#v", runtimeNode.controllerConfig.CertConfig)
	}
	if materializedLogger != panel.logger {
		t.Fatal("expected panel logger to be passed to cert materializer")
	}
}

func TestMaterializeMachineRuntimeNodeRejectsIncompleteSharedWSCapabilities(t *testing.T) {
	panel := New(&Config{})
	config := validMachineModeConfig()
	plan, err := buildRuntimeConfigPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	completeClient := &machineRuntimeNodeTestAPI{}
	incompleteClient := &struct {
		*machineRuntimeNodeTestAPI
		api.WSCapable
	}{
		machineRuntimeNodeTestAPI: completeClient,
	}

	runtimeNode, err := plan.materializeMachineRuntimeNode(machineRuntimeNodePlan{
		binding:  machine.NodeBinding{NodeID: 9, NodeType: "Vless"},
		sharedWS: machine.NewSharedWSRuntime(machine.SharedWSRuntimeConfig{}),
		newAPIClient: func(*api.Config) runtimePanelClient {
			return incompleteClient
		},
		materializeCertConfig: func(any, *controller.Config, *log.Entry) {},
	}, panel.logger)

	if err == nil {
		t.Fatalf("expected incomplete machine capability error, got runtime node %#v", runtimeNode)
	}
	if runtimeNode != nil {
		t.Fatalf("expected no runtime node on capability failure, got %#v", runtimeNode)
	}
	if !strings.Contains(err.Error(), "websocket config") {
		t.Fatalf("expected websocket config error, got %v", err)
	}
}

func TestMachineRuntimeNodePlanUseSharedWSRuntime(t *testing.T) {
	sharedWS := machine.NewSharedWSRuntime(machine.SharedWSRuntimeConfig{})
	tests := []struct {
		name     string
		plan     machineRuntimeNodePlan
		expected bool
	}{
		{
			name:     "shared ws nil",
			plan:     machineRuntimeNodePlan{binding: machine.NodeBinding{NodeType: "Vless"}},
			expected: false,
		},
		{
			name:     "shared ws supported vless",
			plan:     machineRuntimeNodePlan{sharedWS: sharedWS, binding: machine.NodeBinding{NodeType: "Vless"}},
			expected: true,
		},
		{
			name:     "shared ws supported vmess case insensitive",
			plan:     machineRuntimeNodePlan{sharedWS: sharedWS, binding: machine.NodeBinding{NodeType: "vmess"}},
			expected: true,
		},
		{
			name:     "hysteria2 falls back",
			plan:     machineRuntimeNodePlan{sharedWS: sharedWS, binding: machine.NodeBinding{NodeType: "Hysteria2"}},
			expected: false,
		},
		{
			name:     "tuic falls back",
			plan:     machineRuntimeNodePlan{sharedWS: sharedWS, binding: machine.NodeBinding{NodeType: "Tuic"}},
			expected: false,
		},
		{
			name:     "anytls falls back",
			plan:     machineRuntimeNodePlan{sharedWS: sharedWS, binding: machine.NodeBinding{NodeType: "AnyTLS"}},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.plan.useSharedWSRuntime(); got != test.expected {
				t.Fatalf("expected useSharedWSRuntime=%v, got %v", test.expected, got)
			}
		})
	}
}

type machineRuntimeNodeTestAPI struct {
	clientInfo api.ClientInfo
}

func (a *machineRuntimeNodeTestAPI) GetNodeInfo() (*api.NodeInfo, error) { return &api.NodeInfo{}, nil }
func (a *machineRuntimeNodeTestAPI) GetWSConfig() *api.WSConfig          { return &api.WSConfig{} }
func (a *machineRuntimeNodeTestAPI) DiscoverWSEndpoint() (string, error) {
	return "wss://panel.example.com/ws", nil
}
func (a *machineRuntimeNodeTestAPI) GetBaseConfig() *api.BaseConfig { return &api.BaseConfig{} }
func (a *machineRuntimeNodeTestAPI) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	return &api.XrayRCertConfig{}, nil
}
func (a *machineRuntimeNodeTestAPI) GetUserList() (*[]api.UserInfo, error) {
	users := []api.UserInfo{}
	return &users, nil
}
func (a *machineRuntimeNodeTestAPI) GetAliveList() (map[int][]string, error) { return nil, nil }
func (a *machineRuntimeNodeTestAPI) ReportNodeStatus(*api.NodeStatus) error  { return nil }
func (a *machineRuntimeNodeTestAPI) ReportNodeOnlineUsers(*[]api.OnlineUser) error {
	return nil
}
func (a *machineRuntimeNodeTestAPI) ReportUserTraffic(*[]api.UserTraffic) error { return nil }
func (a *machineRuntimeNodeTestAPI) Describe() api.ClientInfo                   { return a.clientInfo }
func (a *machineRuntimeNodeTestAPI) GetNodeRule() (*[]api.DetectRule, error) {
	rules := []api.DetectRule{}
	return &rules, nil
}
func (a *machineRuntimeNodeTestAPI) ReportIllegal(*[]api.DetectResult) error { return nil }
func (a *machineRuntimeNodeTestAPI) Debug()                                  {}

func validMachineModeConfig() *Config {
	return &Config{
		MachineConfig: &MachineConfig{
			Enable:    true,
			PanelType: "NewV2board",
			ApiHost:   "https://panel.example.com",
			MachineID: 7,
			Token:     "machine-token",
			Timeout:   30,
		},
	}
}
