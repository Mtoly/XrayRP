package panel

import (
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/service/controller"
	"github.com/Mtoly/XrayRP/service/machine"
)

func TestValidateMachineModeRejectsStaticNodes(t *testing.T) {
	config := validMachineModeConfig()
	config.NodesConfig = []*NodesConfig{{PanelType: "SSPanel"}}

	err := validateMachineModeConfig(config)
	if err == nil {
		t.Fatal("expected static Nodes conflict error")
	}
	if !strings.Contains(err.Error(), "static Nodes") {
		t.Fatalf("expected static Nodes error, got %v", err)
	}
}

func TestValidateMachineModeRejectsWebSocketEnabled(t *testing.T) {
	config := validMachineModeConfig()
	config.MachineConfig.ControllerConfig = &controller.Config{
		WebSocketConfig: &controller.WebSocketConfig{Enable: true},
	}

	err := validateMachineModeConfig(config)
	if err == nil {
		t.Fatal("expected WebSocket unsupported error")
	}
	if !strings.Contains(err.Error(), "WebSocket") {
		t.Fatalf("expected WebSocket error, got %v", err)
	}
}

func TestBuildMachineSupervisorRejectsStaticNodes(t *testing.T) {
	config := validMachineModeConfig()
	config.NodesConfig = []*NodesConfig{{PanelType: "SSPanel"}}
	panel := New(config)

	service, err := panel.buildMachineSupervisor(nil)
	if err == nil {
		t.Fatal("expected static Nodes conflict error")
	}
	if service != nil {
		t.Fatalf("expected no supervisor service, got %T", service)
	}
	if !strings.Contains(err.Error(), "static Nodes") {
		t.Fatalf("expected static Nodes error, got %v", err)
	}
}

func TestBuildMachineSupervisorRejectsWebSocketEnabled(t *testing.T) {
	config := validMachineModeConfig()
	config.MachineConfig.ControllerConfig = &controller.Config{
		WebSocketConfig: &controller.WebSocketConfig{Enable: true},
	}
	panel := New(config)

	service, err := panel.buildMachineSupervisor(nil)
	if err == nil {
		t.Fatal("expected WebSocket unsupported error")
	}
	if service != nil {
		t.Fatalf("expected no supervisor service, got %T", service)
	}
	if err.Error() != machineModeWebSocketUnsupportedMessage {
		t.Fatalf("expected WebSocket error %q, got %v", machineModeWebSocketUnsupportedMessage, err)
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

			err := validateMachineModeConfig(config)
			if err == nil {
				t.Fatalf("expected error containing %q", test.want)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

func TestBuildMachineNodeAPIConfigIncludesMachineID(t *testing.T) {
	machineConfig := &MachineConfig{
		ApiHost:   " https://panel.example.com ",
		MachineID: 42,
		Token:     " machine-token ",
		Timeout:   31,
	}
	binding := machine.NodeBinding{
		NodeID:   9,
		NodeType: "VLESS",
	}

	apiConfig := buildMachineNodeAPIConfig(machineConfig, binding)
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

	cfg1, err := buildMachineNodeControllerConfig(template)
	if err != nil {
		t.Fatalf("build first controller config: %v", err)
	}
	cfg2, err := buildMachineNodeControllerConfig(template)
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
