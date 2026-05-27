package panel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestConfigExampleParsesRuntimeConfigContract(t *testing.T) {
	exampleConfig, err := os.Open(filepath.Join("..", "release", "config", "config.yml.example"))
	if err != nil {
		t.Fatalf("open config example: %v", err)
	}
	defer exampleConfig.Close()

	config := viper.New()
	config.SetConfigType("yml")
	if err := config.ReadConfig(exampleConfig); err != nil {
		t.Fatalf("read config example: %v", err)
	}

	panelConfig := &Config{}
	if err := config.Unmarshal(panelConfig); err != nil {
		t.Fatalf("unmarshal config example: %v", err)
	}

	requireConfigKey(t, config, "Nodes.0.ApiConfig.SpeedLimit")
	requireConfigKey(t, config, "Nodes.0.ApiConfig.DeviceLimit")
	requireConfigKey(t, config, "Nodes.0.ControllerConfig.WebSocketConfig.Enable")
	requireConfigKey(t, config, "Nodes.0.ControllerConfig.GlobalDeviceLimitConfig.Enable")

	if panelConfig.LogConfig == nil {
		t.Fatal("expected Log config to parse")
	}
	if panelConfig.LogConfig.Level != "warning" {
		t.Fatalf("expected log level warning, got %q", panelConfig.LogConfig.Level)
	}
	if panelConfig.ConnectionConfig == nil {
		t.Fatal("expected ConnectionConfig to parse")
	}
	if panelConfig.ConnectionConfig.Handshake != 4 {
		t.Fatalf("expected handshake 4, got %d", panelConfig.ConnectionConfig.Handshake)
	}
	if len(panelConfig.NodesConfig) == 0 {
		t.Fatal("expected config example to contain at least one node")
	}

	node := panelConfig.NodesConfig[0]
	if node.PanelType != "SSPanel" {
		t.Fatalf("expected first node panel type SSPanel, got %q", node.PanelType)
	}
	if node.ApiConfig == nil {
		t.Fatal("expected first node ApiConfig to parse")
	}
	if node.ApiConfig.APIHost != "http://127.0.0.1:667" {
		t.Fatalf("expected api host http://127.0.0.1:667, got %q", node.ApiConfig.APIHost)
	}
	if node.ApiConfig.NodeID != 41 {
		t.Fatalf("expected node ID 41, got %d", node.ApiConfig.NodeID)
	}
	if node.ApiConfig.SpeedLimit != 0 {
		t.Fatalf("expected api speed limit 0, got %f", node.ApiConfig.SpeedLimit)
	}
	if node.ApiConfig.DeviceLimit != 0 {
		t.Fatalf("expected api device limit 0, got %d", node.ApiConfig.DeviceLimit)
	}

	controllerConfig := node.ControllerConfig
	if controllerConfig == nil {
		t.Fatal("expected first node ControllerConfig to parse")
	}
	if controllerConfig.UpdatePeriodic != 60 {
		t.Fatalf("expected update periodic 60, got %d", controllerConfig.UpdatePeriodic)
	}
	if controllerConfig.WebSocketConfig == nil {
		t.Fatal("expected WebSocketConfig to parse")
	}
	if controllerConfig.WebSocketConfig.Enable {
		t.Fatal("expected websocket config to default to disabled")
	}
	if controllerConfig.WebSocketConfig.HeartbeatInterval != 30 {
		t.Fatalf("expected websocket heartbeat interval 30, got %d", controllerConfig.WebSocketConfig.HeartbeatInterval)
	}
	if controllerConfig.WebSocketConfig.ReconnectBackoff != 5 {
		t.Fatalf("expected websocket reconnect backoff 5, got %d", controllerConfig.WebSocketConfig.ReconnectBackoff)
	}
	if !controllerConfig.WebSocketConfig.ResyncOnReconnect {
		t.Fatal("expected websocket resync on reconnect to parse as true")
	}

	deviceLimitConfig := controllerConfig.GlobalDeviceLimitConfig
	if deviceLimitConfig == nil {
		t.Fatal("expected GlobalDeviceLimitConfig to parse")
	}
	if deviceLimitConfig.Enable {
		t.Fatal("expected global device limit to default to disabled")
	}
	if deviceLimitConfig.RedisNetwork != "tcp" {
		t.Fatalf("expected redis network tcp, got %q", deviceLimitConfig.RedisNetwork)
	}
	if deviceLimitConfig.RedisAddr != "127.0.0.1:6379" {
		t.Fatalf("expected redis addr 127.0.0.1:6379, got %q", deviceLimitConfig.RedisAddr)
	}
	if deviceLimitConfig.Timeout != 5 {
		t.Fatalf("expected redis timeout 5, got %d", deviceLimitConfig.Timeout)
	}
	if deviceLimitConfig.Expiry != 60 {
		t.Fatalf("expected redis expiry 60, got %d", deviceLimitConfig.Expiry)
	}
}

func requireConfigKey(t *testing.T, config *viper.Viper, key string) {
	t.Helper()
	if !config.IsSet(key) {
		t.Fatalf("expected config example to contain %s", key)
	}
}
