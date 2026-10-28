package panel

import (
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/service/controller"
)

func TestGlobalDeviceConfigReachesStaticAndMachineNodes(t *testing.T) {
	prefix := 0
	template := &controller.Config{GlobalDeviceLimitConfig: &limiter.GlobalDeviceLimitConfig{
		Enable: true, Mode: "strict", FailMode: "closed", RedisAddr: "127.0.0.1:6379", IPv6Prefix: &prefix,
	}}
	static, err := buildRuntimeConfigPlan(&Config{NodesConfig: []*NodesConfig{{
		PanelType: "NewV2board", ApiConfig: &api.Config{APIHost: "https://panel.example", NodeType: "Vless"}, ControllerConfig: template,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := buildRuntimeConfigPlan(&Config{MachineConfig: &MachineConfig{
		Enable: true, PanelType: "NewV2board", ApiHost: "https://panel.example", MachineID: 1, Token: "test-token", ControllerConfig: template,
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []*controller.Config{static.staticNodes[0].materializeControllerConfig(), machine.machineNodeControllerConfig()} {
		global := config.GlobalDeviceLimitConfig
		if config.GlobalPanelType != "NewV2board" || global.PanelType != "NewV2board" || global.APIHost != "https://panel.example" || global.Mode != "strict" || global.FailMode != "closed" || global.IPv6Prefix == nil || *global.IPv6Prefix != 0 {
			t.Fatalf("global configuration was not propagated: %#v", global)
		}
		*global.IPv6Prefix = 48
	}
	if prefix != 0 || template.GlobalPanelType != "" {
		t.Fatal("runtime materialization mutated caller configuration")
	}
}

func TestStrictGlobalDeviceConfigRequiresForwardedAcknowledgement(t *testing.T) {
	config := &controller.Config{
		TrustedXForwardedFor:    []string{"CF-Connecting-IP"},
		GlobalDeviceLimitConfig: &limiter.GlobalDeviceLimitConfig{Enable: true, Mode: "strict", RedisAddr: "127.0.0.1:6379"},
	}
	if _, err := buildRuntimeControllerConfig(config, false); err == nil {
		t.Fatal("strict mode accepted header-derived source without acknowledgement")
	}
	config.GlobalDeviceLimitConfig.StrictClientIPSource = "forwarded"
	if _, err := buildRuntimeControllerConfig(config, false); err != nil {
		t.Fatal(err)
	}
}
