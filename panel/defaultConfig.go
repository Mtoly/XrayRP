package panel

import "github.com/Mtoly/XrayRP/service/controller"

func getDefaultLogConfig() *LogConfig {
	return &LogConfig{
		Level:      "none",
		AccessPath: "",
		ErrorPath:  "",
	}
}

func getDefaultConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		Handshake:    4,
		ConnIdle:     30,
		UplinkOnly:   2,
		DownlinkOnly: 4,
		BufferSize:   4, // 4KB per connection; 64KB was too high for 10k-50k users (would consume 3.2GB+ RAM)
	}
}

func getDefaultControllerConfig() *controller.Config {
	return &controller.Config{
		ListenIP:       "0.0.0.0",
		SendIP:         "0.0.0.0",
		UpdatePeriodic: 60,
		DNSType:        "AsIs",
		WebSocketConfig: &controller.WebSocketConfig{
			Enable:            false,
			HeartbeatInterval: 30,
			ReconnectBackoff:  5,
			ResyncOnReconnect: true,
		},
	}
}
