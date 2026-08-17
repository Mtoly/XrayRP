package controller

import (
	"testing"

	"github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/common/mylego"
)

func TestConfigClonePreservesNilAndEmptyCollections(t *testing.T) {
	var nilConfig *Config
	if nilConfig.Clone() != nil {
		t.Fatal("expected cloning a nil config to return nil")
	}

	original := &Config{
		CertConfig:      &mylego.CertConfig{DNSEnv: map[string]string{}},
		FallBackConfigs: make([]*FallBackConfig, 0, 1),
		REALITYConfigs: &REALITYConfig{
			ServerNames: make([]string, 0, 1),
			ShortIds:    make([]string, 0, 1),
		},
	}
	cloned := original.Clone()

	if cloned == nil || cloned == original {
		t.Fatal("expected a distinct config clone")
	}
	if cloned.CertConfig == nil || cloned.CertConfig.DNSEnv == nil {
		t.Fatal("expected empty certificate DNS environment to remain non-nil")
	}
	if cloned.FallBackConfigs == nil {
		t.Fatal("expected empty fallback collection to remain non-nil")
	}
	if cloned.REALITYConfigs == nil || cloned.REALITYConfigs.ServerNames == nil || cloned.REALITYConfigs.ShortIds == nil {
		t.Fatal("expected empty REALITY collections to remain non-nil")
	}
}

func TestConfigCloneDetachesNestedValues(t *testing.T) {
	original := &Config{
		ListenIP: "0.0.0.0",
		CertConfig: &mylego.CertConfig{
			CertMode:    "dns",
			CertDomain:  "node.example.com",
			CertFile:    "/tmp/node.crt",
			KeyFile:     "/tmp/node.key",
			CertContent: "certificate",
			KeyContent:  "private-key",
			Provider:    "dns-provider",
			Email:       "ops@example.com",
			DNSEnv:      map[string]string{"DNS_TOKEN": "source-token"},
		},
		AutoSpeedLimitConfig: &AutoSpeedLimitConfig{
			Limit:         100,
			WarnTimes:     2,
			LimitSpeed:    10,
			LimitDuration: 30,
		},
		GlobalDeviceLimitConfig: &limiter.GlobalDeviceLimitConfig{
			Enable:        true,
			RedisNetwork:  "tcp",
			RedisAddr:     "127.0.0.1:6379",
			RedisUsername: "user",
			RedisPassword: "password",
			RedisDB:       3,
			Timeout:       5,
			Expiry:        60,
		},
		FallBackConfigs: []*FallBackConfig{
			nil,
			{SNI: "fallback.example.com", Alpn: "h2", Path: "/fallback", Dest: "127.0.0.1:8080", ProxyProtocolVer: 2},
		},
		REALITYConfigs: &REALITYConfig{
			Show:             true,
			Dest:             "dest.example.com:443",
			ProxyProtocolVer: 2,
			ServerNames:      []string{"node.example.com"},
			PrivateKey:       "private-key",
			MinClientVer:     "1.0.0",
			MaxClientVer:     "2.0.0",
			MaxTimeDiff:      60,
			ShortIds:         []string{"short-id"},
		},
		WebSocketConfig: &WebSocketConfig{
			Enable:            true,
			Endpoint:          "wss://panel.example/ws",
			HeartbeatInterval: 30,
			ReconnectBackoff:  5,
			ResyncOnReconnect: true,
		},
	}

	cloned := original.Clone()
	if cloned == nil || cloned == original {
		t.Fatal("expected a distinct config clone")
	}
	if cloned.CertConfig == original.CertConfig || cloned.CertConfig.DNSEnv == nil {
		t.Fatal("expected certificate config and DNS environment to be detached")
	}
	if cloned.AutoSpeedLimitConfig == original.AutoSpeedLimitConfig {
		t.Fatal("expected auto speed limit config to be detached")
	}
	if cloned.GlobalDeviceLimitConfig == original.GlobalDeviceLimitConfig {
		t.Fatal("expected global device limit config to be detached")
	}
	if cloned.FallBackConfigs == nil || cloned.FallBackConfigs[1] == original.FallBackConfigs[1] {
		t.Fatal("expected fallback configs to be detached")
	}
	if cloned.REALITYConfigs == original.REALITYConfigs || cloned.WebSocketConfig == original.WebSocketConfig {
		t.Fatal("expected nested runtime configs to be detached")
	}

	cloned.CertConfig.DNSEnv["DNS_TOKEN"] = "clone-token"
	cloned.CertConfig.CertFile = "/tmp/clone.crt"
	cloned.AutoSpeedLimitConfig.Limit = 200
	cloned.GlobalDeviceLimitConfig.RedisAddr = "127.0.0.1:6380"
	cloned.FallBackConfigs[1].SNI = "clone.example.com"
	cloned.REALITYConfigs.ServerNames[0] = "clone.example.com"
	cloned.REALITYConfigs.ShortIds[0] = "clone-short-id"
	cloned.WebSocketConfig.Endpoint = "wss://clone.example/ws"

	if original.CertConfig.DNSEnv["DNS_TOKEN"] != "source-token" || original.CertConfig.CertFile != "/tmp/node.crt" {
		t.Fatalf("certificate config was aliased: %#v", original.CertConfig)
	}
	if original.AutoSpeedLimitConfig.Limit != 100 {
		t.Fatalf("auto speed limit config was aliased: %#v", original.AutoSpeedLimitConfig)
	}
	if original.GlobalDeviceLimitConfig.RedisAddr != "127.0.0.1:6379" {
		t.Fatalf("global device limit config was aliased: %#v", original.GlobalDeviceLimitConfig)
	}
	if original.FallBackConfigs[1].SNI != "fallback.example.com" {
		t.Fatalf("fallback config was aliased: %#v", original.FallBackConfigs)
	}
	if original.REALITYConfigs.ServerNames[0] != "node.example.com" || original.REALITYConfigs.ShortIds[0] != "short-id" {
		t.Fatalf("REALITY config was aliased: %#v", original.REALITYConfigs)
	}
	if original.WebSocketConfig.Endpoint != "wss://panel.example/ws" {
		t.Fatalf("WebSocket config was aliased: %#v", original.WebSocketConfig)
	}
}
