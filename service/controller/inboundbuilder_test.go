package controller_test

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	xrayreality "github.com/xtls/xray-core/transport/internet/reality"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	. "github.com/Mtoly/XrayRP/service/controller"
)

func TestInboundBuilderRejectsUplinkChunkSizeRuntimeOverflow(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "V2ray",
		Port:              8443,
		TransportProtocol: "xhttp",
		UplinkChunkSize:   1 << 31,
	}

	_, err := InboundBuilder(&Config{}, nodeInfo, "test_tag")
	if err == nil || !strings.Contains(err.Error(), "uplinkChunkSize") {
		t.Fatalf("error = %v, want uplinkChunkSize range error", err)
	}
}

func TestBuildV2ray(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "V2ray",
		NodeID:            1,
		Port:              1145,
		SpeedLimit:        0,
		AlterID:           2,
		TransportProtocol: "ws",
		Host:              "test.test.tk",
		Path:              "v2ray",
		EnableTLS:         false,
	}
	certConfig := &mylego.CertConfig{
		CertMode:   "http",
		CertDomain: "test.test.tk",
		Provider:   "alidns",
		Email:      "test@gmail.com",
	}
	config := &Config{
		CertConfig: certConfig,
	}
	_, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Error(err)
	}
}

func TestBuildTrojan(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "Trojan",
		NodeID:            1,
		Port:              1145,
		SpeedLimit:        0,
		AlterID:           2,
		TransportProtocol: "tcp",
		Host:              "trojan.test.tk",
		Path:              "v2ray",
		EnableTLS:         false,
	}
	DNSEnv := make(map[string]string)
	DNSEnv["ALICLOUD_ACCESS_KEY"] = "aaa"
	DNSEnv["ALICLOUD_SECRET_KEY"] = "bbb"
	certConfig := &mylego.CertConfig{
		CertMode:   "dns",
		CertDomain: "trojan.test.tk",
		Provider:   "alidns",
		Email:      "test@gmail.com",
		DNSEnv:     DNSEnv,
	}
	config := &Config{
		CertConfig: certConfig,
	}
	_, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Error(err)
	}
}

func TestBuildSS(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "Shadowsocks",
		NodeID:            1,
		Port:              1145,
		SpeedLimit:        0,
		AlterID:           2,
		TransportProtocol: "tcp",
		CypherMethod:      "aes-128-gcm",
		Host:              "test.test.tk",
		Path:              "v2ray",
		EnableTLS:         false,
	}
	DNSEnv := make(map[string]string)
	DNSEnv["ALICLOUD_ACCESS_KEY"] = "aaa"
	DNSEnv["ALICLOUD_SECRET_KEY"] = "bbb"
	certConfig := &mylego.CertConfig{
		CertMode:   "dns",
		CertDomain: "trojan.test.tk",
		Provider:   "alidns",
		Email:      "test@me.com",
		DNSEnv:     DNSEnv,
	}
	config := &Config{
		CertConfig: certConfig,
	}
	_, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Error(err)
	}
}

func TestInboundBuilderFallsBackToLocalREALITYConfigWhenPanelOmitsRealityOpts(t *testing.T) {
	const privateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	nodeInfo := &api.NodeInfo{
		NodeType:          "V2ray",
		NodeID:            1,
		Port:              1145,
		TransportProtocol: "tcp",
		EnableVless:       true,
		EnableREALITY:     true,
		REALITYConfig:     &api.REALITYConfig{},
	}
	config := &Config{
		EnableREALITY:             true,
		DisableLocalREALITYConfig: false,
		REALITYConfigs: &REALITYConfig{
			Dest:             "example.com:443",
			ProxyProtocolVer: 1,
			ServerNames:      []string{"example.com"},
			PrivateKey:       privateKey,
			ShortIds:         []string{"abcd"},
		},
	}

	inbound, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := inbound.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	streamSettings := receiver.(*proxyman.ReceiverConfig).StreamSettings
	if streamSettings.SecurityType != "xray.transport.internet.reality.Config" {
		t.Fatalf("expected REALITY security, got %q", streamSettings.SecurityType)
	}
	securitySettings, err := streamSettings.SecuritySettings[0].GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	realityConfig := securitySettings.(*xrayreality.Config)
	if realityConfig.Dest != "example.com:443" {
		t.Fatalf("expected local REALITY dest, got %q", realityConfig.Dest)
	}
	if realityConfig.Xver != 1 {
		t.Fatalf("expected local REALITY xver 1, got %d", realityConfig.Xver)
	}
}

func TestInboundBuilderPrefersCompletePanelREALITYConfig(t *testing.T) {
	const privateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	nodeInfo := &api.NodeInfo{
		NodeType:          "V2ray",
		Port:              1145,
		TransportProtocol: "tcp",
		EnableVless:       true,
		EnableREALITY:     true,
		REALITYConfig: &api.REALITYConfig{
			Dest:             "panel.example:443",
			ProxyProtocolVer: 2,
			ServerNames:      []string{"panel.example"},
			PrivateKey:       privateKey,
			ShortIds:         []string{"beef"},
		},
	}
	config := &Config{
		EnableREALITY: true,
		REALITYConfigs: &REALITYConfig{
			Dest:             "local.example:443",
			ProxyProtocolVer: 1,
			ServerNames:      []string{"local.example"},
			PrivateKey:       privateKey,
			ShortIds:         []string{"abcd"},
		},
	}

	inbound, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := inbound.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	streamSettings := receiver.(*proxyman.ReceiverConfig).StreamSettings
	securitySettings, err := streamSettings.SecuritySettings[0].GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	realityConfig := securitySettings.(*xrayreality.Config)
	if realityConfig.Dest != "panel.example:443" || realityConfig.Xver != 2 {
		t.Fatalf("expected panel REALITY settings, got dest %q xver %d", realityConfig.Dest, realityConfig.Xver)
	}
}

func TestInboundBuilderTrustedXForwardedFor(t *testing.T) {
	transports := []struct {
		name     string
		protocol string
	}{
		{"xhttp", "xhttp"}, {"websocket", "ws"}, {"httpupgrade", "httpupgrade"}, {"grpc", "grpc"},
	}
	for _, tt := range transports {
		t.Run(tt.name, func(t *testing.T) {
			node := &api.NodeInfo{NodeType: "V2ray", Port: 8443, TransportProtocol: tt.protocol, EnableVless: true}
			inbound, err := InboundBuilder(&Config{TrustedXForwardedFor: []string{"CF-Connecting-IP"}}, node, "test")
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := inbound.ReceiverSettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			settings := receiver.(*proxyman.ReceiverConfig).StreamSettings
			if settings.SocketSettings == nil || len(settings.SocketSettings.TrustedXForwardedFor) != 1 || settings.SocketSettings.TrustedXForwardedFor[0] != "CF-Connecting-IP" {
				t.Fatalf("socket settings = %#v", settings.SocketSettings)
			}
		})
	}
}

func TestInboundBuilderTrustedXForwardedForPreservesProxyProtocol(t *testing.T) {
	node := &api.NodeInfo{NodeType: "V2ray", Port: 8443, TransportProtocol: "xhttp", EnableVless: true, AcceptProxyProtocol: true}
	inbound, err := InboundBuilder(&Config{EnableProxyProtocol: true, TrustedXForwardedFor: []string{"CF-Connecting-IP"}}, node, "test")
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := inbound.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	settings := receiver.(*proxyman.ReceiverConfig).StreamSettings
	if settings.SocketSettings == nil || !settings.SocketSettings.AcceptProxyProtocol || len(settings.SocketSettings.TrustedXForwardedFor) != 1 {
		t.Fatalf("socket settings = %#v", settings.SocketSettings)
	}
}

func TestInboundBuilderTrustedXForwardedForDefault(t *testing.T) {
	node := &api.NodeInfo{NodeType: "V2ray", Port: 8443, TransportProtocol: "xhttp", EnableVless: true}
	inbound, err := InboundBuilder(&Config{}, node, "test")
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := inbound.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	settings := receiver.(*proxyman.ReceiverConfig).StreamSettings
	if settings.SocketSettings != nil {
		t.Fatalf("socket settings = %#v, want nil", settings.SocketSettings)
	}
}
