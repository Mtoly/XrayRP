package controller_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	xrayvless "github.com/xtls/xray-core/proxy/vless/inbound"
	xrayreality "github.com/xtls/xray-core/transport/internet/reality"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	. "github.com/Mtoly/XrayRP/service/controller"
)

func TestInboundBuilderVlessDecryption(t *testing.T) {
	syntheticKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	decryption := "mlkem768x25519plus.native.0s." + syntheticKey
	tests := []struct {
		name     string
		value    string
		fallback bool
		wantKey  string
		wantFB   int
	}{
		{name: "unset", wantKey: "none"},
		{name: "whitespace", value: "  ", wantKey: "none"},
		{name: "encrypted", value: "  " + decryption + "  ", wantKey: syntheticKey},
		{name: "fallback unset", fallback: true, wantKey: "none", wantFB: 1},
		{name: "fallback none", value: "none", fallback: true, wantKey: "none", wantFB: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{EnableFallback: tt.fallback}
			if tt.fallback {
				config.FallBackConfigs = []*FallBackConfig{{Dest: "127.0.0.1:8080"}}
			}
			node := &api.NodeInfo{NodeType: "Vless", Port: 8443, TransportProtocol: "tcp", VlessDecryption: tt.value}
			built, err := InboundBuilder(config, node, "test")
			if err != nil {
				t.Fatal(err)
			}
			settings, err := built.ProxySettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			vless, ok := settings.(*xrayvless.Config)
			if !ok || vless.Decryption != tt.wantKey || len(vless.Fallbacks) != tt.wantFB {
				t.Fatal("VLESS decryption or fallback did not reach Xray-core")
			}
		})
	}
}

func TestInboundBuilderVlessDecryptionErrorsDoNotExposeValue(t *testing.T) {
	const invalid = "test-vless-decryption"
	node := &api.NodeInfo{NodeType: "Vless", Port: 8443, TransportProtocol: "tcp", VlessDecryption: invalid}
	for _, config := range []*Config{{}, {EnableFallback: true, FallBackConfigs: []*FallBackConfig{{Dest: "127.0.0.1:8080"}}}} {
		_, err := InboundBuilder(config, node, "test")
		if err == nil || strings.Contains(err.Error(), invalid) {
			t.Fatal("invalid VLESS decryption must fail without exposing its value")
		}
	}
}

func TestInboundBuilderUnencryptedVlessTLSXHTTP(t *testing.T) {
	node := &api.NodeInfo{NodeType: "Vless", Port: 8443, TransportProtocol: "xhttp", EnableTLS: true, Path: "/xhttp"}
	config := &Config{CertConfig: &mylego.CertConfig{
		CertMode: "content", CertContent: "test-certificate", KeyContent: "test-private-key",
	}}
	built, err := InboundBuilder(config, node, "test")
	if err != nil {
		t.Fatal(err)
	}
	proxySettings, err := built.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if proxySettings.(*xrayvless.Config).Decryption != "none" {
		t.Fatal("unencrypted VLESS no longer uses none")
	}
	receiverSettings, err := built.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	stream := receiverSettings.(*proxyman.ReceiverConfig).StreamSettings
	if stream.SecurityType != "xray.transport.internet.tls.Config" || len(stream.TransportSettings) == 0 {
		t.Fatal("VLESS TLS or XHTTP transport was lost")
	}
	if stream.TransportSettings[0].ProtocolName != "splithttp" {
		t.Fatal("VLESS XHTTP transport changed")
	}
}

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
