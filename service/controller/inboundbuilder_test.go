package controller_test

import (
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	xrayreality "github.com/xtls/xray-core/transport/internet/reality"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	. "github.com/Mtoly/XrayRP/service/controller"
)

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
