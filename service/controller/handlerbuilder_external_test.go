package controller_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service/controller"
)

var (
	_ func(*controller.Config, *api.NodeInfo) (*controller.NodeHandlerBuilder, error)                      = controller.NewNodeHandlerBuilder
	_ func(*controller.NodeHandlerBuilder, string) (*core.InboundHandlerConfig, error)                     = (*controller.NodeHandlerBuilder).BuildInbound
	_ func(*controller.NodeHandlerBuilder, string, []api.UserInfo) (*core.InboundHandlerConfig, error)     = (*controller.NodeHandlerBuilder).BuildInboundWithUsers
	_ func(*controller.NodeHandlerBuilder, string) (*core.OutboundHandlerConfig, error)                    = (*controller.NodeHandlerBuilder).BuildOutbound
	_ func(*controller.Config, *api.NodeInfo, string) (*core.InboundHandlerConfig, error)                  = controller.InboundBuilder
	_ func(*controller.Config, *api.NodeInfo, string, *[]api.UserInfo) (*core.InboundHandlerConfig, error) = controller.InboundBuilderWithUsers
	_ func(*controller.Config, *api.NodeInfo, string) (*core.OutboundHandlerConfig, error)                 = controller.OutboundBuilder
)

func TestNodeHandlerBuilderMatchesLegacyAdapters(t *testing.T) {
	config := &controller.Config{
		SendIP:          "0.0.0.0",
		EnableDNS:       true,
		EnableFallback:  true,
		FallBackConfigs: []*controller.FallBackConfig{{Dest: "127.0.0.1:8080"}},
	}
	node := &api.NodeInfo{
		NodeType:          "Vless",
		Port:              8443,
		EnableVless:       true,
		TransportProtocol: "tcp",
	}

	builder, err := controller.NewNodeHandlerBuilder(config, node)
	if err != nil {
		t.Fatalf("NewNodeHandlerBuilder() error = %v", err)
	}
	gotInbound, err := builder.BuildInbound("compat")
	if err != nil {
		t.Fatalf("BuildInbound() error = %v", err)
	}
	wantInbound, err := controller.InboundBuilder(config, node, "compat")
	if err != nil {
		t.Fatalf("InboundBuilder() error = %v", err)
	}
	if !proto.Equal(gotInbound, wantInbound) {
		t.Fatal("BuildInbound() differs from InboundBuilder()")
	}

	gotOutbound, err := builder.BuildOutbound("compat")
	if err != nil {
		t.Fatalf("BuildOutbound() error = %v", err)
	}
	wantOutbound, err := controller.OutboundBuilder(config, node, "compat")
	if err != nil {
		t.Fatalf("OutboundBuilder() error = %v", err)
	}
	if !proto.Equal(gotOutbound, wantOutbound) {
		t.Fatal("BuildOutbound() differs from OutboundBuilder()")
	}

	users := []api.UserInfo{{UID: 1, UUID: "first-user"}}
	proxyNode := &api.NodeInfo{NodeType: "Socks", Port: 1080}
	proxyBuilder, err := controller.NewNodeHandlerBuilder(config, proxyNode)
	if err != nil {
		t.Fatalf("NewNodeHandlerBuilder(Socks) error = %v", err)
	}
	gotWithUsers, err := proxyBuilder.BuildInboundWithUsers("users", users)
	if err != nil {
		t.Fatalf("BuildInboundWithUsers() error = %v", err)
	}
	wantWithUsers, err := controller.InboundBuilderWithUsers(config, proxyNode, "users", &users)
	if err != nil {
		t.Fatalf("InboundBuilderWithUsers() error = %v", err)
	}
	if !proto.Equal(gotWithUsers, wantWithUsers) {
		t.Fatalf("BuildInboundWithUsers() differs from InboundBuilderWithUsers()\n got: %v\nwant: %v", gotWithUsers, wantWithUsers)
	}
}

func TestNodeHandlerBuilderOwnsInputsAndKeepsCredentialsOpaque(t *testing.T) {
	const (
		realityPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		certificateKey    = "builder-certificate-private-key"
		dnsSecret         = "builder-dns-secret"
	)
	config := &controller.Config{
		SendIP:          "192.0.2.10",
		EnableDNS:       true,
		EnableFallback:  true,
		FallBackConfigs: []*controller.FallBackConfig{{Dest: "127.0.0.1:8080"}},
		EnableREALITY:   true,
		REALITYConfigs: &controller.REALITYConfig{
			Dest:        "example.com:443",
			ServerNames: []string{"example.com"},
			PrivateKey:  realityPrivateKey,
			ShortIds:    []string{"abcd"},
		},
		CertConfig: &mylego.CertConfig{
			CertMode:   "content",
			KeyContent: certificateKey,
			DNSEnv:     map[string]string{"DNS_SECRET": dnsSecret},
		},
	}
	node := &api.NodeInfo{
		NodeType:          "Vless",
		Port:              443,
		EnableVless:       true,
		EnableREALITY:     true,
		TransportProtocol: "tcp",
		REALITYConfig:     &api.REALITYConfig{},
	}

	gotBuilder, err := controller.NewNodeHandlerBuilder(config, node)
	if err != nil {
		t.Fatalf("NewNodeHandlerBuilder() error = %v", err)
	}
	wantBuilder, err := controller.NewNodeHandlerBuilder(config, node)
	if err != nil {
		t.Fatalf("NewNodeHandlerBuilder(want) error = %v", err)
	}

	config.SendIP = "203.0.113.10"
	config.FallBackConfigs[0].Dest = "127.0.0.1:9090"
	config.REALITYConfigs.Dest = "mutated.example:443"
	config.REALITYConfigs.ServerNames[0] = "mutated.example"
	config.REALITYConfigs.PrivateKey = "mutated-reality-key"
	config.REALITYConfigs.ShortIds[0] = "ffff"
	config.CertConfig.KeyContent = "mutated-certificate-key"
	config.CertConfig.DNSEnv["DNS_SECRET"] = "mutated-dns-secret"
	node.NodeType = "Trojan"
	node.Port = 444
	node.TransportProtocol = "ws"
	node.REALITYConfig.Dest = "mutated-panel.example:443"

	gotInbound, err := gotBuilder.BuildInbound("owned")
	if err != nil {
		t.Fatalf("BuildInbound() error = %v", err)
	}
	wantInbound, err := wantBuilder.BuildInbound("owned")
	if err != nil {
		t.Fatalf("BuildInbound(want) error = %v", err)
	}
	if !proto.Equal(gotInbound, wantInbound) {
		t.Fatal("mutating constructor inputs changed BuildInbound()")
	}
	gotOutbound, err := gotBuilder.BuildOutbound("owned")
	if err != nil {
		t.Fatalf("BuildOutbound() error = %v", err)
	}
	wantOutbound, err := wantBuilder.BuildOutbound("owned")
	if err != nil {
		t.Fatalf("BuildOutbound(want) error = %v", err)
	}
	if !proto.Equal(gotOutbound, wantOutbound) {
		t.Fatal("mutating constructor inputs changed BuildOutbound()")
	}

	rendered := []string{
		fmt.Sprintf("%v", gotBuilder),
		fmt.Sprintf("%+v", gotBuilder),
		fmt.Sprintf("%#v", gotBuilder),
	}
	encoded, err := json.Marshal(gotBuilder)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	rendered = append(rendered, string(encoded))
	for _, output := range rendered {
		for _, secret := range []string{realityPrivateKey, certificateKey, dnsSecret} {
			if strings.Contains(output, secret) {
				t.Fatalf("formatted builder exposed credential %q: %s", secret, output)
			}
		}
	}
}

func TestNodeHandlerBuilderRejectsInvalidOrUninitializedUse(t *testing.T) {
	if _, err := controller.NewNodeHandlerBuilder(nil, &api.NodeInfo{}); err == nil {
		t.Fatal("NewNodeHandlerBuilder(nil config) succeeded")
	}
	if _, err := controller.NewNodeHandlerBuilder(&controller.Config{}, nil); err == nil {
		t.Fatal("NewNodeHandlerBuilder(nil node) succeeded")
	}

	var nilBuilder *controller.NodeHandlerBuilder
	if _, err := nilBuilder.BuildInbound("nil"); err == nil {
		t.Fatal("nil BuildInbound() succeeded")
	}
	if _, err := nilBuilder.BuildInboundWithUsers("nil", nil); err == nil {
		t.Fatal("nil BuildInboundWithUsers() succeeded")
	}
	if _, err := nilBuilder.BuildOutbound("nil"); err == nil {
		t.Fatal("nil BuildOutbound() succeeded")
	}

	zeroBuilder := new(controller.NodeHandlerBuilder)
	if _, err := zeroBuilder.BuildInbound("zero"); err == nil {
		t.Fatal("zero-value BuildInbound() succeeded")
	}
}
