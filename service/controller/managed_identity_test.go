package controller

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/internal/managednode"
)

func TestManagedNodeIdentityBuildsCompatibleTags(t *testing.T) {
	controller := &Controller{config: &Config{ListenIP: "127.0.0.1"}}
	tests := []struct {
		nodeType string
		wantTag  string
		managed  bool
	}{
		{nodeType: "vless", wantTag: "VLESS_127.0.0.1_443_7", managed: true},
		{nodeType: "trojan", wantTag: "Trojan_127.0.0.1_443_7", managed: true},
		{nodeType: "vmess", wantTag: "Vmess_127.0.0.1_443_7", managed: true},
		{nodeType: "v2ray", wantTag: "Vmess_127.0.0.1_443_7", managed: true},
		{nodeType: "shadowsocks", wantTag: "Shadowsocks_127.0.0.1_443_7", managed: true},
		{nodeType: "socks", wantTag: "Socks_127.0.0.1_443_7", managed: true},
		{nodeType: "http", wantTag: "HTTP_127.0.0.1_443_7", managed: true},
		{nodeType: "Custom", wantTag: "Custom_127.0.0.1_443_7", managed: false},
	}

	for _, test := range tests {
		t.Run(test.nodeType, func(t *testing.T) {
			tag := controller.buildNodeTagFrom(&api.NodeInfo{
				NodeType: test.nodeType,
				Port:     443,
				NodeID:   7,
			})
			if tag != test.wantTag {
				t.Fatalf("buildNodeTagFrom() = %q, want %q", tag, test.wantTag)
			}
			if got := managednode.IsTag(tag); got != test.managed {
				t.Fatalf("managednode.IsTag(%q) = %t, want %t", tag, got, test.managed)
			}
		})
	}
}

func TestRuntimeRoutingDecisionRecognizesEveryManagedProtocol(t *testing.T) {
	tags := []string{
		"VLESS_127.0.0.1_443_1",
		"Trojan_127.0.0.1_443_1",
		"Vmess_127.0.0.1_443_1",
		"Shadowsocks_127.0.0.1_443_1",
		"Socks_127.0.0.1_443_1",
		"HTTP_127.0.0.1_443_1",
	}

	for _, tag := range tags {
		t.Run(tag, func(t *testing.T) {
			base := &fakeOutboundHandler{tag: "VLESS_127.0.0.1_443_2"}
			managedBase := &fakeOutboundHandler{tag: tag}
			managed := &dataPathWrapper{Handler: managedBase, tag: tag}
			selector := runtimeRoutingSelector{
				baseTag:     base.tag,
				baseHandler: base,
				obm: &fakeOutboundManager{handlers: map[string]outbound.Handler{
					tag: managed,
				}},
			}
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: tag})

			decision := selector.selectDispatch(ctx)
			if decision.rejectReason != "" {
				t.Fatalf("selectDispatch() rejected managed tag %q: %s", tag, decision.rejectReason)
			}
			if decision.handler != managed || !decision.managedHandoff {
				t.Fatalf("selectDispatch() = %#v, want managed handoff for %q", decision, tag)
			}
		})
	}
}

func TestControllerManagedNodeTagRejectsMalformedLookalikes(t *testing.T) {
	tags := []string{
		"VLESS_",
		"VLESS_127.0.0.1_bad_1",
		"VLESS_127.0.0.1_443_bad",
		"VLESS_127.0.0.1_443_1_extra",
		"VLESSish_127.0.0.1_443_1",
		"vless_127.0.0.1_443_1",
	}

	for _, tag := range tags {
		t.Run(tag, func(t *testing.T) {
			if managednode.IsTag(tag) {
				t.Fatalf("managednode.IsTag(%q) = true, want false", tag)
			}
		})
	}
}
