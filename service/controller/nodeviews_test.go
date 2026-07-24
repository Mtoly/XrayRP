package controller

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"

	"github.com/Mtoly/XrayRP/api"
)

type focusedInboundBuilderContract func(*Config, inboundNodeView, string) (*core.InboundHandlerConfig, error)
type focusedEmbeddedUsersInboundBuilderContract func(*Config, inboundListenerView, string, *[]api.UserInfo) (*core.InboundHandlerConfig, error)
type focusedOutboundBuilderContract func(*Config, outboundNodeView, string) (*core.OutboundHandlerConfig, error)
type focusedRoutingSelectorContract func([]string, routingPolicyValue) ([]string, error)
type focusedVlessUserBuilderContract func(*Controller, *[]api.UserInfo, vlessUserNodeView, string) []*protocol.User

var (
	_ focusedInboundBuilderContract              = buildInbound
	_ focusedEmbeddedUsersInboundBuilderContract = buildInboundWithUsers
	_ focusedOutboundBuilderContract             = buildOutbound
	_ focusedRoutingSelectorContract             = selectOutboundCandidates
	_ focusedVlessUserBuilderContract            = (*Controller).buildVlessUser
)

func TestInboundNodeViewOwnsMutableValues(t *testing.T) {
	padding := [2]int32{1, 2}
	source := &api.NodeInfo{
		NodeType:      "Vless",
		Port:          443,
		Header:        json.RawMessage(`{"type":"http"}`),
		Headers:       map[string]string{"X-Test": "original"},
		XHTTPExtra:    json.RawMessage(`{"mode":"auto"}`),
		XPaddingBytes: &padding,
		REALITYConfig: &api.REALITYConfig{
			Dest:        "example.com:443",
			ServerNames: []string{"example.com"},
			ShortIds:    []string{"abcd"},
		},
	}

	view := normalizeNodeInfo(source).inboundView()
	source.NodeType = "Socks"
	source.Header[0] = '['
	source.Headers["X-Test"] = "mutated"
	source.XHTTPExtra[0] = '['
	source.XPaddingBytes[0] = 99
	source.REALITYConfig.ServerNames[0] = "mutated.example"
	source.REALITYConfig.ShortIds[0] = "ffff"

	if view.listener.nodeType != "Vless" {
		t.Fatalf("listener branch type changed through source: %q", view.listener.nodeType)
	}
	if string(view.transport.header) != `{"type":"http"}` {
		t.Fatalf("header changed through source: %s", view.transport.header)
	}
	if view.transport.headers["X-Test"] != "original" {
		t.Fatalf("headers changed through source: %#v", view.transport.headers)
	}
	if string(view.transport.xhttpExtra) != `{"mode":"auto"}` {
		t.Fatalf("XHTTP extra changed through source: %s", view.transport.xhttpExtra)
	}
	if !view.transport.xPaddingBytes.set || view.transport.xPaddingBytes.from != 1 || view.transport.xPaddingBytes.to != 2 {
		t.Fatalf("XHTTP padding range changed through source: %#v", view.transport.xPaddingBytes)
	}
	if !view.reality.set || view.reality.serverNames[0] != "example.com" || view.reality.shortIDs[0] != "abcd" {
		t.Fatalf("REALITY view changed through source: %#v", view.reality)
	}
}

func TestInboundNodeViewPreservesNilAndNonNilEmptyValues(t *testing.T) {
	nilView := normalizeNodeInfo(&api.NodeInfo{}).inboundView()
	emptyView := normalizeNodeInfo(&api.NodeInfo{
		Header:     make(json.RawMessage, 0),
		Headers:    make(map[string]string),
		XHTTPExtra: make(json.RawMessage, 0),
		REALITYConfig: &api.REALITYConfig{
			ServerNames: make([]string, 0),
			ShortIds:    make([]string, 0),
		},
	}).inboundView()

	if nilView.transport.header != nil || nilView.transport.headers != nil || nilView.transport.xhttpExtra != nil || nilView.reality.set {
		t.Fatalf("nil values changed during projection: %#v", nilView)
	}
	if emptyView.transport.header == nil || emptyView.transport.headers == nil || emptyView.transport.xhttpExtra == nil {
		t.Fatalf("non-nil empty transport values collapsed: %#v", emptyView.transport)
	}
	if !emptyView.reality.set || emptyView.reality.serverNames == nil || emptyView.reality.shortIDs == nil {
		t.Fatalf("non-nil empty REALITY value collapsed: %#v", emptyView.reality)
	}
}

func TestOutboundAndRoutingViewsOwnOnlyConsumedValues(t *testing.T) {
	source := &api.NodeInfo{
		NodeType: "dokodemo-door",
		Port:     8444,
		RoutePolicy: &api.PanelRoutePolicy{
			HasDirectBypass: true,
			DirectDomains:   []string{"unused.example"},
			Outbound: api.OutboundFilterPolicy{
				Candidates: []string{"candidate-a"},
				Include:    []string{"include-a"},
				Exclude:    []string{"exclude-a"},
				Fallback:   []string{"fallback-a"},
			},
		},
	}

	value := normalizeNodeInfo(source)
	outbound := value.outboundView()
	policy := value.routingPolicy()
	source.NodeType = "mutated"
	source.Port = 1
	source.RoutePolicy.Outbound.Candidates[0] = "mutated-candidate"
	source.RoutePolicy.Outbound.Include[0] = "mutated-include"
	source.RoutePolicy.Outbound.Exclude[0] = "mutated-exclude"
	source.RoutePolicy.Outbound.Fallback[0] = "mutated-fallback"

	if outbound.nodeType != "dokodemo-door" || outbound.port != 8444 {
		t.Fatalf("outbound view changed through source: %#v", outbound)
	}
	if !policy.set || policy.candidates[0] != "candidate-a" || policy.include[0] != "include-a" ||
		policy.exclude[0] != "exclude-a" || policy.fallback[0] != "fallback-a" {
		t.Fatalf("routing policy changed through source: %#v", policy)
	}
}

func TestRoutingPolicyValuePreservesUnsetAndNonNilEmpty(t *testing.T) {
	unset := normalizeNodeInfo(&api.NodeInfo{}).routingPolicy()
	empty := normalizeNodeInfo(&api.NodeInfo{
		RoutePolicy: &api.PanelRoutePolicy{
			Outbound: api.OutboundFilterPolicy{
				Candidates: make([]string, 0),
				Include:    make([]string, 0),
				Exclude:    make([]string, 0),
				Fallback:   make([]string, 0),
			},
		},
	}).routingPolicy()

	if unset.set {
		t.Fatalf("nil route policy became set: %#v", unset)
	}
	if !empty.set || empty.candidates == nil || empty.include == nil || empty.exclude == nil || empty.fallback == nil {
		t.Fatalf("non-nil empty route policy collapsed: %#v", empty)
	}
}

func TestUserNodeViewComputesEffectiveVlessFlow(t *testing.T) {
	const vision = "xtls-rprx-vision"
	tests := []struct {
		name      string
		node      api.NodeInfo
		wantFlow  string
		wantType  string
		wantVless bool
	}{
		{
			name:      "TCP TLS permits Vision",
			node:      api.NodeInfo{NodeType: "Vless", EnableVless: true, VlessFlow: " " + vision + " ", TransportProtocol: " TCP ", EnableTLS: true},
			wantFlow:  vision,
			wantType:  "Vless",
			wantVless: true,
		},
		{
			name:     "TCP REALITY permits Vision",
			node:     api.NodeInfo{NodeType: "V2ray", VlessFlow: vision, TransportProtocol: "tcp", EnableREALITY: true},
			wantFlow: vision,
			wantType: "V2ray",
		},
		{
			name:     "non TCP clears Vision",
			node:     api.NodeInfo{VlessFlow: vision, TransportProtocol: "ws", EnableTLS: true},
			wantFlow: "",
		},
		{
			name:     "missing security clears Vision",
			node:     api.NodeInfo{VlessFlow: vision, TransportProtocol: "tcp"},
			wantFlow: "",
		},
		{
			name:     "nil header permits Vision",
			node:     api.NodeInfo{VlessFlow: vision, TransportProtocol: "tcp", EnableTLS: true, Header: nil},
			wantFlow: vision,
		},
		{
			name:     "non nil empty header clears Vision",
			node:     api.NodeInfo{VlessFlow: vision, TransportProtocol: "tcp", EnableTLS: true, Header: make(json.RawMessage, 0)},
			wantFlow: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			view := normalizeNodeInfo(&test.node).userView()
			if view.vless.effectiveFlow != test.wantFlow || view.nodeType != test.wantType || view.enableVless != test.wantVless {
				t.Fatalf("user view = %#v, want flow %q type %q enableVless %t", view, test.wantFlow, test.wantType, test.wantVless)
			}
		})
	}
}

func TestShadowsocksPluginViewsPreserveBothRuntimeLegsAndSource(t *testing.T) {
	source := &api.NodeInfo{
		NodeType:          "Shadowsocks-Plugin",
		Port:              8443,
		TransportProtocol: "ws",
		EnableTLS:         true,
	}

	views := normalizeNodeInfo(source).shadowsocksPluginViews()

	if source.NodeType != "Shadowsocks-Plugin" || source.Port != 8443 || source.TransportProtocol != "ws" || !source.EnableTLS {
		t.Fatalf("source node was mutated: %#v", source)
	}
	if views.regularInbound.listener.nodeType != "Shadowsocks-Plugin" ||
		views.regularInbound.listener.port != 8443 ||
		views.regularInbound.transport.protocol != "tcp" ||
		views.regularInbound.listener.enableTLS {
		t.Fatalf("unexpected regular plugin leg: %#v", views.regularInbound)
	}
	if views.regularOutbound.nodeType != "Shadowsocks-Plugin" || views.regularOutbound.port != 8443 {
		t.Fatalf("unexpected regular plugin outbound: %#v", views.regularOutbound)
	}
	if views.bridgeInbound.listener.nodeType != "dokodemo-door" ||
		views.bridgeInbound.listener.port != 8444 ||
		views.bridgeInbound.transport.protocol != "ws" ||
		!views.bridgeInbound.listener.enableTLS {
		t.Fatalf("unexpected bridge plugin leg: %#v", views.bridgeInbound)
	}
	if views.bridgeOutbound.nodeType != "dokodemo-door" || views.bridgeOutbound.port != 8444 {
		t.Fatalf("unexpected bridge plugin outbound: %#v", views.bridgeOutbound)
	}
}
