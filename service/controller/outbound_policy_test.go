package controller

import (
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestSelectOutboundByPolicy_IncludeExcludeFallback(t *testing.T) {
	candidates := []string{"hk-auto", "sg-auto", "test-dead", "direct"}
	policy := &api.PanelRoutePolicy{
		Outbound: api.OutboundFilterPolicy{
			Include:  []string{"hk-", "sg-"},
			Exclude:  []string{"dead"},
			Fallback: []string{"direct"},
		},
	}

	selected, err := selectOutboundCandidates(candidates, policy)
	if err != nil {
		t.Fatalf("selectOutboundCandidates returned error: %v", err)
	}
	if len(selected) != 2 || selected[0] != "hk-auto" || selected[1] != "sg-auto" {
		t.Fatalf("unexpected selected outbounds: %#v", selected)
	}
}

func TestSelectOutboundByPolicy_UsesFallbackWhenFilteredEmpty(t *testing.T) {
	candidates := []string{"test-dead", "direct"}
	policy := &api.PanelRoutePolicy{
		Outbound: api.OutboundFilterPolicy{
			Include:  []string{"hk-"},
			Exclude:  []string{"dead"},
			Fallback: []string{"direct"},
		},
	}

	selected, err := selectOutboundCandidates(candidates, policy)
	if err != nil {
		t.Fatalf("selectOutboundCandidates returned error: %v", err)
	}
	if len(selected) != 1 || selected[0] != "direct" {
		t.Fatalf("unexpected fallback selection: %#v", selected)
	}
}

func TestSelectOutboundByPolicy_FailsWhenFallbackMissing(t *testing.T) {
	candidates := []string{"test-dead", "proxy"}
	policy := &api.PanelRoutePolicy{
		Outbound: api.OutboundFilterPolicy{
			Include:  []string{"hk-"},
			Exclude:  []string{"dead", "proxy"},
			Fallback: []string{"direct"},
		},
	}

	_, err := selectOutboundCandidates(candidates, policy)
	if err == nil {
		t.Fatal("expected error when no fallback candidates are available")
	}
}

func TestNodeStateChangedTreatsRoutePolicyAsNodeState(t *testing.T) {
	current := &api.NodeInfo{
		NodeType: "V2ray",
		NodeID:   1,
		Port:     443,
		RoutePolicy: &api.PanelRoutePolicy{
			HasDirectBypass: true,
			Outbound: api.OutboundFilterPolicy{
				Candidates: []string{"hk-auto", "sg-auto"},
				Include:    []string{"hk-"},
			},
		},
	}
	next := &api.NodeInfo{
		NodeType: "V2ray",
		NodeID:   1,
		Port:     443,
		RoutePolicy: &api.PanelRoutePolicy{
			HasDirectBypass: true,
			Outbound: api.OutboundFilterPolicy{
				Candidates: []string{"hk-auto", "sg-auto"},
				Include:    []string{"sg-"},
			},
		},
	}

	if !nodeStateChanged(current, next) {
		t.Fatal("expected route policy difference to be treated as node state change")
	}
}

func TestNodeStateChangedIgnoresIdenticalRoutePolicy(t *testing.T) {
	current := &api.NodeInfo{
		NodeType: "V2ray",
		NodeID:   1,
		Port:     443,
		RoutePolicy: &api.PanelRoutePolicy{
			HasDirectBypass: true,
			Outbound: api.OutboundFilterPolicy{
				Candidates: []string{"hk-auto", "sg-auto"},
				Include:    []string{"hk-"},
				Exclude:    []string{"dead"},
				Fallback:   []string{"direct"},
			},
		},
	}
	next := &api.NodeInfo{
		NodeType: "V2ray",
		NodeID:   1,
		Port:     443,
		RoutePolicy: &api.PanelRoutePolicy{
			HasDirectBypass: true,
			Outbound: api.OutboundFilterPolicy{
				Candidates: []string{"hk-auto", "sg-auto"},
				Include:    []string{"hk-"},
				Exclude:    []string{"dead"},
				Fallback:   []string{"direct"},
			},
		},
	}

	if nodeStateChanged(current, next) {
		t.Fatal("expected identical route policy to keep node state unchanged")
	}
}
