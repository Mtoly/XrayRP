package newV2board

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func loadRoutePolicyFixture(t *testing.T) *serverConfig {
	t.Helper()
	raw, err := os.ReadFile("testdata/uniproxy_config_route_policy.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var cfg serverConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return &cfg
}

func TestParseSupportedRoutePolicySubset(t *testing.T) {
	cfg := loadRoutePolicyFixture(t)

	policy, err := cfg.BuildRoutePolicy()
	if err != nil {
		t.Fatalf("BuildRoutePolicy returned error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected non-nil policy")
	}
	if !policy.HasDirectBypass {
		t.Fatal("expected HasDirectBypass to be true")
	}
	if len(policy.Outbound.Candidates) != 3 || policy.Outbound.Candidates[0] != "hk-auto" || policy.Outbound.Candidates[1] != "sg-auto" || policy.Outbound.Candidates[2] != "test-dead" {
		t.Fatalf("unexpected candidate list: %#v", policy.Outbound.Candidates)
	}
	if len(policy.Outbound.Include) != 2 || policy.Outbound.Include[0] != "hk-" || policy.Outbound.Include[1] != "sg-" {
		t.Fatalf("unexpected include list: %#v", policy.Outbound.Include)
	}
	if len(policy.Outbound.Exclude) != 1 || policy.Outbound.Exclude[0] != "dead" {
		t.Fatalf("unexpected exclude list: %#v", policy.Outbound.Exclude)
	}
	if len(policy.Outbound.Fallback) != 2 || policy.Outbound.Fallback[0] != "direct" || policy.Outbound.Fallback[1] != "proxy" {
		t.Fatalf("unexpected fallback list: %#v", policy.Outbound.Fallback)
	}
	if len(policy.DirectDomains) != 1 || policy.DirectDomains[0] != "panel.example.com" {
		t.Fatalf("unexpected direct domains: %#v", policy.DirectDomains)
	}
}

func TestParseV2rayNodeResponseCarriesRoutePolicy(t *testing.T) {
	cfg := loadRoutePolicyFixture(t)
	client := &APIClient{NodeID: 1, NodeType: "V2ray", EnableVless: true}

	nodeInfo, err := client.parseV2rayNodeResponse(cfg)
	if err != nil {
		t.Fatalf("parseV2rayNodeResponse returned error: %v", err)
	}
	if nodeInfo.RoutePolicy == nil {
		t.Fatal("expected RoutePolicy to be populated")
	}
	if !nodeInfo.RoutePolicy.HasDirectBypass {
		t.Fatal("expected HasDirectBypass to be true on node policy")
	}
	if len(nodeInfo.RoutePolicy.Outbound.Include) == 0 || nodeInfo.RoutePolicy.Outbound.Include[0] != "hk-" {
		t.Fatalf("unexpected include list on node policy: %#v", nodeInfo.RoutePolicy.Outbound.Include)
	}
}

func TestParseDNSConfig(t *testing.T) {
	cfg := loadRoutePolicyFixture(t)
	dns := cfg.parseDNSConfig()
	if len(dns) != 1 {
		t.Fatalf("expected one DNS config, got %d", len(dns))
	}
	if dns[0] == nil || dns[0].Address == nil || dns[0].Address.Address == nil {
		t.Fatal("expected DNS config address to be populated")
	}
	if got := dns[0].Address.Address.String(); got != "1.1.1.1" {
		t.Fatalf("unexpected DNS server address: %s", got)
	}
}

func TestGetNodeRuleOnlyIncludesBlockRoutes(t *testing.T) {
	cfg := loadRoutePolicyFixture(t)
	client := &APIClient{}
	client.resp.Store(cfg)

	rules, err := client.GetNodeRule()
	if err != nil {
		t.Fatalf("GetNodeRule returned error: %v", err)
	}
	if len(*rules) != 1 {
		t.Fatalf("expected exactly one detect rule, got %d", len(*rules))
	}
	if (*rules)[0].ID != 1 {
		t.Fatalf("expected block rule index 1, got %d", (*rules)[0].ID)
	}
	if !(*rules)[0].Pattern.MatchString("example-blocked.com") {
		t.Fatal("expected block rule to match blocked domain")
	}
}

func TestReportIllegalReturnsExplicitUnsupportedError(t *testing.T) {
	client := &APIClient{APIHost: "https://panel.example", NodeID: 1, NodeType: "V2ray"}
	results := []api.DetectResult{{UID: 1, RuleID: 2, IP: "1.2.3.4"}}

	err := client.ReportIllegal(&results)
	if err == nil {
		t.Fatal("expected unsupported error, got nil")
	}
	if err != api.ErrUnsupportedPanelFeature {
		t.Fatalf("expected ErrUnsupportedPanelFeature, got %v", err)
	}
}
