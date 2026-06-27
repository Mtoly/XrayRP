package newV2board

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestUniProxySnapshotCacheRoundTrip(t *testing.T) {
	client := New(&api.Config{APIHost: "http://127.0.0.1", NodeID: 1, NodeType: "V2ray"})
	snapshot := &serverConfig{ServerPort: 443}

	client.storeUniProxySnapshot(snapshot)
	cached, ok := client.cachedUniProxySnapshot()
	if !ok {
		t.Fatal("expected cached UniProxy snapshot")
	}
	if cached != snapshot {
		t.Fatalf("expected cached snapshot pointer %p, got %p", snapshot, cached)
	}
}

func mustCompileRegex(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("compile regex %q: %v", pattern, err)
	}
	return re
}

func TestCertConfigFromUniProxySnapshot(t *testing.T) {
	if cert := certConfigFromUniProxySnapshot(nil); cert != nil {
		t.Fatalf("expected nil cert config from nil snapshot, got %#v", cert)
	}
	if cert := certConfigFromUniProxySnapshot(&serverConfig{}); cert != nil {
		t.Fatalf("expected nil cert config without cert payload, got %#v", cert)
	}

	snapshot := &serverConfig{CertConfig: &certConfig{
		Provider: "alidns",
		Email:    "ops@example.com",
		DNSEnv: map[string]string{
			"ALICLOUD_ACCESS_KEY": "ak",
			"ALICLOUD_SECRET_KEY": "sk",
		},
	}}
	cert := certConfigFromUniProxySnapshot(snapshot)
	if cert == nil {
		t.Fatal("expected cert config from snapshot")
	}
	if cert.Provider != "alidns" || cert.Email != "ops@example.com" {
		t.Fatalf("unexpected cert config: %#v", cert)
	}
	if cert.DNSEnv["ALICLOUD_ACCESS_KEY"] != "ak" || cert.DNSEnv["ALICLOUD_SECRET_KEY"] != "sk" {
		t.Fatalf("unexpected cert env: %#v", cert.DNSEnv)
	}
}

func TestBaseConfigFromUniProxySnapshot(t *testing.T) {
	if baseConfig := baseConfigFromUniProxySnapshot(nil); baseConfig != nil {
		t.Fatalf("expected nil base config from nil snapshot, got %#v", baseConfig)
	}
	if baseConfig := baseConfigFromUniProxySnapshot(&serverConfig{}); baseConfig != nil {
		t.Fatalf("expected nil base config without positive intervals, got %#v", baseConfig)
	}

	snapshot := &serverConfig{BaseConfig: api.BaseConfig{PushInterval: 15, PullInterval: 45}}
	baseConfig := baseConfigFromUniProxySnapshot(snapshot)
	if baseConfig == nil {
		t.Fatal("expected base config from snapshot")
	}
	if baseConfig.PushInterval != 15 || baseConfig.PullInterval != 45 {
		t.Fatalf("unexpected base config: %#v", baseConfig)
	}

	baseConfig.PushInterval = 99
	if snapshot.BaseConfig.PushInterval != 15 {
		t.Fatalf("expected returned base config to be a copy, snapshot changed to %#v", snapshot.BaseConfig)
	}
}

func TestAPIClientGetBaseConfigUsesCachedSnapshot(t *testing.T) {
	client := New(&api.Config{APIHost: "http://127.0.0.1", NodeID: 1, NodeType: "V2ray"})
	if baseConfig := client.GetBaseConfig(); baseConfig != nil {
		t.Fatalf("expected nil base config before snapshot is cached, got %#v", baseConfig)
	}

	client.storeUniProxySnapshot(&serverConfig{BaseConfig: api.BaseConfig{PushInterval: 20, PullInterval: 50}})
	baseConfig := client.GetBaseConfig()
	if baseConfig == nil {
		t.Fatal("expected cached base config")
	}
	if baseConfig.PushInterval != 20 || baseConfig.PullInterval != 50 {
		t.Fatalf("unexpected cached base config: %#v", baseConfig)
	}
}

func TestRulesFromUniProxySnapshotIncludesLocalAndBlockRoutes(t *testing.T) {
	localPattern := mustCompileRegex(t, "local-allow")
	snapshot := &serverConfig{Routes: []route{
		{Id: 10, Action: "dns", Match: []string{"1.1.1.1"}, ActionValue: "dns.example"},
		{Id: 11, Action: "block", Match: []string{"example-blocked.com", "ads.example"}},
		{Id: 12, Action: "direct", Match: []string{"direct.example"}},
	}}

	rules, err := rulesFromUniProxySnapshot(snapshot, []api.DetectRule{{ID: -1, Pattern: localPattern}})
	if err != nil {
		t.Fatalf("rulesFromUniProxySnapshot returned error: %v", err)
	}
	if len(*rules) != 2 {
		t.Fatalf("expected one local rule and one block rule, got %d", len(*rules))
	}
	if (*rules)[0].ID != -1 || !(*rules)[0].Pattern.MatchString("local-allow") {
		t.Fatalf("unexpected local rule entry: %#v", (*rules)[0])
	}
	if (*rules)[1].ID != 1 {
		t.Fatalf("expected block rule to use route index 1, got %d", (*rules)[1].ID)
	}
	if !(*rules)[1].Pattern.MatchString("example-blocked.com") || !(*rules)[1].Pattern.MatchString("ads.example") {
		t.Fatalf("expected block pattern to match route domains, got %s", (*rules)[1].Pattern.String())
	}
}

func TestRulesFromUniProxySnapshotRejectsMissingSnapshot(t *testing.T) {
	_, err := rulesFromUniProxySnapshot(nil, nil)
	if err == nil {
		t.Fatal("expected error when snapshot is missing")
	}
}

func TestGetNodeRuleReturnsErrorWhenSnapshotMissing(t *testing.T) {
	client := &APIClient{}
	rules, err := client.GetNodeRule()
	if err == nil {
		t.Fatal("expected GetNodeRule to fail when snapshot is missing")
	}
	if rules != nil {
		t.Fatalf("expected nil rules when snapshot is missing, got %#v", rules)
	}
}

func TestNodeInfoFromUniProxySnapshotRejectsMissingSnapshot(t *testing.T) {
	client := &APIClient{NodeType: "V2ray"}
	nodeInfo, err := client.nodeInfoFromUniProxySnapshot(nil)
	if err == nil {
		t.Fatal("expected error when snapshot is missing")
	}
	if nodeInfo != nil {
		t.Fatalf("expected nil node info when snapshot is missing, got %#v", nodeInfo)
	}
}

func TestNodeInfoFromUniProxySnapshotRejectsUnsupportedNodeType(t *testing.T) {
	client := &APIClient{NodeType: "Mieru"}
	nodeInfo, err := client.nodeInfoFromUniProxySnapshot(&serverConfig{ServerPort: 443})
	if err == nil {
		t.Fatal("expected unsupported node type error")
	}
	if nodeInfo != nil {
		t.Fatalf("expected nil node info for unsupported node type, got %#v", nodeInfo)
	}
}

func TestNodeInfoFromUniProxySnapshotDispatchesV2ray(t *testing.T) {
	client := &APIClient{NodeID: 1, NodeType: "V2ray"}
	snapshot := &serverConfig{ServerPort: 443}
	snapshot.Network = "tcp"
	nodeInfo, err := client.nodeInfoFromUniProxySnapshot(snapshot)
	if err != nil {
		t.Fatalf("nodeInfoFromUniProxySnapshot returned error: %v", err)
	}
	if nodeInfo == nil {
		t.Fatal("expected node info from snapshot")
	}
	if nodeInfo.Port != 443 {
		t.Fatalf("expected derived node port 443, got %d", nodeInfo.Port)
	}
	if nodeInfo.TransportProtocol != "tcp" {
		t.Fatalf("expected derived transport tcp, got %q", nodeInfo.TransportProtocol)
	}
}

func TestNodeInfoFromUniProxySnapshotDispatchesLowercaseMachineVless(t *testing.T) {
	client := &APIClient{NodeID: 1, NodeType: "vless"}
	snapshot := &serverConfig{ServerPort: 443}
	snapshot.Network = "tcp"

	nodeInfo, err := client.nodeInfoFromUniProxySnapshot(snapshot)
	if err != nil {
		t.Fatalf("nodeInfoFromUniProxySnapshot returned error: %v", err)
	}
	if nodeInfo == nil {
		t.Fatal("expected node info from lowercase vless snapshot")
	}
	if nodeInfo.Port != 443 {
		t.Fatalf("expected derived node port 443, got %d", nodeInfo.Port)
	}
	if nodeInfo.NodeType != "vless" {
		t.Fatalf("expected lowercase vless node type to be preserved, got %q", nodeInfo.NodeType)
	}
}

func TestEnrichNodeInfoFromUniProxySnapshotAddsDNSAndRoutePolicy(t *testing.T) {
	snapshot := loadRoutePolicyFixture(t)
	nodeInfo := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}

	enrichNodeInfoFromUniProxySnapshot(snapshot, nodeInfo)

	if nodeInfo.RoutePolicy == nil {
		t.Fatal("expected enrich to populate RoutePolicy")
	}
	if !nodeInfo.RoutePolicy.HasDirectBypass {
		t.Fatal("expected enrich to preserve direct bypass flag")
	}
	if len(nodeInfo.NameServerConfig) != 1 {
		t.Fatalf("expected enrich to populate one DNS config, got %d", len(nodeInfo.NameServerConfig))
	}
}

func TestNodeInfoFromUniProxySnapshotAppliesCommonEnrichForV2ray(t *testing.T) {
	client := &APIClient{NodeID: 1, NodeType: "V2ray", EnableVless: true}
	snapshot := loadRoutePolicyFixture(t)

	nodeInfo, err := client.nodeInfoFromUniProxySnapshot(snapshot)
	if err != nil {
		t.Fatalf("nodeInfoFromUniProxySnapshot returned error: %v", err)
	}
	if nodeInfo.RoutePolicy == nil {
		t.Fatal("expected RoutePolicy after common enrich")
	}
	if len(nodeInfo.NameServerConfig) != 1 {
		t.Fatalf("expected NameServerConfig after common enrich, got %d", len(nodeInfo.NameServerConfig))
	}
}

func TestFetchUniProxySnapshotWithoutETagDoesNotSendOrStoreETag(t *testing.T) {
	var gotIfNoneMatch string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", "etag-from-cert-fetch")
		_, _ = w.Write([]byte(`{"server_port":443,"network":"tcp"}`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
	snapshot, err := client.fetchUniProxySnapshot(false)
	if err != nil {
		t.Fatalf("fetchUniProxySnapshot returned error: %v", err)
	}
	if snapshot.ServerPort != 443 {
		t.Fatalf("expected server port 443, got %d", snapshot.ServerPort)
	}
	if gotIfNoneMatch != "" {
		t.Fatalf("expected fetch without ETag to omit If-None-Match, got %q", gotIfNoneMatch)
	}
	if got := client.eTags["node"]; got != "" {
		t.Fatalf("expected fetch without ETag to leave node etag empty, got %q", got)
	}
	cached, ok := client.cachedUniProxySnapshot()
	if !ok || cached != snapshot {
		t.Fatalf("expected fetched snapshot to be cached, got ok=%v cached=%p snapshot=%p", ok, cached, snapshot)
	}
}

func TestFetchUniProxySnapshotWithETagSendsAndUpdatesETag(t *testing.T) {
	var gotIfNoneMatch string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", "new-etag")
		_, _ = w.Write([]byte(`{"server_port":8443,"network":"tcp"}`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
	client.eTags["node"] = "old-etag"

	snapshot, err := client.fetchUniProxySnapshot(true)
	if err != nil {
		t.Fatalf("fetchUniProxySnapshot returned error: %v", err)
	}
	if snapshot.ServerPort != 8443 {
		t.Fatalf("expected server port 8443, got %d", snapshot.ServerPort)
	}
	if gotIfNoneMatch != "old-etag" {
		t.Fatalf("expected If-None-Match old-etag, got %q", gotIfNoneMatch)
	}
	if got := client.eTags["node"]; got != "new-etag" {
		t.Fatalf("expected updated node etag new-etag, got %q", got)
	}
	cached, ok := client.cachedUniProxySnapshot()
	if !ok || cached != snapshot {
		t.Fatalf("expected fetched snapshot to be cached, got ok=%v cached=%p snapshot=%p", ok, cached, snapshot)
	}
}

func TestFetchUniProxySnapshotWithETagReturnsNodeNotModified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("If-None-Match"); got != "old-etag" {
			t.Fatalf("expected If-None-Match old-etag, got %q", got)
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
	client.eTags["node"] = "old-etag"

	_, err := client.fetchUniProxySnapshot(true)
	if err == nil || err.Error() != api.NodeNotModified {
		t.Fatalf("expected NodeNotModified error, got %v", err)
	}
}
