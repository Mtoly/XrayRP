package newV2board

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestUniProxySnapshotCacheOwnsCommittedData(t *testing.T) {
	client := New(&api.Config{APIHost: "http://127.0.0.1", NodeID: 1, NodeType: "V2ray"})
	snapshot := &serverConfig{
		ServerPort: 443,
		CertConfig: &certConfig{DNSEnv: map[string]string{"TOKEN": "committed"}},
	}

	if err := client.storeUniProxySnapshot(snapshot); err != nil {
		t.Fatalf("store snapshot: %v", err)
	}
	snapshot.ServerPort = 8443
	snapshot.CertConfig.DNSEnv["TOKEN"] = "mutated"

	cached, ok := client.cachedUniProxySnapshot()
	if !ok {
		t.Fatal("expected cached UniProxy snapshot")
	}
	if cached.ServerPort != 443 {
		t.Fatalf("expected committed port 443, got %d", cached.ServerPort)
	}
	if cached.CertConfig.DNSEnv["TOKEN"] != "committed" {
		t.Fatalf("expected committed cert environment, got %#v", cached.CertConfig.DNSEnv)
	}
}

func TestUniProxySnapshotCacheReturnsIndependentReads(t *testing.T) {
	client := New(&api.Config{APIHost: "http://127.0.0.1", NodeID: 1, NodeType: "V2ray"})
	if err := client.storeUniProxySnapshot(&serverConfig{
		ServerPort: 443,
		CertConfig: &certConfig{DNSEnv: map[string]string{"TOKEN": "committed"}},
	}); err != nil {
		t.Fatalf("store snapshot: %v", err)
	}

	first, ok := client.cachedUniProxySnapshot()
	if !ok {
		t.Fatal("expected cached UniProxy snapshot")
	}
	first.ServerPort = 8443
	first.CertConfig.DNSEnv["TOKEN"] = "mutated"

	second, ok := client.cachedUniProxySnapshot()
	if !ok {
		t.Fatal("expected cached UniProxy snapshot on second read")
	}
	if second.ServerPort != 443 || second.CertConfig.DNSEnv["TOKEN"] != "committed" {
		t.Fatalf("expected independent cached read, got %#v", second)
	}
}

func TestUniProxySnapshotCacheRejectsInvalidSnapshotAndKeepsCommittedData(t *testing.T) {
	client := New(&api.Config{APIHost: "http://127.0.0.1", NodeID: 1, NodeType: "V2ray"})
	if err := client.storeUniProxySnapshot(&serverConfig{ServerPort: 443}); err != nil {
		t.Fatalf("store initial snapshot: %v", err)
	}

	invalidRaw := json.RawMessage(`{"unterminated"`)
	invalid := &serverConfig{ServerPort: 8443}
	invalid.NetworkSettings.Headers = &invalidRaw
	if err := client.storeUniProxySnapshot(invalid); err == nil {
		t.Fatal("expected invalid snapshot to be rejected")
	}

	cached, ok := client.cachedUniProxySnapshot()
	if !ok {
		t.Fatal("expected previous cached snapshot to remain available")
	}
	if cached.ServerPort != 443 {
		t.Fatalf("expected previous cached port 443, got %d", cached.ServerPort)
	}
}

func TestNormalizedUniProxySnapshotReturnsIndependentCertConfig(t *testing.T) {
	normalized := normalizeUniProxySnapshot(&serverConfig{
		CertConfig: &certConfig{DNSEnv: map[string]string{"TOKEN": "committed"}},
	}, "vless")

	first := normalized.certConfig()
	first.DNSEnv["TOKEN"] = "mutated"
	second := normalized.certConfig()

	if second.DNSEnv["TOKEN"] != "committed" {
		t.Fatalf("expected independent cert environment, got %#v", second.DNSEnv)
	}
}

func TestUniProxySnapshotCacheRoundTrip(t *testing.T) {
	client := New(&api.Config{APIHost: "http://127.0.0.1", NodeID: 1, NodeType: "V2ray"})
	snapshot := &serverConfig{ServerPort: 443}

	client.storeUniProxySnapshot(snapshot)
	cached, ok := client.cachedUniProxySnapshot()
	if !ok {
		t.Fatal("expected cached UniProxy snapshot")
	}
	if cached == snapshot {
		t.Fatal("expected cache to own an independent snapshot")
	}
	if cached.ServerPort != snapshot.ServerPort {
		t.Fatalf("expected cached port %d, got %d", snapshot.ServerPort, cached.ServerPort)
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

func TestNormalizeUniProxySnapshotMaterializesStableOutputs(t *testing.T) {
	localPattern := mustCompileRegex(t, "local-allow")
	snapshot := &serverConfig{
		ServerPort: 443,
		BaseConfig: api.BaseConfig{PushInterval: 15, PullInterval: 45},
		CertConfig: &certConfig{
			CertMode:    "content",
			Domain:      "node.example.com",
			CertContent: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
			KeyContent:  "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
		},
		Routes: []route{
			{Id: 10, Action: "dns", Match: []string{"dns.example"}, ActionValue: "1.1.1.1"},
			{Id: 11, Action: "block", Match: []string{"blocked.example", "ads.example"}},
		},
	}

	normalized := normalizeUniProxySnapshot(snapshot, "vless")
	if normalized == nil {
		t.Fatal("expected normalized snapshot")
	}
	if normalized.nodeType != "Vless" {
		t.Fatalf("expected normalized node type Vless, got %q", normalized.nodeType)
	}

	cert := normalized.certConfig()
	if cert == nil {
		t.Fatal("expected normalized cert config")
	}
	if cert.CertMode != "content" || cert.CertDomain != "node.example.com" {
		t.Fatalf("unexpected normalized cert config: %#v", cert)
	}
	if cert.CertContent == "" || cert.KeyContent == "" {
		t.Fatalf("expected content cert materialization to preserve inline cert/key content: %#v", cert)
	}

	baseConfig := normalized.baseConfig()
	if baseConfig == nil {
		t.Fatal("expected normalized base config")
	}
	if baseConfig.PushInterval != 15 || baseConfig.PullInterval != 45 {
		t.Fatalf("unexpected normalized base config: %#v", baseConfig)
	}
	baseConfig.PushInterval = 99
	if snapshot.BaseConfig.PushInterval != 15 {
		t.Fatalf("expected normalized base config to be a copy, raw snapshot changed to %#v", snapshot.BaseConfig)
	}

	rules, err := normalized.rules([]api.DetectRule{{ID: -1, Pattern: localPattern}})
	if err != nil {
		t.Fatalf("normalized rules returned error: %v", err)
	}
	if len(*rules) != 2 {
		t.Fatalf("expected local rule plus block rule, got %#v", *rules)
	}
	if (*rules)[0].ID != -1 || !(*rules)[0].Pattern.MatchString("local-allow") {
		t.Fatalf("expected local rule to be preserved first, got %#v", (*rules)[0])
	}
	if (*rules)[1].ID != 1 || !(*rules)[1].Pattern.MatchString("blocked.example") || !(*rules)[1].Pattern.MatchString("ads.example") {
		t.Fatalf("expected block route to materialize as detect rule with route index, got %#v", (*rules)[1])
	}

	nodeInfo := &api.NodeInfo{}
	normalized.enrichNodeInfo(nodeInfo)
	if len(nodeInfo.NameServerConfig) != 1 {
		t.Fatalf("expected normalized snapshot to enrich DNS config, got %d", len(nodeInfo.NameServerConfig))
	}
	if nodeInfo.RoutePolicy == nil {
		t.Fatal("expected normalized snapshot to enrich route policy")
	}
}

func TestNormalizeUniProxySnapshotNormalizesNodeTypes(t *testing.T) {
	tests := map[string]string{
		"vless":       "Vless",
		"vmess":       "Vmess",
		"v2ray":       "Vmess",
		"trojan":      "Trojan",
		"shadowsocks": "Shadowsocks",
		"hysteria":    "Hysteria2",
		"hysteria2":   "Hysteria2",
		"tuic":        "Tuic",
		"anytls":      "AnyTLS",
		"socks":       "Socks",
		"http":        "HTTP",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			normalized := normalizeUniProxySnapshot(&serverConfig{}, input)
			if normalized == nil {
				t.Fatal("expected normalized snapshot")
			}
			if normalized.nodeType != want {
				t.Fatalf("normalized node type for %q = %q, want %q", input, normalized.nodeType, want)
			}
		})
	}
}

func TestCertConfigFromUniProxySnapshot(t *testing.T) {
	if cert := certConfigFromUniProxySnapshot(nil); cert != nil {
		t.Fatalf("expected nil cert config from nil snapshot, got %#v", cert)
	}
	if cert := certConfigFromUniProxySnapshot(&serverConfig{}); cert != nil {
		t.Fatalf("expected nil cert config without cert payload, got %#v", cert)
	}

	snapshot := &serverConfig{CertConfig: &certConfig{
		CertMode:    "content",
		Domain:      "node.example.com",
		CertFile:    "/tmp/node.crt",
		KeyFile:     "/tmp/node.key",
		CertContent: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
		KeyContent:  "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
		Provider:    "alidns",
		Email:       "ops@example.com",
		DNSEnv: map[string]string{
			"ALICLOUD_ACCESS_KEY": "ak",
			"ALICLOUD_SECRET_KEY": "sk",
		},
	}}
	cert := certConfigFromUniProxySnapshot(snapshot)
	if cert == nil {
		t.Fatal("expected cert config from snapshot")
	}
	if cert.CertMode != "content" || cert.CertDomain != "node.example.com" {
		t.Fatalf("unexpected cert mode/domain: %#v", cert)
	}
	if cert.CertFile != "/tmp/node.crt" || cert.KeyFile != "/tmp/node.key" {
		t.Fatalf("unexpected cert files: %#v", cert)
	}
	if cert.CertContent == "" || cert.KeyContent == "" {
		t.Fatalf("expected cert content to be preserved: %#v", cert)
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
	if nodeInfo.NodeType != "Vless" {
		t.Fatalf("expected lowercase vless node type to be normalized, got %q", nodeInfo.NodeType)
	}
}

func TestCanonicalNodeTypeNormalizesMachineTypes(t *testing.T) {
	tests := map[string]string{
		"vless":       "Vless",
		"vmess":       "Vmess",
		"v2ray":       "Vmess",
		"trojan":      "Trojan",
		"shadowsocks": "Shadowsocks",
		"hysteria":    "Hysteria2",
		"hysteria2":   "Hysteria2",
		"tuic":        "Tuic",
		"anytls":      "AnyTLS",
		"socks":       "Socks",
		"http":        "HTTP",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			if got := canonicalNodeType(input); got != want {
				t.Fatalf("canonicalNodeType(%q) = %q, want %q", input, got, want)
			}
		})
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

func TestFetchUniProxySnapshotUsesConfigPathByMode(t *testing.T) {
	tests := []struct {
		name      string
		machineID int
		wantPath  string
	}{
		{name: "single node", wantPath: legacyUniProxyConfigPath},
		{name: "machine node", machineID: 7, wantPath: xboardConfigPath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"server_port":443,"network":"tcp"}`))
			}))
			defer server.Close()

			client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray", MachineID: tt.machineID})
			if _, err := client.fetchUniProxySnapshot(false); err != nil {
				t.Fatalf("fetchUniProxySnapshot returned error: %v", err)
			}
			if got := <-requests; got != tt.wantPath {
				t.Fatalf("expected config path %q, got %q", tt.wantPath, got)
			}
		})
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
	if !ok {
		t.Fatal("expected fetched snapshot to be cached")
	}
	if cached == snapshot {
		t.Fatal("expected cache to own an independent fetched snapshot")
	}
	if cached.ServerPort != snapshot.ServerPort || cached.Network != snapshot.Network {
		t.Fatalf("expected cached snapshot content to match fetch result, got %#v", cached)
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
	if !ok {
		t.Fatal("expected fetched snapshot to be cached")
	}
	if cached == snapshot {
		t.Fatal("expected cache to own an independent fetched snapshot")
	}
	if cached.ServerPort != snapshot.ServerPort || cached.Network != snapshot.Network {
		t.Fatalf("expected cached snapshot content to match fetch result, got %#v", cached)
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
