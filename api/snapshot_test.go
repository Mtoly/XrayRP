package api_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

func TestNodeSnapshotRoundTripPreservesCompatibilityNodeInfo(t *testing.T) {
	disableCache := true
	source := &api.NodeInfo{
		NodeType:          "Vless",
		NodeID:            7,
		Port:              443,
		TransportProtocol: "ws",
		Header:            json.RawMessage(`{"type":"http"}`),
		HttpHeaders: map[string]*conf.StringList{
			"Host": conf.NewStringList([]string{"origin.example.test"}),
			"Nil":  nil,
		},
		Headers: map[string]string{"X-Test": "original"},
		NameServerConfig: []*conf.NameServerConfig{{
			Address:      &conf.Address{Address: net.ParseAddress("1.1.1.1")},
			Domains:      []string{"domain:example.test"},
			DisableCache: &disableCache,
		}},
		REALITYConfig: &api.REALITYConfig{ServerNames: []string{"reality.example.test"}},
		RoutePolicy:   &api.PanelRoutePolicy{Outbound: api.OutboundFilterPolicy{Candidates: []string{"proxy"}}},
	}
	want := api.NormalizeNodeInfo(source).ToNodeInfo()

	snapshot := api.NormalizeNodeInfo(source)
	source.Header[0] = '['
	(*source.HttpHeaders["Host"])[0] = "mutated.example.test"
	source.Headers["X-Test"] = "mutated"
	source.NameServerConfig[0].Domains[0] = "domain:mutated.example.test"
	source.REALITYConfig.ServerNames[0] = "mutated.example.test"
	source.RoutePolicy.Outbound.Candidates[0] = "mutated"

	got := snapshot.ToNodeInfo()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized snapshot changed through source mutation:\n got: %#v\nwant: %#v", got, want)
	}

	got.Header[0] = '['
	(*got.HttpHeaders["Host"])[0] = "mutated-again.example.test"
	got.NameServerConfig[0].Domains[0] = "mutated-again.example.test"
	if !reflect.DeepEqual(snapshot.ToNodeInfo(), want) {
		t.Fatal("compatibility materialization exposed mutable snapshot state")
	}
}

func TestNodeSnapshotMaterializesNeutralNameServers(t *testing.T) {
	disableCache := true
	snapshot := &api.NodeSnapshot{
		NodeType: "Vmess",
		Port:     443,
		NameServers: []*api.NameServerSnapshot{{
			Address:      "1.1.1.1",
			ClientIP:     "192.0.2.1",
			Domains:      []string{"domain:example.test"},
			DisableCache: &disableCache,
		}},
	}

	info := snapshot.ToNodeInfo()
	if len(info.NameServerConfig) != 1 || info.NameServerConfig[0] == nil {
		t.Fatalf("expected one legacy DNS config, got %#v", info.NameServerConfig)
	}
	if got := info.NameServerConfig[0].Address.String(); got != "1.1.1.1" {
		t.Fatalf("address = %q, want 1.1.1.1", got)
	}
	if got := info.NameServerConfig[0].ClientIP.String(); got != "192.0.2.1" {
		t.Fatalf("client IP = %q, want 192.0.2.1", got)
	}
	if !*info.NameServerConfig[0].DisableCache {
		t.Fatal("disableCache pointer was not materialized")
	}
	if len(info.NameServers) != 1 || info.NameServers[0].Address != "1.1.1.1" {
		t.Fatalf("normalized DNS config was not preserved: %#v", info.NameServers)
	}

	roundTripped := api.NormalizeNodeInfo(info).ToNodeInfo()
	if len(roundTripped.NameServers) != 1 || roundTripped.NameServers[0].Address != "1.1.1.1" {
		t.Fatalf("round-tripped normalized DNS config was lost: %#v", roundTripped.NameServers)
	}
}

func TestNodeSnapshotPreservesNilAndEmptyCollections(t *testing.T) {
	snapshot := &api.NodeSnapshot{
		Header:      make(json.RawMessage, 0),
		HTTPHeaders: map[string][]string{},
		Headers:     map[string]string{},
		NameServers: []*api.NameServerSnapshot{{
			Domains:       []string{},
			ExpectedIPs:   []string{},
			ExpectIPs:     []string{},
			UnexpectedIPs: []string{},
		}},
		ServerNames:           []string{},
		ShortIds:              []string{},
		XHTTPExtra:            make(json.RawMessage, 0),
		XHTTPDownloadSettings: make(json.RawMessage, 0),
	}
	clone := snapshot.Clone()
	if clone.Header == nil || clone.HTTPHeaders == nil || clone.Headers == nil || clone.NameServers == nil || clone.NameServers[0].Domains == nil || clone.ServerNames == nil || clone.ShortIds == nil || clone.XHTTPExtra == nil || clone.XHTTPDownloadSettings == nil {
		t.Fatalf("non-nil empty collections collapsed: %#v", clone)
	}
	if api.NormalizeNodeInfo(&api.NodeInfo{}).Clone().Header != nil {
		t.Fatal("nil raw JSON became non-nil during normalization")
	}
}

func TestNodeSnapshotEqualIgnoresPrivateLegacyCompatibilityState(t *testing.T) {
	legacy := api.NormalizeNodeInfo(&api.NodeInfo{
		NameServerConfig: []*conf.NameServerConfig{{
			Address: &conf.Address{Address: net.ParseAddress("1.1.1.1")},
		}},
	})
	normalized := api.NormalizeNodeInfo(&api.NodeInfo{
		NameServers: []*api.NameServerSnapshot{{Address: "1.1.1.1"}},
		NameServerConfig: []*conf.NameServerConfig{{
			Address: &conf.Address{Address: net.ParseAddress("8.8.8.8")},
		}},
	})

	if !legacy.Equal(normalized) || !normalized.Equal(legacy) {
		t.Fatalf("equivalent normalized snapshots compared unequal:\nlegacy=%#v\nnormalized=%#v", legacy, normalized)
	}
}

func TestNodeSnapshotMaterializationFollowsChangedNormalizedLegacyValues(t *testing.T) {
	snapshot := api.NormalizeNodeInfo(&api.NodeInfo{
		HttpHeaders: map[string]*conf.StringList{
			"Host": conf.NewStringList([]string{"old.example.test"}),
		},
		NameServerConfig: []*conf.NameServerConfig{{
			Address: &conf.Address{Address: net.ParseAddress("1.1.1.1")},
		}},
	})
	snapshot.HTTPHeaders["Host"][0] = "new.example.test"
	snapshot.NameServers[0].Address = "8.8.8.8"

	info := snapshot.ToNodeInfo()
	if got := (*info.HttpHeaders["Host"])[0]; got != "new.example.test" {
		t.Fatalf("legacy headers retained stale compatibility value %q", got)
	}
	if got := info.NameServerConfig[0].Address.String(); got != "8.8.8.8" {
		t.Fatalf("legacy name server retained stale compatibility value %q", got)
	}
	if len(info.NameServers) != 1 || info.NameServers[0].Address != "8.8.8.8" {
		t.Fatalf("normalized name server change was not materialized: %#v", info.NameServers)
	}
}
