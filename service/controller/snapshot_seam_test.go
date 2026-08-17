package controller

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestApplyNodeSnapshotUsesNormalizedRuntimeHook(t *testing.T) {
	controller := &Controller{config: &Config{ListenIP: "127.0.0.1"}}
	var received *api.NodeSnapshot
	module := nodeRuntimeStateApplyModule{
		controller: controller,
		hooks: syncApplyHooks{
			runtime: syncApplyRuntimeHooks{
				addTagSnapshot: func(snapshot *api.NodeSnapshot, _ string, _ *Config) error {
					received = snapshot.Clone()
					return nil
				},
			},
			limiter: syncApplyLimiterHooks{
				deleteInbound: func(string) error { return nil },
			},
		},
	}
	want := &api.NodeSnapshot{
		NodeType:          "V2ray",
		NodeID:            7,
		Port:              443,
		TransportProtocol: "ws",
		Host:              "edge.example.test",
		NameServers: []*api.NameServerSnapshot{{
			Address: "https://dns.example.test/dns-query",
		}},
	}

	got, tag, changed, err := module.applyNodeSnapshot(nil, "", nil, want, &Config{}, &Config{}, false, false)
	if err != nil {
		t.Fatalf("applyNodeSnapshot() error = %v", err)
	}
	if !changed {
		t.Fatal("applyNodeSnapshot() reported no change")
	}
	if tag == "" {
		t.Fatal("applyNodeSnapshot() returned an empty tag")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("returned snapshot = %#v, want %#v", got, want)
	}
	if received == nil || !reflect.DeepEqual(received, want) {
		t.Fatalf("runtime hook received %#v, want normalized snapshot %#v", received, want)
	}
	if received.NameServers[0].Address != want.NameServers[0].Address {
		t.Fatalf("runtime hook lost neutral DNS value: %#v", received.NameServers)
	}
}

func TestApplyNodeSnapshotIsolatesRuntimeHookInputs(t *testing.T) {
	controller := &Controller{config: &Config{ListenIP: "127.0.0.1"}}
	config := &Config{ListenIP: "127.0.0.1"}
	want := &api.NodeSnapshot{
		NodeType: "V2ray",
		NodeID:   7,
		Port:     443,
		Header:   []byte(`{"type":"http"}`),
		NameServers: []*api.NameServerSnapshot{{
			Address: "1.1.1.1",
		}},
	}
	module := nodeRuntimeStateApplyModule{
		controller: controller,
		hooks: syncApplyHooks{
			runtime: syncApplyRuntimeHooks{
				addTagSnapshot: func(snapshot *api.NodeSnapshot, _ string, receivedConfig *Config) error {
					snapshot.Port = 8443
					snapshot.Header[0] = '['
					snapshot.NameServers[0].Address = "8.8.8.8"
					receivedConfig.ListenIP = "mutated"
					return nil
				},
			},
			limiter: syncApplyLimiterHooks{
				deleteInbound: func(string) error { return nil },
			},
		},
	}

	got, _, changed, err := module.applyNodeSnapshot(nil, "", nil, want, config, config, false, false)
	if err != nil {
		t.Fatalf("applyNodeSnapshot() error = %v", err)
	}
	if !changed || got.Port != 443 || got.NameServers[0].Address != "1.1.1.1" || string(got.Header) != `{"type":"http"}` {
		t.Fatalf("runtime hook mutated candidate snapshot: %#v", got)
	}
	if config.ListenIP != "127.0.0.1" {
		t.Fatalf("runtime hook mutated controller config: %#v", config)
	}
	state, _, _ := controller.getSnapshotState()
	if state == nil || state.Port != 443 || state.NameServers[0].Address != "1.1.1.1" {
		t.Fatalf("runtime hook mutation leaked into controller state: %#v", state)
	}
}

func TestSyncApplySnapshotLegacyViewOwnsMutableFields(t *testing.T) {
	snapshot := syncApplySnapshot{
		NodeSnapshot: &api.NodeSnapshot{
			Port:   443,
			Header: []byte(`{"type":"http"}`),
		},
		UserList:   &[]api.UserInfo{{UID: 1, Email: "old@example.test"}},
		RuleList:   &[]api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("old")}},
		CertConfig: &api.XrayRCertConfig{DNSEnv: map[string]string{"TOKEN": "value"}},
		BaseConfig: &api.BaseConfig{PushInterval: 15, PullInterval: 45},
	}
	view := snapshot.legacyView()
	view.NodeSnapshot.Header[0] = '['
	view.NodeInfo.Header[0] = ']'
	(*view.UserList)[0].Email = "mutated@example.test"
	(*view.RuleList)[0].ID = 99
	view.CertConfig.DNSEnv["TOKEN"] = "mutated"
	view.BaseConfig.PushInterval = 99

	if string(snapshot.NodeSnapshot.Header) != `{"type":"http"}` || snapshot.NodeInfo != nil {
		t.Fatalf("legacy view aliased node fields: original=%#v view=%#v", snapshot, view)
	}
	if (*snapshot.UserList)[0].Email != "old@example.test" || (*snapshot.RuleList)[0].ID != 1 || snapshot.CertConfig.DNSEnv["TOKEN"] != "value" || snapshot.BaseConfig.PushInterval != 15 {
		t.Fatalf("legacy view aliased snapshot fields: original=%#v", snapshot)
	}
}
