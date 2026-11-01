package newV2board

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
)

func TestGetXrayRCertConfigFetchesConfigWhenCacheEmpty(t *testing.T) {
	payload := `{
		"server_port": 443,
		"network": "tcp",
		"routes": [],
		"cert_config": {
			"provider": "alidns",
			"email": "ops@example.com",
			"dns_env": {
				"ALICLOUD_ACCESS_KEY": "ak",
				"ALICLOUD_SECRET_KEY": "sk"
			}
		}
	}`
	requestHeaders := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHeaders = append(requestHeaders, r.Header.Get("If-None-Match"))
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", "etag-1")
		_, _ = w.Write([]byte(payload))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})

	cert, err := client.GetXrayRCertConfig()
	if err != nil {
		t.Fatalf("GetXrayRCertConfig returned error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert config, got nil")
	}
	if cert.Provider != "alidns" || cert.Email != "ops@example.com" {
		t.Fatalf("unexpected cert config: %#v", cert)
	}
	if cert.DNSEnv["ALICLOUD_ACCESS_KEY"] != "ak" || cert.DNSEnv["ALICLOUD_SECRET_KEY"] != "sk" {
		t.Fatalf("unexpected cert env: %#v", cert.DNSEnv)
	}
	if len(requestHeaders) != 1 || requestHeaders[0] != "" {
		t.Fatalf("expected cert fetch without If-None-Match, got %#v", requestHeaders)
	}

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo after cert fetch returned error: %v", err)
	}
	if nodeInfo == nil || nodeInfo.Port != 443 {
		t.Fatalf("unexpected node info after cert fetch: %#v", nodeInfo)
	}
	if len(requestHeaders) != 2 || requestHeaders[1] != "" {
		t.Fatalf("expected GetNodeInfo to avoid primed If-None-Match after cert fetch, got %#v", requestHeaders)
	}
}

func TestGetAliveSnapshotReadsDeviceCounts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/alivelist" || r.URL.Query().Get("node_id") != "1" {
			t.Errorf("unexpected alive request: %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"alive":{"1":3}}`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
	got, err := client.GetAliveSnapshot()
	want := &api.AliveSnapshot{IPs: map[int][]string{}, Counts: map[int]int{1: 3}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("GetAliveSnapshot() = %#v, %v; want %#v, nil", got, err, want)
	}
}

func TestGetAliveSnapshotPreservesFormats(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
		want    *api.AliveSnapshot
		wantErr bool
	}{
		{name: "absent", payload: `{}`},
		{name: "empty", payload: `{"alive":{}}`, want: &api.AliveSnapshot{IPs: map[int][]string{}}},
		{name: "zero count", payload: `{"alive":{"1":0}}`, want: &api.AliveSnapshot{IPs: map[int][]string{}, Counts: map[int]int{1: 0}}},
		{name: "legacy IPs", payload: `{"alive":{"1":["192.0.2.5_1","2001:db8::1_2","192.0.2.1"],"2":[]}}`, want: &api.AliveSnapshot{
			IPs: map[int][]string{1: {"192.0.2.5", "2001:db8::1", "192.0.2.1"}, 2: {}},
		}},
		{name: "mixed", payload: `{"alive":{"1":3,"2":["192.0.2.5_1"]}}`, want: &api.AliveSnapshot{
			IPs: map[int][]string{2: {"192.0.2.5"}}, Counts: map[int]int{1: 3},
		}},
		{name: "null snapshot", payload: `{"alive":null}`, wantErr: true},
		{name: "array snapshot", payload: `{"alive":[]}`, wantErr: true},
		{name: "negative count", payload: `{"alive":{"1":-1}}`, wantErr: true},
		{name: "fractional count", payload: `{"alive":{"1":1.5}}`, wantErr: true},
		{name: "exponent count", payload: `{"alive":{"1":1e2}}`, wantErr: true},
		{name: "overflow count", payload: `{"alive":{"1":9223372036854775808}}`, wantErr: true},
		{name: "string count", payload: `{"alive":{"1":"3"}}`, wantErr: true},
		{name: "null count", payload: `{"alive":{"1":null}}`, wantErr: true},
		{name: "boolean count", payload: `{"alive":{"1":true}}`, wantErr: true},
		{name: "invalid uid", payload: `{"alive":{"0":3}}`, wantErr: true},
		{name: "malformed IP", payload: `{"alive":{"1":[42]}}`, wantErr: true},
		{name: "valid and invalid values are not partially accepted", payload: `{"alive":{"1":3,"2":["192.0.2.1_1"],"3":-1}}`, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.payload))
			}))
			defer server.Close()

			client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
			got, err := client.GetAliveSnapshot()
			if test.wantErr {
				if err == nil || got != nil {
					t.Fatalf("GetAliveSnapshot() = %#v, %v; want nil snapshot and error", got, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("GetAliveSnapshot() = %#v, %v; want %#v, nil", got, err, test.want)
			}
		})
	}
}

func TestGetAliveSnapshotUsesMachineEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/alivelist" || r.URL.Query().Get("node_id") != "7" || r.URL.Query().Get("machine_id") != "2" {
			t.Errorf("unexpected machine alive request: %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"alive":{"1":2}}`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 7, MachineID: 2, NodeType: "V2ray"})
	got, err := api.GetAliveSnapshotContext(context.Background(), client)
	want := &api.AliveSnapshot{IPs: map[int][]string{}, Counts: map[int]int{1: 2}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("GetAliveSnapshotContext() = %#v, %v; want %#v, nil", got, err, want)
	}
}

func TestGetAliveSnapshotContextCancelsInFlightRequest(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() {
		close(release)
		server.Close()
	}()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		got, err := client.GetAliveSnapshotContext(ctx)
		if got != nil {
			t.Errorf("canceled request returned snapshot %#v", got)
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not reach test server")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("GetAliveSnapshotContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("alive request ignored cancellation")
	}
}

func TestGetAliveListNormalizesAliveIPs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"alive":{"1":["192.0.2.1_1","192.0.2.2_2"],"2":["2001:db8::1_1"]}}`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
	alive, err := client.GetAliveList()
	if err != nil {
		t.Fatalf("GetAliveList returned error: %v", err)
	}
	if len(alive[1]) != 2 || alive[1][0] != "192.0.2.1" || alive[1][1] != "192.0.2.2" {
		t.Fatalf("unexpected normalized alive list for uid 1: %#v", alive[1])
	}
	if len(alive[2]) != 1 || alive[2][0] != "2001:db8::1" {
		t.Fatalf("unexpected normalized alive list for uid 2: %#v", alive[2])
	}
}

func TestGetAliveListDistinguishesAbsentEmptyAndMalformedSnapshots(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		wantNil   bool
		wantEmpty bool
		wantErr   bool
	}{
		{
			name:    "absent snapshot",
			payload: `{}`,
			wantNil: true,
		},
		{
			name:      "authoritative empty snapshot",
			payload:   `{"alive":{}}`,
			wantEmpty: true,
		},
		{
			name:    "counts cannot be projected as IPs",
			payload: `{"alive":{"1":3}}`,
			wantNil: true,
		},
		{
			name:    "zero count is not an empty IP snapshot",
			payload: `{"alive":{"1":0}}`,
			wantNil: true,
		},
		{
			name:    "mixed snapshot cannot be partially projected",
			payload: `{"alive":{"1":3,"2":["192.0.2.1_1"]}}`,
			wantNil: true,
		},
		{
			name:    "alive is null",
			payload: `{"alive":null}`,
			wantErr: true,
		},
		{
			name:    "alive is not an object",
			payload: `{"alive":[]}`,
			wantErr: true,
		},
		{
			name:    "uid is malformed",
			payload: `{"alive":{"not-a-uid":["192.0.2.1_1"]}}`,
			wantErr: true,
		},
		{
			name:    "uid is zero",
			payload: `{"alive":{"0":["192.0.2.1_1"]}}`,
			wantErr: true,
		},
		{
			name:    "uid is negative",
			payload: `{"alive":{"-1":["192.0.2.1_1"]}}`,
			wantErr: true,
		},
		{
			name:    "valid and invalid uids are not partially accepted",
			payload: `{"alive":{"1":["192.0.2.1_1"],"0":[]}}`,
			wantErr: true,
		},
		{
			name:    "ip list is malformed",
			payload: `{"alive":{"1":"192.0.2.1_1"}}`,
			wantErr: true,
		},
		{
			name:    "ip entry is malformed",
			payload: `{"alive":{"1":[42]}}`,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.payload))
			}))
			defer server.Close()

			client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
			alive, err := client.GetAliveList()

			if test.wantErr {
				if err == nil {
					t.Fatalf("GetAliveList error = nil, alive = %#v", alive)
				}
				if alive != nil {
					t.Fatalf("GetAliveList returned partial snapshot %#v with error %v", alive, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetAliveList returned error: %v", err)
			}
			if test.wantNil && alive != nil {
				t.Fatalf("alive = %#v, want nil", alive)
			}
			if test.wantEmpty && (alive == nil || len(alive) != 0) {
				t.Fatalf("alive = %#v, want non-nil empty snapshot", alive)
			}
		})
	}
}

func TestParseV2rayNodeResponsePreservesRealityAndVlessFlow(t *testing.T) {
	cfg := &serverConfig{}
	cfg.ServerPort = 443
	cfg.Network = "tcp"
	cfg.Tls = 2
	cfg.VlessFlow = "xtls-rprx-vision"
	cfg.VlessTlsSettings.Dest = "origin.example.com"
	cfg.VlessTlsSettings.ServerPort = "8443"
	cfg.VlessTlsSettings.XVer = 1
	cfg.VlessTlsSettings.Sni = "panel.example.com"
	cfg.VlessTlsSettings.PrivateKey = "private-key"
	cfg.VlessTlsSettings.ShortId = "abcd"

	client := &APIClient{NodeID: 1, NodeType: "V2ray", EnableVless: true}
	nodeInfo, err := client.parseV2rayNodeResponse(cfg)
	if err != nil {
		t.Fatalf("parseV2rayNodeResponse returned error: %v", err)
	}
	if !nodeInfo.EnableREALITY {
		t.Fatal("expected EnableREALITY to be true")
	}
	if nodeInfo.REALITYConfig == nil {
		t.Fatal("expected REALITYConfig to be populated")
	}
	if nodeInfo.REALITYConfig.Dest != "origin.example.com:8443" {
		t.Fatalf("unexpected REALITY dest: %s", nodeInfo.REALITYConfig.Dest)
	}
	if len(nodeInfo.REALITYConfig.ShortIds) != 1 || nodeInfo.REALITYConfig.ShortIds[0] != "abcd" {
		t.Fatalf("unexpected REALITY short ids: %#v", nodeInfo.REALITYConfig.ShortIds)
	}
	if !nodeInfo.EnableVless {
		t.Fatal("expected EnableVless to be true")
	}
	if nodeInfo.VlessFlow != "xtls-rprx-vision" {
		t.Fatalf("unexpected VlessFlow: %s", nodeInfo.VlessFlow)
	}
}
