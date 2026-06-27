package newV2board_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
)

func TestNewV2boardClientOmitsMachineIDWhenUnset(t *testing.T) {
	query := getUserListQuery(t, &api.Config{
		NodeID:   11,
		NodeType: "Vless",
		Key:      "node-token",
	})

	if values, ok := query["machine_id"]; ok {
		t.Fatalf("expected machine_id to be absent, got %#v", values)
	}
	if nodeID := query.Get("node_id"); nodeID != "11" {
		t.Fatalf("expected node_id 11, got %q", nodeID)
	}
	if nodeType := query.Get("node_type"); nodeType != "vless" {
		t.Fatalf("expected node_type vless, got %q", nodeType)
	}
	if token := query.Get("token"); token != "node-token" {
		t.Fatalf("expected token node-token, got %q", token)
	}
}

func TestNewV2boardClientSendsMachineIDWhenConfigured(t *testing.T) {
	query := getMachineUserListQuery(t, &api.Config{
		NodeID:    11,
		NodeType:  "Vless",
		Key:       "machine-token",
		MachineID: 7,
	})

	if machineID := query.Get("machine_id"); machineID != "7" {
		t.Fatalf("expected machine_id 7, got %q", machineID)
	}
	if nodeID := query.Get("node_id"); nodeID != "11" {
		t.Fatalf("expected node_id 11, got %q", nodeID)
	}
	if values, ok := query["node_type"]; ok {
		t.Fatalf("expected node_type to be absent in machine mode, got %#v", values)
	}
	if token := query.Get("token"); token != "machine-token" {
		t.Fatalf("expected token machine-token, got %q", token)
	}
}

func TestNewV2boardMachineClientUsesV2Endpoints(t *testing.T) {
	testNewV2boardMachineClientUsesV2Endpoints(t, "Vless")
}

func TestNewV2boardMachineClientAcceptsLowercaseVlessUsers(t *testing.T) {
	testNewV2boardMachineClientUsesV2Endpoints(t, "vless")
}

func testNewV2boardMachineClientUsesV2Endpoints(t *testing.T, nodeType string) {
	t.Helper()

	requests := make(chan *http.Request, 5)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/server/config":
			_, _ = w.Write([]byte(`{"server_port":443,"network":"tcp","base_config":{"push_interval":15,"pull_interval":30}}`))
		case "/api/v2/server/user":
			_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"user-uuid","speed_limit":0,"device_limit":0}]}`))
		case "/api/v2/server/report":
			_, _ = w.Write([]byte(`{"data":true}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newV2board.New(&api.Config{
		APIHost:   server.URL,
		NodeID:    11,
		NodeType:  nodeType,
		Key:       "machine-token",
		MachineID: 7,
	})
	if _, err := client.GetNodeInfo(); err != nil {
		t.Fatalf("GetNodeInfo returned error: %v", err)
	}
	if _, err := client.GetUserList(); err != nil {
		t.Fatalf("GetUserList returned error: %v", err)
	}
	if err := client.ReportNodeStatus(&api.NodeStatus{CPU: 12, Mem: 34, Disk: 56}); err != nil {
		t.Fatalf("ReportNodeStatus returned error: %v", err)
	}
	if err := client.ReportNodeOnlineUsers(&[]api.OnlineUser{{UID: 1, IP: "127.0.0.1"}}); err != nil {
		t.Fatalf("ReportNodeOnlineUsers returned error: %v", err)
	}
	if err := client.ReportUserTraffic(&[]api.UserTraffic{{UID: 1, Upload: 2, Download: 3}}); err != nil {
		t.Fatalf("ReportUserTraffic returned error: %v", err)
	}

	for i, wantPath := range []string{
		"/api/v2/server/config",
		"/api/v2/server/user",
		"/api/v2/server/report",
		"/api/v2/server/report",
		"/api/v2/server/report",
	} {
		got := <-requests
		if got.URL.Path != wantPath {
			t.Fatalf("request %d path: got %s want %s", i, got.URL.Path, wantPath)
		}
		query := got.URL.Query()
		if query.Get("machine_id") != "7" || query.Get("node_id") != "11" || query.Get("token") != "machine-token" {
			t.Fatalf("request %d unexpected auth query: %s", i, got.URL.RawQuery)
		}
		if values, ok := query["node_type"]; ok {
			t.Fatalf("request %d should omit node_type in machine mode, got %#v", i, values)
		}
	}
}

func getUserListQuery(t *testing.T, config *api.Config) url.Values {
	t.Helper()

	queries := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/api/v1/server/UniProxy/user" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		queries <- r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"user-uuid","speed_limit":0,"device_limit":0}]}`))
	}))
	defer server.Close()

	config.APIHost = server.URL
	client := newV2board.New(config)
	if _, err := client.GetUserList(); err != nil {
		t.Fatalf("GetUserList returned error: %v", err)
	}

	return <-queries
}

func getMachineUserListQuery(t *testing.T, config *api.Config) url.Values {
	t.Helper()

	queries := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/api/v2/server/user" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		queries <- r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"user-uuid","speed_limit":0,"device_limit":0}]}`))
	}))
	defer server.Close()

	config.APIHost = server.URL
	client := newV2board.New(config)
	if _, err := client.GetUserList(); err != nil {
		t.Fatalf("GetUserList returned error: %v", err)
	}

	return <-queries
}
