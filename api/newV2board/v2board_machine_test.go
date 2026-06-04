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
	query := getUserListQuery(t, &api.Config{
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
	if nodeType := query.Get("node_type"); nodeType != "vless" {
		t.Fatalf("expected node_type vless, got %q", nodeType)
	}
	if token := query.Get("token"); token != "machine-token" {
		t.Fatalf("expected token machine-token, got %q", token)
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
