package newV2board

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestDiscoverWSEndpointUsesHandshakeURLWhenEnabled(t *testing.T) {
	t.Parallel()

	var gotNodeID, gotNodeType, gotToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/handshake" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		gotNodeID = r.URL.Query().Get("node_id")
		gotNodeType = r.URL.Query().Get("node_type")
		gotToken = r.URL.Query().Get("token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"websocket":{"enabled":true,"ws_url":"wss://panel.example/ws"}}`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, Key: "secret", NodeID: 7, NodeType: "V2ray", EnableVless: true})
	endpoint, err := client.DiscoverWSEndpoint()
	if err != nil {
		t.Fatalf("DiscoverWSEndpoint returned error: %v", err)
	}
	if endpoint != "wss://panel.example/ws" {
		t.Fatalf("unexpected endpoint: got %q", endpoint)
	}
	if gotNodeID != "7" || gotNodeType != "vless" || gotToken != "secret" {
		t.Fatalf("unexpected handshake query: node_id=%q node_type=%q token=%q", gotNodeID, gotNodeType, gotToken)
	}
}

func TestDiscoverWSEndpointFallsBackWhenDisabled(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"websocket":{"enabled":false,"ws_url":"wss://panel.example/ws"}}`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, Key: "secret", NodeID: 7, NodeType: "V2ray"})
	endpoint, err := client.DiscoverWSEndpoint()
	if err != nil {
		t.Fatalf("DiscoverWSEndpoint returned error: %v", err)
	}
	if endpoint != "" {
		t.Fatalf("expected empty fallback endpoint, got %q", endpoint)
	}
}

func TestDiscoverWSEndpointFallsBackOn404(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, Key: "secret", NodeID: 7, NodeType: "V2ray"})
	endpoint, err := client.DiscoverWSEndpoint()
	if err != nil {
		t.Fatalf("DiscoverWSEndpoint returned error: %v", err)
	}
	if endpoint != "" {
		t.Fatalf("expected empty fallback endpoint, got %q", endpoint)
	}
}

func TestDiscoverWSEndpointFallsBackOnMalformedJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, Key: "secret", NodeID: 7, NodeType: "V2ray"})
	endpoint, err := client.DiscoverWSEndpoint()
	if err != nil {
		t.Fatalf("DiscoverWSEndpoint returned error: %v", err)
	}
	if endpoint != "" {
		t.Fatalf("expected empty fallback endpoint, got %q", endpoint)
	}
}
