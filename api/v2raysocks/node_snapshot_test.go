package v2raysocks

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestGetNodeSnapshotContextReturnsDirectSnapshotWithoutRefetch(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Etag", "config-v1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"inbounds":[{"port":8443,"protocol":"vmess","streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/socket","headers":{"Host":"edge.example"}}}}]}`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, Key: "fixture-key", NodeID: 17, NodeType: "V2ray"})
	snapshot, err := client.GetNodeSnapshotContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.NodeID != 17 || snapshot.NodeType != "V2ray" || snapshot.Port != 8443 || snapshot.TransportProtocol != "ws" || !snapshot.EnableTLS || snapshot.Host != "edge.example" || snapshot.Path != "/socket" {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
	if got := client.eTags.Get("config"); got != "config-v1" {
		t.Fatalf("ETag = %q, want config-v1", got)
	}
	if client.ConfigResp == nil {
		t.Fatal("ConfigResp is nil after successful snapshot fetch")
	}
}

func TestGetNodeSnapshotContextAcceptsCaseInsensitiveNodeType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"inbounds":[{"port":8443,"protocol":"vless","streamSettings":{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}}]}`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, Key: "fixture-key", NodeID: 17, NodeType: "vless"})
	snapshot, err := client.GetNodeSnapshotContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.NodeType != "vless" || snapshot.Port != 8443 || !snapshot.EnableVless || snapshot.TransportProtocol != "tcp" {
		t.Fatalf("unexpected case-insensitive snapshot: %#v", snapshot)
	}
}
