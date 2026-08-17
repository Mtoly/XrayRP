package sspanel

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
		w.Header().Set("ETag", "ss-node-v1")
		writeResponse(t, w, map[string]any{
			"node_speedlimit": 8.0,
			"version":         "2024.1",
			"custom_config": map[string]any{
				"offset_port_node": "8443",
				"network":          "ws",
				"security":         "tls",
				"host":             "edge.example",
				"sni":              "sni.example",
				"path":             "/socket",
				"flow":             "vision",
			},
		})
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, Key: testKey, NodeID: testNodeID, NodeType: "V2ray"})
	snapshot, err := client.GetNodeSnapshotContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.NodeID != testNodeID || snapshot.Port != 8443 || snapshot.TransportProtocol != "ws" || !snapshot.EnableTLS || snapshot.Host != "edge.example" || snapshot.SNI != "sni.example" || snapshot.Path != "/socket" || snapshot.VlessFlow != "vision" || snapshot.SpeedLimit != 1_000_000 {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
	if got := client.eTags.Get("node"); got != "ss-node-v1" {
		t.Fatalf("ETag = %q, want ss-node-v1", got)
	}
}
