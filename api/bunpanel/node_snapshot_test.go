package bunpanel_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestGetNodeSnapshotContextReturnsDirectSnapshotWithoutRefetch(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) != 1 {
			t.Errorf("unexpected request count: %d", requests.Load())
		}
		w.Header().Set("ETag", "bun-node-v1")
		writeResponse(w, 200, map[string]any{
			"serverPort": 8443,
			"network":    "ws",
			"security":   "tls",
			"flow":       "xtls-rprx-vision",
			"wsSettings": map[string]any{
				"path":    "/socket",
				"headers": map[string]any{"Host": "edge.example"},
			},
		})
	}))
	defer server.Close()

	client := newContractClient(server)
	snapshot, err := client.GetNodeSnapshotContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.NodeID != contractNodeID || snapshot.Port != 8443 || snapshot.TransportProtocol != "ws" || !snapshot.EnableTLS || snapshot.Host != "edge.example" || snapshot.Path != "/socket" || snapshot.VlessFlow != "xtls-rprx-vision" {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}
