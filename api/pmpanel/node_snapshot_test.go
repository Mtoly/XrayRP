package pmpanel_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestGetNodeSnapshotContextReturnsDirectSnapshotWithoutRefetch(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		writePMResponse(w, 200, map[string]any{
			"outPort":    8443,
			"alterId":    4,
			"network":    "ws",
			"security":   "tls",
			"host":       "edge.example",
			"path":       "/socket",
			"speedlimit": 16,
		})
	}))
	defer server.Close()

	client := newContractClient(server, "V2ray")
	snapshot, err := client.GetNodeSnapshotContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.NodeID != contractNodeID || snapshot.Port != 8443 || snapshot.AlterID != 4 || snapshot.TransportProtocol != "ws" || !snapshot.EnableTLS || snapshot.Host != "edge.example" || snapshot.Path != "/socket" || snapshot.SpeedLimit != 2_000_000 {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}
