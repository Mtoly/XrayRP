package proxypanel_test

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
		writeProxyResponse(w, "success", map[string]any{
			"v2_port":         8443,
			"v2_alter_id":     4,
			"v2_net":          "ws",
			"v2_type":         "none",
			"v2_host":         "edge.example",
			"v2_path":         "/socket",
			"v2_tls":          true,
			"speed_limit":     16,
			"client_limit":    3,
			"v2_method":       "auto",
			"v2_tls_provider": "fixture",
		})
	}))
	defer server.Close()

	client := newContractClient(server, "V2ray")
	snapshot, err := client.GetNodeSnapshotContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.NodeID != contractNodeID || snapshot.Port != 8443 || snapshot.AlterID != 4 || snapshot.TransportProtocol != "ws" || snapshot.FakeType != "none" || !snapshot.EnableTLS || snapshot.Host != "edge.example" || snapshot.Path != "/socket" || snapshot.SpeedLimit != 2_000_000 || client.DeviceLimit != 3 {
		t.Fatalf("unexpected snapshot: %#v, device limit %d", snapshot, client.DeviceLimit)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}
