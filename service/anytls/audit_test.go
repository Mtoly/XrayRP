package anytls

import (
	"context"
	"net"
	"regexp"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service/controller"
)

func TestRoutedConnectionAuditsExplicitUID(t *testing.T) {
	service := New(&configurablePanelClient{}, &controller.Config{})
	service.tag = "node"
	service.users["auth-user"] = userRecord{UID: 17}
	if err := service.rules.UpdateRule("node", []api.DetectRule{{
		ID:      3,
		Pattern: regexp.MustCompile(`blocked\.example`),
	}}); err != nil {
		t.Fatalf("UpdateRule() error = %v", err)
	}

	connection, peer := net.Pipe()
	defer peer.Close()
	tracked := (&anyTLSTracker{svc: service}).RoutedConnection(
		context.Background(),
		connection,
		adapter.InboundContext{User: "auth-user", Domain: "blocked.example"},
		nil,
		nil,
	)
	counter, ok := tracked.(*connCounter)
	if !ok || !counter.blocked {
		t.Fatalf("RoutedConnection() = %#v, want blocked connCounter", tracked)
	}

	results, err := service.rules.GetDetectResult("node")
	if err != nil {
		t.Fatalf("GetDetectResult() error = %v", err)
	}
	if results == nil || len(*results) != 1 || (*results)[0].UID != 17 {
		t.Fatalf("audit results = %#v, want explicit UID 17", results)
	}
}
