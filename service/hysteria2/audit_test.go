package hysteria2

import (
	"net"
	"regexp"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service/controller"
)

func TestEventLoggerAuditsExplicitUID(t *testing.T) {
	service := New(&configurablePanelClient{}, &controller.Config{})
	service.tag = "node"
	service.users["auth-user"] = userRecord{UID: 17}
	if err := service.rules.UpdateRule("node", []api.DetectRule{{
		ID:      3,
		Pattern: regexp.MustCompile(`blocked\.example`),
	}}); err != nil {
		t.Fatalf("UpdateRule() error = %v", err)
	}

	(&hyEventLogger{svc: service}).auditRequest(
		&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234},
		"auth-user",
		"blocked.example:443",
	)
	service.mu.RLock()
	blocked := service.blockedIDs["auth-user"]
	service.mu.RUnlock()
	if !blocked {
		t.Fatal("auditRequest() did not schedule the matching user for disconnect")
	}

	results, err := service.rules.GetDetectResult("node")
	if err != nil {
		t.Fatalf("GetDetectResult() error = %v", err)
	}
	if results == nil || len(*results) != 1 || (*results)[0].UID != 17 {
		t.Fatalf("audit results = %#v, want explicit UID 17", results)
	}
}
