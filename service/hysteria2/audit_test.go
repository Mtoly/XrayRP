package hysteria2

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"

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

func TestTrafficLoggerAuditDisconnectRedactsAuthenticationID(t *testing.T) {
	const authenticationID = "secret-audit-authentication-id"
	for _, removed := range []bool{false, true} {
		name := "known user"
		if removed {
			name = "removed user"
		}
		t.Run(name, func(t *testing.T) {
			service := limiterTestService()
			service.tag = "node"
			service.users[authenticationID] = userRecord{UID: 17}
			logger, hook := logtest.NewNullLogger()
			service.logger = logger.WithField("test", "audit")
			if err := service.rules.UpdateRule("node", []api.DetectRule{{
				ID:      3,
				Pattern: regexp.MustCompile(`blocked\.example`),
			}}); err != nil {
				t.Fatalf("UpdateRule() error = %v", err)
			}
			(&hyEventLogger{svc: service}).auditRequest(
				&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234},
				authenticationID,
				"blocked.example:443",
			)
			if removed {
				delete(service.users, authenticationID)
			}
			hook.Reset()

			if (&hyTrafficLogger{svc: service}).LogTraffic(authenticationID, 1, 0) {
				t.Fatal("LogTraffic() = true, want audit rejection")
			}
			if service.blockedIDs[authenticationID] {
				t.Fatal("LogTraffic() retained the consumed audit flag")
			}
			entries := hook.AllEntries()
			if len(entries) != 1 || entries[0].Message != "Hysteria2 closing connection due to audit rule" {
				t.Fatalf("audit disconnect log = %#v, want one disconnect warning", entries)
			}
			entry := entries[0]
			if strings.Contains(entry.Message, authenticationID) {
				t.Fatal("audit disconnect message leaked authentication ID")
			}
			for key, value := range entry.Data {
				if strings.Contains(key, authenticationID) || strings.Contains(fmt.Sprint(value), authenticationID) {
					t.Fatalf("audit disconnect field %q leaked authentication ID", key)
				}
			}
			if _, exists := entry.Data["id"]; exists {
				t.Fatal("audit disconnect log retained an authentication ID field")
			}
			if uid, exists := entry.Data["uid"]; removed {
				if exists {
					t.Fatal("audit disconnect log identified a removed user")
				}
			} else if !exists || uid != 17 {
				t.Fatalf("audit disconnect UID = %v, want 17", uid)
			}
		})
	}
}
