package hysteria2

import (
	"errors"
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

func newLocalAuditTestService(t *testing.T) *Hysteria2Service {
	t.Helper()
	service := New(&configurablePanelClient{}, &controller.Config{})
	service.tag = "node"
	service.users["auth-user"] = userRecord{UID: 17}
	if err := service.rules.UpdateRule("node", []api.DetectRule{{
		ID:      3,
		Pattern: regexp.MustCompile(`blocked\.example`),
	}}); err != nil {
		t.Fatalf("UpdateRule() error = %v", err)
	}
	return service
}

func TestLocalAuditDisconnectsOnlyAuditedConnection(t *testing.T) {
	service := newLocalAuditTestService(t)
	authenticator := &hyAuthenticator{svc: service}
	events := &hyEventLogger{svc: service}
	traffic := &hyTrafficLogger{svc: service}
	first := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000}
	second := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5001}
	ok, firstID := authenticator.Authenticate(first, "auth-user", 0)
	if !ok {
		t.Fatal("Authenticate() rejected the first device")
	}
	ok, secondID := authenticator.Authenticate(second, "auth-user", 0)
	if !ok {
		t.Fatal("Authenticate() rejected the second device")
	}

	events.TCPRequest(first, firstID, "blocked.example:443")
	// The other device sends traffic while the audited connection is dialing.
	if !traffic.LogTraffic(secondID, 32*1024, 0) {
		t.Error("LogTraffic() disconnected the other device")
	}
	if traffic.LogTraffic(firstID, 512, 0) {
		t.Error("LogTraffic() allowed the audited connection")
	}
}

func TestLocalAuditMarkRemovedAfterFailedDialDisconnect(t *testing.T) {
	service := newLocalAuditTestService(t)
	authenticator := &hyAuthenticator{svc: service}
	events := &hyEventLogger{svc: service}
	traffic := &hyTrafficLogger{svc: service}
	first := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000}
	ok, firstID := authenticator.Authenticate(first, "auth-user", 0)
	if !ok {
		t.Fatal("Authenticate() rejected the initial connection")
	}

	// A failed audited dial has no traffic callback before the core disconnects.
	events.TCPRequest(first, firstID, "blocked.example:443")
	events.TCPError(first, firstID, "blocked.example:443", errors.New("dial failed"))
	traffic.LogOnlineState(firstID, false)
	events.Disconnect(first, firstID, nil)
	service.mu.RLock()
	marks := len(service.blockedIDs)
	service.mu.RUnlock()
	if marks != 0 {
		t.Errorf("Disconnect() retained %d audit marks, want none", marks)
	}

	second := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5001}
	ok, secondID := authenticator.Authenticate(second, "auth-user", 0)
	if !ok {
		t.Fatal("Authenticate() rejected the new connection")
	}
	events.TCPRequest(second, secondID, "allowed.example:443")
	if !traffic.LogTraffic(secondID, 100, 0) {
		t.Fatal("LogTraffic() disconnected the new connection after the audited connection ended")
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

// TestLocalDisconnectKeepsIPWhileAnotherSessionStaysOpen verifies that
// disconnecting one local-mode connection does not remove the online-IP record
// while a second connection from the same IP is still active.
func TestLocalDisconnectKeepsIPWhileAnotherSessionStaysOpen(t *testing.T) {
	service := newLocalAuditTestService(t)
	authenticator := &hyAuthenticator{svc: service}
	events := &hyEventLogger{svc: service}
	sharedAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000}

	ok, firstID := authenticator.Authenticate(sharedAddr, "auth-user", 0)
	if !ok {
		t.Fatal("Authenticate() rejected first connection")
	}
	ok, secondID := authenticator.Authenticate(sharedAddr, "auth-user", 0)
	if !ok {
		t.Fatal("Authenticate() rejected second connection from same IP")
	}

	// Disconnect only the first connection.
	events.Disconnect(sharedAddr, firstID, nil)

	// The IP must still be tracked because secondID is alive.
	service.mu.RLock()
	ipSet := service.onlineIPs["auth-user"]
	_, ipPresent := ipSet[sharedAddr.IP.String()]
	service.mu.RUnlock()
	if !ipPresent {
		t.Error("onlineIPs lost the shared IP after first disconnect; second session still open")
	}

	// Now disconnect the second connection too; the IP must be gone.
	events.Disconnect(sharedAddr, secondID, nil)

	service.mu.RLock()
	ipSet = service.onlineIPs["auth-user"]
	_, ipPresent = ipSet[sharedAddr.IP.String()]
	service.mu.RUnlock()
	if ipPresent {
		t.Error("onlineIPs retained IP after both connections disconnected")
	}
}

// TestLocalLiveSessionIPsIncludesLocalSessions verifies that liveSessionIPsLocked
// reports local-mode sessions in the online-IP map, consistent with the
// keep-while-alive behaviour introduced by this fix.
func TestLocalLiveSessionIPsIncludesLocalSessions(t *testing.T) {
	service := newLocalAuditTestService(t)
	authenticator := &hyAuthenticator{svc: service}
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 6000}

	ok, _ := authenticator.Authenticate(addr, "auth-user", 0)
	if !ok {
		t.Fatal("Authenticate() rejected connection")
	}

	service.mu.RLock()
	live := service.liveSessionIPsLocked()
	service.mu.RUnlock()

	if len(live) == 0 {
		t.Fatal("liveSessionIPsLocked() returned nothing for a live local session")
	}
	uid := service.users["auth-user"].UID
	ips := live[uid]
	found := false
	for _, ip := range ips {
		if ip == addr.IP.String() {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("liveSessionIPsLocked() did not include local session IP %s; got %v", addr.IP, ips)
	}
}
