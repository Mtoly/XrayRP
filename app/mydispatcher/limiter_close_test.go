package mydispatcher

import (
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/limiter"
)

func TestDefaultDispatcherCloseClosesLimiter(t *testing.T) {
	admissionLimiter := limiter.New()
	dispatcher := &DefaultDispatcher{Limiter: admissionLimiter}

	if err := dispatcher.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
	if err := admissionLimiter.AddInboundLimiter("inbound", 0, &users, nil); err == nil {
		t.Fatal("limiter mutation after dispatcher Close() error = nil")
	}
	if err := dispatcher.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
