package limiter

import (
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestRuntimeUserKeyMatchesOpaqueControllerTag(t *testing.T) {
	users := []api.UserInfo{{UID: 17, Email: "node-tag|17", UUID: "test-user-uuid"}}
	limiter := New()
	t.Cleanup(func() {
		if err := limiter.Close(); err != nil {
			t.Errorf("Limiter.Close() error = %v", err)
		}
	})

	if err := limiter.AddInboundLimiter("node-tag", 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	if _, _, rejected := limiter.GetUserBucket("node-tag", "node-tag|17", "192.0.2.1"); rejected {
		t.Fatal("opaque runtime user key was rejected")
	}
}
