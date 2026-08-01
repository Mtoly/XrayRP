package hysteria2

import (
	"context"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
)

var _ service.SnapshotSyncSubmitter = (*Hysteria2Service)(nil)

func TestHysteria2SnapshotUserTriggerAppliesAuthoritativeUsersWithoutReload(t *testing.T) {
	client := &configurablePanelClient{
		nodeInfo: &api.NodeInfo{NodeID: 9, NodeType: "Hysteria2", Port: 443},
		users:    []api.UserInfo{{UID: 1, UUID: "user-1", Email: "user@example.test"}},
	}
	runtime := New(client, &controller.Config{})
	runtime.lifecycleMu.Lock()
	runtime.nodeInfo = cloneNodeInfo(client.nodeInfo)
	runtime.state = stateRunning
	runtime.lifecycleMu.Unlock()

	if err := runtime.syncCoordinator.StartContext(context.Background()); err != nil {
		t.Fatalf("start snapshot coordinator: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := runtime.syncCoordinator.CloseContext(ctx); err != nil {
			t.Fatalf("close snapshot coordinator: %v", err)
		}
	})

	runtime.SubmitSnapshotSync(service.SnapshotSyncTrigger{
		Scope:  service.SnapshotSyncUsers,
		Source: service.SnapshotSyncSourceWebSocket,
	})

	waitForHysteria2User(t, runtime, "user-1")
	if client.userListCalls != 1 {
		t.Fatalf("GetUserList calls = %d, want 1", client.userListCalls)
	}
	if client.nodeInfoCalls != 0 {
		t.Fatalf("GetNodeInfo calls = %d, want 0 for user-only trigger", client.nodeInfoCalls)
	}
}

func waitForHysteria2User(t *testing.T, runtime *Hysteria2Service, key string) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		runtime.mu.RLock()
		_, found := runtime.users[key]
		runtime.mu.RUnlock()
		if found {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("timeout waiting for Hysteria2 user %q", key)
		case <-ticker.C:
		}
	}
}
