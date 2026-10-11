package tuic

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
)

var _ service.SnapshotSyncSubmitter = (*TuicService)(nil)

func TestTUICSnapshotUserTriggerAppliesAuthoritativeUsersWithoutReload(t *testing.T) {
	client := &configurablePanelClient{
		nodeInfo: &api.NodeInfo{NodeID: 8, NodeType: "Tuic", Port: 443},
		users:    []api.UserInfo{{UID: 1, UUID: "user-1", Email: "user@example.test"}},
	}
	runtime := New(client, &controller.Config{})
	events := &lifecycleEvents{}
	runtime.lifecycleMu.Lock()
	runtime.nodeInfo = cloneNodeInfo(client.nodeInfo)
	runtime.box = &fakeRuntimeInstance{events: events}
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

	waitForTUICUser(t, runtime, "user-1")
	if got, want := events.snapshot(), []string{"update-users:user-1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime events = %v, want %v", got, want)
	}
	if client.userListCalls != 1 {
		t.Fatalf("GetUserList calls = %d, want 1", client.userListCalls)
	}
	if client.nodeInfoCalls != 0 {
		t.Fatalf("GetNodeInfo calls = %d, want 0 for user-only trigger", client.nodeInfoCalls)
	}
}

func TestTUICUserSyncKeepsAppliedUsersWhenRuntimeRejectsUpdate(t *testing.T) {
	runtime := New(&configurablePanelClient{}, &controller.Config{})
	fake := &fakeRuntimeInstance{events: &lifecycleEvents{}}
	runtime.lifecycleMu.Lock()
	runtime.box = fake
	runtime.lifecycleMu.Unlock()
	applied := []api.UserInfo{{UID: 1, UUID: "applied-user"}}
	if err := runtime.syncUsers(&applied); err != nil {
		t.Fatalf("syncUsers(applied) error = %v", err)
	}

	fake.updateUsersErr = errors.New("runtime rejected users")
	next := []api.UserInfo{{UID: 2, UUID: "next-user"}}
	if err := runtime.syncUsers(&next); !errors.Is(err, fake.updateUsersErr) {
		t.Fatalf("syncUsers(next) error = %v, want %v", err, fake.updateUsersErr)
	}

	runtime.mu.RLock()
	_, keptApplied := runtime.users["applied-user"]
	_, appliedNext := runtime.users["next-user"]
	runtime.mu.RUnlock()
	if !keptApplied || appliedNext {
		t.Fatalf("users after rejected update: kept applied=%v applied next=%v", keptApplied, appliedNext)
	}
}

func waitForTUICUser(t *testing.T, runtime *TuicService, key string) {
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
			t.Fatalf("timeout waiting for TUIC user %q", key)
		case <-ticker.C:
		}
	}
}
