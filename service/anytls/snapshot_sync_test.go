package anytls

import (
	"context"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
)

var _ service.SnapshotSyncSubmitter = (*AnyTLSService)(nil)

func TestAnyTLSSnapshotUserTriggerAppliesAuthoritativeUsersWithoutReload(t *testing.T) {
	client := &configurablePanelClient{
		nodeInfo: &api.NodeInfo{NodeID: 7, NodeType: "AnyTLS", Port: 443},
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

	for range 5000 {
		runtime.SubmitSnapshotSync(service.SnapshotSyncTrigger{
			Scope:  service.SnapshotSyncUsers,
			Source: service.SnapshotSyncSourceWebSocket,
		})
	}

	waitForAnyTLSUser(t, runtime, "user-1")
	waitForAnyTLSSnapshotExecutions(t, runtime, 1)
	if client.userListCalls != 1 {
		t.Fatalf("GetUserList calls = %d, want 1", client.userListCalls)
	}
	if client.nodeInfoCalls != 0 {
		t.Fatalf("GetNodeInfo calls = %d, want 0 for user-only trigger", client.nodeInfoCalls)
	}

	for range 5000 {
		runtime.SubmitSnapshotSync(service.SnapshotSyncTrigger{
			Scope:  service.SnapshotSyncNode,
			Source: service.SnapshotSyncSourceWebSocket,
		})
	}
	waitForAnyTLSSnapshotExecutions(t, runtime, 2)
	if client.nodeInfoCalls != 1 {
		t.Fatalf("GetNodeInfo calls = %d, want 1 for config burst", client.nodeInfoCalls)
	}
	if snapshot := runtime.syncCoordinator.Snapshot(); snapshot.Submitted != 10000 {
		t.Fatalf("submitted triggers = %d, want 10000", snapshot.Submitted)
	}

	runtime.config.UpdatePeriodic = 1
	runtime.lifecycleMu.Lock()
	runtime.startAt = time.Now().Add(-2 * time.Second)
	runtime.lifecycleMu.Unlock()
	if err := runtime.userMonitorContext(context.Background()); err != nil {
		t.Fatalf("polling user monitor: %v", err)
	}
	waitForAnyTLSSnapshotExecutions(t, runtime, 3)
	if client.userListCalls != 2 {
		t.Fatalf("GetUserList calls after polling = %d, want 2", client.userListCalls)
	}
}

type lateAnyTLSUserClient struct {
	*configurablePanelClient
	entered chan struct{}
	release chan struct{}
}

func (c *lateAnyTLSUserClient) GetUserListContext(context.Context) (*[]api.UserInfo, error) {
	close(c.entered)
	<-c.release
	return &c.users, nil
}

func TestAnyTLSSnapshotCancellationDoesNotPublishLateUsers(t *testing.T) {
	client := &lateAnyTLSUserClient{
		configurablePanelClient: &configurablePanelClient{
			nodeInfo: &api.NodeInfo{NodeID: 7, NodeType: "AnyTLS", Port: 443},
			users:    []api.UserInfo{{UID: 2, UUID: "late-user"}},
		},
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	runtime := New(client, &controller.Config{})
	runtime.lifecycleMu.Lock()
	runtime.nodeInfo = cloneNodeInfo(client.nodeInfo)
	runtime.state = stateRunning
	runtime.lifecycleMu.Unlock()
	initialUsers := []api.UserInfo{{UID: 1, UUID: "applied-user"}}
	runtime.syncUsers(&initialUsers)

	if err := runtime.syncCoordinator.StartContext(context.Background()); err != nil {
		t.Fatalf("start snapshot coordinator: %v", err)
	}
	runtime.SubmitSnapshotSync(service.SnapshotSyncTrigger{Scope: service.SnapshotSyncUsers})
	waitForAnyTLSSignal(t, client.entered, "late user fetch")
	if err := runtime.syncCoordinator.StopContext(context.Background()); err != nil {
		t.Fatalf("stop snapshot coordinator: %v", err)
	}
	close(client.release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.syncCoordinator.WaitContext(ctx); err != nil {
		t.Fatalf("wait snapshot coordinator: %v", err)
	}

	runtime.mu.RLock()
	_, keptApplied := runtime.users["applied-user"]
	_, publishedLate := runtime.users["late-user"]
	runtime.mu.RUnlock()
	if !keptApplied || publishedLate {
		t.Fatalf("users after cancellation: kept applied=%v published late=%v", keptApplied, publishedLate)
	}
}

func waitForAnyTLSUser(t *testing.T, runtime *AnyTLSService, key string) {
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
			t.Fatalf("timeout waiting for AnyTLS user %q", key)
		case <-ticker.C:
		}
	}
}

func waitForAnyTLSSnapshotExecutions(t *testing.T, runtime *AnyTLSService, want uint64) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot := runtime.syncCoordinator.Snapshot()
		if snapshot.Executions >= want && !snapshot.InFlight {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("timeout waiting for %d snapshot executions; got %+v", want, snapshot)
		case <-ticker.C:
		}
	}
}

func waitForAnyTLSSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for %s", name)
	}
}
