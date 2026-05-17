package controller

import (
	"reflect"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
)

func TestWSIntegration_ControlEventTriggersRESTFetchAndApply(t *testing.T) {
	requireV2boardWSIntegration(t)

	harness := newV2boardWSIntegrationHarness(t)
	harness.start(t)

	assertWSIntegrationHandshake(t, harness.server.waitForHandshake(t))

	runtime := waitForControllerWSRuntime(t, harness.controller)
	waitForWSRuntimeDegradedState(t, runtime, false)

	wantUsers := []api.UserInfo{{UID: 1, Email: "ws@example.com"}, {UID: 2, Email: "new@example.com"}}
	harness.api.SetUserList(wantUsers)
	harness.api.ResetCalls()
	harness.server.sendEvent(t, newV2board.WSEventUsersChanged, map[string]any{"revision": 2})

	waitForIntegrationSnapshotCount(t, harness.recorder, 1)
	waitForControllerSyncIdle(t, harness.controller)

	calls := harness.api.SnapshotCalls()
	if calls.UserList != 1 {
		t.Fatalf("expected websocket users_changed to fetch user list once, got %d", calls.UserList)
	}
	if calls.NodeInfo != 0 {
		t.Fatalf("expected websocket users_changed to avoid node fetches, got %d", calls.NodeInfo)
	}

	snapshot := harness.recorder.appliedSnapshots[0]
	if snapshot.Action.Source != syncActionSourceWS || snapshot.Action.Type != syncActionTypeSyncUsers {
		t.Fatalf("expected websocket users_changed apply action, got source=%q type=%q", snapshot.Action.Source, snapshot.Action.Type)
	}

	_, _, gotUsers := harness.controller.getStateSnapshot()
	if gotUsers == nil || !reflect.DeepEqual(*gotUsers, wantUsers) {
		t.Fatalf("expected controller user state to match websocket-triggered REST snapshot, got %#v", gotUsers)
	}
}

func TestWSIntegration_DisconnectReconnectTriggersResyncAll(t *testing.T) {
	requireV2boardWSIntegration(t)

	harness := newV2boardWSIntegrationHarness(t)
	harness.start(t)

	_ = harness.server.waitForHandshake(t)
	runtime := waitForControllerWSRuntime(t, harness.controller)
	waitForWSRuntimeDegradedState(t, runtime, false)

	wantNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 9443, SpeedLimit: 200}
	wantUsers := []api.UserInfo{{UID: 1, Email: "reconnect@example.com"}}
	harness.api.SetNodeInfo(wantNode)
	harness.api.SetUserList(wantUsers)
	harness.api.ResetCalls()

	harness.server.closeCurrentConnection(t)
	_ = harness.server.waitForHandshake(t)
	waitForWSRuntimeDegradedState(t, runtime, false)

	waitForIntegrationSnapshotCount(t, harness.recorder, 1)
	waitForControllerSyncIdle(t, harness.controller)

	calls := harness.api.SnapshotCalls()
	if calls.NodeInfo != 1 || calls.UserList != 1 {
		t.Fatalf("expected reconnect resync to fetch node+users once, got node=%d users=%d", calls.NodeInfo, calls.UserList)
	}

	snapshot := harness.recorder.appliedSnapshots[0]
	if snapshot.Action.Source != syncActionSourceReconnect || snapshot.Action.Type != syncActionTypeResyncAll {
		t.Fatalf("expected reconnect apply action to be ResyncAll from reconnect, got source=%q type=%q", snapshot.Action.Source, snapshot.Action.Type)
	}

	gotNode, _, gotUsers := harness.controller.getStateSnapshot()
	if gotNode == nil || gotNode.Port != wantNode.Port || gotNode.SpeedLimit != wantNode.SpeedLimit {
		t.Fatalf("expected controller node state to refresh after reconnect, got %#v", gotNode)
	}
	if gotUsers == nil || !reflect.DeepEqual(*gotUsers, wantUsers) {
		t.Fatalf("expected controller users to refresh after reconnect, got %#v", gotUsers)
	}
}

func TestWSIntegration_BadEndpointDegradesToPollingOnly(t *testing.T) {
	requireV2boardWSIntegration(t)

	harness := newV2boardWSIntegrationHarness(t)
	harness.controller.config.WebSocketConfig.Endpoint = harness.server.badEndpoint()
	harness.start(t)

	runtime := waitForControllerWSRuntime(t, harness.controller)
	waitForWSRuntimeDegradedState(t, runtime, true)

	wantNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 7443, SpeedLimit: 300}
	wantUsers := []api.UserInfo{{UID: 9, Email: "poll@example.com"}}
	harness.api.SetNodeInfo(wantNode)
	harness.api.SetUserList(wantUsers)
	harness.api.ResetCalls()

	harness.controller.startAt = time.Now().Add(-2 * time.Hour)
	if err := harness.controller.nodeInfoMonitor(); err != nil {
		t.Fatalf("nodeInfoMonitor returned error: %v", err)
	}

	waitForIntegrationSnapshotCount(t, harness.recorder, 1)
	waitForControllerSyncIdle(t, harness.controller)

	snapshot := harness.recorder.appliedSnapshots[0]
	if snapshot.Action.Source != syncActionSourcePolling || snapshot.Action.Type != syncActionTypeResyncAll {
		t.Fatalf("expected degraded mode to keep polling ResyncAll active, got source=%q type=%q", snapshot.Action.Source, snapshot.Action.Type)
	}

	gotNode, _, gotUsers := harness.controller.getStateSnapshot()
	if gotNode == nil || gotNode.Port != wantNode.Port {
		t.Fatalf("expected polling-only node refresh after websocket handshake failure, got %#v", gotNode)
	}
	if gotUsers == nil || !reflect.DeepEqual(*gotUsers, wantUsers) {
		t.Fatalf("expected polling-only user refresh after websocket handshake failure, got %#v", gotUsers)
	}
}
