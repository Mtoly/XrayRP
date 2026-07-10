package controller

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
)

type trackingSyncExecutor struct {
	delegate syncActionExecutor

	mu        sync.Mutex
	calls     []syncActionType
	active    int
	maxActive int
	started   chan syncActionType
	blocked   map[int]chan struct{}
}

func newTrackingSyncExecutor(delegate syncActionExecutor) *trackingSyncExecutor {
	return &trackingSyncExecutor{
		delegate: delegate,
		started:  make(chan syncActionType, 32),
		blocked:  make(map[int]chan struct{}),
	}
}

func (e *trackingSyncExecutor) blockCall(index int) chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()

	release := make(chan struct{})
	e.blocked[index] = release
	return release
}

func (e *trackingSyncExecutor) ExecuteSyncAction(ctx context.Context, action syncAction) error {
	e.mu.Lock()
	callIndex := len(e.calls) + 1
	e.calls = append(e.calls, action.Type)
	e.active++
	if e.active > e.maxActive {
		e.maxActive = e.active
	}
	release := e.blocked[callIndex]
	e.mu.Unlock()

	e.started <- action.Type

	if release != nil {
		<-release
	}

	err := e.delegate.ExecuteSyncAction(ctx, action)

	e.mu.Lock()
	e.active--
	e.mu.Unlock()
	return err
}

func (e *trackingSyncExecutor) Calls() []syncActionType {
	e.mu.Lock()
	defer e.mu.Unlock()

	calls := make([]syncActionType, len(e.calls))
	copy(calls, e.calls)
	return calls
}

func (e *trackingSyncExecutor) MaxActive() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.maxActive
}

func waitForAppliedSnapshots(t *testing.T, recorder *syncApplyRecorder, want int) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if recorder.appliedSnapshotCount() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %d applied snapshot(s), got %d", want, recorder.appliedSnapshotCount())
}

func TestDualActive_WSTriggerThenPollingConverges(t *testing.T) {
	wsUsers := []api.UserInfo{{UID: 1, Email: "ws@example.com"}}
	pollUsers := []api.UserInfo{{UID: 1, Email: "poll@example.com"}, {UID: 2, Email: "new@example.com"}}
	pollRules := []api.DetectRule{{ID: 11, Pattern: regexp.MustCompile("poll.example")}}
	wsNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, SpeedLimit: 100, RoutePolicy: routePolicyWithCandidate("ws-candidate")}
	pollNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 8443, SpeedLimit: 200, RoutePolicy: routePolicyWithCandidate("poll-candidate")}
	fakeAPI := &fakeSyncApplyAPI{
		nodeInfo: wsNode,
		userList: &wsUsers,
		ruleList: &[]api.DetectRule{},
	}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	controller.config.ListenIP = "127.0.0.1"
	controller.startAt = time.Now().Add(-time.Minute)

	initialNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 80, SpeedLimit: 10, RoutePolicy: routePolicyWithCandidate("initial-candidate")}
	initialUsers := []api.UserInfo{{UID: 1, Email: "initial@example.com"}}
	controller.setNodeState(initialNode, controller.buildNodeTagFrom(initialNode))
	controller.setUserList(&initialUsers)

	coordinator := newSyncCoordinator(controller)
	defer coordinator.Stop()
	controller.syncCoordinator = coordinator

	client := newStubWSRuntimeClient()
	runtime := newWSRuntime(newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client}).Build, coordinator, wsRuntimeOptions{ReconnectBackoff: time.Millisecond, ResyncOnReconnect: true})
	runtime.Start()
	defer runtime.Stop()

	client.emitControlEvent(newV2board.WSEventUsersChanged)
	waitForAppliedSnapshots(t, recorder, 1)
	waitForCoordinatorIdle(t, coordinator)

	stateNode, stateTag, stateUsers := controller.getStateSnapshot()
	if stateNode != initialNode {
		t.Fatalf("expected ws user sync to keep node state unchanged, got %#v", stateNode)
	}
	if stateTag != controller.buildNodeTagFrom(initialNode) {
		t.Fatalf("expected ws user sync to keep node tag unchanged, got %q", stateTag)
	}
	if stateUsers == nil || !reflect.DeepEqual(*stateUsers, wsUsers) {
		t.Fatalf("expected ws user sync to apply websocket snapshot users, got %#v", stateUsers)
	}
	firstSnapshot, ok := recorder.appliedSnapshotAt(0)
	if !ok {
		t.Fatal("expected first applied snapshot")
	}
	if firstSnapshot.Action.Source != syncActionSourceWS || firstSnapshot.Action.Type != syncActionTypeSyncUsers {
		t.Fatalf("expected first apply from ws user sync, got source=%q type=%q", firstSnapshot.Action.Source, firstSnapshot.Action.Type)
	}

	fakeAPI.nodeInfo = pollNode
	fakeAPI.userList = &pollUsers
	fakeAPI.ruleList = &pollRules

	if err := controller.nodeInfoMonitor(); err != nil {
		t.Fatalf("nodeInfoMonitor returned error: %v", err)
	}
	waitForAppliedSnapshots(t, recorder, 2)
	waitForCoordinatorIdle(t, coordinator)

	stateNode, _, stateUsers = controller.getStateSnapshot()
	if stateNode == nil || stateNode.Port != pollNode.Port || stateNode.SpeedLimit != pollNode.SpeedLimit {
		t.Fatalf("expected polling resync to converge node state to latest snapshot, got %#v", stateNode)
	}
	if stateUsers == nil || !reflect.DeepEqual(*stateUsers, pollUsers) {
		t.Fatalf("expected polling resync to converge users to latest snapshot, got %#v", stateUsers)
	}
	secondSnapshot, ok := recorder.appliedSnapshotAt(1)
	if !ok {
		t.Fatal("expected second applied snapshot")
	}
	if secondSnapshot.Action.Source != syncActionSourcePolling || secondSnapshot.Action.Type != syncActionTypeResyncAll {
		t.Fatalf("expected second apply from polling resync, got source=%q type=%q", secondSnapshot.Action.Source, secondSnapshot.Action.Type)
	}
	state := controller.runtimeStateSnapshot()
	if recorder.lastRuleTag != state.tag || len(recorder.lastRules) != 1 || recorder.lastRules[0].Pattern.String() != "poll.example" {
		t.Fatalf("expected polling correction to update rules on converged runtime, got tag=%q rules=%#v", recorder.lastRuleTag, recorder.lastRules)
	}
}

func TestDualActive_DuplicateWSAndPollingDoNotRunInfiniteConcurrentSyncs(t *testing.T) {
	users := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	rules := []api.DetectRule{{ID: 21, Pattern: regexp.MustCompile("example")}}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, SpeedLimit: 100, RoutePolicy: routePolicyWithCandidate("candidate")}
	fakeAPI := &fakeSyncApplyAPI{nodeInfo: node, userList: &users, ruleList: &rules}
	controller, _ := newTestSyncApplyController(fakeAPI)
	controller.config.ListenIP = "127.0.0.1"
	controller.startAt = time.Now().Add(-time.Minute)
	controller.setNodeState(node, controller.buildNodeTagFrom(node))
	controller.setUserList(&users)

	executor := newTrackingSyncExecutor(controller)
	releaseFirst := executor.blockCall(1)
	coordinator := newSyncCoordinator(executor)
	defer coordinator.Stop()
	controller.syncCoordinator = coordinator

	client := newStubWSRuntimeClient()
	runtime := newWSRuntime(newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client}).Build, coordinator, wsRuntimeOptions{ReconnectBackoff: time.Millisecond, ResyncOnReconnect: true})
	runtime.Start()
	defer runtime.Stop()

	client.emitControlEvent(newV2board.WSEventUsersChanged)
	waitForCoordinatorAction(t, executor.started, syncActionTypeSyncUsers)

	for i := 0; i < 8; i++ {
		client.emitControlEvent(newV2board.WSEventUsersChanged)
		if err := controller.nodeInfoMonitor(); err != nil {
			t.Fatalf("nodeInfoMonitor returned error: %v", err)
		}
	}

	runtime.Stop()
	close(releaseFirst)
	waitForCoordinatorIdle(t, coordinator)

	gotCalls := executor.Calls()
	wantCalls := []syncActionType{syncActionTypeSyncUsers, syncActionTypeResyncAll}
	if !reflect.DeepEqual(gotCalls, wantCalls) {
		t.Fatalf("expected duplicate ws+polling work to collapse into finite serial syncs, got %v want %v", gotCalls, wantCalls)
	}
	if maxActive := executor.MaxActive(); maxActive != 1 {
		t.Fatalf("expected dual-active sync execution to stay serial, got max concurrency %d", maxActive)
	}
}

func TestDualActive_HandshakeFailureDegradesToPollingOnly(t *testing.T) {
	users := []api.UserInfo{{UID: 1, Email: "poll@example.com"}}
	rules := []api.DetectRule{{ID: 31, Pattern: regexp.MustCompile("poll-only")}}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, SpeedLimit: 100, RoutePolicy: routePolicyWithCandidate("poll-only")}
	fakeAPI := &fakeSyncApplyAPI{nodeInfo: node, userList: &users, ruleList: &rules}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	controller.config.ListenIP = "127.0.0.1"
	controller.startAt = time.Now().Add(-time.Minute)
	controller.setNodeState(node, controller.buildNodeTagFrom(node))
	controller.setUserList(&users)

	coordinator := newSyncCoordinator(controller)
	defer coordinator.Stop()
	controller.syncCoordinator = coordinator

	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{err: errors.New("handshake failed")})
	runtime := newWSRuntime(factory.Build, coordinator, wsRuntimeOptions{ReconnectBackoff: 25 * time.Millisecond, ResyncOnReconnect: true})
	runtime.sleep = func(ctx context.Context, _ time.Duration) bool {
		<-ctx.Done()
		return false
	}
	runtime.Start()
	defer runtime.Stop()

	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, true)

	if err := controller.nodeInfoMonitor(); err != nil {
		t.Fatalf("nodeInfoMonitor returned error: %v", err)
	}
	waitForAppliedSnapshots(t, recorder, 1)
	waitForCoordinatorIdle(t, coordinator)

	if recorder.appliedSnapshotCount() != 1 {
		t.Fatalf("expected polling-only degradation to still apply one snapshot, got %d", recorder.appliedSnapshotCount())
	}
	pollingSnapshot, ok := recorder.appliedSnapshotAt(0)
	if !ok {
		t.Fatal("expected polling snapshot after degradation")
	}
	if pollingSnapshot.Action.Source != syncActionSourcePolling || pollingSnapshot.Action.Type != syncActionTypeResyncAll {
		t.Fatalf("expected polling to stay active after handshake failure, got source=%q type=%q", pollingSnapshot.Action.Source, pollingSnapshot.Action.Type)
	}
	if !runtime.Degraded() {
		t.Fatal("expected runtime to remain degraded after handshake failure")
	}
}

func TestDualActive_ParseErrorDoesNotKillWSChannel(t *testing.T) {
	users := []api.UserInfo{{UID: 1, Email: "after-parse@example.com"}}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, SpeedLimit: 100, RoutePolicy: routePolicyWithCandidate("after-parse")}
	fakeAPI := &fakeSyncApplyAPI{nodeInfo: node, userList: &users, ruleList: &[]api.DetectRule{}}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	controller.config.ListenIP = "127.0.0.1"
	controller.setNodeState(node, controller.buildNodeTagFrom(node))
	controller.setUserList(&[]api.UserInfo{{UID: 1, Email: "before-parse@example.com"}})

	coordinator := newSyncCoordinator(controller)
	defer coordinator.Stop()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	runtime := newWSRuntime(factory.Build, coordinator, wsRuntimeOptions{ReconnectBackoff: 25 * time.Millisecond, ResyncOnReconnect: true})
	runtime.Start()
	defer runtime.Stop()

	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	client.emitParseError()
	waitForAppliedSnapshots(t, recorder, 1)
	waitForCoordinatorIdle(t, coordinator)
	if runtime.Degraded() {
		t.Fatal("expected parse error isolation to keep websocket runtime healthy")
	}
	parseSnapshot, ok := recorder.appliedSnapshotAt(0)
	if !ok {
		t.Fatal("expected parse-error resync snapshot")
	}
	if parseSnapshot.Action.Source != syncActionSourceWS || parseSnapshot.Action.Type != syncActionTypeResyncAll || parseSnapshot.Action.Metadata.Trigger != syncActionTriggerWSParseError {
		t.Fatalf("expected parse error to submit ws ResyncAll, got source=%q type=%q trigger=%q", parseSnapshot.Action.Source, parseSnapshot.Action.Type, parseSnapshot.Action.Metadata.Trigger)
	}

	client.emitControlEvent(newV2board.WSEventUsersChanged)
	waitForAppliedSnapshots(t, recorder, 2)
	waitForCoordinatorIdle(t, coordinator)

	if recorder.appliedSnapshotCount() != 2 {
		t.Fatalf("expected parse-error resync and subsequent websocket event, got %d snapshots", recorder.appliedSnapshotCount())
	}
	wsSnapshot, ok := recorder.appliedSnapshotAt(1)
	if !ok {
		t.Fatal("expected websocket snapshot after parse error")
	}
	if wsSnapshot.Action.Source != syncActionSourceWS || wsSnapshot.Action.Type != syncActionTypeSyncUsers {
		t.Fatalf("expected subsequent websocket event to remain on ws path, got source=%q type=%q", wsSnapshot.Action.Source, wsSnapshot.Action.Type)
	}
}

func TestDualActive_ReconnectForcesResyncAll(t *testing.T) {
	users := []api.UserInfo{{UID: 1, Email: "reconnect@example.com"}}
	rules := []api.DetectRule{{ID: 41, Pattern: regexp.MustCompile("reconnect")}}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, SpeedLimit: 100, RoutePolicy: routePolicyWithCandidate("reconnect")}
	fakeAPI := &fakeSyncApplyAPI{nodeInfo: node, userList: &users, ruleList: &rules}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	controller.config.ListenIP = "127.0.0.1"
	controller.setNodeState(node, controller.buildNodeTagFrom(node))
	controller.setUserList(&users)

	coordinator := newSyncCoordinator(controller)
	defer coordinator.Stop()

	firstClient := newStubWSRuntimeClient()
	secondClient := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(
		wsRuntimeFactoryResult{client: firstClient},
		wsRuntimeFactoryResult{client: secondClient},
	)
	runtime := newWSRuntime(factory.Build, coordinator, wsRuntimeOptions{ReconnectBackoff: 25 * time.Millisecond, ResyncOnReconnect: true})
	backoffCalled := make(chan time.Duration, 1)
	releaseBackoff := make(chan struct{})
	runtime.sleep = func(ctx context.Context, d time.Duration) bool {
		backoffCalled <- d
		select {
		case <-ctx.Done():
			return false
		case <-releaseBackoff:
			return true
		}
	}
	runtime.Start()
	defer runtime.Stop()

	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	firstClient.failTransport()
	waitForWSRuntimeBackoff(t, backoffCalled, 25*time.Millisecond)
	waitForWSRuntimeDegradedState(t, runtime, true)
	waitForAppliedSnapshots(t, recorder, 1)
	disconnectSnapshot, ok := recorder.appliedSnapshotAt(0)
	if !ok {
		t.Fatal("expected disconnect clear snapshot")
	}
	if disconnectSnapshot.Action.Source != syncActionSourceReconnect || disconnectSnapshot.Action.Type != syncActionTypeClearGlobalDevices || disconnectSnapshot.Action.Metadata.Trigger != syncActionTriggerWSDisconnect {
		t.Fatalf("expected disconnect to clear global devices, got source=%q type=%q trigger=%q", disconnectSnapshot.Action.Source, disconnectSnapshot.Action.Type, disconnectSnapshot.Action.Metadata.Trigger)
	}

	close(releaseBackoff)

	waitForWSRuntimeAttempt(t, factory, 2)
	waitForWSRuntimeDegradedState(t, runtime, false)
	waitForAppliedSnapshots(t, recorder, 2)
	waitForCoordinatorIdle(t, coordinator)

	if recorder.appliedSnapshotCount() != 2 {
		t.Fatalf("expected disconnect clear and reconnect recovery snapshots, got %d", recorder.appliedSnapshotCount())
	}
	reconnectSnapshot, ok := recorder.appliedSnapshotAt(1)
	if !ok {
		t.Fatal("expected reconnect snapshot")
	}
	if reconnectSnapshot.Action.Source != syncActionSourceReconnect || reconnectSnapshot.Action.Type != syncActionTypeResyncAll {
		t.Fatalf("expected reconnect to force ResyncAll, got source=%q type=%q", reconnectSnapshot.Action.Source, reconnectSnapshot.Action.Type)
	}
}
