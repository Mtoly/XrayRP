package controller

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/limiter"
)

type fakeControllerAPI struct {
	nodeInfo *api.NodeInfo
	userList *[]api.UserInfo
}

func newFakeControllerAPI() *fakeControllerAPI {
	users := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	return &fakeControllerAPI{
		nodeInfo: &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, SpeedLimit: 100},
		userList: &users,
	}
}

func (f *fakeControllerAPI) GetNodeInfo() (*api.NodeInfo, error)               { return f.nodeInfo, nil }
func (f *fakeControllerAPI) GetXrayRCertConfig() (*api.XrayRCertConfig, error) { return nil, nil }
func (f *fakeControllerAPI) GetUserList() (*[]api.UserInfo, error)             { return f.userList, nil }
func (f *fakeControllerAPI) GetAliveList() (map[int][]string, error)           { return nil, nil }
func (f *fakeControllerAPI) ReportNodeStatus(*api.NodeStatus) error            { return nil }
func (f *fakeControllerAPI) ReportNodeOnlineUsers(*[]api.OnlineUser) error     { return nil }
func (f *fakeControllerAPI) ReportUserTraffic(*[]api.UserTraffic) error        { return nil }
func (f *fakeControllerAPI) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: "https://panel.example.com", NodeID: 1, NodeType: "V2ray"}
}
func (f *fakeControllerAPI) GetNodeRule() (*[]api.DetectRule, error) {
	rules := []api.DetectRule{}
	return &rules, nil
}
func (f *fakeControllerAPI) ReportIllegal(*[]api.DetectResult) error { return nil }
func (f *fakeControllerAPI) Debug()                                  {}

type fakeControllerWSCapableAPI struct {
	*fakeControllerAPI
	wsConfig *api.WSConfig
}

func newFakeControllerWSCapableAPI() *fakeControllerWSCapableAPI {
	base := newFakeControllerAPI()
	return &fakeControllerWSCapableAPI{
		fakeControllerAPI: base,
		wsConfig: &api.WSConfig{
			APIHost:  "https://panel.example.com",
			NodeID:   1,
			Key:      "secret",
			NodeType: "v2ray",
		},
	}
}

func (f *fakeControllerWSCapableAPI) GetWSConfig() *api.WSConfig { return f.wsConfig }

type fakeLifecycleCoordinator struct {
	actions []syncAction
	order   *[]string
	stopped bool
}

func (f *fakeLifecycleCoordinator) Submit(action syncAction) {
	f.actions = append(f.actions, action)
}

func (f *fakeLifecycleCoordinator) Stop() {
	f.stopped = true
	if f.order != nil {
		*f.order = append(*f.order, "coordinator")
	}
}

type fakeLifecycleWSRuntime struct {
	submitter   syncActionSubmitter
	startAction *syncAction
	started     bool
	stopped     bool
	order       *[]string
}

func (f *fakeLifecycleWSRuntime) Start() {
	f.started = true
	if f.startAction != nil {
		f.submitter.Submit(*f.startAction)
	}
}

func (f *fakeLifecycleWSRuntime) Stop() {
	f.stopped = true
	if f.order != nil {
		*f.order = append(*f.order, "ws")
	}
}

func waitForControllerPeriodicBootstrap() {
	// Controller.Start() launches periodic tasks in goroutines and each Periodic
	// executes once immediately. Give that bootstrap execute a moment to observe
	// the future startAt guard before tests mutate controller state.
	time.Sleep(30 * time.Millisecond)
}

func newLifecycleTestController(apiClient api.API, enableWS bool) *Controller {
	return &Controller{
		config: &Config{
			ListenIP:       "127.0.0.1",
			UpdatePeriodic: 3600,
			DisableGetRule: true,
			WebSocketConfig: &WebSocketConfig{
				Enable:            enableWS,
				Endpoint:          "wss://panel.example.com/custom-ws",
				HeartbeatInterval: 30,
				ReconnectBackoff:  5,
				ResyncOnReconnect: true,
			},
		},
		apiClient: apiClient,
		panelType: "NewV2board",
		logger:    log.NewEntry(log.New()),
		startAt:   time.Now().Add(time.Hour),
		syncApplyHooks: syncApplyHooks{
			addNewTag:         func(*api.NodeInfo, string) error { return nil },
			addNewUser:        func(*[]api.UserInfo, *api.NodeInfo, string) error { return nil },
			addInboundLimiter: func(string, uint64, *[]api.UserInfo, *limiter.GlobalDeviceLimitConfig) error { return nil },
			updateRule:        func(string, []api.DetectRule) error { return nil },
		},
	}
}

func TestController_WSStartInitializesRuntimeWhenCapableAndEnabled(t *testing.T) {
	apiClient := newFakeControllerWSCapableAPI()
	controller := newLifecycleTestController(apiClient, true)

	coordinator := &fakeLifecycleCoordinator{}
	var submitter syncActionSubmitter
	wsRuntime := &fakeLifecycleWSRuntime{}
	controller.syncCoordinatorFactory = func(syncActionExecutor) syncCoordinatorLifecycle {
		return coordinator
	}
	controller.wsRuntimeFactory = func(s syncActionSubmitter) (wsRuntimeLifecycle, error) {
		submitter = s
		wsRuntime.submitter = s
		return wsRuntime, nil
	}

	if err := controller.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	waitForControllerPeriodicBootstrap()
	defer controller.Close()

	if controller.syncCoordinator != coordinator {
		t.Fatal("expected controller to keep sync coordinator runtime state")
	}
	if controller.wsRuntime != wsRuntime {
		t.Fatal("expected controller to keep websocket runtime state")
	}
	if submitter != coordinator {
		t.Fatal("expected websocket runtime to receive controller coordinator as submitter")
	}
	if !wsRuntime.started {
		t.Fatal("expected websocket runtime to start when panel is ws capable and config enabled")
	}
}

func TestController_DualActivePollingAndWSShareCoordinator(t *testing.T) {
	apiClient := newFakeControllerWSCapableAPI()
	controller := newLifecycleTestController(apiClient, true)

	coordinator := &fakeLifecycleCoordinator{}
	wsAction := newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"})
	wsRuntime := &fakeLifecycleWSRuntime{startAction: &wsAction}
	controller.syncCoordinatorFactory = func(syncActionExecutor) syncCoordinatorLifecycle {
		return coordinator
	}
	controller.wsRuntimeFactory = func(s syncActionSubmitter) (wsRuntimeLifecycle, error) {
		wsRuntime.submitter = s
		return wsRuntime, nil
	}

	if err := controller.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	waitForControllerPeriodicBootstrap()
	defer controller.Close()

	controller.startAt = time.Now().Add(-2 * time.Hour)
	if err := controller.nodeInfoMonitor(); err != nil {
		t.Fatalf("nodeInfoMonitor returned error: %v", err)
	}

	if len(coordinator.actions) != 2 {
		t.Fatalf("expected ws and polling to submit two actions through same coordinator, got %d", len(coordinator.actions))
	}
	if coordinator.actions[0].Source != syncActionSourceWS {
		t.Fatalf("expected first action from ws runtime, got %q", coordinator.actions[0].Source)
	}
	if coordinator.actions[1].Source != syncActionSourcePolling {
		t.Fatalf("expected second action from polling path, got %q", coordinator.actions[1].Source)
	}
	if wsRuntime.submitter != coordinator {
		t.Fatal("expected websocket runtime to share the same coordinator instance")
	}
}

func TestController_DualActiveCloseStopsRuntimeAndCoordinator(t *testing.T) {
	apiClient := newFakeControllerWSCapableAPI()
	controller := newLifecycleTestController(apiClient, true)

	order := []string{}
	coordinator := &fakeLifecycleCoordinator{order: &order}
	wsRuntime := &fakeLifecycleWSRuntime{order: &order}
	controller.syncCoordinatorFactory = func(syncActionExecutor) syncCoordinatorLifecycle {
		return coordinator
	}
	controller.wsRuntimeFactory = func(s syncActionSubmitter) (wsRuntimeLifecycle, error) {
		wsRuntime.submitter = s
		return wsRuntime, nil
	}

	if err := controller.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	waitForControllerPeriodicBootstrap()

	if err := controller.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	if !wsRuntime.stopped {
		t.Fatal("expected websocket runtime to stop during controller close")
	}
	if !coordinator.stopped {
		t.Fatal("expected sync coordinator to stop during controller close")
	}
	if len(order) != 2 || order[0] != "ws" || order[1] != "coordinator" {
		t.Fatalf("expected close order ws -> coordinator after periodic tasks, got %v", order)
	}
}

func TestController_WSDisabledStaysPollingOnly(t *testing.T) {
	apiClient := newFakeControllerWSCapableAPI()
	controller := newLifecycleTestController(apiClient, false)

	coordinator := &fakeLifecycleCoordinator{}
	wsFactoryCalled := false
	controller.syncCoordinatorFactory = func(syncActionExecutor) syncCoordinatorLifecycle {
		return coordinator
	}
	controller.wsRuntimeFactory = func(syncActionSubmitter) (wsRuntimeLifecycle, error) {
		wsFactoryCalled = true
		return &fakeLifecycleWSRuntime{}, nil
	}

	if err := controller.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	waitForControllerPeriodicBootstrap()
	defer controller.Close()

	if wsFactoryCalled {
		t.Fatal("expected websocket runtime factory to stay disabled when config enable=false")
	}
	if controller.wsRuntime != nil {
		t.Fatal("expected controller to remain polling-only when websocket is disabled")
	}

	controller.startAt = time.Now().Add(-2 * time.Hour)
	if err := controller.nodeInfoMonitor(); err != nil {
		t.Fatalf("nodeInfoMonitor returned error: %v", err)
	}
	if len(coordinator.actions) != 1 {
		t.Fatalf("expected polling-only mode to submit one polling action, got %d", len(coordinator.actions))
	}
	if coordinator.actions[0].Source != syncActionSourcePolling {
		t.Fatalf("expected polling-only action source, got %q", coordinator.actions[0].Source)
	}
}
