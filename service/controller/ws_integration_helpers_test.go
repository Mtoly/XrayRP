package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Mtoly/XrayRP/api"
)

const v2boardWSIntegrationEnv = "XRAYRP_RUN_V2BOARD_WS_INTEGRATION"

func requireV2boardWSIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(v2boardWSIntegrationEnv) != "1" {
		t.Skipf("skipping websocket integration test; set %s=1 to enable", v2boardWSIntegrationEnv)
	}
}

type wsIntegrationAPICalls struct {
	NodeInfo int
	UserList int
	NodeRule int
	CertCfg  int
}

type fakeV2boardWSIntegrationAPI struct {
	mu sync.Mutex

	nodeInfo   *api.NodeInfo
	userList   *[]api.UserInfo
	ruleList   *[]api.DetectRule
	certConfig *api.XrayRCertConfig
	wsConfig   *api.WSConfig
	calls      wsIntegrationAPICalls
}

func newFakeV2boardWSIntegrationAPI(serverURL string) *fakeV2boardWSIntegrationAPI {
	users := []api.UserInfo{{UID: 1, Email: "bootstrap@example.com"}}
	return &fakeV2boardWSIntegrationAPI{
		nodeInfo: &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, SpeedLimit: 100},
		userList: &users,
		ruleList: &[]api.DetectRule{},
		wsConfig: &api.WSConfig{
			APIHost:  serverURL,
			NodeID:   1,
			Key:      "integration-secret",
			NodeType: "v2ray",
		},
	}
}

func (f *fakeV2boardWSIntegrationAPI) GetNodeInfo() (*api.NodeInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls.NodeInfo++
	return cloneRecordedNodeInfo(f.nodeInfo), nil
}

func (f *fakeV2boardWSIntegrationAPI) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls.CertCfg++
	return clonePanelCertConfig(f.certConfig), nil
}

func (f *fakeV2boardWSIntegrationAPI) GetUserList() (*[]api.UserInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls.UserList++
	users := cloneIntegrationUsers(f.userList)
	return &users, nil
}

func (f *fakeV2boardWSIntegrationAPI) GetAliveList() (map[int][]string, error) {
	return nil, nil
}

func (f *fakeV2boardWSIntegrationAPI) ReportNodeStatus(*api.NodeStatus) error        { return nil }
func (f *fakeV2boardWSIntegrationAPI) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (f *fakeV2boardWSIntegrationAPI) ReportUserTraffic(*[]api.UserTraffic) error    { return nil }
func (f *fakeV2boardWSIntegrationAPI) ReportIllegal(*[]api.DetectResult) error       { return nil }
func (f *fakeV2boardWSIntegrationAPI) Debug()                                        {}

func (f *fakeV2boardWSIntegrationAPI) Describe() api.ClientInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return api.ClientInfo{APIHost: f.wsConfig.APIHost, NodeID: f.wsConfig.NodeID, NodeType: "V2ray"}
}

func (f *fakeV2boardWSIntegrationAPI) GetNodeRule() (*[]api.DetectRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls.NodeRule++
	rules := cloneIntegrationRules(f.ruleList)
	return &rules, nil
}

func (f *fakeV2boardWSIntegrationAPI) GetWSConfig() *api.WSConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.wsConfig == nil {
		return nil
	}
	copied := *f.wsConfig
	return &copied
}

func (f *fakeV2boardWSIntegrationAPI) SetNodeInfo(nodeInfo *api.NodeInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodeInfo = cloneRecordedNodeInfo(nodeInfo)
}

func (f *fakeV2boardWSIntegrationAPI) SetUserList(users []api.UserInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := append([]api.UserInfo(nil), users...)
	f.userList = &copied
}

func (f *fakeV2boardWSIntegrationAPI) ResetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = wsIntegrationAPICalls{}
}

func (f *fakeV2boardWSIntegrationAPI) SnapshotCalls() wsIntegrationAPICalls {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func cloneIntegrationUsers(users *[]api.UserInfo) []api.UserInfo {
	if users == nil {
		return nil
	}
	return append([]api.UserInfo(nil), (*users)...)
}

func cloneIntegrationRules(rules *[]api.DetectRule) []api.DetectRule {
	if rules == nil {
		return nil
	}
	copied := make([]api.DetectRule, len(*rules))
	copy(copied, *rules)
	return copied
}

type wsIntegrationHandshake struct {
	Path     string
	NodeID   string
	NodeType string
	Token    string
}

type mockV2boardWSServer struct {
	server *httptest.Server

	mu          sync.Mutex
	writeMu     sync.Mutex
	currentConn *websocket.Conn
	handshakes  chan wsIntegrationHandshake
}

func newMockV2boardWSServer(t *testing.T) *mockV2boardWSServer {
	t.Helper()

	s := &mockV2boardWSServer{
		handshakes: make(chan wsIntegrationHandshake, 8),
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bad":
			http.Error(w, "handshake rejected", http.StatusForbidden)
			return
		case "/ws":
		default:
			http.NotFound(w, r)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}

		handshake := wsIntegrationHandshake{
			Path:     r.URL.Path,
			NodeID:   r.URL.Query().Get("node_id"),
			NodeType: r.URL.Query().Get("node_type"),
			Token:    r.URL.Query().Get("token"),
		}
		select {
		case s.handshakes <- handshake:
		default:
			t.Errorf("handshake buffer full")
		}

		s.mu.Lock()
		s.currentConn = conn
		s.mu.Unlock()

		defer func() {
			s.mu.Lock()
			if s.currentConn == conn {
				s.currentConn = nil
			}
			s.mu.Unlock()
			_ = conn.Close()
		}()

		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))

	return s
}

func (s *mockV2boardWSServer) endpoint() string {
	return s.server.URL + "/ws"
}

func (s *mockV2boardWSServer) badEndpoint() string {
	return s.server.URL + "/bad"
}

func (s *mockV2boardWSServer) waitForHandshake(t *testing.T) wsIntegrationHandshake {
	t.Helper()
	select {
	case handshake := <-s.handshakes:
		return handshake
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for websocket handshake")
		return wsIntegrationHandshake{}
	}
}

func (s *mockV2boardWSServer) sendEvent(t *testing.T, event string, payload map[string]any) {
	t.Helper()
	conn := s.currentConnection(t)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := conn.WriteJSON(map[string]any{"event": event, "payload": payload}); err != nil {
		t.Fatalf("write websocket event failed: %v", err)
	}
}

func (s *mockV2boardWSServer) closeCurrentConnection(t *testing.T) {
	t.Helper()
	conn := s.currentConnection(t)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	deadline := time.Now().Add(time.Second)
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"), deadline)
	_ = conn.Close()
}

func (s *mockV2boardWSServer) currentConnection(t *testing.T) *websocket.Conn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		conn := s.currentConn
		s.mu.Unlock()
		if conn != nil {
			return conn
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for active websocket connection")
	return nil
}

func (s *mockV2boardWSServer) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	conn := s.currentConn
	s.currentConn = nil
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	if s.server != nil {
		s.server.Close()
	}
}

type v2boardWSIntegrationHarness struct {
	controller  *Controller
	recorder    *syncApplyRecorder
	api         *fakeV2boardWSIntegrationAPI
	server      *mockV2boardWSServer
	coordinator *syncCoordinator
}

func newV2boardWSIntegrationHarness(t *testing.T) *v2boardWSIntegrationHarness {
	t.Helper()

	server := newMockV2boardWSServer(t)
	apiClient := newFakeV2boardWSIntegrationAPI(server.server.URL)
	controller, recorder := newTestSyncApplyController(apiClient)
	controller.panelType = "NewV2board"
	controller.config.DisableGetRule = true
	controller.config.UpdatePeriodic = 3600
	controller.config.WebSocketConfig = &WebSocketConfig{
		Enable:            true,
		Endpoint:          server.endpoint(),
		HeartbeatInterval: 0,
		ReconnectBackoff:  0,
		ResyncOnReconnect: true,
	}
	controller.startAt = time.Now().Add(time.Hour)

	harness := &v2boardWSIntegrationHarness{
		controller: controller,
		recorder:   recorder,
		api:        apiClient,
		server:     server,
	}
	controller.syncCoordinatorFactory = func(executor syncActionExecutor) syncCoordinatorLifecycle {
		harness.coordinator = newSyncCoordinator(executor)
		return harness.coordinator
	}
	controller.wsRuntimeFactory = controller.newConfiguredWSRuntime

	return harness
}

func (h *v2boardWSIntegrationHarness) start(t *testing.T) {
	t.Helper()
	if err := h.controller.Start(); err != nil {
		t.Fatalf("controller.Start returned error: %v", err)
	}
	waitForControllerPeriodicBootstrap()
	t.Cleanup(func() {
		if err := h.controller.Close(); err != nil {
			t.Fatalf("controller.Close returned error: %v", err)
		}
		h.server.Close()
	})
}

func assertWSIntegrationHandshake(t *testing.T, handshake wsIntegrationHandshake) {
	t.Helper()
	if handshake.Path != "/ws" {
		t.Fatalf("unexpected websocket handshake path: got %q want %q", handshake.Path, "/ws")
	}
	if handshake.NodeID != "1" {
		t.Fatalf("unexpected websocket handshake node_id: got %q want %q", handshake.NodeID, "1")
	}
	if handshake.NodeType != "v2ray" {
		t.Fatalf("unexpected websocket handshake node_type: got %q want %q", handshake.NodeType, "v2ray")
	}
	if handshake.Token != "integration-secret" {
		t.Fatalf("unexpected websocket handshake token: got %q want %q", handshake.Token, "integration-secret")
	}
}

func waitForControllerWSRuntime(t *testing.T, controller *Controller) *wsRuntime {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime, ok := controller.wsRuntime.(*wsRuntime); ok && runtime != nil {
			return runtime
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for controller websocket runtime")
	return nil
}

func waitForIntegrationSnapshotCount(t *testing.T, recorder *syncApplyRecorder, want int) {
	t.Helper()
	waitForAppliedSnapshots(t, recorder, want)
}

func waitForControllerSyncIdle(t *testing.T, controller *Controller) {
	t.Helper()
	coordinator, ok := controller.syncCoordinator.(*syncCoordinator)
	if !ok || coordinator == nil {
		t.Fatal("controller sync coordinator unavailable")
	}
	waitForCoordinatorIdle(t, coordinator)
}

func assertIntegrationUsersEqual(t *testing.T, got *[]api.UserInfo, want []api.UserInfo) {
	t.Helper()
	if got == nil || !reflect.DeepEqual(*got, want) {
		t.Fatalf("unexpected users: got %#v want %#v", got, want)
	}
}

func (c wsIntegrationAPICalls) String() string {
	return fmt.Sprintf("node=%d users=%d rules=%d cert=%d", c.NodeInfo, c.UserList, c.NodeRule, c.CertCfg)
}
