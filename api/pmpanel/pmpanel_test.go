package pmpanel_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/pmpanel"
)

const (
	contractKey    = "contract-key"
	contractNodeID = 17
)

type capturedRequest struct {
	method string
	path   string
	query  map[string]string
	key    string
	body   json.RawMessage
}

func newContractClient(server *httptest.Server, nodeType string) *pmpanel.APIClient {
	return pmpanel.New(&api.Config{
		APIHost:  server.URL,
		Key:      contractKey,
		NodeID:   contractNodeID,
		NodeType: nodeType,
	})
}

func captureRequest(r *http.Request) capturedRequest {
	request := capturedRequest{
		method: r.Method,
		path:   r.URL.Path,
		query:  make(map[string]string),
		key:    r.Header.Get("key"),
	}
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			request.query[key] = values[0]
		}
	}
	_ = json.NewDecoder(r.Body).Decode(&request.body)
	return request
}

func writePMResponse(w http.ResponseWriter, ret int, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ret": ret, "data": data})
}

func requirePMPanelIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("XRAYRP_RUN_PMPANEL_INTEGRATION") != "1" {
		t.Skip("skipping pmpanel integration test; set XRAYRP_RUN_PMPANEL_INTEGRATION=1 to enable")
	}
}

func TestContractFetches(t *testing.T) {
	tests := []struct {
		name, path string
		data       any
		run        func(*pmpanel.APIClient) (any, error)
		check      func(*testing.T, any)
	}{
		{
			name: "node", path: "/api/node",
			data: map[string]any{"outPort": 8443, "alterId": 0, "network": "ws", "security": "tls", "host": "edge.example", "path": "/socket", "speedlimit": 16},
			run:  func(c *pmpanel.APIClient) (any, error) { return c.GetNodeInfo() },
			check: func(t *testing.T, value any) {
				node := value.(*api.NodeInfo)
				if node.NodeID != contractNodeID || node.NodeType != "V2ray" || node.Port != 8443 || node.SpeedLimit != 2_000_000 || node.TransportProtocol != "ws" || !node.EnableTLS || node.Host != "edge.example" || node.Path != "/socket" {
					t.Fatalf("unexpected node: %#v", node)
				}
			},
		},
		{
			name: "users", path: "/api/users",
			data: []map[string]any{{"id": 9, "passwd": "user-secret", "nodeSpeedlimit": 24, "nodeConnector": 3}},
			run:  func(c *pmpanel.APIClient) (any, error) { return c.GetUserList() },
			check: func(t *testing.T, value any) {
				users := *value.(*[]api.UserInfo)
				want := []api.UserInfo{{UID: 9, Passwd: "user-secret", UUID: "user-secret", SpeedLimit: 3_000_000, DeviceLimit: 3}}
				if !reflect.DeepEqual(users, want) {
					t.Fatalf("users = %#v, want %#v", users, want)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan capturedRequest, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- captureRequest(r)
				writePMResponse(w, 200, tc.data)
			}))
			defer server.Close()
			client := newContractClient(server, "V2ray")
			value, err := tc.run(client)
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, value)
			request := <-requests
			if request.method != http.MethodGet || request.path != tc.path || request.key != contractKey || request.query["type"] != "v2ray" || request.query["nodeId"] != fmt.Sprint(contractNodeID) {
				t.Fatalf("unexpected request: %#v", request)
			}
			if tc.name == "users" && request.query["all"] != "true" {
				t.Fatalf("all query = %q", request.query["all"])
			}
			if client.Describe().Key != "" {
				t.Fatal("Describe leaked key")
			}
		})
	}
}

func TestContractRules(t *testing.T) {
	requests := make(chan capturedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- captureRequest(r)
		writePMResponse(w, 200, []map[string]any{{"id": 4, "regex": `blocked\.example`}, {"id": 5, "regex": "["}})
	}))
	defer server.Close()
	client := newContractClient(server, "V2ray")
	client.LocalRuleList = []api.DetectRule{{ID: -1, Pattern: regexp.MustCompile(`local\.example`)}}
	rules, err := client.GetNodeRule()
	if err != nil {
		t.Fatal(err)
	}
	if len(*rules) != 2 || (*rules)[0].ID != -1 || (*rules)[1].ID != 4 || !(*rules)[1].Pattern.MatchString("blocked.example") {
		t.Fatalf("unexpected rules: %#v", *rules)
	}
	request := <-requests
	if request.path != "/api/rules" || request.key != contractKey || request.query["type"] != "v2ray" || request.query["nodeId"] != fmt.Sprint(contractNodeID) {
		t.Fatalf("unexpected request: %#v", request)
	}
}

func CreateClient() *pmpanel.APIClient {
	apiConfig := &api.Config{
		APIHost:  "http://webapi.yyds.me",
		Key:      "123456",
		NodeID:   4,
		NodeType: "V2ray",
	}
	client := pmpanel.New(apiConfig)
	return client
}

func TestContractReports(t *testing.T) {
	tests := []struct {
		name, path string
		run        func(*pmpanel.APIClient) error
		check      func(*testing.T, json.RawMessage)
	}{
		{
			name: "online", path: "/api/online",
			run: func(c *pmpanel.APIClient) error {
				users := []api.OnlineUser{{UID: 9, IP: "192.0.2.9"}}
				return c.ReportNodeOnlineUsers(&users)
			},
			check: func(t *testing.T, body json.RawMessage) {
				var got struct {
					Type    string `json:"type"`
					NodeID  int    `json:"nodeId"`
					Onlines []struct {
						UID int    `json:"user_id"`
						IP  string `json:"ip"`
					} `json:"onlines"`
				}
				if err := json.Unmarshal(body, &got); err != nil || got.Type != "v2ray" || got.NodeID != contractNodeID || len(got.Onlines) != 1 || got.Onlines[0].UID != 9 || got.Onlines[0].IP != "192.0.2.9" {
					t.Fatalf("unexpected online body %s: %v", body, err)
				}
			},
		},
		{
			name: "traffic", path: "/api/traffic",
			run: func(c *pmpanel.APIClient) error {
				traffic := []api.UserTraffic{{UID: 9, Upload: 123, Download: 456}}
				return c.ReportUserTraffic(&traffic)
			},
			check: func(t *testing.T, body json.RawMessage) {
				var got struct {
					Type   string `json:"type"`
					NodeID int    `json:"nodeId"`
					Users  []struct {
						UID      int   `json:"id"`
						Upload   int64 `json:"up"`
						Download int64 `json:"down"`
					} `json:"users"`
				}
				if err := json.Unmarshal(body, &got); err != nil || got.Type != "v2ray" || got.NodeID != contractNodeID || len(got.Users) != 1 || got.Users[0].UID != 9 || got.Users[0].Upload != 123 || got.Users[0].Download != 456 {
					t.Fatalf("unexpected traffic body %s: %v", body, err)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan capturedRequest, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- captureRequest(r)
				writePMResponse(w, 200, map[string]any{})
			}))
			defer server.Close()
			if err := tc.run(newContractClient(server, "V2ray")); err != nil {
				t.Fatal(err)
			}
			request := <-requests
			if request.method != http.MethodPost || request.path != tc.path || request.key != contractKey {
				t.Fatalf("unexpected request: %#v", request)
			}
			tc.check(t, request.body)
		})
	}
}

func TestContractErrorsAndUnsupportedNodeType(t *testing.T) {
	tests := []struct {
		name   string
		status int
		ret    int
		body   string
		run    func(*pmpanel.APIClient) error
		want   string
	}{
		{"malformed JSON", 200, 0, `{`, func(c *pmpanel.APIClient) error { _, err := c.GetUserList(); return err }, "unexpected end of JSON input"},
		{"GET status", 500, 0, "", func(c *pmpanel.APIClient) error { _, err := c.GetUserList(); return err }, "status 500"},
		{"POST status", 500, 0, "", func(c *pmpanel.APIClient) error { users := []api.OnlineUser{}; return c.ReportNodeOnlineUsers(&users) }, "status 500"},
		{"ret code", 200, 401, "", func(c *pmpanel.APIClient) error { _, err := c.GetNodeRule(); return err }, "ret code: 401"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if tc.status != 200 {
					w.WriteHeader(tc.status)
					return
				}
				if tc.body != "" {
					_, _ = w.Write([]byte(tc.body))
					return
				}
				writePMResponse(w, tc.ret, map[string]any{})
			}))
			defer server.Close()
			err := tc.run(newContractClient(server, "V2ray"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls = %d, want 1", calls.Load())
			}
		})
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := newContractClient(server, "invalid")
	if _, err := client.GetNodeInfo(); err == nil || !strings.Contains(err.Error(), "NodeType Error") {
		t.Fatalf("node error = %v", err)
	}
	if _, err := client.GetUserList(); err == nil || !strings.Contains(err.Error(), "NodeType Error") {
		t.Fatalf("user error = %v", err)
	}
	if _, err := client.GetNodeRule(); err == nil || !strings.Contains(err.Error(), "NodeType Error") {
		t.Fatalf("rule error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("unsupported type sent %d requests", calls.Load())
	}
}

func TestContractNoOpCapabilities(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := newContractClient(server, "V2ray")
	status := &api.NodeStatus{}
	results := []api.DetectResult{{UID: 1, RuleID: 2}}
	if err := client.ReportNodeStatus(status); err != nil {
		t.Fatal(err)
	}
	if err := client.ReportIllegal(&results); err != nil {
		t.Fatal(err)
	}
	if cfg, err := client.GetXrayRCertConfig(); err != nil || cfg != nil {
		t.Fatalf("cert = %#v, err = %v", cfg, err)
	}
	if alive, err := client.GetAliveList(); err != nil || alive != nil {
		t.Fatalf("alive = %#v, err = %v", alive, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("no-op methods sent %d requests", calls.Load())
	}
}

func TestGetV2rayNodeinfo(t *testing.T) {
	requirePMPanelIntegration(t)
	client := CreateClient()
	client.Debug()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetSSNodeinfo(t *testing.T) {
	requirePMPanelIntegration(t)
	apiConfig := &api.Config{
		APIHost:  "http://webapi.yyds.me",
		Key:      "123456",
		NodeID:   1,
		NodeType: "Shadowsocks",
	}
	client := pmpanel.New(apiConfig)
	client.Debug()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetTrojanNodeinfo(t *testing.T) {
	requirePMPanelIntegration(t)
	apiConfig := &api.Config{
		APIHost:  "http://webapi.yyds.me",
		Key:      "123456",
		NodeID:   1,
		NodeType: "Trojan",
	}
	client := pmpanel.New(apiConfig)
	client.Debug()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetSSinfo(t *testing.T) {
	requirePMPanelIntegration(t)
	client := CreateClient()

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetUserList(t *testing.T) {
	requirePMPanelIntegration(t)
	client := CreateClient()

	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
		return
	}
	if userList == nil {
		t.Fatal("expected user list, got nil")
	}

	t.Log(userList)
}

func TestReportNodeStatus(t *testing.T) {
	requirePMPanelIntegration(t)
	client := CreateClient()
	nodeStatus := &api.NodeStatus{
		CPU: 1, Mem: 1, Disk: 1, Uptime: 256,
	}
	err := client.ReportNodeStatus(nodeStatus)
	if err != nil {
		t.Error(err)
	}
}

func TestReportReportNodeOnlineUsers(t *testing.T) {
	requirePMPanelIntegration(t)
	client := CreateClient()
	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
		return
	}
	if userList == nil {
		t.Fatal("expected user list, got nil")
	}

	onlineUserList := make([]api.OnlineUser, len(*userList))
	for i, userInfo := range *userList {
		onlineUserList[i] = api.OnlineUser{
			UID: userInfo.UID,
			IP:  fmt.Sprintf("1.1.1.%d", i),
		}
	}
	// client.Debug()
	err = client.ReportNodeOnlineUsers(&onlineUserList)
	if err != nil {
		t.Error(err)
	}
}

func TestReportReportUserTraffic(t *testing.T) {
	requirePMPanelIntegration(t)
	client := CreateClient()
	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
		return
	}
	if userList == nil {
		t.Fatal("expected user list, got nil")
	}
	generalUserTraffic := make([]api.UserTraffic, len(*userList))
	for i, userInfo := range *userList {
		generalUserTraffic[i] = api.UserTraffic{
			UID:      userInfo.UID,
			Upload:   114514,
			Download: 114514,
		}
	}
	// client.Debug()
	err = client.ReportUserTraffic(&generalUserTraffic)
	if err != nil {
		t.Error(err)
	}
}

func TestGetNodeRule(t *testing.T) {
	requirePMPanelIntegration(t)
	client := CreateClient()

	ruleList, err := client.GetNodeRule()
	if err != nil {
		t.Error(err)
	}

	t.Log(ruleList)
}

func TestReportIllegal(t *testing.T) {
	requirePMPanelIntegration(t)
	client := CreateClient()

	detectResult := []api.DetectResult{
		{UID: 1, RuleID: 2},
		{UID: 1, RuleID: 3},
	}
	client.Debug()
	err := client.ReportIllegal(&detectResult)
	if err != nil {
		t.Error(err)
	}
}
