package proxypanel_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/proxypanel"
)

const (
	contractKey    = "contract-key"
	contractNodeID = 17
)

type capturedRequest struct {
	method    string
	path      string
	key       string
	timestamp string
	body      json.RawMessage
}

func newContractClient(server *httptest.Server, nodeType string) *proxypanel.APIClient {
	return proxypanel.New(&api.Config{
		APIHost:  server.URL,
		Key:      contractKey,
		NodeID:   contractNodeID,
		NodeType: nodeType,
	})
}

func captureRequest(r *http.Request) capturedRequest {
	request := capturedRequest{
		method:    r.Method,
		path:      r.URL.Path,
		key:       r.Header.Get("key"),
		timestamp: r.Header.Get("timestamp"),
	}
	_ = json.NewDecoder(r.Body).Decode(&request.body)
	return request
}

func writeProxyResponse(w http.ResponseWriter, status string, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "data": data})
}

func assertContractRequest(t *testing.T, request capturedRequest, method, path string) {
	t.Helper()
	if request.method != method || request.path != path || request.key != contractKey {
		t.Fatalf("unexpected request: %#v", request)
	}
	unix, err := strconv.ParseInt(request.timestamp, 10, 64)
	if err != nil || request.timestamp == "" {
		t.Fatalf("timestamp = %q, want Unix timestamp: %v", request.timestamp, err)
	}
	if delta := time.Since(time.Unix(unix, 0)); delta < -5*time.Second || delta > 5*time.Second {
		t.Fatalf("timestamp = %q, outside reasonable range", request.timestamp)
	}
}

func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func requireProxyPanelIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("XRAYRP_RUN_PROXYPANEL_INTEGRATION") != "1" {
		t.Skip("skipping proxypanel integration test; set XRAYRP_RUN_PROXYPANEL_INTEGRATION=1 to enable")
	}
}

func TestContractFetches(t *testing.T) {
	tests := []struct {
		name, path string
		data       any
		run        func(*proxypanel.APIClient) (any, error)
		check      func(*testing.T, any, *proxypanel.APIClient)
	}{
		{
			name: "node", path: "/api/v2ray/v1/node/17",
			data: map[string]any{"v2_port": 8443, "v2_alter_id": 4, "v2_net": "ws", "v2_type": "none", "v2_host": "edge.example", "v2_path": "/socket", "v2_tls": true, "speed_limit": 16, "client_limit": 3},
			run:  func(c *proxypanel.APIClient) (any, error) { return c.GetNodeInfo() },
			check: func(t *testing.T, value any, client *proxypanel.APIClient) {
				node := value.(*api.NodeInfo)
				if node.NodeID != contractNodeID || node.NodeType != "V2ray" || node.Port != 8443 || node.AlterID != 4 || node.SpeedLimit != 2_000_000 || node.TransportProtocol != "ws" || node.FakeType != "none" || !node.EnableTLS || node.Host != "edge.example" || node.Path != "/socket" || client.DeviceLimit != 3 {
					t.Fatalf("unexpected node: %#v, device limit %d", node, client.DeviceLimit)
				}
			},
		},
		{
			name: "users", path: "/api/v2ray/v1/userList/17",
			data: []map[string]any{{"uid": 9, "vmess_uid": "98a30d33-3214-4d85-82ee-efbbce687561", "speed_limit": 24}},
			run:  func(c *proxypanel.APIClient) (any, error) { c.DeviceLimit = 3; return c.GetUserList() },
			check: func(t *testing.T, value any, _ *proxypanel.APIClient) {
				users := *value.(*[]api.UserInfo)
				want := []api.UserInfo{{UID: 9, UUID: "98a30d33-3214-4d85-82ee-efbbce687561", SpeedLimit: 3_000_000, DeviceLimit: 3}}
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
				writeProxyResponse(w, "success", tc.data)
			}))
			defer server.Close()
			client := newContractClient(server, "V2ray")
			value, err := tc.run(client)
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, value, client)
			assertContractRequest(t, <-requests, http.MethodGet, tc.path)
			if got := client.Describe(); got.Key != "" || got.APIHost != server.URL || got.NodeID != contractNodeID || got.NodeType != "V2ray" {
				t.Fatalf("Describe leaked key or lost identity: %#v", got)
			}
		})
	}
}

func TestContractRules(t *testing.T) {
	tests := []struct {
		name string
		data map[string]any
		want []int
	}{
		{"reject merges reg and skips invalid", map[string]any{"mode": "reject", "rules": []map[string]any{{"id": 4, "type": "reg", "pattern": `blocked\.example`}, {"id": 5, "type": "domain", "pattern": "ignored.example"}, {"id": 6, "type": "reg", "pattern": "["}}}, []int{-1, 4}},
		{"non-reject returns local", map[string]any{"mode": "allow", "rules": []map[string]any{{"id": 4, "type": "reg", "pattern": `blocked\.example`}}}, []int{-1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan capturedRequest, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- captureRequest(r)
				writeProxyResponse(w, "success", tc.data)
			}))
			defer server.Close()
			client := newContractClient(server, "V2ray")
			client.LocalRuleList = []api.DetectRule{{ID: -1, Pattern: mustCompile(t, `local\.example`)}}
			rules, err := client.GetNodeRule()
			if err != nil {
				t.Fatal(err)
			}
			if len(*rules) != len(tc.want) {
				t.Fatalf("rules = %#v", *rules)
			}
			for i, id := range tc.want {
				if (*rules)[i].ID != id {
					t.Fatalf("rule IDs = %#v, want %#v", *rules, tc.want)
				}
			}
			if len(*rules) == 2 && !(*rules)[1].Pattern.MatchString("blocked.example") {
				t.Fatalf("panel regex did not match: %s", (*rules)[1].Pattern)
			}
			assertContractRequest(t, <-requests, http.MethodGet, "/api/v2ray/v1/nodeRule/17")
		})
	}
}

func CreateClient() *proxypanel.APIClient {
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:8888",
		Key:      "naBDpLvREiwY9qPr",
		NodeID:   1,
		NodeType: "V2ray",
	}
	client := proxypanel.New(apiConfig)
	return client
}

func TestContractReports(t *testing.T) {
	tests := []struct {
		name, path string
		run        func(*proxypanel.APIClient) error
		check      func(*testing.T, json.RawMessage)
	}{
		{
			name: "node status", path: "/api/v2ray/v1/nodeStatus/17",
			run: func(c *proxypanel.APIClient) error {
				return c.ReportNodeStatus(&api.NodeStatus{CPU: 25, Mem: 50, Disk: 75, Uptime: 256})
			},
			check: func(t *testing.T, body json.RawMessage) {
				var got struct {
					CPU, Mem, Disk string
					Uptime         int
				}
				if err := json.Unmarshal(body, &got); err != nil || got.CPU != "25%" || got.Mem != "50%" || got.Disk != "75%" || got.Uptime != 256 {
					t.Fatalf("status body %s: %v", body, err)
				}
			},
		},
		{
			name: "online", path: "/api/v2ray/v1/nodeOnline/17",
			run: func(c *proxypanel.APIClient) error {
				users := []api.OnlineUser{{UID: 9, IP: "192.0.2.9"}}
				return c.ReportNodeOnlineUsers(&users)
			},
			check: func(t *testing.T, body json.RawMessage) {
				var got []struct {
					UID int    `json:"uid"`
					IP  string `json:"ip"`
				}
				if err := json.Unmarshal(body, &got); err != nil || len(got) != 1 || got[0].UID != 9 || got[0].IP != "192.0.2.9" {
					t.Fatalf("online body %s: %v", body, err)
				}
			},
		},
		{
			name: "traffic", path: "/api/v2ray/v1/userTraffic/17",
			run: func(c *proxypanel.APIClient) error {
				traffic := []api.UserTraffic{{UID: 9, Upload: 123, Download: 456}}
				return c.ReportUserTraffic(&traffic)
			},
			check: func(t *testing.T, body json.RawMessage) {
				var got []struct {
					UID      int   `json:"uid"`
					Upload   int64 `json:"upload"`
					Download int64 `json:"download"`
				}
				if err := json.Unmarshal(body, &got); err != nil || len(got) != 1 || got[0].UID != 9 || got[0].Upload != 123 || got[0].Download != 456 {
					t.Fatalf("traffic body %s: %v", body, err)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan capturedRequest, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- captureRequest(r)
				writeProxyResponse(w, "success", map[string]any{})
			}))
			defer server.Close()
			if err := tc.run(newContractClient(server, "V2ray")); err != nil {
				t.Fatal(err)
			}
			request := <-requests
			assertContractRequest(t, request, http.MethodPost, tc.path)
			tc.check(t, request.body)
		})
	}
}

func TestContractReportIllegal(t *testing.T) {
	requests := make(chan capturedRequest, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- captureRequest(r)
		writeProxyResponse(w, "success", map[string]any{})
	}))
	defer server.Close()
	results := []api.DetectResult{{UID: 9, RuleID: 4}, {UID: 10, RuleID: 5}}
	if err := newContractClient(server, "V2ray").ReportIllegal(&results); err != nil {
		t.Fatal(err)
	}
	for i, want := range results {
		request := <-requests
		assertContractRequest(t, request, http.MethodPost, "/api/v2ray/v1/trigger/17")
		var got struct {
			RuleID int    `json:"rule_id"`
			UID    int    `json:"uid"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(request.body, &got); err != nil || got.RuleID != want.RuleID || got.UID != want.UID || got.Reason != "XrayR cannot save reason" {
			t.Fatalf("illegal body %d = %s: %v", i, request.body, err)
		}
	}
}

func TestContractReportIllegalStopsOnError(t *testing.T) {
	var calls atomic.Int32
	requests := make(chan capturedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		requests <- captureRequest(r)
		writeProxyResponse(w, "error", map[string]any{})
	}))
	defer server.Close()
	results := []api.DetectResult{{UID: 9, RuleID: 4}, {UID: 10, RuleID: 5}}
	err := newContractClient(server, "V2ray").ReportIllegal(&results)
	if err == nil || !strings.Contains(err.Error(), "unexpected status") || calls.Load() != 1 {
		t.Fatalf("error = %v, calls = %d", err, calls.Load())
	}
	assertContractRequest(t, <-requests, http.MethodPost, "/api/v2ray/v1/trigger/17")
}

func TestContractErrorsAndUnsupportedNodeType(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		run    func(*proxypanel.APIClient) error
		want   string
	}{
		{"malformed JSON", 200, `{`, func(c *proxypanel.APIClient) error { _, err := c.GetUserList(); return err }, "unexpected end of JSON input"},
		{"GET status", 500, "", func(c *proxypanel.APIClient) error { _, err := c.GetUserList(); return err }, "status 500"},
		{"POST status", 500, "", func(c *proxypanel.APIClient) error {
			users := []api.OnlineUser{}
			return c.ReportNodeOnlineUsers(&users)
		}, "status 500"},
		{"envelope status", 200, `{"status":"error","data":{}}`, func(c *proxypanel.APIClient) error { _, err := c.GetNodeRule(); return err }, "unexpected status: error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			requests := make(chan capturedRequest, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				requests <- captureRequest(r)
				if tc.status != 200 {
					w.WriteHeader(tc.status)
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			err := tc.run(newContractClient(server, "V2ray"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls = %d, want 1", calls.Load())
			}
			method := http.MethodGet
			path := "/api/v2ray/v1/userList/17"
			if tc.name == "POST status" {
				method = http.MethodPost
				path = "/api/v2ray/v1/nodeOnline/17"
			} else if tc.name == "envelope status" {
				path = "/api/v2ray/v1/nodeRule/17"
			}
			assertContractRequest(t, <-requests, method, path)
		})
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := newContractClient(server, "invalid")
	checks := []func() error{
		func() error { _, err := client.GetNodeInfo(); return err },
		func() error { _, err := client.GetUserList(); return err },
		func() error { _, err := client.GetNodeRule(); return err },
		func() error { return client.ReportNodeStatus(&api.NodeStatus{}) },
		func() error { users := []api.OnlineUser{}; return client.ReportNodeOnlineUsers(&users) },
		func() error { traffic := []api.UserTraffic{}; return client.ReportUserTraffic(&traffic) },
		func() error { results := []api.DetectResult{}; return client.ReportIllegal(&results) },
	}
	for _, check := range checks {
		if err := check(); err == nil || !strings.Contains(err.Error(), "unsupported Node type") {
			t.Fatalf("unsupported error = %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("unsupported type sent %d requests", calls.Load())
	}
}

func TestContractAbsentCapabilities(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := newContractClient(server, "V2ray")
	if cfg, err := client.GetXrayRCertConfig(); err != nil || cfg != nil {
		t.Fatalf("cert = %#v, err = %v", cfg, err)
	}
	if alive, err := client.GetAliveList(); err != nil || alive != nil {
		t.Fatalf("alive = %#v, err = %v", alive, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("absence methods sent %d requests", calls.Load())
	}
}

func TestGetV2rayNodeinfo(t *testing.T) {
	requireProxyPanelIntegration(t)
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:8888",
		Key:      "naBDpLvREiwY9qPr",
		NodeID:   1,
		NodeType: "V2ray",
	}
	client := proxypanel.New(apiConfig)

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetSSNodeinfo(t *testing.T) {
	requireProxyPanelIntegration(t)
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:8888",
		Key:      "8VtrYVGFHL0Q9azc",
		NodeID:   3,
		NodeType: "Shadowsocks",
	}
	client := proxypanel.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetTrojanNodeinfo(t *testing.T) {
	requireProxyPanelIntegration(t)
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:8888",
		Key:      "kgnO2O66FmvP8rDV",
		NodeID:   2,
		NodeType: "Trojan",
	}
	client := proxypanel.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetSSinfo(t *testing.T) {
	requireProxyPanelIntegration(t)
	client := CreateClient()

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetUserList(t *testing.T) {
	requireProxyPanelIntegration(t)
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
	requireProxyPanelIntegration(t)
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
	requireProxyPanelIntegration(t)
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
	requireProxyPanelIntegration(t)
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
	client.Debug()
	err = client.ReportUserTraffic(&generalUserTraffic)
	if err != nil {
		t.Error(err)
	}
}

func TestGetNodeRule(t *testing.T) {
	requireProxyPanelIntegration(t)
	client := CreateClient()
	client.Debug()
	ruleList, err := client.GetNodeRule()
	if err != nil {
		t.Error(err)
	}

	t.Log(ruleList)
}

func TestReportIllegal(t *testing.T) {
	requireProxyPanelIntegration(t)
	client := CreateClient()

	detectResult := []api.DetectResult{
		{UID: 1, RuleID: 1},
		{UID: 1, RuleID: 2},
	}
	client.Debug()
	err := client.ReportIllegal(&detectResult)
	if err != nil {
		t.Error(err)
	}
}
