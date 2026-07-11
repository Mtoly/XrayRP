package sspanel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

const (
	testKey    = "contract-key"
	testNodeID = 23
)

func requireSSPanelIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("XRAYRP_RUN_SSPANEL_INTEGRATION") != "1" {
		t.Skip("skipping sspanel integration test; set XRAYRP_RUN_SSPANEL_INTEGRATION=1 to enable")
	}
}

func newContractClient(server *httptest.Server) *APIClient {
	return New(&api.Config{APIHost: server.URL, Key: testKey, NodeID: testNodeID, NodeType: "V2ray", DisableCustomConfig: true})
}

func assertAuthentication(t *testing.T, r *http.Request, wantNodeID bool) {
	t.Helper()
	if got := r.URL.Query().Get("key"); got != testKey {
		t.Fatalf("key query = %q, want %q", got, testKey)
	}
	if got := r.URL.Query().Get("muKey"); got != testKey {
		t.Fatalf("muKey query = %q, want %q", got, testKey)
	}
	if wantNodeID && r.URL.Query().Get("node_id") != fmt.Sprint(testNodeID) {
		t.Fatalf("node_id query = %q, want %d", r.URL.Query().Get("node_id"), testNodeID)
	}
}

func writeResponse(t *testing.T, w http.ResponseWriter, data any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"ret": 1, "data": data}); err != nil {
		t.Fatal(err)
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

func TestContractFetches(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantNodeID bool
		data       any
		run        func(*testing.T, *APIClient)
	}{
		{
			name: "node info", path: "/mod_mu/nodes/23/info",
			data: map[string]any{"node_speedlimit": 8.0, "server": "node.example.com;8443;0;ws;;path=/socket|host=edge.example.com", "version": "2024.1"},
			run: func(t *testing.T, c *APIClient) {
				got, err := c.GetNodeInfo()
				if err != nil {
					t.Fatal(err)
				}
				if got.NodeID != testNodeID || got.NodeType != "V2ray" || got.Port != 8443 || got.SpeedLimit != 1_000_000 || got.TransportProtocol != "ws" || got.Path != "/socket" || got.Host != "edge.example.com" {
					t.Fatalf("unexpected node info: %#v", got)
				}
			},
		},
		{
			name: "users", path: "/mod_mu/users", wantNodeID: true,
			data: []map[string]any{{"id": 7, "uuid": "98a30d33-3214-4d85-82ee-efbbce687561", "passwd": "secret", "port": 18080, "method": "aes-128-gcm", "node_speedlimit": 16.0, "node_iplimit": 3, "alive_ip": 1}},
			run: func(t *testing.T, c *APIClient) {
				got, err := c.GetUserList()
				if err != nil {
					t.Fatal(err)
				}
				want := []api.UserInfo{{UID: 7, UUID: "98a30d33-3214-4d85-82ee-efbbce687561", Passwd: "secret", Port: 18080, Method: "aes-128-gcm", SpeedLimit: 2_000_000, DeviceLimit: 2}}
				if !reflect.DeepEqual(*got, want) {
					t.Fatalf("user list = %#v, want %#v", *got, want)
				}
			},
		},
		{
			name: "rules", path: "/mod_mu/func/detect_rules",
			data: []map[string]any{{"id": 12, "regex": `blocked\.example`}},
			run: func(t *testing.T, c *APIClient) {
				c.LocalRuleList = []api.DetectRule{{ID: -1, Pattern: mustCompile(t, `local\.example`)}}
				got, err := c.GetNodeRule()
				if err != nil {
					t.Fatal(err)
				}
				if len(*got) != 2 || (*got)[0].ID != -1 || (*got)[0].Pattern.String() != `local\.example` || (*got)[1].ID != 12 || (*got)[1].Pattern.String() != `blocked\.example` || !(*got)[1].Pattern.MatchString("blocked.example") {
					t.Fatalf("unexpected merged rules: %#v", *got)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != tc.path {
					t.Fatalf("request = %s %s, want GET %s", r.Method, r.URL.Path, tc.path)
				}
				assertAuthentication(t, r, tc.wantNodeID)
				writeResponse(t, w, tc.data)
			}))
			defer server.Close()
			client := newContractClient(server)
			tc.run(t, client)
			if got := client.Describe(); got.Key != "" || got.APIHost != server.URL || got.NodeID != testNodeID || got.NodeType != "V2ray" {
				t.Fatalf("Describe() leaked key or lost identity: %#v", got)
			}
		})
	}
}

func TestContractReports(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantNodeID bool
		run        func(*testing.T, *APIClient)
		checkBody  func(*testing.T, json.RawMessage)
	}{
		{
			name: "node status", path: "/mod_mu/nodes/23/info",
			run: func(t *testing.T, c *APIClient) {
				if err := c.ReportNodeStatus(&api.NodeStatus{CPU: 25, Mem: 50, Disk: 75, Uptime: 256}); err != nil {
					t.Fatal(err)
				}
			},
			checkBody: func(t *testing.T, body json.RawMessage) {
				var got SystemLoad
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				if got.Uptime != "256" || got.Load != "0.25 0.50 0.75" {
					t.Fatalf("status body = %#v", got)
				}
			},
		},
		{
			name: "online users", path: "/mod_mu/users/aliveip", wantNodeID: true,
			run: func(t *testing.T, c *APIClient) {
				users := []api.OnlineUser{{UID: 7, IP: "192.0.2.1"}, {UID: 7, IP: "192.0.2.2"}, {UID: 8, IP: "192.0.2.3"}}
				if err := c.ReportNodeOnlineUsers(&users); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(c.LastReportOnline, map[int]int{7: 2, 8: 1}) {
					t.Fatalf("LastReportOnline = %#v", c.LastReportOnline)
				}
			},
			checkBody: func(t *testing.T, body json.RawMessage) {
				var got struct {
					Data []OnlineUser `json:"data"`
				}
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				want := []OnlineUser{{UID: 7, IP: "192.0.2.1"}, {UID: 7, IP: "192.0.2.2"}, {UID: 8, IP: "192.0.2.3"}}
				if !reflect.DeepEqual(got.Data, want) {
					t.Fatalf("online body = %#v, want %#v", got.Data, want)
				}
			},
		},
		{
			name: "user traffic", path: "/mod_mu/users/traffic", wantNodeID: true,
			run: func(t *testing.T, c *APIClient) {
				traffic := []api.UserTraffic{{UID: 7, Upload: 123, Download: 456}}
				if err := c.ReportUserTraffic(&traffic); err != nil {
					t.Fatal(err)
				}
			},
			checkBody: func(t *testing.T, body json.RawMessage) {
				var got struct {
					Data []UserTraffic `json:"data"`
				}
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				want := []UserTraffic{{UID: 7, Upload: 123, Download: 456}}
				if !reflect.DeepEqual(got.Data, want) {
					t.Fatalf("traffic body = %#v, want %#v", got.Data, want)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != tc.path {
					t.Fatalf("request = %s %s, want POST %s", r.Method, r.URL.Path, tc.path)
				}
				assertAuthentication(t, r, tc.wantNodeID)
				var body json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				tc.checkBody(t, body)
				writeResponse(t, w, map[string]any{})
			}))
			defer server.Close()
			tc.run(t, newContractClient(server))
		})
	}
}

func TestContractMalformedJSONAndHTTPError(t *testing.T) {
	t.Run("malformed data", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertAuthentication(t, r, true)
			_, _ = w.Write([]byte(`{"ret":1,"data":"not-a-user-list"}`))
		}))
		defer server.Close()
		_, err := newContractClient(server).GetUserList()
		if err == nil || !strings.Contains(err.Error(), "unmarshal") {
			t.Fatalf("error = %v, want explicit unmarshal error", err)
		}
	})

	tests := []struct {
		name, method string
		run          func(*APIClient) error
	}{
		{"GET", http.MethodGet, func(c *APIClient) error { _, err := c.GetUserList(); return err }},
		{"POST", http.MethodPost, func(c *APIClient) error { return c.ReportNodeStatus(&api.NodeStatus{}) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != tc.method {
					t.Fatalf("method = %s, want %s", r.Method, tc.method)
				}
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			err := tc.run(newContractClient(server))
			if err == nil || !strings.Contains(err.Error(), "status 500") {
				t.Fatalf("error = %v, want status 500", err)
			}
			if calls != 1 {
				t.Fatalf("calls = %d, want no status retry", calls)
			}
		})
	}
}

func TestContractETagNotModified(t *testing.T) {
	tests := []struct {
		name, path, etagKey string
		wantNodeID          bool
		wantErr             error
		data                any
		run                 func(*APIClient) error
	}{
		{"node", "/mod_mu/nodes/23/info", "node", false, api.ErrNodeNotModified, map[string]any{"server": "n;8443;0;tcp;;", "version": "2024.1"}, func(c *APIClient) error { _, err := c.GetNodeInfo(); return err }},
		{"users", "/mod_mu/users", "users", true, api.ErrUserNotModified, []any{}, func(c *APIClient) error { _, err := c.GetUserList(); return err }},
		{"rules", "/mod_mu/func/detect_rules", "rules", false, api.ErrRuleNotModified, []any{}, func(c *APIClient) error { _, err := c.GetNodeRule(); return err }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != tc.path {
					t.Fatalf("path = %s, want %s", r.URL.Path, tc.path)
				}
				assertAuthentication(t, r, tc.wantNodeID)
				if calls == 1 {
					if r.Header.Get("If-None-Match") != "" {
						t.Fatalf("first If-None-Match = %q", r.Header.Get("If-None-Match"))
					}
					w.Header().Set("ETag", `"fixture-v1"`)
					writeResponse(t, w, tc.data)
					return
				}
				if got := r.Header.Get("If-None-Match"); got != `"fixture-v1"` {
					t.Fatalf("second If-None-Match = %q", got)
				}
				w.WriteHeader(http.StatusNotModified)
			}))
			defer server.Close()
			client := newContractClient(server)
			if err := tc.run(client); err != nil {
				t.Fatalf("initial fetch: %v", err)
			}
			if client.eTags[tc.etagKey] != `"fixture-v1"` {
				t.Fatalf("cached ETag = %q", client.eTags[tc.etagKey])
			}
			if err := tc.run(client); !errors.Is(err, tc.wantErr) {
				t.Fatalf("304 error = %v, want %v", err, tc.wantErr)
			}
			if calls != 2 {
				t.Fatalf("calls = %d, want 2", calls)
			}
		})
	}
}

func integrationClient() *APIClient {
	return New(&api.Config{APIHost: "http://127.0.0.1:667", Key: "123", NodeID: 3, NodeType: "V2ray"})
}
func TestGetV2rayNodeInfo(t *testing.T) {
	requireSSPanelIntegration(t)
	nodeInfo, err := integrationClient().GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}
func TestGetSSNodeInfo(t *testing.T) {
	requireSSPanelIntegration(t)
	client := New(&api.Config{APIHost: "http://127.0.0.1:667", Key: "123", NodeID: 64, NodeType: "Shadowsocks"})
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}
func TestGetTrojanNodeInfo(t *testing.T) {
	requireSSPanelIntegration(t)
	client := New(&api.Config{APIHost: "http://127.0.0.1:667", Key: "123", NodeID: 72, NodeType: "Trojan"})
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}
func TestGetSSInfo(t *testing.T) {
	requireSSPanelIntegration(t)
	nodeInfo, err := integrationClient().GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}
func TestGetUserList(t *testing.T) {
	requireSSPanelIntegration(t)
	users, err := integrationClient().GetUserList()
	if err != nil {
		t.Fatal(err)
	}
	if users == nil {
		t.Fatal("expected user list, got nil")
	}
	t.Log(users)
}
func TestReportNodeStatus(t *testing.T) {
	requireSSPanelIntegration(t)
	if err := integrationClient().ReportNodeStatus(&api.NodeStatus{CPU: 1, Mem: 1, Disk: 1, Uptime: 256}); err != nil {
		t.Error(err)
	}
}
func TestReportReportNodeOnlineUsers(t *testing.T) {
	requireSSPanelIntegration(t)
	client := integrationClient()
	users, err := client.GetUserList()
	if err != nil {
		t.Fatal(err)
	}
	online := make([]api.OnlineUser, len(*users))
	for i, user := range *users {
		online[i] = api.OnlineUser{UID: user.UID, IP: fmt.Sprintf("1.1.1.%d", i)}
	}
	if err := client.ReportNodeOnlineUsers(&online); err != nil {
		t.Error(err)
	}
}
func TestReportReportUserTraffic(t *testing.T) {
	requireSSPanelIntegration(t)
	client := integrationClient()
	users, err := client.GetUserList()
	if err != nil {
		t.Fatal(err)
	}
	traffic := make([]api.UserTraffic, len(*users))
	for i, user := range *users {
		traffic[i] = api.UserTraffic{UID: user.UID, Upload: 114514, Download: 114514}
	}
	if err := client.ReportUserTraffic(&traffic); err != nil {
		t.Error(err)
	}
}
func TestGetNodeRule(t *testing.T) {
	requireSSPanelIntegration(t)
	rules, err := integrationClient().GetNodeRule()
	if err != nil {
		t.Error(err)
	}
	t.Log(rules)
}
func TestReportIllegal(t *testing.T) {
	requireSSPanelIntegration(t)
	results := []api.DetectResult{{UID: 1, RuleID: 2}, {UID: 1, RuleID: 3}}
	if err := integrationClient().ReportIllegal(&results); err != nil {
		t.Error(err)
	}
}
