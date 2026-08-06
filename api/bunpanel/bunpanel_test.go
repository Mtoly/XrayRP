package bunpanel_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/bunpanel"
)

const (
	contractKey    = "contract-key"
	contractNodeID = 17
)

func TestSplitHTTPSettingsKeepsXPaddingBytesPublicType(t *testing.T) {
	var settings bunpanel.SplitHTTPSettings
	var _ *[2]int32 = settings.XPaddingBytes
}

type capturedRequest struct {
	method string
	path   string
	query  map[string]string
	header http.Header
	body   json.RawMessage
}

func newContractClient(server *httptest.Server) *bunpanel.APIClient {
	return bunpanel.New(&api.Config{
		APIHost:  server.URL,
		Key:      contractKey,
		NodeID:   contractNodeID,
		NodeType: "V2ray",
	})
}

func captureRequest(r *http.Request) capturedRequest {
	request := capturedRequest{
		method: r.Method,
		path:   r.URL.Path,
		query:  make(map[string]string),
		header: r.Header.Clone(),
	}
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			request.query[key] = values[0]
		}
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&request.body)
	}
	return request
}

func writeResponse(w http.ResponseWriter, statusCode int, datas any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": statusCode, "datas": datas})
}

func assertContractRequest(t *testing.T, request capturedRequest, method, path string) {
	t.Helper()
	if request.method != method || request.path != path {
		t.Fatalf("request = %s %s, want %s %s", request.method, request.path, method, path)
	}
	wantQuery := map[string]string{
		"serverId": fmt.Sprint(contractNodeID),
		"nodeType": "v2ray",
		"token":    contractKey,
	}
	if !reflect.DeepEqual(request.query, wantQuery) {
		t.Fatalf("query = %#v, want %#v", request.query, wantQuery)
	}
}

func requireBunpanelIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("XRAYRP_RUN_BUNPANEL_INTEGRATION") != "1" {
		t.Skip("skipping bunpanel integration test; set XRAYRP_RUN_BUNPANEL_INTEGRATION=1 to enable")
	}
}

func TestContractFetches(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		data  any
		run   func(*bunpanel.APIClient) (any, error)
		check func(*testing.T, any)
	}{
		{
			name: "node",
			path: "/v2/server/17/get",
			data: map[string]any{
				"serverPort": 8443,
				"network":    "ws",
				"security":   "tls",
				"flow":       "xtls-rprx-vision",
				"wsSettings": map[string]any{
					"path":    "/socket",
					"headers": map[string]any{"Host": "edge.example"},
				},
			},
			run: func(c *bunpanel.APIClient) (any, error) { return c.GetNodeInfo() },
			check: func(t *testing.T, value any) {
				node := value.(*api.NodeInfo)
				if node.Port != 8443 || node.TransportProtocol != "ws" || !node.EnableTLS || node.Host != "edge.example" || node.Path != "/socket" || node.VlessFlow != "xtls-rprx-vision" {
					t.Fatalf("unexpected node: %#v", node)
				}
			},
		},
		{
			name: "users",
			path: "/v2/user/get",
			data: []map[string]any{
				{"id": 9, "uuid": "user-nine", "speedLimit": 24, "ipLimit": 3, "onlineIp": 2},
				{"id": 10, "uuid": "user-ten", "speedLimit": 8, "ipLimit": 1, "onlineIp": 1},
			},
			run: func(c *bunpanel.APIClient) (any, error) {
				online := []api.OnlineUser{{UID: 9, IP: "192.0.2.9"}, {UID: 9, IP: "192.0.2.10"}}
				if err := c.ReportNodeOnlineUsers(&online); err != nil {
					return nil, err
				}
				return c.GetUserList()
			},
			check: func(t *testing.T, value any) {
				users := *value.(*[]api.UserInfo)
				want := []api.UserInfo{{UID: 9, UUID: "user-nine", Passwd: "user-nine", Email: "user-nine@bunpanel.user", SpeedLimit: 3_000_000, DeviceLimit: 3}}
				if !reflect.DeepEqual(users, want) {
					t.Fatalf("users = %#v, want %#v", users, want)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan capturedRequest, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- captureRequest(r)
				if r.URL.Path == "/v2/user/online/create" {
					writeResponse(w, 200, map[string]any{})
					return
				}
				writeResponse(w, 200, tc.data)
			}))
			defer server.Close()
			client := newContractClient(server)
			value, err := tc.run(client)
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, value)
			if tc.name == "users" {
				assertContractRequest(t, <-requests, http.MethodPost, "/v2/user/online/create")
			}
			assertContractRequest(t, <-requests, http.MethodGet, tc.path)
			if client.Describe().Key != "" {
				t.Fatal("Describe leaked token")
			}
		})
	}
}

func TestContractReports(t *testing.T) {
	tests := []struct {
		name string
		path string
		run  func(*bunpanel.APIClient) error
		want any
	}{
		{
			name: "online",
			path: "/v2/user/online/create",
			run: func(c *bunpanel.APIClient) error {
				users := []api.OnlineUser{{UID: 9, IP: "192.0.2.9"}, {UID: 9, IP: "192.0.2.10"}, {UID: 10, IP: "192.0.2.11"}}
				return c.ReportNodeOnlineUsers(&users)
			},
			want: map[string]any{"data": []any{
				map[string]any{"userId": float64(9), "ip": "192.0.2.9"},
				map[string]any{"userId": float64(9), "ip": "192.0.2.10"},
				map[string]any{"userId": float64(10), "ip": "192.0.2.11"},
			}},
		},
		{
			name: "traffic",
			path: "/v2/user/data-usage/create",
			run: func(c *bunpanel.APIClient) error {
				traffic := []api.UserTraffic{{UID: 9, Upload: 123, Download: 456}}
				return c.ReportUserTraffic(&traffic)
			},
			want: map[string]any{"data": []any{map[string]any{"userId": float64(9), "u": float64(123), "d": float64(456)}}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan capturedRequest, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- captureRequest(r)
				writeResponse(w, 200, map[string]any{})
			}))
			defer server.Close()
			client := newContractClient(server)
			if err := tc.run(client); err != nil {
				t.Fatal(err)
			}
			request := <-requests
			assertContractRequest(t, request, http.MethodPost, tc.path)
			var body any
			if err := json.Unmarshal(request.body, &body); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(body, tc.want) {
				t.Fatalf("body = %#v, want %#v", body, tc.want)
			}
			if tc.name == "online" {
				wantOnline := map[int]int{9: 2, 10: 1}
				if !reflect.DeepEqual(client.LastReportOnline, wantOnline) {
					t.Fatalf("LastReportOnline = %#v, want %#v", client.LastReportOnline, wantOnline)
				}
			}
		})
	}
}

func TestContractLocalRulesAndNoOpCapabilities(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	rulesPath := t.TempDir() + "/rules.txt"
	if err := os.WriteFile(rulesPath, []byte("blocked\\.example\n[\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := bunpanel.New(&api.Config{APIHost: server.URL, Key: contractKey, NodeID: contractNodeID, NodeType: "V2ray", RuleListPath: rulesPath})
	rules, err := client.GetNodeRule()
	if err != nil {
		t.Fatal(err)
	}
	if len(*rules) != 1 || (*rules)[0].ID != -1 || !(*rules)[0].Pattern.MatchString("blocked.example") {
		t.Fatalf("unexpected local rules: %#v", *rules)
	}
	status := &api.NodeStatus{}
	results := []api.DetectResult{{UID: 1, RuleID: 2}}
	if err := client.ReportNodeStatus(status); err != nil {
		t.Fatal(err)
	}
	if err := client.ReportIllegal(&results); err != nil {
		t.Fatal(err)
	}
	if alive, err := client.GetAliveList(); !errors.Is(err, api.ErrUnsupportedPanelFeature) || alive != nil {
		t.Fatalf("alive = %#v, err = %v", alive, err)
	}
	if cert, err := client.GetXrayRCertConfig(); !errors.Is(err, api.ErrUnsupportedPanelFeature) || cert != nil {
		t.Fatalf("cert = %#v, err = %v", cert, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("local/no-op methods sent %d requests", calls.Load())
	}
}

func TestContractErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		run    func(*bunpanel.APIClient) error
		want   string
	}{
		{"GET HTTP status", http.StatusBadGateway, "", func(c *bunpanel.APIClient) error { _, err := c.GetNodeInfo(); return err }, "status 502"},
		{"POST HTTP status", http.StatusServiceUnavailable, "", func(c *bunpanel.APIClient) error {
			traffic := []api.UserTraffic{}
			return c.ReportUserTraffic(&traffic)
		}, "status 503"},
		{"GET envelope status", http.StatusOK, `{"statusCode":401,"datas":{}}`, func(c *bunpanel.APIClient) error { _, err := c.GetNodeInfo(); return err }, "unexpected status code: 401"},
		{"POST envelope status", http.StatusOK, `{"statusCode":422,"datas":{}}`, func(c *bunpanel.APIClient) error {
			traffic := []api.UserTraffic{}
			return c.ReportUserTraffic(&traffic)
		}, "unexpected status code: 422"},
		{"GET malformed JSON", http.StatusOK, `{`, func(c *bunpanel.APIClient) error { _, err := c.GetUserList(); return err }, "unexpected end of JSON input"},
		{"POST malformed JSON", http.StatusOK, `{`, func(c *bunpanel.APIClient) error {
			traffic := []api.UserTraffic{}
			return c.ReportUserTraffic(&traffic)
		}, "unexpected end of JSON input"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if tc.status != http.StatusOK {
					w.WriteHeader(tc.status)
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			err := tc.run(newContractClient(server))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestContractETagNotModified(t *testing.T) {
	tests := []struct {
		name string
		path string
		data any
		run  func(*bunpanel.APIClient) error
		want error
	}{
		{"node", "/v2/server/17/get", map[string]any{"serverPort": 8443, "network": "ws", "security": "tls", "wsSettings": map[string]any{"path": "/socket", "headers": map[string]any{"Host": "edge.example"}}}, func(c *bunpanel.APIClient) error { _, err := c.GetNodeInfo(); return err }, api.ErrNodeNotModified},
		{"users", "/v2/user/get", []any{}, func(c *bunpanel.APIClient) error { _, err := c.GetUserList(); return err }, api.ErrUserNotModified},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan capturedRequest, 2)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- captureRequest(r)
				if calls.Add(1) == 1 {
					w.Header().Set("ETag", `"fixture-v1"`)
					writeResponse(w, 200, tc.data)
					return
				}
				w.WriteHeader(http.StatusNotModified)
			}))
			defer server.Close()
			client := newContractClient(server)
			if err := tc.run(client); err != nil {
				t.Fatalf("initial fetch: %v", err)
			}
			if err := tc.run(client); !errors.Is(err, tc.want) {
				t.Fatalf("304 error = %v, want %v", err, tc.want)
			}
			first, second := <-requests, <-requests
			assertContractRequest(t, first, http.MethodGet, tc.path)
			assertContractRequest(t, second, http.MethodGet, tc.path)
			if first.header.Get("If-None-Match") != "" {
				t.Fatalf("first If-None-Match = %q", first.header.Get("If-None-Match"))
			}
			if second.header.Get("If-None-Match") != `"fixture-v1"` {
				t.Fatalf("second If-None-Match = %q", second.header.Get("If-None-Match"))
			}
		})
	}
}

func TestTransportErrorsDoNotPanic(t *testing.T) {
	client := bunpanel.New(&api.Config{APIHost: "://invalid", Key: contractKey, NodeID: contractNodeID, NodeType: "V2ray", Timeout: 1})
	tests := []struct {
		name string
		run  func() error
	}{
		{"node", func() error { _, err := client.GetNodeInfo(); return err }},
		{"users", func() error { _, err := client.GetUserList(); return err }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil || !strings.Contains(err.Error(), "request") {
				t.Fatalf("error = %v, want request failure", err)
			}
		})
	}
}

func TestGetNodeInfoParseErrorDoesNotExposeRealityPrivateKey(t *testing.T) {
	const privateKey = "reality-private-key-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeResponse(w, http.StatusOK, map[string]any{
			"serverPort":      8443,
			"network":         "xhttp",
			"security":        "reality",
			"realitySettings": map[string]any{"privateKey": privateKey},
			"xhttpSettings":   map[string]any{"xPaddingBytes": []int{1}},
		})
	}))
	defer server.Close()

	_, err := newContractClient(server).GetNodeInfo()
	if err == nil {
		t.Fatal("GetNodeInfo() returned nil error")
	}
	if got := err.Error(); got != "parse panel node info failed" {
		t.Fatalf("error = %q, want redacted parse error", got)
	}
	if strings.Contains(err.Error(), privateKey) {
		t.Fatalf("error exposed REALITY private key: %v", err)
	}
	if errors.Unwrap(err) == nil {
		t.Fatal("parse error did not preserve its cause")
	}
}

func TestParseNodeInfoPreservesAdapterSpecificTransportFallbacks(t *testing.T) {
	client := bunpanel.New(&api.Config{NodeID: contractNodeID, NodeType: "V2ray"})
	t.Run("unknown transport falls back to websocket endpoint", func(t *testing.T) {
		node, err := client.ParseNodeInfo(&bunpanel.Server{
			Port:       8443,
			Network:    "unknown",
			WsSettings: json.RawMessage(`{"path":"/fallback","headers":{"Host":"fallback.example"}}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		if node.TransportProtocol != "unknown" || node.Host != "fallback.example" || node.Path != "/fallback" {
			t.Fatalf("unexpected fallback node: %#v", node)
		}
	})

	t.Run("present XHTTP settings do not fall back to SplitHTTP", func(t *testing.T) {
		node, err := client.ParseNodeInfo(&bunpanel.Server{
			Port:              8443,
			Network:           "xhttp",
			XHTTPSettings:     json.RawMessage(`{}`),
			SplitHTTPSettings: json.RawMessage(`{"host":"split.example","path":"/split","mode":"auto"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		if node.Host != "" || node.Path != "" || node.XHTTPMode != "" {
			t.Fatalf("SplitHTTP unexpectedly replaced present XHTTP settings: %#v", node)
		}
	})
}

func TestParseNodeInfoProjectsTransportFieldsAgainstLiteralOracle(t *testing.T) {
	client := bunpanel.New(&api.Config{NodeID: contractNodeID, NodeType: "V2ray"})
	node, err := client.ParseNodeInfo(&bunpanel.Server{
		Port:     8443,
		Network:  "xhttp",
		Security: "tls",
		Flow:     "fallback-flow",
		XHTTPSettings: json.RawMessage(`{
			"host":"edge.example",
			"path":"/xhttp",
			"headers":{},
			"mode":"stream-one",
			"extra":{},
			"xPaddingBytes":[100,200],
			"xPaddingObfsMode":true,
			"xPaddingKey":"padding-key",
			"xPaddingHeader":"padding-header",
			"xPaddingPlacement":"header",
			"xPaddingMethod":"random",
			"uplinkHTTPMethod":"POST",
			"sessionPlacement":"query",
			"sessionKey":"session-key",
			"seqPlacement":"path",
			"seqKey":"seq-key",
			"uplinkDataPlacement":"body",
			"uplinkDataKey":"data-key",
			"uplinkChunkSize":4096,
			"noGRPCHeader":true,
			"noSSEHeader":true
		}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	paddingBytes := [2]int32{100, 200}
	want := &api.NodeInfo{
		NodeType:            "V2ray",
		NodeID:              contractNodeID,
		Port:                8443,
		TransportProtocol:   "xhttp",
		Host:                "edge.example",
		Path:                "/xhttp",
		EnableTLS:           true,
		VlessFlow:           "fallback-flow",
		Headers:             map[string]string{},
		REALITYConfig:       &api.REALITYConfig{},
		XHTTPMode:           "stream-one",
		XHTTPExtra:          json.RawMessage(`{}`),
		XPaddingBytes:       &paddingBytes,
		XPaddingObfsMode:    true,
		XPaddingKey:         "padding-key",
		XPaddingHeader:      "padding-header",
		XPaddingPlacement:   "header",
		XPaddingMethod:      "random",
		UplinkHTTPMethod:    "POST",
		SessionPlacement:    "query",
		SessionKey:          "session-key",
		SeqPlacement:        "path",
		SeqKey:              "seq-key",
		UplinkDataPlacement: "body",
		UplinkDataKey:       "data-key",
		UplinkChunkSize:     4096,
		NoGRPCHeader:        true,
		NoSSEHeader:         true,
	}
	if !reflect.DeepEqual(node, want) {
		t.Fatalf("node info = %#v, want %#v", node, want)
	}
	if node.Headers == nil || node.XHTTPExtra == nil || node.XPaddingBytes == nil || node.REALITYConfig == nil {
		t.Fatalf("non-nil transport values became nil: %#v", node)
	}
}

func TestParseNodeInfoRejectsInvalidXPaddingBytesLength(t *testing.T) {
	client := bunpanel.New(&api.Config{NodeID: contractNodeID, NodeType: "V2ray"})
	_, err := client.ParseNodeInfo(&bunpanel.Server{
		Port:          8443,
		Network:       "xhttp",
		XHTTPSettings: json.RawMessage(`{"xPaddingBytes":[100]}`),
	})
	if err == nil || !strings.Contains(err.Error(), "xPaddingBytes") {
		t.Fatalf("error = %v, want xPaddingBytes length error", err)
	}
}

func TestParseNodeInfoRejectsUplinkChunkSizeRuntimeOverflow(t *testing.T) {
	client := bunpanel.New(&api.Config{NodeID: contractNodeID, NodeType: "V2ray"})
	_, err := client.ParseNodeInfo(&bunpanel.Server{
		Port:          8443,
		Network:       "xhttp",
		XHTTPSettings: json.RawMessage(`{"uplinkChunkSize":2147483648}`),
	})
	if err == nil || !strings.Contains(err.Error(), "uplinkChunkSize") {
		t.Fatalf("error = %v, want uplinkChunkSize range error", err)
	}
}

func integrationClient() *bunpanel.APIClient {
	return bunpanel.New(&api.Config{
		APIHost:  "http://localhost:8080",
		Key:      "123456",
		NodeID:   1,
		NodeType: "V2ray",
	})
}

func CreateClient() *bunpanel.APIClient {
	return integrationClient()
}

func TestGetV2rayNodeInfo(t *testing.T) {
	requireBunpanelIntegration(t)
	client := CreateClient()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetSSNodeInfo(t *testing.T) {
	requireBunpanelIntegration(t)
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:668",
		Key:      "qwertyuiopasdfghjkl",
		NodeID:   1,
		NodeType: "Shadowsocks",
	}
	client := bunpanel.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetTrojanNodeInfo(t *testing.T) {
	requireBunpanelIntegration(t)
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:668",
		Key:      "qwertyuiopasdfghjkl",
		NodeID:   1,
		NodeType: "Trojan",
	}
	client := bunpanel.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetUserList(t *testing.T) {
	requireBunpanelIntegration(t)
	client := CreateClient()

	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}
	if userList == nil {
		t.Fatal("expected user list, got nil")
	}

	t.Log(userList)
}

func TestReportReportUserTraffic(t *testing.T) {
	requireBunpanelIntegration(t)
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
			Upload:   1111,
			Download: 2222,
		}
	}
	// client.Debug()
	err = client.ReportUserTraffic(&generalUserTraffic)
	if err != nil {
		t.Error(err)
	}
}

func TestGetNodeRule(t *testing.T) {
	requireBunpanelIntegration(t)
	client := CreateClient()
	client.Debug()
	ruleList, err := client.GetNodeRule()
	if err != nil {
		t.Error(err)
	}

	t.Log(ruleList)
}
