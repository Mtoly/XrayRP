package gov2panel_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/gov2panel"
)

const (
	contractKey    = "contract-key"
	contractNodeID = 17
)

type capturedRequest struct {
	method      string
	path        string
	contentType string
	query       url.Values
	body        []byte
	captureErr  error
}

func captureRequest(r *http.Request) capturedRequest {
	body, err := io.ReadAll(r.Body)
	return capturedRequest{
		method:      r.Method,
		path:        r.URL.Path,
		contentType: r.Header.Get("Content-Type"),
		query:       r.URL.Query(),
		body:        body,
		captureErr:  err,
	}
}

func writeResponse(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func newContractClient(server *httptest.Server, nodeType string) *gov2panel.APIClient {
	return gov2panel.New(&api.Config{
		APIHost:     server.URL,
		Key:         contractKey,
		NodeID:      contractNodeID,
		NodeType:    nodeType,
		EnableVless: true,
		VlessFlow:   "xtls-rprx-vision",
		DeviceLimit: 3,
	})
}

func requestData(t *testing.T, request capturedRequest) map[string]any {
	t.Helper()
	if request.captureErr != nil {
		t.Fatalf("capture request: %v", request.captureErr)
	}
	if !strings.HasPrefix(request.contentType, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", request.contentType)
	}
	var data map[string]any
	if err := json.Unmarshal(request.body, &data); err != nil {
		t.Fatalf("request body = %q, want JSON object: %v", request.body, err)
	}
	return data
}

func assertRequest(t *testing.T, request capturedRequest, method, path string) map[string]any {
	t.Helper()
	if request.method != method || request.path != path {
		t.Fatalf("request = %s %s, want %s %s", request.method, request.path, method, path)
	}
	if method == http.MethodGet {
		data := requestData(t, request)
		if data["token"] != contractKey || data["node_id"] != float64(contractNodeID) {
			t.Fatalf("GET data = %#v, want token and node_id", data)
		}
		if len(request.query) != 0 {
			t.Fatalf("GET query = %#v, want empty", request.query)
		}
		return data
	}
	data := requestData(t, request)
	if data["token"] != contractKey || data["node_id"] != float64(contractNodeID) {
		t.Fatalf("POST data = %#v, want token and node_id", data)
	}
	if len(request.query) != 0 {
		t.Fatalf("POST query = %#v, want empty", request.query)
	}
	return data
}

func TestContractGetNodeInfo(t *testing.T) {
	requests := make(chan capturedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- captureRequest(r)
		writeResponse(w, http.StatusOK, `{"code":0,"data":{"port":8443,"transport_protocol":"ws","enable_tls":true,"routes":[{"id":1,"match":["domain:example.com"],"action":"dns","action_value":"1.1.1.1"},{"id":2,"match":["ignored"],"action":"direct","action_value":""}]}}`)
	}))
	defer server.Close()

	node, err := newContractClient(server, "Vless").GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	if node.NodeType != "Vless" || node.NodeID != contractNodeID || node.Port != 8443 || node.TransportProtocol != "ws" || !node.EnableTLS || !node.EnableVless || node.VlessFlow != "xtls-rprx-vision" {
		t.Fatalf("unexpected node: %#v", node)
	}
	if len(node.NameServerConfig) != 1 || node.NameServerConfig[0].Address == nil || node.NameServerConfig[0].Address.Address.String() != "1.1.1.1" || !reflect.DeepEqual(node.NameServerConfig[0].Domains, []string{"domain:example.com"}) {
		t.Fatalf("unexpected DNS config: %#v", node.NameServerConfig)
	}
	assertRequest(t, <-requests, http.MethodPost, "/api/server/config")
}

func TestContractGetNodeInfoValidation(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"null data", `{"code":0,"data":null}`, "node config data is null"},
		{"zero port", `{"code":0,"data":{"port":0}}`, "server port must > 0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan capturedRequest, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- captureRequest(r)
				writeResponse(w, http.StatusOK, tc.body)
			}))
			defer server.Close()
			_, err := newContractClient(server, "V2ray").GetNodeInfo()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			assertRequest(t, <-requests, http.MethodPost, "/api/server/config")
		})
	}
}

func TestContractGetUserList(t *testing.T) {
	requests := make(chan capturedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- captureRequest(r)
		writeResponse(w, http.StatusOK, `{"code":0,"data":{"users":[{"id":9,"uuid":"98a30d33-3214-4d85-82ee-efbbce687561","speed_limit":24}]}}`)
	}))
	defer server.Close()

	users, err := newContractClient(server, "Shadowsocks").GetUserList()
	if err != nil {
		t.Fatal(err)
	}
	want := []api.UserInfo{{
		UID:         9,
		UUID:        "98a30d33-3214-4d85-82ee-efbbce687561",
		Passwd:      "98a30d33-3214-4d85-82ee-efbbce687561",
		SpeedLimit:  3_000_000,
		DeviceLimit: 3,
		Email:       "98a30d33-3214-4d85-82ee-efbbce687561@gov2panel.user",
	}}
	if !reflect.DeepEqual(*users, want) {
		t.Fatalf("users = %#v, want %#v", *users, want)
	}
	assertRequest(t, <-requests, http.MethodGet, "/api/server/user")
}

func TestContractUnsupportedNodeTypeDoesNotRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	_, err := newContractClient(server, "invalid").GetUserList()
	if err == nil || !strings.Contains(err.Error(), "unsupported node type") {
		t.Fatalf("error = %v, want unsupported node type", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("unsupported node type sent %d requests", calls.Load())
	}
}

func TestContractGetNodeRule(t *testing.T) {
	rulePath := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(rulePath, []byte("local\\.example\n[\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	requests := make(chan capturedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- captureRequest(r)
		writeResponse(w, http.StatusOK, `{"code":0,"data":{"routes":[{"id":4,"match":["blocked\\.example","["],"action":"block"},{"id":5,"match":["allowed\\.example"],"action":"direct"}]}}`)
	}))
	defer server.Close()
	client := gov2panel.New(&api.Config{APIHost: server.URL, Key: contractKey, NodeID: contractNodeID, NodeType: "V2ray", RuleListPath: rulePath})

	rules, err := client.GetNodeRule()
	if err != nil {
		t.Fatal(err)
	}
	if len(*rules) != 2 || (*rules)[0].ID != -1 || (*rules)[1].ID != 0 || !(*rules)[0].Pattern.MatchString("local.example") || !(*rules)[1].Pattern.MatchString("blocked.example") {
		t.Fatalf("unexpected rules: %#v", *rules)
	}
	assertRequest(t, <-requests, http.MethodPost, "/api/server/config")
}

func TestContractReportUserTraffic(t *testing.T) {
	requests := make(chan capturedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- captureRequest(r)
		writeResponse(w, http.StatusOK, `{"code":0,"message":"ok"}`)
	}))
	defer server.Close()
	traffic := []api.UserTraffic{{UID: 9, Upload: 123, Download: 456}}
	if err := newContractClient(server, "V2ray").ReportUserTraffic(&traffic); err != nil {
		t.Fatal(err)
	}
	data := assertRequest(t, <-requests, http.MethodPost, "/api/server/push")
	encoded, err := json.Marshal(data["data"])
	if err != nil {
		t.Fatal(err)
	}
	var got []api.UserTraffic
	if err := json.Unmarshal(encoded, &got); err != nil || !reflect.DeepEqual(got, traffic) {
		t.Fatalf("traffic data = %s, want %#v: %v", encoded, traffic, err)
	}
}

func TestContractNoOpAndAbsentCapabilitiesDoNotRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := newContractClient(server, "V2ray")
	if err := client.ReportNodeStatus(&api.NodeStatus{}); err != nil {
		t.Fatal(err)
	}
	online := []api.OnlineUser{{UID: 9, IP: "192.0.2.9"}}
	if err := client.ReportNodeOnlineUsers(&online); err != nil {
		t.Fatal(err)
	}
	illegal := []api.DetectResult{{UID: 9, RuleID: 4}}
	if err := client.ReportIllegal(&illegal); err != nil {
		t.Fatal(err)
	}
	if alive, err := client.GetAliveList(); err != nil || alive != nil {
		t.Fatalf("alive = %#v, err = %v", alive, err)
	}
	if cert, err := client.GetXrayRCertConfig(); err != nil || cert != nil {
		t.Fatalf("cert = %#v, err = %v", cert, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("no-op or absent capabilities sent %d requests", calls.Load())
	}
}

func TestContractResponseErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		run    func(*gov2panel.APIClient) error
		want   string
	}{
		{"malformed JSON", http.StatusOK, `{`, func(c *gov2panel.APIClient) error { _, err := c.GetUserList(); return err }, "valid JSON"},
		{"HTTP 500 with successful envelope", http.StatusInternalServerError, `{"code":0,"data":{"users":[]}}`, func(c *gov2panel.APIClient) error { _, err := c.GetUserList(); return err }, "status 500"},
		{"nonzero code", http.StatusOK, `{"code":12,"message":"panel rejected"}`, func(c *gov2panel.APIClient) error { _, err := c.GetNodeRule(); return err }, "panel rejected"},
		{"traffic nonzero code", http.StatusOK, `{"code":13,"message":"traffic rejected"}`, func(c *gov2panel.APIClient) error {
			traffic := []api.UserTraffic{{UID: 9, Upload: 1, Download: 2}}
			return c.ReportUserTraffic(&traffic)
		}, "traffic rejected"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan capturedRequest, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- captureRequest(r)
				writeResponse(w, tc.status, tc.body)
			}))
			defer server.Close()
			err := tc.run(newContractClient(server, "V2ray"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			request := <-requests
			if request.path == "/api/server/user" {
				assertRequest(t, request, http.MethodGet, request.path)
			} else {
				assertRequest(t, request, http.MethodPost, request.path)
			}
		})
	}
}

func requireGov2panelIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("XRAYRP_RUN_GOV2PANEL_INTEGRATION") != "1" {
		t.Skip("skipping gov2panel integration test; set XRAYRP_RUN_GOV2PANEL_INTEGRATION=1 to enable")
	}
}

func integrationClient() api.API {
	return gov2panel.New(&api.Config{APIHost: "http://localhost:8080", Key: "123456", NodeID: 90, NodeType: "V2ray"})
}

func TestIntegrationGetNodeInfo(t *testing.T) {
	requireGov2panelIntegration(t)
	node, err := integrationClient().GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	if node == nil {
		t.Fatal("expected node info, got nil")
	}
}

func TestIntegrationGetUserList(t *testing.T) {
	requireGov2panelIntegration(t)
	users, err := integrationClient().GetUserList()
	if err != nil {
		t.Fatal(err)
	}
	if users == nil {
		t.Fatal("expected user list, got nil")
	}
}

func TestIntegrationReportUserTraffic(t *testing.T) {
	requireGov2panelIntegration(t)
	traffic := []api.UserTraffic{{UID: 1, Upload: 1, Download: 1}}
	if err := integrationClient().ReportUserTraffic(&traffic); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationGetNodeRule(t *testing.T) {
	requireGov2panelIntegration(t)
	if _, err := integrationClient().GetNodeRule(); err != nil {
		t.Fatal(err)
	}
}
