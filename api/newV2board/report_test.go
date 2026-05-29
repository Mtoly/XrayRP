package newV2board

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestBuildReportStatusPayloadIncludesStatusFields(t *testing.T) {
	payload, err := buildReportStatusPayload(&api.NodeStatus{
		CPU:    12.3,
		Mem:    45.4,
		Disk:   60.6,
		Uptime: 123456,
	})
	if err != nil {
		t.Fatalf("buildReportStatusPayload returned error: %v", err)
	}

	if payload["type"] != "status" {
		t.Fatalf("unexpected type: %#v", payload["type"])
	}
	status, ok := payload["status"].(map[string]any)
	if !ok {
		t.Fatalf("status payload has unexpected type: %#v", payload["status"])
	}
	if status["cpu"] != 12.3 {
		t.Fatalf("unexpected cpu: %#v", status["cpu"])
	}
	if status["uptime"] != uint64(123456) {
		t.Fatalf("unexpected uptime: %#v", status["uptime"])
	}

	mem := status["mem"].(map[string]int)
	if mem["total"] != 100 || mem["used"] != 45 {
		t.Fatalf("unexpected mem: %#v", mem)
	}
	disk := status["disk"].(map[string]int)
	if disk["total"] != 100 || disk["used"] != 61 {
		t.Fatalf("unexpected disk: %#v", disk)
	}
	swap := status["swap"].(map[string]int)
	if swap["total"] != 0 || swap["used"] != 0 {
		t.Fatalf("unexpected swap: %#v", swap)
	}
}

func TestBuildReportStatusPayloadClampsPercentages(t *testing.T) {
	payload, err := buildReportStatusPayload(&api.NodeStatus{Mem: -10, Disk: 120})
	if err != nil {
		t.Fatalf("buildReportStatusPayload returned error: %v", err)
	}
	status := payload["status"].(map[string]any)
	mem := status["mem"].(map[string]int)
	disk := status["disk"].(map[string]int)
	if mem["used"] != 0 {
		t.Fatalf("expected mem used to clamp to 0, got %d", mem["used"])
	}
	if disk["used"] != 100 {
		t.Fatalf("expected disk used to clamp to 100, got %d", disk["used"])
	}
}

func TestBuildReportStatusPayloadRejectsNilStatus(t *testing.T) {
	_, err := buildReportStatusPayload(nil)
	if err == nil {
		t.Fatal("expected error for nil status")
	}
	if !errors.Is(err, errNilNodeStatus) {
		t.Fatalf("expected errNilNodeStatus, got %v", err)
	}
}

func TestBuildReportAlivePayloadSkipsInvalidUsers(t *testing.T) {
	users := []api.OnlineUser{
		{UID: 1, IP: "1.2.3.4"},
		{UID: 0, IP: "skip.zero.uid"},
		{UID: 2, IP: ""},
		{UID: 1, IP: "5.6.7.8"},
	}

	payload := buildReportAlivePayload(&users, 100)
	if payload["type"] != "alive" {
		t.Fatalf("unexpected type: %#v", payload["type"])
	}
	alive, ok := payload["alive"].(map[int][]string)
	if !ok {
		t.Fatalf("alive payload has unexpected type: %#v", payload["alive"])
	}
	got := alive[1]
	want := []string{"1.2.3.4_100", "5.6.7.8_100"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unexpected alive users: got %#v want %#v", got, want)
	}
	if _, ok := alive[0]; ok {
		t.Fatalf("zero UID should be skipped: %#v", alive)
	}
	if _, ok := alive[2]; ok {
		t.Fatalf("empty IP should be skipped: %#v", alive)
	}
}

func TestBuildReportAlivePayloadAllowsNilAndEmpty(t *testing.T) {
	for name, users := range map[string]*[]api.OnlineUser{
		"nil":   nil,
		"empty": ptrToSlice([]api.OnlineUser{}),
	} {
		t.Run(name, func(t *testing.T) {
			payload := buildReportAlivePayload(users, 100)
			alive := payload["alive"].(map[int][]string)
			if len(alive) != 0 {
				t.Fatalf("expected empty alive map, got %#v", alive)
			}
		})
	}
}

func TestBuildReportTrafficPayloadPreservesTrafficMap(t *testing.T) {
	traffic := []api.UserTraffic{
		{UID: 1, Upload: 123, Download: 456},
		{UID: 2, Upload: 789, Download: 1000},
	}

	payload := buildReportTrafficPayload(&traffic)
	if payload["type"] != "traffic" {
		t.Fatalf("unexpected type: %#v", payload["type"])
	}
	got := payload["traffic"].(map[int][]int64)
	if got[1][0] != 123 || got[1][1] != 456 {
		t.Fatalf("unexpected UID 1 traffic: %#v", got[1])
	}
	if got[2][0] != 789 || got[2][1] != 1000 {
		t.Fatalf("unexpected UID 2 traffic: %#v", got[2])
	}
}

func TestBuildReportTrafficPayloadAllowsNilAndEmpty(t *testing.T) {
	for name, traffic := range map[string]*[]api.UserTraffic{
		"nil":   nil,
		"empty": ptrToSlice([]api.UserTraffic{}),
	} {
		t.Run(name, func(t *testing.T) {
			payload := buildReportTrafficPayload(traffic)
			got := payload["traffic"].(map[int][]int64)
			if len(got) != 0 {
				t.Fatalf("expected empty traffic map, got %#v", got)
			}
		})
	}
}

func TestIsReportEndpointUnsupported(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"404", 404, `{"message":"anything"}`, true},
		{"405", 405, ``, true},
		{"501", 501, ``, true},
		{"non2xx unsupported body", 400, `{"message":"Route Not Found"}`, true},
		{"non2xx not support body", 400, `not support this endpoint`, true},
		{"2xx unsupported body ignored", 200, `{"message":"not found"}`, false},
		{"401 no fallback", 401, `unauthorized`, false},
		{"401 unsupported body ignored", 401, `route not found`, false},
		{"403 no fallback", 403, `forbidden`, false},
		{"403 unsupported body ignored", 403, `route not found`, false},
		{"500 no fallback", 500, `internal server error`, false},
		{"500 recognized unsupported", 500, `not implemented`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isReportEndpointUnsupported(tt.status, []byte(tt.body))
			if got != tt.want {
				t.Fatalf("isReportEndpointUnsupported(%d, %q) = %v, want %v", tt.status, tt.body, got, tt.want)
			}
		})
	}
}

func TestReportNodeStatusRejectsNilStatusWithoutRequest(t *testing.T) {
	t.Parallel()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		t.Fatalf("unexpected request for nil status: %s", r.URL.Path)
	}))
	defer server.Close()

	client := newReportTestClient(server.URL)
	err := client.ReportNodeStatus(nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errNilNodeStatus) {
		t.Fatalf("expected errNilNodeStatus, got %v", err)
	}
	if requestCount != 0 {
		t.Fatalf("expected no requests, got %d", requestCount)
	}
}

func TestReportNodeStatusPostsToXboardReport(t *testing.T) {
	t.Parallel()

	requests := make(chan capturedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != xboardReportPath {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		requests <- readJSONRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":true}`))
	}))
	defer server.Close()

	client := newReportTestClient(server.URL)
	err := client.ReportNodeStatus(&api.NodeStatus{CPU: 1.5, Mem: 2, Disk: 3, Uptime: 4})
	if err != nil {
		t.Fatalf("ReportNodeStatus returned error: %v", err)
	}

	got := <-requests
	if got.NodeID != "100" || got.NodeType != "vless" || got.Token != "secret" {
		t.Fatalf("unexpected query params: %#v", got)
	}
	if got.Body["type"] != "status" {
		t.Fatalf("unexpected body: %#v", got.Body)
	}
}

func TestReportNodeOnlineUsersPostsToXboardReport(t *testing.T) {
	t.Parallel()

	requests := make(chan capturedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != xboardReportPath {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		requests <- readJSONRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":true}`))
	}))
	defer server.Close()

	client := newReportTestClient(server.URL)
	users := []api.OnlineUser{{UID: 1, IP: "1.2.3.4"}}
	if err := client.ReportNodeOnlineUsers(&users); err != nil {
		t.Fatalf("ReportNodeOnlineUsers returned error: %v", err)
	}

	got := <-requests
	if got.Body["type"] != "alive" {
		t.Fatalf("unexpected body: %#v", got.Body)
	}
}

func TestReportNodeOnlineUsersAllowsNilAndEmpty(t *testing.T) {
	t.Parallel()

	requests := make(chan capturedRequest, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != xboardReportPath {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		requests <- readJSONRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":true}`))
	}))
	defer server.Close()

	client := newReportTestClient(server.URL)
	if err := client.ReportNodeOnlineUsers(nil); err != nil {
		t.Fatalf("ReportNodeOnlineUsers(nil) returned error: %v", err)
	}
	empty := []api.OnlineUser{}
	if err := client.ReportNodeOnlineUsers(&empty); err != nil {
		t.Fatalf("ReportNodeOnlineUsers(empty) returned error: %v", err)
	}

	for i := 0; i < 2; i++ {
		got := <-requests
		alive, ok := got.Body["alive"].(map[string]any)
		if !ok {
			t.Fatalf("alive payload has unexpected type: %#v", got.Body["alive"])
		}
		if len(alive) != 0 {
			t.Fatalf("expected empty alive payload, got %#v", alive)
		}
	}
}

func TestReportUserTrafficPostsToXboardReport(t *testing.T) {
	t.Parallel()

	requests := make(chan capturedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != xboardReportPath {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		requests <- readJSONRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":true}`))
	}))
	defer server.Close()

	client := newReportTestClient(server.URL)
	traffic := []api.UserTraffic{{UID: 1, Upload: 123, Download: 456}}
	if err := client.ReportUserTraffic(&traffic); err != nil {
		t.Fatalf("ReportUserTraffic returned error: %v", err)
	}

	got := <-requests
	if got.Body["type"] != "traffic" {
		t.Fatalf("unexpected body: %#v", got.Body)
	}
}

func TestReportUserTrafficAllowsNilAndEmpty(t *testing.T) {
	t.Parallel()

	requests := make(chan capturedRequest, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != xboardReportPath {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		requests <- readJSONRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":true}`))
	}))
	defer server.Close()

	client := newReportTestClient(server.URL)
	if err := client.ReportUserTraffic(nil); err != nil {
		t.Fatalf("ReportUserTraffic(nil) returned error: %v", err)
	}
	empty := []api.UserTraffic{}
	if err := client.ReportUserTraffic(&empty); err != nil {
		t.Fatalf("ReportUserTraffic(empty) returned error: %v", err)
	}

	for i := 0; i < 2; i++ {
		got := <-requests
		traffic, ok := got.Body["traffic"].(map[string]any)
		if !ok {
			t.Fatalf("traffic payload has unexpected type: %#v", got.Body["traffic"])
		}
		if len(traffic) != 0 {
			t.Fatalf("expected empty traffic payload, got %#v", traffic)
		}
	}
}

func TestReportNodeStatusFallsBackToLegacyWhenXboardReportUnsupported(t *testing.T) {
	t.Parallel()

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case xboardReportPath:
			http.NotFound(w, r)
		case "/api/v1/server/UniProxy/status":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":true}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newReportTestClient(server.URL)
	if err := client.ReportNodeStatus(&api.NodeStatus{}); err != nil {
		t.Fatalf("ReportNodeStatus returned error: %v", err)
	}
	assertPaths(t, paths, []string{xboardReportPath, "/api/v1/server/UniProxy/status"})
}

func TestReportNodeOnlineUsersFallsBackToLegacyWhenXboardReportUnsupported(t *testing.T) {
	t.Parallel()

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case xboardReportPath:
			http.NotFound(w, r)
		case "/api/v1/server/UniProxy/alive":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":true}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newReportTestClient(server.URL)
	users := []api.OnlineUser{{UID: 1, IP: "1.2.3.4"}}
	if err := client.ReportNodeOnlineUsers(&users); err != nil {
		t.Fatalf("ReportNodeOnlineUsers returned error: %v", err)
	}
	assertPaths(t, paths, []string{xboardReportPath, "/api/v1/server/UniProxy/alive"})
}

func TestReportUserTrafficFallsBackToLegacyWhenXboardReportUnsupported(t *testing.T) {
	t.Parallel()

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case xboardReportPath:
			http.NotFound(w, r)
		case "/api/v1/server/UniProxy/push":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":true}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newReportTestClient(server.URL)
	traffic := []api.UserTraffic{{UID: 1, Upload: 123, Download: 456}}
	if err := client.ReportUserTraffic(&traffic); err != nil {
		t.Fatalf("ReportUserTraffic returned error: %v", err)
	}
	assertPaths(t, paths, []string{xboardReportPath, "/api/v1/server/UniProxy/push"})
}

func TestReportFallbacksOnRecognizedUnsupportedBody(t *testing.T) {
	t.Parallel()

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case xboardReportPath:
			http.Error(w, `{"message":"route not found"}`, http.StatusBadRequest)
		case "/api/v1/server/UniProxy/status":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":true}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newReportTestClient(server.URL)
	if err := client.ReportNodeStatus(&api.NodeStatus{}); err != nil {
		t.Fatalf("ReportNodeStatus returned error: %v", err)
	}
	assertPaths(t, paths, []string{xboardReportPath, "/api/v1/server/UniProxy/status"})
}

func TestReportUnsupportedCacheSkipsXboardReportAfterFirstUnsupported(t *testing.T) {
	t.Parallel()

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case xboardReportPath:
			http.NotFound(w, r)
		case "/api/v1/server/UniProxy/status", "/api/v1/server/UniProxy/push":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":true}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newReportTestClient(server.URL)
	if err := client.ReportNodeStatus(&api.NodeStatus{}); err != nil {
		t.Fatalf("ReportNodeStatus returned error: %v", err)
	}
	traffic := []api.UserTraffic{{UID: 1, Upload: 1, Download: 2}}
	if err := client.ReportUserTraffic(&traffic); err != nil {
		t.Fatalf("ReportUserTraffic returned error: %v", err)
	}

	assertPaths(t, paths, []string{
		xboardReportPath,
		"/api/v1/server/UniProxy/status",
		"/api/v1/server/UniProxy/push",
	})
}

func TestReportDoesNotFallbackOnAuthOrServerErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"401", http.StatusUnauthorized, `unauthorized`},
		{"403", http.StatusForbidden, `forbidden`},
		{"500", http.StatusInternalServerError, `internal server error`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				http.Error(w, tt.body, tt.status)
			}))
			defer server.Close()

			client := newReportTestClient(server.URL)
			err := client.ReportNodeStatus(&api.NodeStatus{})
			if err == nil {
				t.Fatal("expected error")
			}
			assertPaths(t, paths, []string{xboardReportPath})
		})
	}
}

func TestReportDoesNotFallbackOnMalformedSuccessfulJSON(t *testing.T) {
	t.Parallel()

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer server.Close()

	client := newReportTestClient(server.URL)
	err := client.ReportNodeStatus(&api.NodeStatus{})
	if err == nil {
		t.Fatal("expected malformed JSON error")
	}
	assertPaths(t, paths, []string{xboardReportPath})
}

type capturedRequest struct {
	Path     string
	NodeID   string
	NodeType string
	Token    string
	Body     map[string]any
}

func readJSONRequest(t *testing.T, r *http.Request) capturedRequest {
	t.Helper()

	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	return capturedRequest{
		Path:     r.URL.Path,
		NodeID:   r.URL.Query().Get("node_id"),
		NodeType: r.URL.Query().Get("node_type"),
		Token:    r.URL.Query().Get("token"),
		Body:     body,
	}
}

func newReportTestClient(serverURL string) *APIClient {
	return New(&api.Config{
		APIHost:     serverURL,
		Key:         "secret",
		NodeID:      100,
		NodeType:    "V2ray",
		EnableVless: true,
	})
}

func assertPaths(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("unexpected paths: got %#v want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected paths: got %#v want %#v", got, want)
		}
	}
}

func ptrToSlice[T any](items []T) *[]T {
	return &items
}
