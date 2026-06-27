package newV2board

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
)

func TestDiscoverMachineNodesPostsMachineCredentials(t *testing.T) {
	t.Parallel()

	requests := make(chan machineDiscoveryRequestCapture, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/api/v2/server/machine/nodes" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if contentType := r.Header.Get("Content-Type"); !strings.Contains(contentType, "application/json") {
			t.Fatalf("unexpected content type: %q", contentType)
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		requests <- machineDiscoveryRequestCapture{Body: body}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nodes":[{"id":11,"type":"Vless","name":"primary"},{"id":12,"type":"Trojan","name":"backup"}],"base_config":{"push_interval":15,"pull_interval":30}}`))
	}))
	defer server.Close()

	resp, err := DiscoverMachineNodes(MachineDiscoveryConfig{
		APIHost:   server.URL,
		MachineID: 7,
		Token:     "machine-token",
		Timeout:   time.Second,
	})
	if err != nil {
		t.Fatalf("DiscoverMachineNodes returned error: %v", err)
	}

	got := <-requests
	if got.Body["machine_id"] != float64(7) || got.Body["token"] != "machine-token" {
		t.Fatalf("unexpected request body: %#v", got.Body)
	}
	if len(resp.Nodes) != 2 {
		t.Fatalf("unexpected nodes: %#v", resp.Nodes)
	}
	if resp.Nodes[0].ID != 11 || resp.Nodes[0].Type != "Vless" || resp.Nodes[0].Name != "primary" {
		t.Fatalf("unexpected first node: %#v", resp.Nodes[0])
	}
	if resp.Nodes[1].ID != 12 || resp.Nodes[1].Type != "Trojan" || resp.Nodes[1].Name != "backup" {
		t.Fatalf("unexpected second node: %#v", resp.Nodes[1])
	}
	if resp.BaseConfig.PushInterval != 15 || resp.BaseConfig.PullInterval != 30 {
		t.Fatalf("unexpected base_config: %#v", resp.BaseConfig)
	}
}

func TestDiscoverMachineNodesRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config MachineDiscoveryConfig
	}{
		{
			name:   "empty APIHost",
			config: MachineDiscoveryConfig{APIHost: " ", MachineID: 7, Token: "machine-token"},
		},
		{
			name:   "zero MachineID",
			config: MachineDiscoveryConfig{APIHost: "http://example.test", MachineID: 0, Token: "machine-token"},
		},
		{
			name:   "negative MachineID",
			config: MachineDiscoveryConfig{APIHost: "http://example.test", MachineID: -1, Token: "machine-token"},
		},
		{
			name:   "empty Token",
			config: MachineDiscoveryConfig{APIHost: "http://example.test", MachineID: 7, Token: " "},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := DiscoverMachineNodes(tt.config)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDiscoverMachineNodesReturnsHTTPError(t *testing.T) {
	tests := []int{http.StatusForbidden, http.StatusInternalServerError}

	for _, status := range tests {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, http.StatusText(status), status)
			}))
			defer server.Close()

			_, err := DiscoverMachineNodes(MachineDiscoveryConfig{
				APIHost:   server.URL,
				MachineID: 7,
				Token:     "machine-token",
			})
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), strconv.Itoa(status)) {
				t.Fatalf("expected error to contain status code %d, got %v", status, err)
			}
		})
	}
}

func TestDiscoverMachineNodesRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer server.Close()

	_, err := DiscoverMachineNodes(MachineDiscoveryConfig{
		APIHost:   server.URL,
		MachineID: 7,
		Token:     "machine-token",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDiscoverMachineNodesRequiresNodesArray(t *testing.T) {
	tests := map[string]string{
		"missing nodes": `{"base_config":{"push_interval":15,"pull_interval":30}}`,
		"nodes null":    `{"nodes":null}`,
		"nodes object":  `{"nodes":{}}`,
		"nodes string":  `{"nodes":"invalid"}`,
	}

	for name, body := range tests {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()

			_, err := DiscoverMachineNodes(MachineDiscoveryConfig{
				APIHost:   server.URL,
				MachineID: 7,
				Token:     "machine-token",
			})
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDiscoverMachineNodesAllowsMissingBaseConfig(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nodes":[]}`))
	}))
	defer server.Close()

	resp, err := DiscoverMachineNodes(MachineDiscoveryConfig{
		APIHost:   server.URL,
		MachineID: 7,
		Token:     "machine-token",
	})
	if err != nil {
		t.Fatalf("DiscoverMachineNodes returned error: %v", err)
	}
	if len(resp.Nodes) != 0 {
		t.Fatalf("unexpected nodes: %#v", resp.Nodes)
	}
	if resp.BaseConfig.PushInterval != 0 || resp.BaseConfig.PullInterval != 0 {
		t.Fatalf("unexpected base_config: %#v", resp.BaseConfig)
	}
}

func TestReportMachineStatusPostsMachinePayload(t *testing.T) {
	t.Parallel()

	requests := make(chan machineDiscoveryRequestCapture, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/api/v2/server/machine/status" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if contentType := r.Header.Get("Content-Type"); !strings.Contains(contentType, "application/json") {
			t.Fatalf("unexpected content type: %q", contentType)
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		requests <- machineDiscoveryRequestCapture{Body: body}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":true}`))
	}))
	defer server.Close()

	err := ReportMachineStatus(MachineDiscoveryConfig{
		APIHost:   server.URL,
		MachineID: 7,
		Token:     "machine-token",
	}, api.MachineStatus{
		CPU:         12.3,
		MemTotal:    1000,
		MemUsed:     400,
		SwapTotal:   200,
		SwapUsed:    50,
		DiskTotal:   5000,
		DiskUsed:    1234,
		NetInSpeed:  1024,
		NetOutSpeed: 2048,
	})
	if err != nil {
		t.Fatalf("ReportMachineStatus returned error: %v", err)
	}

	got := <-requests
	if got.Body["machine_id"] != float64(7) || got.Body["token"] != "machine-token" {
		t.Fatalf("unexpected auth body: %#v", got.Body)
	}
	if got.Body["cpu"] != 12.3 {
		t.Fatalf("unexpected cpu: %#v", got.Body["cpu"])
	}
	mem := got.Body["mem"].(map[string]any)
	if mem["total"] != float64(1000) || mem["used"] != float64(400) {
		t.Fatalf("unexpected mem: %#v", mem)
	}
	swap := got.Body["swap"].(map[string]any)
	if swap["total"] != float64(200) || swap["used"] != float64(50) {
		t.Fatalf("unexpected swap: %#v", swap)
	}
	disk := got.Body["disk"].(map[string]any)
	if disk["total"] != float64(5000) || disk["used"] != float64(1234) {
		t.Fatalf("unexpected disk: %#v", disk)
	}
	net := got.Body["net"].(map[string]any)
	if net["in_speed"] != float64(1024) || net["out_speed"] != float64(2048) {
		t.Fatalf("unexpected net: %#v", net)
	}
}

func TestReportMachineStatusOmitsUnavailableNetworkSpeed(t *testing.T) {
	t.Parallel()

	requests := make(chan machineDiscoveryRequestCapture, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		requests <- machineDiscoveryRequestCapture{Body: body}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":true}`))
	}))
	defer server.Close()

	if err := ReportMachineStatus(MachineDiscoveryConfig{APIHost: server.URL, MachineID: 7, Token: "machine-token"}, api.MachineStatus{NetInSpeed: -1, NetOutSpeed: -1}); err != nil {
		t.Fatalf("ReportMachineStatus returned error: %v", err)
	}
	got := <-requests
	if _, ok := got.Body["net"]; ok {
		t.Fatalf("expected unavailable net speeds to be omitted, got %#v", got.Body["net"])
	}
}

func TestReportMachineStatusReturnsHTTPError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}))
	defer server.Close()

	err := ReportMachineStatus(MachineDiscoveryConfig{APIHost: server.URL, MachineID: 7, Token: "machine-token"}, api.MachineStatus{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected status code in error, got %v", err)
	}
}

type machineDiscoveryRequestCapture struct {
	Body map[string]any
}
