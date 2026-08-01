package cmd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/panel"
	"github.com/Mtoly/XrayRP/service"
)

type mutableObservabilitySource struct {
	mu       sync.RWMutex
	snapshot service.RuntimeSnapshot
}

func (s *mutableObservabilitySource) ObservabilitySnapshot() service.RuntimeSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot.Clone()
}

func (s *mutableObservabilitySource) set(snapshot service.RuntimeSnapshot) {
	s.mu.Lock()
	s.snapshot = snapshot
	s.mu.Unlock()
}

func TestObservabilityHandlersReadinessMatrix(t *testing.T) {
	now := time.Now()
	source := &mutableObservabilitySource{}
	runtime, err := newObservabilityServer(&panel.ObservabilityConfig{
		Enable:              true,
		Listen:              "127.0.0.1:0",
		ReadinessStaleAfter: 180,
	}, source)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		snapshot   service.RuntimeSnapshot
		wantCode   int
		wantStatus string
		wantLive   int
		wantReady  string
	}{
		{
			name: "normal",
			snapshot: panelSnapshotWithChild(service.RuntimeSnapshot{
				Kind:               service.RuntimeKindController,
				Lifecycle:          service.RuntimeLifecycleRunning,
				LastSuccessfulSync: now,
				WebSocket:          service.WebSocketConnected,
			}),
			wantCode:   http.StatusOK,
			wantStatus: `"status":"ready"`,
			wantLive:   http.StatusOK,
			wantReady:  "xrayrp_ready 1",
		},
		{
			name: "degraded",
			snapshot: panelSnapshotWithChild(service.RuntimeSnapshot{
				Kind:               service.RuntimeKindController,
				Lifecycle:          service.RuntimeLifecycleRunning,
				LastSuccessfulSync: now,
				WebSocket:          service.WebSocketDegraded,
			}),
			wantCode:   http.StatusOK,
			wantStatus: `"status":"degraded"`,
			wantLive:   http.StatusOK,
			wantReady:  "xrayrp_ready 1",
		},
		{
			name: "failed owned",
			snapshot: service.RuntimeSnapshot{
				Kind:           service.RuntimeKindPanel,
				Lifecycle:      service.RuntimeLifecycleFailedOwned,
				CleanupPending: true,
			},
			wantCode:   http.StatusServiceUnavailable,
			wantStatus: `"status":"not_ready"`,
			wantLive:   http.StatusOK,
			wantReady:  "xrayrp_ready 0",
		},
		{
			name: "stale",
			snapshot: panelSnapshotWithChild(service.RuntimeSnapshot{
				Kind:               service.RuntimeKindController,
				Lifecycle:          service.RuntimeLifecycleRunning,
				LastSuccessfulSync: now.Add(-10 * time.Minute),
			}),
			wantCode:   http.StatusServiceUnavailable,
			wantStatus: `"status":"not_ready"`,
			wantLive:   http.StatusOK,
			wantReady:  "xrayrp_ready 0",
		},
		{
			name: "shutdown",
			snapshot: service.RuntimeSnapshot{
				Kind:      service.RuntimeKindPanel,
				Lifecycle: service.RuntimeLifecycleClosed,
			},
			wantCode:   http.StatusServiceUnavailable,
			wantStatus: `"status":"not_ready"`,
			wantLive:   http.StatusServiceUnavailable,
			wantReady:  "xrayrp_ready 0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source.set(test.snapshot)

			ready := httptest.NewRecorder()
			runtime.handleReady(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if ready.Code != test.wantCode || !strings.Contains(ready.Body.String(), test.wantStatus) {
				t.Fatalf("/readyz = code:%d body:%s", ready.Code, ready.Body.String())
			}

			live := httptest.NewRecorder()
			runtime.handleLive(live, httptest.NewRequest(http.MethodGet, "/livez", nil))
			if live.Code != test.wantLive {
				t.Fatalf("/livez code = %d, want %d", live.Code, test.wantLive)
			}

			metrics := httptest.NewRecorder()
			runtime.handleMetrics(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if metrics.Code != http.StatusOK || !strings.Contains(metrics.Body.String(), test.wantReady) {
				t.Fatalf("/metrics = code:%d body:%s", metrics.Code, metrics.Body.String())
			}
		})
	}
}

func TestMetricsUseOnlyBoundedLabelsAndNeverExposeIdentifiers(t *testing.T) {
	secret := "token-secret-value"
	snapshot := service.RuntimeSnapshot{
		Kind:             service.RuntimeKind(secret),
		Mode:             service.RuntimeMode(secret),
		Lifecycle:        service.RuntimeLifecycle(secret),
		WebSocket:        service.WebSocketState(secret),
		LastFailureStage: service.FailureStage(secret),
		Children: []service.RuntimeSnapshot{{
			Kind:               service.RuntimeKindController,
			NodeID:             424242,
			Lifecycle:          service.RuntimeLifecycleRunning,
			LastSuccessfulSync: time.Now(),
		}},
	}
	payload := string(renderMetrics(snapshot, service.Readiness{Ready: true}, true))
	for _, forbidden := range []string{secret, "424242", "user_id=", "ip=", "uuid=", "token=", "password=", "private_key="} {
		if strings.Contains(strings.ToLower(payload), strings.ToLower(forbidden)) {
			t.Fatalf("metrics contain forbidden value %q:\n%s", forbidden, payload)
		}
	}

	labelPattern := regexp.MustCompile(`([a-z_]+)=`)
	allowed := map[string]bool{
		"kind": true, "mode": true, "lifecycle": true,
		"node_slot": true, "websocket": true, "failure_stage": true,
	}
	for _, match := range labelPattern.FindAllStringSubmatch(payload, -1) {
		if !allowed[match[1]] {
			t.Fatalf("metrics contain unbounded label %q:\n%s", match[1], payload)
		}
	}
}

func TestObservabilityServerLifecycleAndAddressPolicy(t *testing.T) {
	for _, address := range []string{"0.0.0.0:10085", "203.0.113.10:10085", ":10085"} {
		if _, err := newObservabilityServer(&panel.ObservabilityConfig{Enable: true, Listen: address}, &mutableObservabilitySource{}); err == nil {
			t.Fatalf("newObservabilityServer(%q) error = nil", address)
		}
	}

	source := &mutableObservabilitySource{snapshot: panelSnapshotWithChild(service.RuntimeSnapshot{
		Kind:               service.RuntimeKindController,
		Lifecycle:          service.RuntimeLifecycleRunning,
		LastSuccessfulSync: time.Now(),
	})}
	runtime, err := newObservabilityServer(&panel.ObservabilityConfig{
		Enable: true,
		Listen: "127.0.0.1:0",
	}, source)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.StartContext(ctx); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://" + runtime.address() + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("/readyz status = %d", response.StatusCode)
	}

	runtime.BeginShutdown()
	response, err = client.Get("http://" + runtime.address() + "/livez")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/livez during shutdown status = %d", response.StatusCode)
	}
	if err := runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
}

func panelSnapshotWithChild(child service.RuntimeSnapshot) service.RuntimeSnapshot {
	return service.RuntimeSnapshot{
		Kind:      service.RuntimeKindPanel,
		Mode:      service.RuntimeModeStatic,
		Lifecycle: service.RuntimeLifecycleRunning,
		Children:  []service.RuntimeSnapshot{child},
	}
}
