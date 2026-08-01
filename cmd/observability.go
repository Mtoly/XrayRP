package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mtoly/XrayRP/panel"
	"github.com/Mtoly/XrayRP/service"
)

const (
	defaultObservabilityListen = "127.0.0.1:10085"
	minReadinessStaleAfter     = 30 * time.Second
)

type observabilityRuntimeConfig struct {
	enabled    bool
	listen     string
	staleAfter time.Duration
}

type observabilityServer struct {
	config observabilityRuntimeConfig
	source service.RuntimeSnapshotProvider

	mu       sync.Mutex
	server   *http.Server
	listener net.Listener
	done     chan error
	started  bool
	closed   bool
	stopping atomic.Bool
}

func newObservabilityServer(config *panel.ObservabilityConfig, source service.RuntimeSnapshotProvider) (*observabilityServer, error) {
	normalized, err := normalizeObservabilityConfig(config)
	if err != nil {
		return nil, err
	}
	if normalized.enabled && source == nil {
		return nil, errors.New("observability snapshot source must not be nil")
	}
	runtime := &observabilityServer{config: normalized, source: source}
	if !normalized.enabled {
		return runtime, nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/livez", runtime.handleLive)
	mux.HandleFunc("/readyz", runtime.handleReady)
	mux.HandleFunc("/metrics", runtime.handleMetrics)
	runtime.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return runtime, nil
}

func normalizeObservabilityConfig(config *panel.ObservabilityConfig) (observabilityRuntimeConfig, error) {
	if config == nil || !config.Enable {
		return observabilityRuntimeConfig{}, nil
	}
	listen := strings.TrimSpace(config.Listen)
	if listen == "" {
		listen = defaultObservabilityListen
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return observabilityRuntimeConfig{}, fmt.Errorf("invalid observability listen address: %w", err)
	}
	if strings.TrimSpace(host) == "" {
		return observabilityRuntimeConfig{}, errors.New("observability listen host must not be empty")
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return observabilityRuntimeConfig{}, fmt.Errorf("invalid observability listen port: %w", err)
	}
	if !safeObservabilityHost(host) {
		return observabilityRuntimeConfig{}, errors.New("observability listen host must be loopback or a private IP because authentication and TLS are not configured")
	}

	staleAfter := time.Duration(config.ReadinessStaleAfter) * time.Second
	if staleAfter == 0 {
		staleAfter = service.DefaultReadinessStaleAfter
	}
	if staleAfter < minReadinessStaleAfter {
		return observabilityRuntimeConfig{}, fmt.Errorf("observability readiness stale threshold must be at least %s", minReadinessStaleAfter)
	}
	return observabilityRuntimeConfig{enabled: true, listen: listen, staleAfter: staleAfter}, nil
}

func safeObservabilityHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func (s *observabilityServer) StartContext(ctx context.Context) error {
	if s == nil || !s.config.enabled {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("observability server is closed")
	}
	if s.started {
		return nil
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.config.listen)
	if err != nil {
		return fmt.Errorf("listen for observability: %w", err)
	}
	done := make(chan error, 1)
	s.listener = listener
	s.done = done
	s.started = true
	go func() {
		err := s.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
		close(done)
	}()
	return nil
}

func (s *observabilityServer) BeginShutdown() {
	if s != nil {
		s.stopping.Store(true)
	}
}

func (s *observabilityServer) CloseContext(ctx context.Context) error {
	if s == nil || !s.config.enabled {
		return nil
	}
	s.BeginShutdown()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	started := s.started
	server := s.server
	done := s.done
	s.mu.Unlock()
	if !started {
		return nil
	}

	shutdownErr := server.Shutdown(ctx)
	var serveErr error
	if done != nil {
		select {
		case <-ctx.Done():
			serveErr = ctx.Err()
		case serveErr = <-done:
		}
	}
	return errors.Join(shutdownErr, serveErr)
}

func (s *observabilityServer) address() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *observabilityServer) snapshot() service.RuntimeSnapshot {
	if s == nil || s.source == nil {
		return service.RuntimeSnapshot{Kind: service.RuntimeKindPanel, Lifecycle: service.RuntimeLifecycleClosed, WebSocket: service.WebSocketDisabled}
	}
	return s.source.ObservabilitySnapshot().Clone()
}

func (s *observabilityServer) handleLive(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	snapshot := s.snapshot()
	live := !s.stopping.Load() && snapshot.Lifecycle != service.RuntimeLifecycleStopping && snapshot.Lifecycle != service.RuntimeLifecycleClosed
	status := http.StatusOK
	value := "live"
	if !live {
		status = http.StatusServiceUnavailable
		value = "shutdown"
	}
	writeJSON(writer, status, struct {
		Status string `json:"status"`
	}{Status: value})
}

func (s *observabilityServer) handleReady(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	readiness := service.EvaluateReadiness(s.snapshot(), time.Now(), s.config.staleAfter)
	status := http.StatusOK
	value := "ready"
	if !readiness.Ready {
		status = http.StatusServiceUnavailable
		value = "not_ready"
	} else if readiness.Degraded {
		value = "degraded"
	}
	writeJSON(writer, status, struct {
		Status  string                    `json:"status"`
		Reasons []service.ReadinessReason `json:"reasons,omitempty"`
	}{
		Status:  value,
		Reasons: readiness.Reasons,
	})
}

func (s *observabilityServer) handleMetrics(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	snapshot := s.snapshot()
	readiness := service.EvaluateReadiness(snapshot, time.Now(), s.config.staleAfter)
	live := !s.stopping.Load() && snapshot.Lifecycle != service.RuntimeLifecycleStopping && snapshot.Lifecycle != service.RuntimeLifecycleClosed
	payload := renderMetrics(snapshot, readiness, live)
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(payload)
	}
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(value); err != nil {
		http.Error(writer, "encoding error", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(payload.Bytes())
}

func renderMetrics(snapshot service.RuntimeSnapshot, readiness service.Readiness, live bool) []byte {
	var buffer bytes.Buffer
	writeMetricHeader(&buffer, "xrayrp_live", "Whether the process is accepting health checks.", "gauge")
	writeGauge(&buffer, "xrayrp_live", nil, boolFloat(live))
	writeMetricHeader(&buffer, "xrayrp_ready", "Whether all required runtimes are ready.", "gauge")
	writeGauge(&buffer, "xrayrp_ready", nil, boolFloat(readiness.Ready))

	slot := 0
	var visit func(service.RuntimeSnapshot, string)
	visit = func(current service.RuntimeSnapshot, nodeSlot string) {
		labels := map[string]string{
			"kind":          boundedRuntimeKind(current.Kind),
			"mode":          boundedRuntimeMode(current.Mode),
			"lifecycle":     boundedLifecycle(current.Lifecycle),
			"node_slot":     nodeSlot,
			"websocket":     boundedWebSocket(current.WebSocket),
			"failure_stage": boundedFailureStage(current.LastFailureStage),
		}
		writeGauge(&buffer, "xrayrp_runtime_state", labels, 1)
		writeGauge(&buffer, "xrayrp_topology_generation", labels, float64(current.TopologyGeneration))
		writeGauge(&buffer, "xrayrp_last_successful_sync_timestamp_seconds", labels, unixSeconds(current.LastSuccessfulSync))
		writeGauge(&buffer, "xrayrp_last_failure_timestamp_seconds", labels, unixSeconds(current.LastFailureAt))
		writeGauge(&buffer, "xrayrp_cleanup_pending", labels, boolFloat(current.CleanupPending))
		writeGauge(&buffer, "xrayrp_traffic_report_backlog", labels, float64(current.TrafficReportBacklog))
		writeGauge(&buffer, "xrayrp_certificate_expiry_timestamp_seconds", labels, unixSeconds(current.CertificateExpiresAt))
		for _, child := range current.Children {
			childSlot := ""
			if isNodeRuntime(child.Kind) {
				childSlot = strconv.Itoa(slot)
				slot++
			}
			visit(child, childSlot)
		}
	}
	writeMetricHeader(&buffer, "xrayrp_runtime_state", "Current bounded runtime lifecycle state.", "gauge")
	writeMetricHeader(&buffer, "xrayrp_topology_generation", "Current machine topology generation.", "gauge")
	writeMetricHeader(&buffer, "xrayrp_last_successful_sync_timestamp_seconds", "Last successful runtime synchronization time.", "gauge")
	writeMetricHeader(&buffer, "xrayrp_last_failure_timestamp_seconds", "Last bounded runtime failure observation time.", "gauge")
	writeMetricHeader(&buffer, "xrayrp_cleanup_pending", "Whether owned runtime cleanup remains pending.", "gauge")
	writeMetricHeader(&buffer, "xrayrp_traffic_report_backlog", "Count of traffic records pending successful reporting.", "gauge")
	writeMetricHeader(&buffer, "xrayrp_certificate_expiry_timestamp_seconds", "Earliest observed certificate expiry time.", "gauge")
	visit(snapshot, "")
	return buffer.Bytes()
}

func isNodeRuntime(kind service.RuntimeKind) bool {
	switch kind {
	case service.RuntimeKindController, service.RuntimeKindAnyTLS, service.RuntimeKindTUIC, service.RuntimeKindHysteria2:
		return true
	default:
		return false
	}
}

func writeMetricHeader(buffer *bytes.Buffer, name, help, metricType string) {
	fmt.Fprintf(buffer, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func writeGauge(buffer *bytes.Buffer, name string, labels map[string]string, value float64) {
	buffer.WriteString(name)
	if len(labels) != 0 {
		keys := []string{"kind", "mode", "lifecycle", "node_slot", "websocket", "failure_stage"}
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			fmt.Fprintf(buffer, `%s=%q`, key, labels[key])
		}
		buffer.WriteByte('}')
	}
	fmt.Fprintf(buffer, " %g\n", value)
}

func boundedRuntimeKind(value service.RuntimeKind) string {
	switch value {
	case service.RuntimeKindPanel, service.RuntimeKindMachine, service.RuntimeKindController, service.RuntimeKindAnyTLS, service.RuntimeKindTUIC, service.RuntimeKindHysteria2:
		return string(value)
	default:
		return "unknown"
	}
}

func boundedRuntimeMode(value service.RuntimeMode) string {
	switch value {
	case service.RuntimeModeStatic, service.RuntimeModeMachine:
		return string(value)
	default:
		return "unknown"
	}
}

func boundedLifecycle(value service.RuntimeLifecycle) string {
	switch value {
	case service.RuntimeLifecycleStopped, service.RuntimeLifecycleStarting, service.RuntimeLifecycleRunning,
		service.RuntimeLifecycleReloading, service.RuntimeLifecycleStopping, service.RuntimeLifecycleFailed,
		service.RuntimeLifecycleFailedOwned, service.RuntimeLifecycleRetiring, service.RuntimeLifecycleClosed:
		return string(value)
	default:
		return "unknown"
	}
}

func boundedWebSocket(value service.WebSocketState) string {
	switch value {
	case service.WebSocketDisabled, service.WebSocketDisconnected, service.WebSocketConnected, service.WebSocketDegraded:
		return string(value)
	default:
		return "unknown"
	}
}

func boundedFailureStage(value service.FailureStage) string {
	switch value {
	case service.FailureStageNone, service.FailureStageStart, service.FailureStageSync, service.FailureStageWebSocket,
		service.FailureStageReconcile, service.FailureStageReport, service.FailureStageCertificate,
		service.FailureStageRuntime, service.FailureStageClose, service.FailureStageCleanup:
		return string(value)
	default:
		return "unknown"
	}
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func unixSeconds(value time.Time) float64 {
	if value.IsZero() {
		return 0
	}
	return float64(value.Unix())
}
