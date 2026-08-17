package controller

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/internal/wslifecycle"
)

const wsRuntimeReconnectTrigger = "ws_reconnect"

type wsRuntimeClient interface {
	Events() <-chan *newV2board.WSEvent
	Errors() <-chan error
	Done() <-chan struct{}
	KeepAlive() error
	Close() error
}

type wsRuntimePonger interface {
	Pong() error
}

type wsRuntimeDeviceReporter interface {
	SendDeviceReport(map[int][]string) error
}

type wsRuntimeClientFactory func(context.Context) (wsRuntimeClient, error)

type WSRuntimeLifecycle interface {
	Start()
	Stop()
}

type wsRuntimeLifecycle = WSRuntimeLifecycle

func (c *Controller) buildWSRuntime(ctx context.Context, submitter syncActionSubmitter) (wsRuntimeLifecycle, error) {
	if c.wsRuntimeFactory == nil {
		return nil, errors.New("controller: websocket runtime factory not configured")
	}
	return c.wsRuntimeFactory(ctx, submitter)
}

type WSEventRuntimeFactory func(WSEventSubmitter) (WSRuntimeLifecycle, error)

func (c *Controller) SetWSEventRuntimeFactory(factory WSEventRuntimeFactory) {
	if factory == nil {
		c.wsRuntimeFactory = c.newConfiguredWSRuntimeContext
		return
	}

	c.wsRuntimeFactory = func(_ context.Context, submitter syncActionSubmitter) (wsRuntimeLifecycle, error) {
		return factory(wsEventSubmitter{submitter: submitter})
	}
}

type wsEventSubmitter struct {
	submitter syncActionSubmitter
}

func (s wsEventSubmitter) SubmitWSEvent(event *newV2board.WSEvent) {
	if s.submitter == nil {
		return
	}
	action, ok := syncActionFromWSEventPayload(event, time.Now())
	if !ok {
		return
	}
	s.submitter.Submit(action)
}

func (s wsEventSubmitter) SubmitWSParseError() {
	if s.submitter == nil {
		return
	}
	s.submitter.Submit(syncActionFromWSParseError(time.Now()))
}

func (s wsEventSubmitter) SubmitWSDisconnect() {
	if s.submitter == nil {
		return
	}
	s.submitter.Submit(syncActionFromWSDisconnect(time.Now()))
}

func (s wsEventSubmitter) SubmitWSReconnect() {
	if s.submitter == nil {
		return
	}
	s.submitter.Submit(newSyncAction(syncActionTypeResyncAll, syncActionSourceReconnect, syncActionMetadata{
		Trigger:    wsRuntimeReconnectTrigger,
		OccurredAt: time.Now(),
		Reason:     "websocket runtime reconnected",
	}))
}

func (c *Controller) shouldStartWSRuntime() bool {
	if c.config == nil || c.config.WebSocketConfig == nil || !c.config.WebSocketConfig.Enable {
		return false
	}
	_, ok := c.apiClient.(api.WSCapable)
	return ok
}

func (c *Controller) newConfiguredWSRuntime(submitter syncActionSubmitter) (wsRuntimeLifecycle, error) {
	return c.newConfiguredWSRuntimeContext(context.Background(), submitter)
}

func (c *Controller) newConfiguredWSRuntimeContext(ctx context.Context, submitter syncActionSubmitter) (wsRuntimeLifecycle, error) {
	capable, ok := c.apiClient.(api.WSCapable)
	if !ok {
		return nil, api.ErrUnsupportedPanelFeature
	}
	wsConfig := capable.GetWSConfig()
	if wsConfig == nil {
		return nil, errors.New("controller: websocket config unavailable")
	}
	endpoint, err := resolveWSEndpointContext(ctx, c.apiClient, wsConfig, c.config.WebSocketConfig)
	if err != nil {
		return nil, err
	}
	options := wsRuntimeOptions{
		ReconnectBackoff:  time.Duration(c.config.WebSocketConfig.ReconnectBackoff) * time.Second,
		HeartbeatInterval: time.Duration(c.config.WebSocketConfig.HeartbeatInterval) * time.Second,
		ResyncOnReconnect: c.config.WebSocketConfig.ResyncOnReconnect,
	}
	factory := func(ctx context.Context) (wsRuntimeClient, error) {
		return newV2board.NewWSClientContext(ctx, endpoint)
	}
	return newWSRuntime(factory, submitter, options), nil
}

func resolveWSEndpoint(apiClient any, wsConfig *api.WSConfig, runtimeConfig *WebSocketConfig) (string, error) {
	return resolveWSEndpointContext(context.Background(), apiClient, wsConfig, runtimeConfig)
}

func resolveWSEndpointContext(ctx context.Context, apiClient any, wsConfig *api.WSConfig, runtimeConfig *WebSocketConfig) (string, error) {
	if wsConfig == nil {
		return "", errors.New("controller: websocket config unavailable")
	}
	if runtimeConfig != nil && strings.TrimSpace(runtimeConfig.Endpoint) != "" {
		return BuildWSEndpoint(wsConfig, runtimeConfig)
	}

	if discoverer, ok := apiClient.(api.WSEndpointDiscoverer); ok {
		if endpoint, err := api.DiscoverWSEndpointContext(ctx, discoverer); err == nil && strings.TrimSpace(endpoint) != "" {
			if err := validateDiscoveredWSEndpoint(wsConfig.APIHost, endpoint); err != nil {
				return "", err
			}
			derived := WebSocketConfig{}
			if runtimeConfig != nil {
				derived = *runtimeConfig
			}
			derived.Endpoint = endpoint
			return BuildWSEndpoint(wsConfig, &derived)
		}
	}

	return BuildWSEndpoint(wsConfig, runtimeConfig)
}

func validateDiscoveredWSEndpoint(apiHost, endpoint string) error {
	base, err := url.Parse(strings.TrimSpace(apiHost))
	if err != nil {
		return fmt.Errorf("controller: parse panel api host: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return errors.New("controller: panel api host must be absolute")
	}

	discovered, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return fmt.Errorf("controller: parse discovered websocket endpoint: %w", err)
	}
	discovered = base.ResolveReference(discovered)

	baseScheme, basePort, err := websocketOrigin(base)
	if err != nil {
		return err
	}
	discoveredScheme, discoveredPort, err := websocketOrigin(discovered)
	if err != nil {
		return err
	}
	if baseScheme != discoveredScheme ||
		!strings.EqualFold(base.Hostname(), discovered.Hostname()) ||
		basePort != discoveredPort {
		return errors.New("controller: discovered websocket endpoint must use the panel origin")
	}
	return nil
}

func websocketOrigin(endpoint *url.URL) (scheme, port string, err error) {
	switch strings.ToLower(endpoint.Scheme) {
	case "http", "ws":
		scheme = "ws"
		port = endpoint.Port()
		if port == "" {
			port = "80"
		}
	case "https", "wss":
		scheme = "wss"
		port = endpoint.Port()
		if port == "" {
			port = "443"
		}
	default:
		return "", "", fmt.Errorf("controller: unsupported websocket endpoint scheme %q", endpoint.Scheme)
	}
	return scheme, port, nil
}

func buildWSEndpoint(wsConfig *api.WSConfig, runtimeConfig *WebSocketConfig) (string, error) {
	return BuildWSEndpoint(wsConfig, runtimeConfig)
}

func BuildWSEndpoint(wsConfig *api.WSConfig, runtimeConfig *WebSocketConfig) (string, error) {
	if wsConfig == nil {
		return "", errors.New("controller: websocket config unavailable")
	}

	rawEndpoint := ""
	if runtimeConfig != nil {
		rawEndpoint = strings.TrimSpace(runtimeConfig.Endpoint)
	}
	if rawEndpoint == "" {
		rawEndpoint = strings.TrimRight(wsConfig.APIHost, "/") + "/api/v1/server/UniProxy/ws"
	}

	parsed, err := url.Parse(rawEndpoint)
	if err != nil {
		return "", fmt.Errorf("controller: parse websocket endpoint: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		base, err := url.Parse(wsConfig.APIHost)
		if err != nil {
			return "", fmt.Errorf("controller: parse panel api host: %w", err)
		}
		parsed = base.ResolveReference(parsed)
	}

	switch parsed.Scheme {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("controller: unsupported websocket endpoint scheme %q", parsed.Scheme)
	}

	query := parsed.Query()
	if wsConfig.MachineID > 0 {
		query.Del("node_id")
		query.Del("node_type")
		if query.Get("machine_id") == "" {
			query.Set("machine_id", strconv.Itoa(wsConfig.MachineID))
		}
	} else {
		if query.Get("node_id") == "" {
			query.Set("node_id", strconv.Itoa(wsConfig.NodeID))
		}
		if query.Get("node_type") == "" {
			query.Set("node_type", wsConfig.NodeType)
		}
	}
	if query.Get("token") == "" {
		query.Set("token", wsConfig.Key)
	}
	parsed.RawQuery = query.Encode()

	return parsed.String(), nil
}

type contextWSRuntimeLifecycle interface {
	StartContext(context.Context) error
	StopContext(context.Context) error
}

func startWSRuntimeContext(ctx context.Context, runtime wsRuntimeLifecycle) error {
	if runtime == nil {
		return nil
	}
	if contextual, ok := runtime.(interface {
		StartContext(context.Context) error
	}); ok {
		return contextual.StartContext(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime.Start()
	return ctx.Err()
}

func stopWSRuntimeContext(ctx context.Context, runtime wsRuntimeLifecycle) error {
	if runtime == nil {
		return nil
	}
	if contextual, ok := runtime.(interface {
		StopContext(context.Context) error
	}); ok {
		return contextual.StopContext(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime.Stop()
	return ctx.Err()
}

type WSEventSubmitter interface {
	SubmitWSEvent(*newV2board.WSEvent)
	SubmitWSParseError()
	SubmitWSDisconnect()
	SubmitWSReconnect()
}

type wsRuntimeOptions struct {
	ReconnectBackoff  time.Duration
	HeartbeatInterval time.Duration
	ResyncOnReconnect bool
}

type wsRuntime struct {
	factory   wsRuntimeClientFactory
	submitter syncActionSubmitter
	lifecycle *wslifecycle.Runtime

	mu                sync.RWMutex
	degraded          bool
	lastFailureAt     time.Time
	resyncOnReconnect bool
}

func newWSRuntime(factory wsRuntimeClientFactory, submitter syncActionSubmitter, options wsRuntimeOptions) *wsRuntime {
	if factory == nil {
		panic("controller: nil websocket runtime factory")
	}
	if submitter == nil {
		panic("controller: nil websocket runtime submitter")
	}
	runtime := &wsRuntime{
		factory:           factory,
		submitter:         submitter,
		resyncOnReconnect: options.ResyncOnReconnect,
	}
	runtime.lifecycle = wslifecycle.New(wslifecycle.Config{
		Factory: func(ctx context.Context) (wslifecycle.Client, error) {
			return runtime.factory(ctx)
		},
		HandleEvent:       runtime.handleEvent,
		HandleOutcome:     runtime.handleOutcome,
		ReconnectBackoff:  options.ReconnectBackoff,
		HeartbeatInterval: options.HeartbeatInterval,
	})
	return runtime
}

func (r *wsRuntime) Start() {
	_ = r.StartContext(context.Background())
}

func (r *wsRuntime) StartContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	if r.lifecycle.StartContext(ctx) {
		// Connection outcomes use the same lock, so none can overtake this reset.
		r.degraded = false
	}
	r.mu.Unlock()
	return ctx.Err()
}

func (r *wsRuntime) Stop() {
	_ = r.StopContext(context.Background())
}

func (r *wsRuntime) StopContext(ctx context.Context) error {
	return r.lifecycle.CloseContext(ctx)
}

func (r *wsRuntime) Done() <-chan struct{} {
	return r.lifecycle.Done()
}

func (r *wsRuntime) Degraded() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.degraded
}

func (r *wsRuntime) WebSocketObservabilitySnapshot() service.WebSocketSnapshot {
	r.mu.RLock()
	degraded := r.degraded
	lastFailureAt := r.lastFailureAt
	r.mu.RUnlock()

	state := service.WebSocketDisconnected
	if r.lifecycle.Current() != nil {
		state = service.WebSocketConnected
	}
	if degraded {
		state = service.WebSocketDegraded
	}
	return service.WebSocketSnapshot{State: state, LastFailureAt: lastFailureAt}
}

func (r *wsRuntime) ReportDevices(devices map[int][]string) error {
	client := r.lifecycle.Current()
	if client == nil {
		return nil
	}

	reporter, ok := client.(wsRuntimeDeviceReporter)
	if !ok {
		return nil
	}

	return reporter.SendDeviceReport(devices)
}

func (r *wsRuntime) DeviceReporterReady() bool {
	_, ok := r.lifecycle.Current().(wsRuntimeDeviceReporter)
	return ok
}

func (r *wsRuntime) handleEvent(client wslifecycle.Client, event *newV2board.WSEvent) {
	if event == nil {
		return
	}

	switch event.Event {
	case newV2board.WSEventPing:
		if ponger, ok := client.(wsRuntimePonger); ok {
			_ = ponger.Pong()
		}
		return
	case newV2board.WSEventPong,
		newV2board.WSEventXboardAuthSuccess,
		newV2board.WSEventXboardError:
		return
	}

	action, ok := syncActionFromWSEventPayload(event, time.Now())
	if !ok {
		return
	}

	r.submitter.Submit(action)
}

func (r *wsRuntime) handleOutcome(outcome wslifecycle.Outcome) {
	switch outcome {
	case wslifecycle.OutcomeConnectFailed:
		r.setDegraded(true)
	case wslifecycle.OutcomeConnected:
		r.setDegraded(false)
	case wslifecycle.OutcomeParseError:
		r.recordFailure()
		r.submitter.Submit(syncActionFromWSParseError(time.Now()))
	case wslifecycle.OutcomeDisconnected:
		r.recordFailure()
		r.submitter.Submit(syncActionFromWSDisconnect(time.Now()))
		r.setDegraded(true)
	case wslifecycle.OutcomeReconnected:
		r.submitReconnectResync()
	}
}

func (r *wsRuntime) submitReconnectResync() {
	if !r.resyncOnReconnect {
		return
	}

	r.submitter.Submit(newSyncAction(syncActionTypeResyncAll, syncActionSourceReconnect, syncActionMetadata{
		Trigger:    wsRuntimeReconnectTrigger,
		OccurredAt: time.Now(),
		Reason:     "websocket runtime reconnected",
	}))
}

func (r *wsRuntime) setDegraded(degraded bool) {
	r.mu.Lock()
	r.degraded = degraded
	if degraded {
		r.lastFailureAt = time.Now()
	}
	r.mu.Unlock()
}

func (r *wsRuntime) recordFailure() {
	r.mu.Lock()
	r.lastFailureAt = time.Now()
	r.mu.Unlock()
}
