package controller

import (
	"context"
	"sync"
	"time"

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
