package controller

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/api/newV2board"
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

type WSEventSubmitter interface {
	SubmitWSEvent(*newV2board.WSEvent)
	SubmitWSParseError()
	SubmitWSDisconnect()
	SubmitWSReconnect()
}

type wsRuntimeTicker interface {
	C() <-chan time.Time
	Stop()
}

type wsRuntimeTickerFactory func(time.Duration) wsRuntimeTicker

type wsRuntimeOptions struct {
	ReconnectBackoff  time.Duration
	HeartbeatInterval time.Duration
	ResyncOnReconnect bool
}

type wsRuntime struct {
	factory           wsRuntimeClientFactory
	submitter         syncActionSubmitter
	reconnectBackoff  time.Duration
	heartbeatInterval time.Duration
	resyncOnReconnect bool
	sleep             func(context.Context, time.Duration) bool
	tickerFactory     wsRuntimeTickerFactory

	mu       sync.RWMutex
	started  bool
	degraded bool
	cancel   context.CancelFunc
	done     chan struct{}
	client   wsRuntimeClient
}

func newWSRuntime(factory wsRuntimeClientFactory, submitter syncActionSubmitter, options wsRuntimeOptions) *wsRuntime {
	if factory == nil {
		panic("controller: nil websocket runtime factory")
	}
	if submitter == nil {
		panic("controller: nil websocket runtime submitter")
	}
	if options.ReconnectBackoff < 0 {
		options.ReconnectBackoff = 0
	}
	if options.HeartbeatInterval < 0 {
		options.HeartbeatInterval = 0
	}

	return &wsRuntime{
		factory:           factory,
		submitter:         submitter,
		reconnectBackoff:  options.ReconnectBackoff,
		heartbeatInterval: options.HeartbeatInterval,
		resyncOnReconnect: options.ResyncOnReconnect,
		sleep:             sleepWithContext,
		tickerFactory:     newRealWSRuntimeTicker,
		done:              make(chan struct{}),
	}
}

func (r *wsRuntime) Start() {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return
	}
	if r.done == nil || doneClosed(r.done) {
		r.done = make(chan struct{})
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := r.done
	r.started = true
	r.degraded = false
	r.cancel = cancel
	r.client = nil
	r.mu.Unlock()

	go r.run(ctx, done)
}

func (r *wsRuntime) Stop() {
	r.mu.RLock()
	if !r.started {
		r.mu.RUnlock()
		return
	}
	cancel := r.cancel
	client := r.client
	done := r.done
	r.mu.RUnlock()

	if cancel != nil {
		cancel()
	}
	if client != nil {
		_ = client.Close()
	}
	if done != nil {
		<-done
	}
}

func (r *wsRuntime) Done() <-chan struct{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.done
}

func (r *wsRuntime) Degraded() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.degraded
}

func (r *wsRuntime) ReportDevices(devices map[int][]string) error {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()
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
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.client.(wsRuntimeDeviceReporter)
	return ok
}

func (r *wsRuntime) run(ctx context.Context, done chan struct{}) {
	defer func() {
		r.mu.Lock()
		if r.done == done {
			close(done)
			r.started = false
			r.cancel = nil
			r.client = nil
		}
		r.mu.Unlock()
	}()

	needsResyncOnConnect := false

	for {
		client, err := r.connect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			r.setDegraded(true)
			needsResyncOnConnect = true
			if !r.sleep(ctx, r.reconnectBackoff) {
				return
			}
			continue
		}

		r.setClient(client)
		r.setDegraded(false)
		if needsResyncOnConnect {
			r.submitReconnectResync()
			needsResyncOnConnect = false
		}

		disconnected := r.consumeClient(ctx, client)
		r.clearClient(client)
		_ = client.Close()

		if ctx.Err() != nil || !disconnected {
			return
		}

		r.submitter.Submit(syncActionFromWSDisconnect(time.Now()))
		r.setDegraded(true)
		needsResyncOnConnect = true
		if !r.sleep(ctx, r.reconnectBackoff) {
			return
		}
	}
}

func (r *wsRuntime) connect(ctx context.Context) (wsRuntimeClient, error) {
	client, err := r.factory(ctx)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("controller: websocket runtime factory returned nil client")
	}
	return client, nil
}

func (r *wsRuntime) consumeClient(ctx context.Context, client wsRuntimeClient) bool {
	var (
		heartbeat <-chan time.Time
		ticker    wsRuntimeTicker
	)
	if r.heartbeatInterval > 0 && r.tickerFactory != nil {
		ticker = r.tickerFactory(r.heartbeatInterval)
		heartbeat = ticker.C()
		defer ticker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			return false
		case <-heartbeat:
			select {
			case <-ctx.Done():
				return false
			default:
			}
			if err := client.KeepAlive(); err != nil {
				return true
			}
		case event, ok := <-client.Events():
			if !ok {
				return true
			}
			r.handleEvent(client, event)
		case err, ok := <-client.Errors():
			if !ok {
				return true
			}
			if r.handleError(err) {
				continue
			}
			return true
		case <-client.Done():
			return true
		}
	}
}

func (r *wsRuntime) handleEvent(client wsRuntimeClient, event *newV2board.WSEvent) {
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

func (r *wsRuntime) handleError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, newV2board.ErrWSClientParse) {
		r.submitter.Submit(syncActionFromWSParseError(time.Now()))
		return true
	}
	return false
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
	r.mu.Unlock()
}

func (r *wsRuntime) setClient(client wsRuntimeClient) {
	r.mu.Lock()
	r.client = client
	r.mu.Unlock()
}

func (r *wsRuntime) clearClient(client wsRuntimeClient) {
	r.mu.Lock()
	if r.client == client {
		r.client = nil
	}
	r.mu.Unlock()
}

func doneClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

type realWSRuntimeTicker struct {
	ticker *time.Ticker
}

func newRealWSRuntimeTicker(interval time.Duration) wsRuntimeTicker {
	return &realWSRuntimeTicker{ticker: time.NewTicker(interval)}
}

func (t *realWSRuntimeTicker) C() <-chan time.Time {
	return t.ticker.C
}

func (t *realWSRuntimeTicker) Stop() {
	t.ticker.Stop()
}
