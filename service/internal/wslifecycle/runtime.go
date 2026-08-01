package wslifecycle

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/service"
)

type Client interface {
	Events() <-chan *newV2board.WSEvent
	Errors() <-chan error
	Done() <-chan struct{}
	KeepAlive() error
	Close() error
}

type contextClientCloser interface {
	CloseContext(context.Context) error
}

type Factory func(context.Context) (Client, error)

type Outcome uint8

const (
	OutcomeConnectFailed Outcome = iota
	OutcomeConnected
	OutcomeParseError
	OutcomeDisconnected
	OutcomeReconnected
)

type ticker interface {
	C() <-chan time.Time
	Stop()
}

type tickerFactory func(time.Duration) ticker

type Config struct {
	Factory              Factory
	HandleEvent          func(Client, *newV2board.WSEvent)
	HandleEventContext   func(context.Context, Client, *newV2board.WSEvent)
	HandleOutcome        func(Outcome)
	HandleOutcomeContext func(context.Context, Outcome)
	ReconnectBackoff     time.Duration
	HeartbeatInterval    time.Duration
}

type Runtime struct {
	config        Config
	sleep         func(context.Context, time.Duration) bool
	tickerFactory tickerFactory

	mu      sync.RWMutex
	started bool
	closing bool
	cancel  context.CancelFunc
	done    chan struct{}
	client  Client
}

func New(config Config) *Runtime {
	if config.Factory == nil {
		panic("websocket lifecycle factory must not be nil")
	}
	if config.ReconnectBackoff < 0 {
		config.ReconnectBackoff = 0
	}
	if config.HeartbeatInterval < 0 {
		config.HeartbeatInterval = 0
	}
	return &Runtime{
		config:        config,
		sleep:         sleepWithContext,
		tickerFactory: newRealTicker,
		done:          make(chan struct{}),
	}
}

func (r *Runtime) Start() bool {
	return r.StartContext(context.Background())
}

func (r *Runtime) StartContext(ctx context.Context) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return false
	}

	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return false
	}
	if r.done == nil || doneClosed(r.done) {
		r.done = make(chan struct{})
	}

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := r.done
	r.started = true
	r.closing = false
	r.cancel = cancel
	r.client = nil
	r.mu.Unlock()

	go r.run(runCtx, done)
	return true
}

func (r *Runtime) Close() {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	_ = r.CloseContext(ctx)
}

func (r *Runtime) CloseContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	if !r.started {
		r.mu.Unlock()
		return nil
	}
	if r.closing {
		done := r.done
		r.mu.Unlock()
		return waitDoneContext(ctx, done)
	}
	r.closing = true
	cancel := r.cancel
	done := r.done
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return waitDoneContext(ctx, done)
}

func (r *Runtime) Done() <-chan struct{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.done
}

func (r *Runtime) Current() Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.client
}

func (r *Runtime) run(ctx context.Context, done chan struct{}) {
	defer func() {
		r.mu.Lock()
		if r.done == done {
			close(done)
			r.started = false
			r.closing = false
			r.cancel = nil
			r.client = nil
		}
		r.mu.Unlock()
	}()

	needsReconnect := false
	for {
		client, err := r.connect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.handleOutcome(ctx, OutcomeConnectFailed)
			needsReconnect = true
			if !r.sleep(ctx, r.config.ReconnectBackoff) {
				return
			}
			continue
		}
		if !r.publishClient(ctx, client) {
			r.closeClient(client)
			return
		}

		r.handleOutcome(ctx, OutcomeConnected)
		if needsReconnect {
			r.handleOutcome(ctx, OutcomeReconnected)
			needsReconnect = false
		}

		disconnected := r.consume(ctx, client)
		r.clearClient(client)
		r.closeClient(client)
		if ctx.Err() != nil || !disconnected {
			return
		}

		r.handleOutcome(ctx, OutcomeDisconnected)
		needsReconnect = true
		if !r.sleep(ctx, r.config.ReconnectBackoff) {
			return
		}
	}
}

func (r *Runtime) closeClient(client Client) {
	if client == nil {
		return
	}
	ctx, cancel := service.CleanupContext(context.Background())
	defer cancel()
	if contextual, ok := client.(contextClientCloser); ok {
		_ = contextual.CloseContext(ctx)
		return
	}
	_ = client.Close()
}

func (r *Runtime) connect(ctx context.Context) (Client, error) {
	client, err := r.config.Factory(ctx)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("websocket lifecycle factory returned nil client")
	}
	return client, nil
}

func (r *Runtime) consume(ctx context.Context, client Client) bool {
	var heartbeat <-chan time.Time
	var ticker ticker
	if r.config.HeartbeatInterval > 0 && r.tickerFactory != nil {
		ticker = r.tickerFactory(r.config.HeartbeatInterval)
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
			r.handleEvent(ctx, client, event)
		case err, ok := <-client.Errors():
			if !ok {
				return true
			}
			if err == nil {
				continue
			}
			if errors.Is(err, newV2board.ErrWSClientParse) {
				r.handleOutcome(ctx, OutcomeParseError)
				continue
			}
			return true
		case <-client.Done():
			return true
		}
	}
}

func (r *Runtime) handleEvent(ctx context.Context, client Client, event *newV2board.WSEvent) {
	if ctx.Err() != nil {
		return
	}
	if r.config.HandleEventContext != nil {
		r.config.HandleEventContext(ctx, client, event)
		return
	}
	if r.config.HandleEvent != nil {
		r.config.HandleEvent(client, event)
	}
}

func (r *Runtime) handleOutcome(ctx context.Context, outcome Outcome) {
	if ctx.Err() != nil {
		return
	}
	if r.config.HandleOutcomeContext != nil {
		r.config.HandleOutcomeContext(ctx, outcome)
		return
	}
	if r.config.HandleOutcome != nil {
		r.config.HandleOutcome(outcome)
	}
}

func (r *Runtime) publishClient(ctx context.Context, client Client) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started || r.closing || ctx.Err() != nil {
		return false
	}
	r.client = client
	return true
}

func (r *Runtime) clearClient(client Client) {
	r.mu.Lock()
	if r.client == client {
		r.client = nil
	}
	r.mu.Unlock()
}

func waitDoneContext(ctx context.Context, done <-chan struct{}) error {
	if done == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func doneClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func sleepWithContext(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}

	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

type realTicker struct {
	ticker *time.Ticker
}

func newRealTicker(interval time.Duration) ticker {
	return &realTicker{ticker: time.NewTicker(interval)}
}

func (t *realTicker) C() <-chan time.Time {
	return t.ticker.C
}

func (t *realTicker) Stop() {
	t.ticker.Stop()
}
