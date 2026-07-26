package wslifecycle

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/api/newV2board"
)

type Client interface {
	Events() <-chan *newV2board.WSEvent
	Errors() <-chan error
	Done() <-chan struct{}
	KeepAlive() error
	Close() error
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
	Factory           Factory
	HandleEvent       func(Client, *newV2board.WSEvent)
	HandleOutcome     func(Outcome)
	ReconnectBackoff  time.Duration
	HeartbeatInterval time.Duration
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

func (r *Runtime) Start() {
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
	r.closing = false
	r.cancel = cancel
	r.client = nil
	r.mu.Unlock()

	go r.run(ctx, done)
}

func (r *Runtime) Close() {
	r.mu.Lock()
	if !r.started {
		r.mu.Unlock()
		return
	}
	if r.closing {
		done := r.done
		r.mu.Unlock()
		if done != nil {
			<-done
		}
		return
	}
	r.closing = true
	cancel := r.cancel
	done := r.done
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
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
			r.handleOutcome(OutcomeConnectFailed)
			needsReconnect = true
			if !r.sleep(ctx, r.config.ReconnectBackoff) {
				return
			}
			continue
		}
		if !r.publishClient(ctx, client) {
			_ = client.Close()
			return
		}

		r.handleOutcome(OutcomeConnected)
		if needsReconnect {
			r.handleOutcome(OutcomeReconnected)
			needsReconnect = false
		}

		disconnected := r.consume(ctx, client)
		r.clearClient(client)
		_ = client.Close()
		if ctx.Err() != nil || !disconnected {
			return
		}

		r.handleOutcome(OutcomeDisconnected)
		needsReconnect = true
		if !r.sleep(ctx, r.config.ReconnectBackoff) {
			return
		}
	}
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
			if r.config.HandleEvent != nil {
				r.config.HandleEvent(client, event)
			}
		case err, ok := <-client.Errors():
			if !ok {
				return true
			}
			if err == nil {
				continue
			}
			if errors.Is(err, newV2board.ErrWSClientParse) {
				r.handleOutcome(OutcomeParseError)
				continue
			}
			return true
		case <-client.Done():
			return true
		}
	}
}

func (r *Runtime) handleOutcome(outcome Outcome) {
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
