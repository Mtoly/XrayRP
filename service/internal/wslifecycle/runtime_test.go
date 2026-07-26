package wslifecycle

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api/newV2board"
)

type contractClient struct {
	events    chan *newV2board.WSEvent
	errs      chan error
	done      chan struct{}
	closed    chan struct{}
	keepAlive chan struct{}

	closeOnce sync.Once
	closeCall int
	keepErr   error

	closeEntered chan struct{}
	closeRelease <-chan struct{}
}

func newContractClient() *contractClient {
	return &contractClient{
		events:    make(chan *newV2board.WSEvent, 1),
		errs:      make(chan error, 1),
		done:      make(chan struct{}),
		closed:    make(chan struct{}),
		keepAlive: make(chan struct{}, 1),
	}
}

func (c *contractClient) Events() <-chan *newV2board.WSEvent { return c.events }
func (c *contractClient) Errors() <-chan error               { return c.errs }
func (c *contractClient) Done() <-chan struct{}              { return c.done }
func (c *contractClient) KeepAlive() error {
	c.keepAlive <- struct{}{}
	return c.keepErr
}
func (c *contractClient) Close() error {
	c.closeCall++
	if c.closeEntered != nil {
		select {
		case c.closeEntered <- struct{}{}:
		default:
		}
	}
	if c.closeRelease != nil {
		<-c.closeRelease
	}
	c.closeOnce.Do(func() {
		close(c.closed)
		close(c.done)
	})
	return nil
}

func (c *contractClient) terminate() {
	c.closeOnce.Do(func() {
		close(c.closed)
		close(c.done)
	})
}

type factoryResult struct {
	client Client
	err    error
}

type contractFactory struct {
	results []factoryResult
	called  chan int
}

func (f *contractFactory) connect(ctx context.Context) (Client, error) {
	call := cap(f.called) - len(f.results) + 1
	f.called <- call
	if len(f.results) == 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	result := f.results[0]
	f.results = f.results[1:]
	return result.client, result.err
}

type contractTicker struct {
	ticks   chan time.Time
	stopped chan struct{}
	once    sync.Once
}

func newContractTicker() *contractTicker {
	return &contractTicker{
		ticks:   make(chan time.Time, 1),
		stopped: make(chan struct{}),
	}
}

func (t *contractTicker) C() <-chan time.Time { return t.ticks }
func (t *contractTicker) Stop()               { t.once.Do(func() { close(t.stopped) }) }

func TestRuntimeInitialConnectionPublishesClientAndClosesOwnedWork(t *testing.T) {
	client := newContractClient()
	factory := &contractFactory{
		results: []factoryResult{{client: client}},
		called:  make(chan int, 1),
	}
	outcomes := make(chan Outcome, 4)
	runtime := New(Config{
		Factory: factory.connect,
		HandleOutcome: func(outcome Outcome) {
			outcomes <- outcome
		},
	})

	if !runtime.Start() {
		t.Fatal("initial Start was not accepted")
	}
	if call := <-factory.called; call != 1 {
		t.Fatalf("factory call = %d, want 1", call)
	}
	if outcome := <-outcomes; outcome != OutcomeConnected {
		t.Fatalf("outcome = %v, want connected", outcome)
	}
	if runtime.Current() != client {
		t.Fatal("connected client was not published")
	}

	done := runtime.Done()
	runtime.Close()
	<-client.closed
	<-done
	if runtime.Current() != nil {
		t.Fatal("closed runtime retained current client")
	}
	if client.closeCall != 1 {
		t.Fatalf("client Close calls = %d, want 1", client.closeCall)
	}
}

func TestRuntimeRetriesInitialFailureAndReportsReconnect(t *testing.T) {
	connectErr := errors.New("connect failed")
	client := newContractClient()
	factory := &contractFactory{
		results: []factoryResult{{err: connectErr}, {client: client}},
		called:  make(chan int, 2),
	}
	outcomes := make(chan Outcome, 8)
	backoffEntered := make(chan time.Duration, 1)
	backoffRelease := make(chan struct{})
	runtime := New(Config{
		Factory:          factory.connect,
		ReconnectBackoff: 25 * time.Second,
		HandleOutcome: func(outcome Outcome) {
			outcomes <- outcome
		},
	})
	runtime.sleep = func(ctx context.Context, duration time.Duration) bool {
		backoffEntered <- duration
		select {
		case <-ctx.Done():
			return false
		case <-backoffRelease:
			return true
		}
	}

	if !runtime.Start() {
		t.Fatal("initial Start was not accepted")
	}
	<-factory.called
	if outcome := <-outcomes; outcome != OutcomeConnectFailed {
		t.Fatalf("outcome = %v, want connect failed", outcome)
	}
	if duration := <-backoffEntered; duration != 25*time.Second {
		t.Fatalf("backoff = %s, want 25s", duration)
	}
	close(backoffRelease)
	<-factory.called
	if outcome := <-outcomes; outcome != OutcomeConnected {
		t.Fatalf("outcome = %v, want connected", outcome)
	}
	if outcome := <-outcomes; outcome != OutcomeReconnected {
		t.Fatalf("outcome = %v, want reconnected", outcome)
	}

	runtime.Close()
}

func TestRuntimeRecoversAfterMultipleReconnectFailures(t *testing.T) {
	initialClient := newContractClient()
	recoveredClient := newContractClient()
	factory := &contractFactory{
		results: []factoryResult{
			{client: initialClient},
			{err: errors.New("first reconnect failed")},
			{err: errors.New("second reconnect failed")},
			{client: recoveredClient},
		},
		called: make(chan int, 4),
	}
	outcomes := make(chan Outcome, 8)
	backoffEntered := make(chan struct{}, 3)
	backoffRelease := make(chan struct{}, 3)
	runtime := New(Config{
		Factory: factory.connect,
		HandleOutcome: func(outcome Outcome) {
			outcomes <- outcome
		},
	})
	runtime.sleep = func(ctx context.Context, _ time.Duration) bool {
		backoffEntered <- struct{}{}
		select {
		case <-ctx.Done():
			return false
		case <-backoffRelease:
			return true
		}
	}

	if !runtime.Start() {
		t.Fatal("initial Start was not accepted")
	}
	expectContractCall(t, factory.called, 1)
	expectContractOutcome(t, outcomes, OutcomeConnected)

	initialClient.errs <- errors.New("connection lost")
	expectContractOutcome(t, outcomes, OutcomeDisconnected)
	releaseContractBackoff(t, backoffEntered, backoffRelease)

	expectContractCall(t, factory.called, 2)
	expectContractOutcome(t, outcomes, OutcomeConnectFailed)
	releaseContractBackoff(t, backoffEntered, backoffRelease)

	expectContractCall(t, factory.called, 3)
	expectContractOutcome(t, outcomes, OutcomeConnectFailed)
	releaseContractBackoff(t, backoffEntered, backoffRelease)

	expectContractCall(t, factory.called, 4)
	expectContractOutcome(t, outcomes, OutcomeConnected)
	expectContractOutcome(t, outcomes, OutcomeReconnected)
	if runtime.Current() != recoveredClient {
		t.Fatal("recovered client was not published")
	}
	select {
	case outcome := <-outcomes:
		t.Fatalf("unexpected duplicate recovery outcome %v", outcome)
	default:
	}

	runtime.Close()
}

func TestRuntimeHeartbeatEnabledAndDisabled(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		client := newContractClient()
		factory := &contractFactory{
			results: []factoryResult{{client: client}},
			called:  make(chan int, 1),
		}
		heartbeatTicker := newContractTicker()
		connected := make(chan struct{}, 1)
		runtime := New(Config{
			Factory:           factory.connect,
			HeartbeatInterval: time.Minute,
			HandleOutcome: func(outcome Outcome) {
				if outcome == OutcomeConnected {
					connected <- struct{}{}
				}
			},
		})
		runtime.tickerFactory = func(time.Duration) ticker { return heartbeatTicker }

		runtime.Start()
		<-factory.called
		<-connected
		heartbeatTicker.ticks <- time.Now()
		<-client.keepAlive
		runtime.Close()
		<-heartbeatTicker.stopped
	})

	t.Run("disabled", func(t *testing.T) {
		client := newContractClient()
		factory := &contractFactory{
			results: []factoryResult{{client: client}},
			called:  make(chan int, 1),
		}
		connected := make(chan struct{}, 1)
		runtime := New(Config{
			Factory: factory.connect,
			HandleOutcome: func(outcome Outcome) {
				if outcome == OutcomeConnected {
					connected <- struct{}{}
				}
			},
		})
		runtime.tickerFactory = func(time.Duration) ticker {
			panic("disabled heartbeat created a ticker")
		}

		runtime.Start()
		<-factory.called
		<-connected
		runtime.Close()
	})
}

func TestRuntimeTerminalOutcomeHasSingleOwner(t *testing.T) {
	client := newContractClient()
	factory := &contractFactory{
		results: []factoryResult{{client: client}},
		called:  make(chan int, 2),
	}
	outcomes := make(chan Outcome, 8)
	backoffEntered := make(chan struct{}, 1)
	runtime := New(Config{
		Factory: factory.connect,
		HandleOutcome: func(outcome Outcome) {
			outcomes <- outcome
		},
	})
	runtime.sleep = func(ctx context.Context, _ time.Duration) bool {
		backoffEntered <- struct{}{}
		<-ctx.Done()
		return false
	}

	if !runtime.Start() {
		t.Fatal("initial Start was not accepted")
	}
	<-factory.called
	if outcome := <-outcomes; outcome != OutcomeConnected {
		t.Fatalf("outcome = %v, want connected", outcome)
	}
	client.errs <- errors.New("terminal")
	client.terminate()
	<-backoffEntered

	disconnects := 0
drain:
	for {
		select {
		case outcome := <-outcomes:
			if outcome == OutcomeDisconnected {
				disconnects++
			}
		default:
			break drain
		}
	}
	if disconnects != 1 {
		t.Fatalf("disconnect outcomes = %d, want 1", disconnects)
	}
	if client.closeCall != 1 {
		t.Fatalf("client Close calls = %d, want 1", client.closeCall)
	}
	runtime.Close()
}

func TestRuntimeCloseCancelsConnectAndBackoffAndJoins(t *testing.T) {
	t.Run("connect", func(t *testing.T) {
		connectEntered := make(chan struct{}, 1)
		connectExited := make(chan struct{})
		runtime := New(Config{
			Factory: func(ctx context.Context) (Client, error) {
				connectEntered <- struct{}{}
				<-ctx.Done()
				close(connectExited)
				return nil, ctx.Err()
			},
		})

		runtime.Start()
		<-connectEntered
		closeDone := make(chan struct{})
		go func() {
			runtime.Close()
			close(closeDone)
		}()
		<-connectExited
		<-closeDone
	})

	t.Run("backoff", func(t *testing.T) {
		sleepEntered := make(chan struct{}, 1)
		sleepExited := make(chan struct{})
		runtime := New(Config{
			Factory: func(context.Context) (Client, error) {
				return nil, errors.New("connect failed")
			},
		})
		runtime.sleep = func(ctx context.Context, _ time.Duration) bool {
			sleepEntered <- struct{}{}
			<-ctx.Done()
			close(sleepExited)
			return false
		}

		runtime.Start()
		<-sleepEntered
		closeDone := make(chan struct{})
		go func() {
			runtime.Close()
			close(closeDone)
		}()
		<-sleepExited
		<-closeDone
	})
}

func TestRuntimeCloseRejectsClientReturnedAfterConnectCancellation(t *testing.T) {
	client := newContractClient()
	connectEntered := make(chan struct{})
	cancelObserved := make(chan struct{})
	releaseFactory := make(chan struct{})
	outcomes := make(chan Outcome, 4)
	runtime := New(Config{
		Factory: func(ctx context.Context) (Client, error) {
			close(connectEntered)
			<-ctx.Done()
			close(cancelObserved)
			<-releaseFactory
			return client, nil
		},
		HandleOutcome: func(outcome Outcome) {
			outcomes <- outcome
		},
	})

	if !runtime.Start() {
		t.Fatal("initial Start was not accepted")
	}
	<-connectEntered
	closeDone := make(chan struct{})
	go func() {
		runtime.Close()
		close(closeDone)
	}()
	<-cancelObserved
	close(releaseFactory)
	<-closeDone

	if runtime.Current() != nil {
		t.Fatal("cancelled connect published a client")
	}
	if client.closeCall != 1 {
		t.Fatalf("client Close calls = %d, want 1", client.closeCall)
	}
	select {
	case outcome := <-outcomes:
		t.Fatalf("cancelled connect emitted outcome %v", outcome)
	default:
	}
}

func expectContractCall(t *testing.T, calls <-chan int, want int) {
	t.Helper()
	select {
	case got := <-calls:
		if got != want {
			t.Fatalf("factory call = %d, want %d", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for factory call %d", want)
	}
}

func expectContractOutcome(t *testing.T, outcomes <-chan Outcome, want Outcome) {
	t.Helper()
	select {
	case got := <-outcomes:
		if got != want {
			t.Fatalf("outcome = %v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for outcome %v", want)
	}
}

func releaseContractBackoff(t *testing.T, entered <-chan struct{}, release chan<- struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for reconnect backoff")
	}
	release <- struct{}{}
}

func TestRuntimeConcurrentAndRepeatedCloseJoinOneOwner(t *testing.T) {
	closeEntered := make(chan struct{}, 1)
	closeRelease := make(chan struct{})
	client := newContractClient()
	client.closeEntered = closeEntered
	client.closeRelease = closeRelease
	connected := make(chan struct{}, 1)
	runtime := New(Config{
		Factory: func(context.Context) (Client, error) {
			return client, nil
		},
		HandleOutcome: func(outcome Outcome) {
			if outcome == OutcomeConnected {
				connected <- struct{}{}
			}
		},
	})

	runtime.Start()
	<-connected

	firstDone := make(chan struct{})
	go func() {
		runtime.Close()
		close(firstDone)
	}()
	<-closeEntered

	secondInvoked := make(chan struct{})
	secondDone := make(chan struct{})
	go func() {
		close(secondInvoked)
		runtime.Close()
		close(secondDone)
	}()
	<-secondInvoked
	select {
	case <-secondDone:
		t.Fatal("concurrent Close returned before owned client cleanup")
	default:
	}

	close(closeRelease)
	<-firstDone
	<-secondDone
	runtime.Close()

	if client.closeCall != 1 {
		t.Fatalf("client Close calls = %d, want 1", client.closeCall)
	}
}

func TestRuntimeRepeatedStartAndCloseUsesFreshOwnership(t *testing.T) {
	first := newContractClient()
	second := newContractClient()
	factory := &contractFactory{
		results: []factoryResult{{client: first}, {client: second}},
		called:  make(chan int, 2),
	}
	connected := make(chan struct{}, 2)
	runtime := New(Config{
		Factory: factory.connect,
		HandleOutcome: func(outcome Outcome) {
			if outcome == OutcomeConnected {
				connected <- struct{}{}
			}
		},
	})

	if !runtime.Start() {
		t.Fatal("initial Start was not accepted")
	}
	if runtime.Start() {
		t.Fatal("repeated Start unexpectedly acquired new ownership")
	}
	<-factory.called
	<-connected
	firstDone := runtime.Done()
	runtime.Close()
	<-firstDone

	if !runtime.Start() {
		t.Fatal("restart after Close was not accepted")
	}
	<-factory.called
	<-connected
	secondDone := runtime.Done()
	if firstDone == secondDone {
		t.Fatal("restart reused the previous done channel")
	}
	runtime.Close()
	<-secondDone
}
