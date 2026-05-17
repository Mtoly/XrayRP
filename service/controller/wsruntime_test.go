package controller

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api/newV2board"
)

type stubWSRuntimeClient struct {
	mu        sync.Mutex
	events    chan *newV2board.WSEvent
	errs      chan error
	done      chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func newStubWSRuntimeClient() *stubWSRuntimeClient {
	return &stubWSRuntimeClient{
		events: make(chan *newV2board.WSEvent, 8),
		errs:   make(chan error, 8),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
	}
}

func (c *stubWSRuntimeClient) Events() <-chan *newV2board.WSEvent {
	return c.events
}

func (c *stubWSRuntimeClient) Errors() <-chan error {
	return c.errs
}

func (c *stubWSRuntimeClient) Done() <-chan struct{} {
	return c.done
}

func (c *stubWSRuntimeClient) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		close(c.events)
		close(c.errs)
		close(c.closed)
	})
	return nil
}

func (c *stubWSRuntimeClient) emitControlEvent(event string) {
	c.events <- &newV2board.WSEvent{
		Event:    event,
		Category: newV2board.WSEventCategoryControl,
		Payload:  map[string]any{"revision": 1},
	}
}

func (c *stubWSRuntimeClient) emitParseError() {
	c.errs <- errors.Join(newV2board.ErrWSClientParse, errors.New("invalid websocket payload"))
}

func (c *stubWSRuntimeClient) failTransport() {
	c.errs <- errors.Join(newV2board.ErrWSClientTransport, io.EOF)
}

type wsRuntimeFactoryResult struct {
	client wsRuntimeClient
	err    error
}

type scriptedWSRuntimeFactory struct {
	mu       sync.Mutex
	results  []wsRuntimeFactoryResult
	attempts int
	called   chan int
}

func newScriptedWSRuntimeFactory(results ...wsRuntimeFactoryResult) *scriptedWSRuntimeFactory {
	return &scriptedWSRuntimeFactory{
		results: results,
		called:  make(chan int, len(results)+8),
	}
}

func (f *scriptedWSRuntimeFactory) Build(context.Context) (wsRuntimeClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.attempts++
	attempt := f.attempts
	f.called <- attempt

	if attempt > len(f.results) {
		return nil, errors.New("unexpected websocket runtime connect attempt")
	}

	result := f.results[attempt-1]
	return result.client, result.err
}

type recordingWSRuntimeSubmitter struct {
	mu      sync.Mutex
	actions []syncAction
	ch      chan syncAction
}

func newRecordingWSRuntimeSubmitter() *recordingWSRuntimeSubmitter {
	return &recordingWSRuntimeSubmitter{ch: make(chan syncAction, 16)}
}

func (s *recordingWSRuntimeSubmitter) Submit(action syncAction) {
	s.mu.Lock()
	s.actions = append(s.actions, action)
	s.mu.Unlock()
	s.ch <- action
}

func (s *recordingWSRuntimeSubmitter) WaitAction(t *testing.T) syncAction {
	t.Helper()

	select {
	case action := <-s.ch:
		return action
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sync action")
		return syncAction{}
	}
}

func (s *recordingWSRuntimeSubmitter) ExpectNoAction(t *testing.T, wait time.Duration) {
	t.Helper()

	select {
	case action := <-s.ch:
		t.Fatalf("expected no sync action, got %#v", action)
	case <-time.After(wait):
	}
}

func TestWSRuntime_StartsClientAndConsumesEvents(t *testing.T) {
	t.Parallel()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, time.Second)

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	client.emitControlEvent(newV2board.WSEventNodeChanged)

	action := submitter.WaitAction(t)
	if action.Type != syncActionTypeSyncNodeConfig {
		t.Fatalf("unexpected action type: got %q want %q", action.Type, syncActionTypeSyncNodeConfig)
	}
	if action.Source != syncActionSourceWS {
		t.Fatalf("unexpected action source: got %q want %q", action.Source, syncActionSourceWS)
	}
	if action.Metadata.Trigger != newV2board.WSEventNodeChanged {
		t.Fatalf("unexpected action trigger: got %q want %q", action.Metadata.Trigger, newV2board.WSEventNodeChanged)
	}

	runtime.Stop()
}

func TestWSRuntime_ReconnectsWithBackoffAndResyncsAllOnRecovery(t *testing.T) {
	t.Parallel()

	firstClient := newStubWSRuntimeClient()
	secondClient := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(
		wsRuntimeFactoryResult{client: firstClient},
		wsRuntimeFactoryResult{client: secondClient},
	)
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, 25*time.Millisecond)

	backoffCalled := make(chan time.Duration, 1)
	releaseBackoff := make(chan struct{})
	runtime.sleep = func(ctx context.Context, d time.Duration) bool {
		backoffCalled <- d
		select {
		case <-ctx.Done():
			return false
		case <-releaseBackoff:
			return true
		}
	}

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	firstClient.failTransport()

	waitForWSRuntimeBackoff(t, backoffCalled, 25*time.Millisecond)
	waitForWSRuntimeDegradedState(t, runtime, true)
	submitter.ExpectNoAction(t, 50*time.Millisecond)

	close(releaseBackoff)

	waitForWSRuntimeAttempt(t, factory, 2)
	waitForWSRuntimeDegradedState(t, runtime, false)

	action := submitter.WaitAction(t)
	if action.Type != syncActionTypeResyncAll {
		t.Fatalf("unexpected reconnect action type: got %q want %q", action.Type, syncActionTypeResyncAll)
	}
	if action.Source != syncActionSourceReconnect {
		t.Fatalf("unexpected reconnect action source: got %q want %q", action.Source, syncActionSourceReconnect)
	}

	runtime.Stop()
}

func TestWSRuntime_DegradesToPollingOnlyWhenWebSocketUnavailable(t *testing.T) {
	t.Parallel()

	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{err: errors.New("dial failed")})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, 25*time.Millisecond)

	backoffCalled := make(chan time.Duration, 1)
	runtime.sleep = func(ctx context.Context, d time.Duration) bool {
		backoffCalled <- d
		<-ctx.Done()
		return false
	}

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeBackoff(t, backoffCalled, 25*time.Millisecond)
	waitForWSRuntimeDegradedState(t, runtime, true)
	submitter.ExpectNoAction(t, 50*time.Millisecond)

	runtime.Stop()
}

func TestWSRuntime_ParseErrorsDoNotDegradeOrReconnectAndSubsequentEventsStillSubmit(t *testing.T) {
	t.Parallel()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, 25*time.Millisecond)

	backoffCalled := make(chan time.Duration, 1)
	runtime.sleep = func(ctx context.Context, d time.Duration) bool {
		backoffCalled <- d
		<-ctx.Done()
		return false
	}

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	client.emitParseError()
	waitForWSRuntimeDegradedState(t, runtime, false)
	submitter.ExpectNoAction(t, 50*time.Millisecond)
	expectNoWSRuntimeBackoff(t, backoffCalled, 50*time.Millisecond)
	expectNoWSRuntimeAttempt(t, factory, 2, 50*time.Millisecond)

	client.emitControlEvent(newV2board.WSEventUsersChanged)

	action := submitter.WaitAction(t)
	if action.Type != syncActionTypeSyncUsers {
		t.Fatalf("unexpected action type after parse error: got %q want %q", action.Type, syncActionTypeSyncUsers)
	}
	if action.Source != syncActionSourceWS {
		t.Fatalf("unexpected action source after parse error: got %q want %q", action.Source, syncActionSourceWS)
	}
	if action.Metadata.Trigger != newV2board.WSEventUsersChanged {
		t.Fatalf("unexpected action trigger after parse error: got %q want %q", action.Metadata.Trigger, newV2board.WSEventUsersChanged)
	}

	runtime.Stop()
}

func TestWSRuntime_CanRestartAfterStop(t *testing.T) {
	t.Parallel()

	firstClient := newStubWSRuntimeClient()
	secondClient := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(
		wsRuntimeFactoryResult{client: firstClient},
		wsRuntimeFactoryResult{client: secondClient},
	)
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, time.Second)

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	firstDone := runtime.Done()
	runtime.Stop()
	waitForChannelClosed(t, firstDone)

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 2)
	waitForWSRuntimeDegradedState(t, runtime, false)

	secondDone := runtime.Done()
	if firstDone == secondDone {
		t.Fatal("expected restart to allocate a fresh done channel")
	}

	secondClient.emitControlEvent(newV2board.WSEventNodeChanged)

	action := submitter.WaitAction(t)
	if action.Type != syncActionTypeSyncNodeConfig {
		t.Fatalf("unexpected action type after restart: got %q want %q", action.Type, syncActionTypeSyncNodeConfig)
	}
	if action.Source != syncActionSourceWS {
		t.Fatalf("unexpected action source after restart: got %q want %q", action.Source, syncActionSourceWS)
	}
	if action.Metadata.Trigger != newV2board.WSEventNodeChanged {
		t.Fatalf("unexpected action trigger after restart: got %q want %q", action.Metadata.Trigger, newV2board.WSEventNodeChanged)
	}

	runtime.Stop()
	waitForChannelClosed(t, secondDone)
}

func waitForWSRuntimeAttempt(t *testing.T, factory *scriptedWSRuntimeFactory, want int) {
	t.Helper()

	select {
	case got := <-factory.called:
		if got != want {
			t.Fatalf("unexpected connect attempt: got %d want %d", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for connect attempt %d", want)
	}
}

func waitForWSRuntimeBackoff(t *testing.T, called <-chan time.Duration, want time.Duration) {
	t.Helper()

	select {
	case got := <-called:
		if got != want {
			t.Fatalf("unexpected backoff: got %v want %v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for backoff %v", want)
	}
}

func expectNoWSRuntimeBackoff(t *testing.T, called <-chan time.Duration, wait time.Duration) {
	t.Helper()

	select {
	case got := <-called:
		t.Fatalf("expected no backoff, got %v", got)
	case <-time.After(wait):
	}
}

func expectNoWSRuntimeAttempt(t *testing.T, factory *scriptedWSRuntimeFactory, want int, wait time.Duration) {
	t.Helper()

	select {
	case got := <-factory.called:
		t.Fatalf("expected no connect attempt %d, got attempt %d", want, got)
	case <-time.After(wait):
	}
}

func waitForChannelClosed(t *testing.T, ch <-chan struct{}) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for channel close")
	}
}

func waitForWSRuntimeDegradedState(t *testing.T, runtime *wsRuntime, want bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.Degraded() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for degraded state %t", want)
}
