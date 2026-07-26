package controller

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api/newV2board"
)

type stubWSRuntimeClient struct {
	mu             sync.Mutex
	events         chan *newV2board.WSEvent
	errs           chan error
	done           chan struct{}
	closed         chan struct{}
	keepAliveCh    chan struct{}
	deviceReportCh chan map[int][]string
	keepAliveCount int
	keepAliveErr   error
	pongCh         chan struct{}
	pongCount      int
	pongErr        error
	closeOnce      sync.Once
}

func newStubWSRuntimeClient() *stubWSRuntimeClient {
	return &stubWSRuntimeClient{
		events:         make(chan *newV2board.WSEvent, 8),
		errs:           make(chan error, 8),
		done:           make(chan struct{}),
		closed:         make(chan struct{}),
		keepAliveCh:    make(chan struct{}, 16),
		deviceReportCh: make(chan map[int][]string, 16),
		pongCh:         make(chan struct{}, 16),
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

func (c *stubWSRuntimeClient) KeepAlive() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.keepAliveCount++
	select {
	case c.keepAliveCh <- struct{}{}:
	default:
	}
	return c.keepAliveErr
}

func (c *stubWSRuntimeClient) Pong() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pongCount++
	select {
	case c.pongCh <- struct{}{}:
	default:
	}
	return c.pongErr
}

func (c *stubWSRuntimeClient) SendDeviceReport(devices map[int][]string) error {
	var copied map[int][]string
	if devices != nil {
		copied = make(map[int][]string, len(devices))
		for uid, ips := range devices {
			copied[uid] = append([]string(nil), ips...)
		}
	}

	c.deviceReportCh <- copied
	return nil
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

func (c *stubWSRuntimeClient) KeepAliveCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keepAliveCount
}

func (c *stubWSRuntimeClient) PongCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pongCount
}

func (c *stubWSRuntimeClient) emitControlEvent(event string) {
	c.events <- &newV2board.WSEvent{
		Event:    event,
		Category: newV2board.WSEventCategoryControl,
		Payload:  map[string]any{"revision": 1},
	}
}

func (c *stubWSRuntimeClient) emitEvent(event string, category newV2board.WSEventCategory) {
	c.events <- &newV2board.WSEvent{
		Event:    event,
		Category: category,
		Payload:  map[string]any{},
	}
}

func (c *stubWSRuntimeClient) emitParseError() {
	c.errs <- errors.Join(newV2board.ErrWSClientParse, errors.New("invalid websocket payload"))
}

func (c *stubWSRuntimeClient) failTransport() {
	c.errs <- errors.Join(newV2board.ErrWSClientTransport, io.EOF)
}

type wsRuntimeFactoryResult struct {
	client  wsRuntimeClient
	err     error
	release <-chan struct{}
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

func (f *scriptedWSRuntimeFactory) Build(ctx context.Context) (wsRuntimeClient, error) {
	f.mu.Lock()
	f.attempts++
	attempt := f.attempts
	var result wsRuntimeFactoryResult
	if attempt <= len(f.results) {
		result = f.results[attempt-1]
	}
	f.mu.Unlock()

	f.called <- attempt

	if attempt > len(f.results) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if result.release != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-result.release:
		}
	}
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
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{ReconnectBackoff: time.Second, ResyncOnReconnect: true})

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
	releaseReconnect := make(chan struct{})
	factory := newScriptedWSRuntimeFactory(
		wsRuntimeFactoryResult{client: firstClient},
		wsRuntimeFactoryResult{client: secondClient, release: releaseReconnect},
	)
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{ResyncOnReconnect: true})

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	firstClient.failTransport()

	clearAction := submitter.WaitAction(t)
	if clearAction.Type != syncActionTypeClearGlobalDevices {
		t.Fatalf("unexpected disconnect action type: got %q want %q", clearAction.Type, syncActionTypeClearGlobalDevices)
	}
	if clearAction.Source != syncActionSourceReconnect {
		t.Fatalf("unexpected disconnect action source: got %q want %q", clearAction.Source, syncActionSourceReconnect)
	}
	if clearAction.Metadata.Trigger != syncActionTriggerWSDisconnect {
		t.Fatalf("unexpected disconnect trigger: got %q want %q", clearAction.Metadata.Trigger, syncActionTriggerWSDisconnect)
	}

	waitForWSRuntimeAttempt(t, factory, 2)
	waitForWSRuntimeDegradedState(t, runtime, true)

	close(releaseReconnect)
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
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{ResyncOnReconnect: true})

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeAttempt(t, factory, 2)
	waitForWSRuntimeDegradedState(t, runtime, true)
	submitter.ExpectNoAction(t, 50*time.Millisecond)

	runtime.Stop()
}

func TestWSRuntime_RepeatedStartDoesNotClearDegradedState(t *testing.T) {
	t.Parallel()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{})

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	client.failTransport()
	_ = submitter.WaitAction(t)
	waitForWSRuntimeAttempt(t, factory, 2)
	if !runtime.Degraded() {
		t.Fatal("disconnect did not mark runtime degraded")
	}

	runtime.Start()
	if !runtime.Degraded() {
		t.Fatal("repeated Start cleared degraded state")
	}

	runtime.Stop()
}

func TestWSRuntime_ParseErrorsDoNotDegradeOrReconnectAndSubsequentEventsStillSubmit(t *testing.T) {
	t.Parallel()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{ResyncOnReconnect: true})

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	client.emitParseError()
	parseAction := submitter.WaitAction(t)
	if parseAction.Type != syncActionTypeResyncAll {
		t.Fatalf("unexpected parse-error action type: got %q want %q", parseAction.Type, syncActionTypeResyncAll)
	}
	if parseAction.Source != syncActionSourceWS {
		t.Fatalf("unexpected parse-error action source: got %q want %q", parseAction.Source, syncActionSourceWS)
	}
	if parseAction.Metadata.Trigger != syncActionTriggerWSParseError {
		t.Fatalf("unexpected parse-error trigger: got %q want %q", parseAction.Metadata.Trigger, syncActionTriggerWSParseError)
	}
	waitForWSRuntimeDegradedState(t, runtime, false)
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

func TestWSRuntime_HeartbeatEnabledTriggersKeepAlive(t *testing.T) {
	t.Parallel()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{HeartbeatInterval: time.Millisecond})

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	waitForKeepAlive(t, client)

	if got := client.KeepAliveCount(); got < 1 {
		t.Fatalf("unexpected keepalive count: got %d want at least 1", got)
	}

	runtime.Stop()
}

func TestWSRuntime_HeartbeatDisabledDoesNotTriggerKeepAlive(t *testing.T) {
	t.Parallel()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{HeartbeatInterval: 0})

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	expectNoKeepAlive(t, client, 25*time.Millisecond)
	if got := client.KeepAliveCount(); got != 0 {
		t.Fatalf("unexpected keepalive count when heartbeat disabled: got %d want 0", got)
	}

	runtime.Stop()
}

func TestWSRuntime_StopStopsHeartbeatLoop(t *testing.T) {
	t.Parallel()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{HeartbeatInterval: time.Millisecond})

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	waitForKeepAlive(t, client)

	runtime.Stop()
	waitForChannelClosed(t, runtime.Done())

	for {
		select {
		case <-client.keepAliveCh:
			continue
		default:
		}
		break
	}
	baseline := client.KeepAliveCount()
	expectNoKeepAlive(t, client, 25*time.Millisecond)
	if got := client.KeepAliveCount(); got != baseline {
		t.Fatalf("keepalive count changed after stop: got %d want %d", got, baseline)
	}
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
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{ReconnectBackoff: time.Second, ResyncOnReconnect: true})

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

func TestWSRuntime_RepliesToAppLevelPing(t *testing.T) {
	t.Parallel()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{})

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	client.emitEvent(newV2board.WSEventPing, newV2board.WSEventCategoryStatus)

	select {
	case <-client.pongCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for app-level pong")
	}
	if got := client.PongCount(); got != 1 {
		t.Fatalf("unexpected pong count: got %d want 1", got)
	}
	submitter.ExpectNoAction(t, 50*time.Millisecond)

	runtime.Stop()
}

func TestWSRuntime_ReportDevicesForwardsToConnectedClient(t *testing.T) {
	t.Parallel()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{})

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeClient(t, runtime, client)

	devices := map[int][]string{1: []string{"192.0.2.1"}}
	if err := runtime.ReportDevices(devices); err != nil {
		t.Fatalf("ReportDevices returned error: %v", err)
	}
	devices[1][0] = "198.51.100.1"

	select {
	case got := <-client.deviceReportCh:
		want := map[int][]string{1: []string{"192.0.2.1"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unexpected device report: got %#v want %#v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for device report")
	}

	runtime.Stop()
}

func TestWSRuntime_IgnoresXboardNonActionEvents(t *testing.T) {
	t.Parallel()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{})

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	for _, event := range []string{
		newV2board.WSEventPong,
		newV2board.WSEventXboardAuthSuccess,
		newV2board.WSEventXboardError,
	} {
		client.emitEvent(event, newV2board.WSEventCategoryStatus)
	}

	submitter.ExpectNoAction(t, 100*time.Millisecond)

	runtime.Stop()
}

func TestWSRuntime_SubmitsXboardSyncEvents(t *testing.T) {
	t.Parallel()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{})

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	client.emitControlEvent(newV2board.WSEventXboardSyncConfig)
	action := submitter.WaitAction(t)
	if action.Type != syncActionTypeSyncNodeConfig {
		t.Fatalf("unexpected sync.config action type: got %q want %q", action.Type, syncActionTypeSyncNodeConfig)
	}

	client.emitControlEvent(newV2board.WSEventXboardSyncUsers)
	action = submitter.WaitAction(t)
	if action.Type != syncActionTypeSyncUsers {
		t.Fatalf("unexpected sync.users action type: got %q want %q", action.Type, syncActionTypeSyncUsers)
	}

	client.emitControlEvent(newV2board.WSEventXboardSyncUserDelta)
	action = submitter.WaitAction(t)
	if action.Type != syncActionTypeSyncUsers {
		t.Fatalf("unexpected sync.user.delta action type: got %q want %q", action.Type, syncActionTypeSyncUsers)
	}

	client.emitControlEvent(newV2board.WSEventXboardSyncNodes)
	action = submitter.WaitAction(t)
	if action.Type != syncActionTypeResyncAll {
		t.Fatalf("unexpected sync.nodes action type: got %q want %q", action.Type, syncActionTypeResyncAll)
	}

	runtime.Stop()
}

func TestWSRuntime_SubmitsSyncDevicesAction(t *testing.T) {
	t.Parallel()

	client := newStubWSRuntimeClient()
	factory := newScriptedWSRuntimeFactory(wsRuntimeFactoryResult{client: client})
	submitter := newRecordingWSRuntimeSubmitter()
	runtime := newWSRuntime(factory.Build, submitter, wsRuntimeOptions{})

	runtime.Start()
	waitForWSRuntimeAttempt(t, factory, 1)
	waitForWSRuntimeDegradedState(t, runtime, false)

	client.events <- &newV2board.WSEvent{
		Event:    newV2board.WSEventXboardSyncDevices,
		Category: newV2board.WSEventCategoryConfig,
		Payload: map[string]any{
			"users": map[string]any{
				"1": []any{"192.0.2.1"},
			},
		},
	}

	action := submitter.WaitAction(t)
	if action.Type != syncActionTypeSyncDevices {
		t.Fatalf("unexpected sync.devices action type: got %q want %q", action.Type, syncActionTypeSyncDevices)
	}
	if action.Source != syncActionSourceWS {
		t.Fatalf("unexpected sync.devices source: got %q want %q", action.Source, syncActionSourceWS)
	}
	if action.Metadata.Trigger != newV2board.WSEventXboardSyncDevices {
		t.Fatalf("unexpected sync.devices trigger: got %q", action.Metadata.Trigger)
	}
	wantDevices := map[int][]string{1: []string{"192.0.2.1"}}
	if !reflect.DeepEqual(action.Payload.Devices, wantDevices) {
		t.Fatalf("unexpected sync.devices payload: got %#v want %#v", action.Payload.Devices, wantDevices)
	}

	runtime.Stop()
}

func waitForKeepAlive(t *testing.T, client *stubWSRuntimeClient) {
	t.Helper()

	select {
	case <-client.keepAliveCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for keepalive")
	}
}

func expectNoKeepAlive(t *testing.T, client *stubWSRuntimeClient, wait time.Duration) {
	t.Helper()

	select {
	case <-client.keepAliveCh:
		t.Fatal("expected no keepalive")
	case <-time.After(wait):
	}
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

func waitForWSRuntimeClient(t *testing.T, runtime *wsRuntime, want wsRuntimeClient) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := runtime.lifecycle.Current().(wsRuntimeClient)
		if got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("timed out waiting for websocket runtime client")
}
