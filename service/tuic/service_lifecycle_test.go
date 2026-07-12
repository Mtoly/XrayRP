package tuic

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/service/controller"
)

type lifecycleEvents struct {
	mu     sync.Mutex
	events []string
}

func (e *lifecycleEvents) add(event string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *lifecycleEvents) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.events...)
}

func waitForEvents(t *testing.T, events *lifecycleEvents, want []string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := events.snapshot(); reflect.DeepEqual(got, want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("events = %v, want %v", events.snapshot(), want)
}

type fakeRuntimeInstance struct {
	events     *lifecycleEvents
	startErr   error
	closeErr   error
	startBlock <-chan struct{}
	started    chan<- struct{}
}

func (f *fakeRuntimeInstance) Start() error {
	f.events.add("start")
	if f.started != nil {
		close(f.started)
	}
	if f.startBlock != nil {
		<-f.startBlock
	}
	if f.startErr == nil {
		f.events.add("ready")
	}
	return f.startErr
}

func (f *fakeRuntimeInstance) Close() error {
	f.events.add("stop")
	f.events.add("close")
	return f.closeErr
}

func TestRuntimeLifecycleSeamCompiles(t *testing.T) {
	var runtime runtimeInstance = &fakeRuntimeInstance{events: &lifecycleEvents{}}
	var factory runtimeFactory = func(*TuicService) (runtimeInstance, string, error) {
		return runtime, "test-inbound", nil
	}

	service := &TuicService{runtimeFactory: factory}
	if service.runtimeFactory == nil {
		t.Fatal("runtime factory seam is nil")
	}
}

func TestBuildRuntimeRecordsBuildAndReturnsFactoryError(t *testing.T) {
	wantErr := errors.New("build failed")
	events := &lifecycleEvents{}
	service := &TuicService{
		runtimeFactory: func(*TuicService) (runtimeInstance, string, error) {
			events.add("build")
			return nil, "", wantErr
		},
	}

	_, _, err := service.buildRuntime()
	if !errors.Is(err, wantErr) {
		t.Fatalf("buildRuntime() error = %v, want %v", err, wantErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build"}) {
		t.Fatalf("events = %v, want [build]", got)
	}
}

func TestBuildRuntimeReturnsInjectedFake(t *testing.T) {
	events := &lifecycleEvents{}
	wantRuntime := &fakeRuntimeInstance{events: events}
	service := &TuicService{
		runtimeFactory: func(*TuicService) (runtimeInstance, string, error) {
			events.add("build")
			return wantRuntime, "test-inbound", nil
		},
	}

	gotRuntime, gotTag, err := service.buildRuntime()
	if err != nil {
		t.Fatalf("buildRuntime() error = %v", err)
	}
	if gotRuntime != wantRuntime {
		t.Fatalf("buildRuntime() runtime = %T, want injected fake", gotRuntime)
	}
	if gotTag != "test-inbound" {
		t.Fatalf("buildRuntime() tag = %q, want test-inbound", gotTag)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build"}) {
		t.Fatalf("events = %v, want [build]", got)
	}
}

func TestNewInstallsDefaultsWithoutSharingFactoryState(t *testing.T) {
	client := tuicPanelClientContractStub{}
	first := New(client, &controller.Config{})
	second := New(client, &controller.Config{})

	if first.runtimeFactory == nil || first.startRuntime == nil || first.closeRuntime == nil {
		t.Fatal("New() did not install lifecycle defaults")
	}
	first.runtimeFactory = func(*TuicService) (runtimeInstance, string, error) {
		return &fakeRuntimeInstance{events: &lifecycleEvents{}}, "test-inbound", nil
	}
	first.startRuntime = func(runtimeInstance) error { return errors.New("test start") }
	first.closeRuntime = func(runtimeInstance) error { return errors.New("test close") }
	if reflect.ValueOf(second.runtimeFactory).Pointer() != reflect.ValueOf(defaultRuntimeFactory).Pointer() {
		t.Fatal("overriding one service factory changed another New() instance")
	}
	if reflect.ValueOf(second.startRuntime).Pointer() != reflect.ValueOf(defaultStartRuntime).Pointer() {
		t.Fatal("overriding one start helper changed another New() instance")
	}
	if reflect.ValueOf(second.closeRuntime).Pointer() != reflect.ValueOf(defaultCloseRuntime).Pointer() {
		t.Fatal("overriding one close helper changed another New() instance")
	}
}

func TestRuntimeFakeSupportsControlledStartAndClose(t *testing.T) {
	events := &lifecycleEvents{}
	startBlock := make(chan struct{})
	started := make(chan struct{})
	runtime := &fakeRuntimeInstance{
		events:     events,
		startBlock: startBlock,
		started:    started,
	}

	startDone := make(chan error, 1)
	go func() {
		startDone <- runtime.Start()
		events.add("join")
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Start did not reach controlled block")
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"start"}) {
		t.Fatalf("events before release = %v, want [start]", got)
	}

	close(startBlock)
	if err := <-startDone; err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForEvents(t, events, []string{"start", "ready", "join"})
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"start", "ready", "join", "stop", "close"}) {
		t.Fatalf("events = %v, want [start ready join stop close]", got)
	}
}

func TestRuntimeFakeInjectsStartAndCloseErrors(t *testing.T) {
	startErr := errors.New("start failed")
	closeErr := errors.New("close failed")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeInstance{
		events:   events,
		startErr: startErr,
		closeErr: closeErr,
	}

	if err := runtime.Start(); !errors.Is(err, startErr) {
		t.Fatalf("Start() error = %v, want %v", err, startErr)
	}
	if err := runtime.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close() error = %v, want %v", err, closeErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"start", "stop", "close"}) {
		t.Fatalf("events = %v, want [start stop close]", got)
	}
}

func TestRuntimeHelpersPropagateErrorsAndControlledBlocking(t *testing.T) {
	startErr := errors.New("start failed")
	closeErr := errors.New("close failed")
	events := &lifecycleEvents{}
	release := make(chan struct{})
	entered := make(chan struct{})
	runtime := &fakeRuntimeInstance{
		events:     events,
		startErr:   startErr,
		closeErr:   closeErr,
		startBlock: release,
		started:    entered,
	}
	service := &TuicService{
		startRuntime: defaultStartRuntime,
		closeRuntime: defaultCloseRuntime,
	}

	startDone := make(chan error, 1)
	go func() {
		startDone <- service.startRuntime(runtime)
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("startRuntime did not reach controlled block")
	}
	select {
	case err := <-startDone:
		t.Fatalf("startRuntime returned before release: %v", err)
	default:
	}

	close(release)
	if err := <-startDone; !errors.Is(err, startErr) {
		t.Fatalf("startRuntime() error = %v, want %v", err, startErr)
	}
	if err := service.closeRuntime(runtime); !errors.Is(err, closeErr) {
		t.Fatalf("closeRuntime() error = %v, want %v", err, closeErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"start", "stop", "close"}) {
		t.Fatalf("events = %v, want [start stop close]", got)
	}
}
