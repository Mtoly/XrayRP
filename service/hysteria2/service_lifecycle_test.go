package hysteria2

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/server"

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

type fakeRuntimeServer struct {
	events     *lifecycleEvents
	serveErr   error
	closeErr   error
	serveBlock <-chan struct{}
	serving    chan<- struct{}
}

func (f *fakeRuntimeServer) Serve() error {
	f.events.add("serve")
	if f.serving != nil {
		close(f.serving)
	}
	if f.serveBlock != nil {
		<-f.serveBlock
	}
	return f.serveErr
}

func (f *fakeRuntimeServer) Close() error {
	f.events.add("stop")
	f.events.add("close")
	return f.closeErr
}

func TestRuntimeLifecycleSeamCompiles(t *testing.T) {
	var runtime runtimeServer = &fakeRuntimeServer{events: &lifecycleEvents{}}
	var configFactory serverConfigFactory = func(*Hysteria2Service) (*server.Config, error) {
		return &server.Config{}, nil
	}
	var factory runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		return runtime, nil
	}

	service := &Hysteria2Service{
		serverConfigFactory:  configFactory,
		runtimeServerFactory: factory,
	}
	if service.serverConfigFactory == nil || service.runtimeServerFactory == nil {
		t.Fatal("runtime factory seams are nil")
	}
}

func TestBuildRuntimeServerRecordsBuildOrder(t *testing.T) {
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events}
	service := &Hysteria2Service{
		serverConfigFactory: func(*Hysteria2Service) (*server.Config, error) {
			events.add("build-config")
			return &server.Config{}, nil
		},
		runtimeServerFactory: func(*server.Config) (runtimeServer, error) {
			events.add("build-server")
			return runtime, nil
		},
	}

	gotRuntime, err := service.buildRuntimeServer()
	if err != nil {
		t.Fatalf("buildRuntimeServer() error = %v", err)
	}
	if gotRuntime != runtime {
		t.Fatalf("buildRuntimeServer() runtime = %T, want fake runtime", gotRuntime)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build-config", "build-server"}) {
		t.Fatalf("events = %v, want [build-config build-server]", got)
	}
}

func TestBuildRuntimeServerStopsAfterConfigError(t *testing.T) {
	wantErr := errors.New("config failed")
	events := &lifecycleEvents{}
	service := &Hysteria2Service{
		serverConfigFactory: func(*Hysteria2Service) (*server.Config, error) {
			events.add("build-config")
			return nil, wantErr
		},
		runtimeServerFactory: func(*server.Config) (runtimeServer, error) {
			events.add("build-server")
			return nil, nil
		},
	}

	_, err := service.buildRuntimeServer()
	if !errors.Is(err, wantErr) {
		t.Fatalf("buildRuntimeServer() error = %v, want %v", err, wantErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build-config"}) {
		t.Fatalf("events = %v, want [build-config]", got)
	}
}

func TestBuildRuntimeServerReturnsInjectedFakeAndFactoryError(t *testing.T) {
	wantErr := errors.New("server failed")
	events := &lifecycleEvents{}
	wantRuntime := &fakeRuntimeServer{events: events}
	service := &Hysteria2Service{
		serverConfigFactory: func(*Hysteria2Service) (*server.Config, error) {
			events.add("build-config")
			return &server.Config{}, nil
		},
		runtimeServerFactory: func(*server.Config) (runtimeServer, error) {
			events.add("build-server")
			return nil, wantErr
		},
	}

	if _, err := service.buildRuntimeServer(); !errors.Is(err, wantErr) {
		t.Fatalf("buildRuntimeServer() error = %v, want %v", err, wantErr)
	}
	service.runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		events.add("build-server")
		return wantRuntime, nil
	}
	gotRuntime, err := service.buildRuntimeServer()
	if err != nil {
		t.Fatalf("buildRuntimeServer() error = %v", err)
	}
	if gotRuntime != wantRuntime {
		t.Fatalf("buildRuntimeServer() runtime = %T, want injected fake", gotRuntime)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"build-config", "build-server", "build-config", "build-server"}) {
		t.Fatalf("events = %v, want two ordered builds", got)
	}
}

func TestNewInstallsDefaultsWithoutSharingFactoryState(t *testing.T) {
	client := hysteria2PanelClientContractStub{}
	first := New(client, &controller.Config{})
	second := New(client, &controller.Config{})

	if first.serverConfigFactory == nil || first.runtimeServerFactory == nil || first.serveRuntime == nil || first.closeRuntime == nil {
		t.Fatal("New() did not install lifecycle defaults")
	}
	first.runtimeServerFactory = func(*server.Config) (runtimeServer, error) {
		return &fakeRuntimeServer{events: &lifecycleEvents{}}, nil
	}
	first.serveRuntime = func(runtimeServer) error { return errors.New("test serve") }
	first.closeRuntime = func(runtimeServer) error { return errors.New("test close") }
	if reflect.ValueOf(second.runtimeServerFactory).Pointer() != reflect.ValueOf(defaultRuntimeServerFactory).Pointer() {
		t.Fatal("overriding one service factory changed another New() instance")
	}
	if reflect.ValueOf(second.serveRuntime).Pointer() != reflect.ValueOf(defaultServeRuntime).Pointer() {
		t.Fatal("overriding one serve helper changed another New() instance")
	}
	if reflect.ValueOf(second.closeRuntime).Pointer() != reflect.ValueOf(defaultCloseRuntime).Pointer() {
		t.Fatal("overriding one close helper changed another New() instance")
	}
}

func TestRuntimeServerFakeSupportsControlledServeAndClose(t *testing.T) {
	events := &lifecycleEvents{}
	serveBlock := make(chan struct{})
	serving := make(chan struct{})
	runtime := &fakeRuntimeServer{
		events:     events,
		serveBlock: serveBlock,
		serving:    serving,
	}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- runtime.Serve()
		events.add("join")
	}()

	select {
	case <-serving:
	case <-time.After(time.Second):
		t.Fatal("Serve did not reach controlled block")
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"serve"}) {
		t.Fatalf("events before release = %v, want [serve]", got)
	}

	close(serveBlock)
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	waitForEvents(t, events, []string{"serve", "join"})
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"serve", "join", "stop", "close"}) {
		t.Fatalf("events = %v, want [serve join stop close]", got)
	}
}

func TestRuntimeServerFakeInjectsServeAndCloseErrors(t *testing.T) {
	serveErr := errors.New("serve failed")
	closeErr := errors.New("close failed")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{
		events:   events,
		serveErr: serveErr,
		closeErr: closeErr,
	}

	if err := runtime.Serve(); !errors.Is(err, serveErr) {
		t.Fatalf("Serve() error = %v, want %v", err, serveErr)
	}
	if err := runtime.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close() error = %v, want %v", err, closeErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"serve", "stop", "close"}) {
		t.Fatalf("events = %v, want [serve stop close]", got)
	}
}

func TestRuntimeHelpersPropagateErrorsAndControlledBlocking(t *testing.T) {
	serveErr := errors.New("serve failed")
	closeErr := errors.New("close failed")
	events := &lifecycleEvents{}
	release := make(chan struct{})
	entered := make(chan struct{})
	runtime := &fakeRuntimeServer{
		events:     events,
		serveErr:   serveErr,
		closeErr:   closeErr,
		serveBlock: release,
		serving:    entered,
	}
	service := &Hysteria2Service{
		serveRuntime: defaultServeRuntime,
		closeRuntime: defaultCloseRuntime,
	}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- service.serveRuntime(runtime)
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("serveRuntime did not reach controlled block")
	}
	select {
	case err := <-serveDone:
		t.Fatalf("serveRuntime returned before release: %v", err)
	default:
	}

	close(release)
	if err := <-serveDone; !errors.Is(err, serveErr) {
		t.Fatalf("serveRuntime() error = %v, want %v", err, serveErr)
	}
	if err := service.closeRuntime(runtime); !errors.Is(err, closeErr) {
		t.Fatalf("closeRuntime() error = %v, want %v", err, closeErr)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"serve", "stop", "close"}) {
		t.Fatalf("events = %v, want [serve stop close]", got)
	}
}
