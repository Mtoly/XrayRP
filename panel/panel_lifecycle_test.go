package panel

import (
	"errors"
	"reflect"
	"testing"

	"github.com/xtls/xray-core/core"

	"github.com/Mtoly/XrayRP/service"
)

type lifecycleTestService struct {
	name     string
	events   *[]string
	startErr error
	closeErr error
	starts   int
	closes   int
}

func (s *lifecycleTestService) Start() error {
	s.starts++
	*s.events = append(*s.events, s.name+":start")
	return s.startErr
}

func (s *lifecycleTestService) Close() error {
	s.closes++
	*s.events = append(*s.events, s.name+":close")
	return s.closeErr
}

func TestPanelStartClosesCoreWhenRuntimePlanFails(t *testing.T) {
	planErr := errors.New("runtime plan failed")
	server := &core.Instance{}
	coreStarts := 0
	coreCloses := 0

	p := New(&Config{})
	p.lifecycle.loadCore = func(*Panel, *Config) (*core.Instance, error) {
		return server, nil
	}
	p.lifecycle.startCore = func(got *core.Instance) error {
		if got != server {
			t.Fatalf("startCore received unexpected server: %p", got)
		}
		coreStarts++
		return nil
	}
	p.lifecycle.closeCore = func(got *core.Instance) error {
		if got != server {
			t.Fatalf("closeCore received unexpected server: %p", got)
		}
		coreCloses++
		return nil
	}
	p.lifecycle.buildRuntimePlan = func(*Config) (runtimeConfigPlan, error) {
		return runtimeConfigPlan{}, planErr
	}

	err := p.Start()
	if !errors.Is(err, planErr) {
		t.Fatalf("Start() error = %v, want errors.Is(..., planErr)", err)
	}
	if coreStarts != 1 {
		t.Fatalf("core start calls = %d, want 1", coreStarts)
	}
	if coreCloses != 1 {
		t.Fatalf("core close calls = %d, want 1", coreCloses)
	}
	assertPanelUnpublished(t, p)
}

func TestPanelStartClosesCoreWhenCoreStartFails(t *testing.T) {
	startErr := errors.New("core start failed")
	events := []string{}
	server := &core.Instance{}
	p := New(&Config{})
	p.lifecycle.loadCore = func(*Panel, *Config) (*core.Instance, error) { return server, nil }
	p.lifecycle.startCore = func(got *core.Instance) error {
		if got != server {
			t.Fatalf("startCore received unexpected server: %p", got)
		}
		events = append(events, "core:start")
		return startErr
	}
	p.lifecycle.closeCore = func(got *core.Instance) error {
		if got != server {
			t.Fatalf("closeCore received unexpected server: %p", got)
		}
		events = append(events, "core:close")
		return nil
	}
	p.lifecycle.buildRuntimePlan = func(*Config) (runtimeConfigPlan, error) {
		t.Fatal("runtime plan must not be built after core start failure")
		return runtimeConfigPlan{}, nil
	}

	err := p.Start()
	if !errors.Is(err, startErr) {
		t.Fatalf("Start() error = %v, want errors.Is(..., startErr)", err)
	}
	wantEvents := []string{"core:start", "core:close"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	assertPanelUnpublished(t, p)
}

func TestPanelStartRollsBackCoreWhenModuleBuildFails(t *testing.T) {
	tests := []struct {
		name string
		mode runtimeConfigMode
	}{
		{name: "static", mode: runtimeConfigModeStatic},
		{name: "machine", mode: runtimeConfigModeMachine},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buildErr := errors.New(tt.name + " module build failed")
			events := []string{}
			p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
				return nil, buildErr
			})
			p.lifecycle.buildRuntimePlan = func(*Config) (runtimeConfigPlan, error) {
				return runtimeConfigPlan{mode: tt.mode}, nil
			}
			p.lifecycle.buildMachineModule = func(*Panel, *core.Instance, runtimeConfigPlan) (service.Service, error) {
				return nil, buildErr
			}

			err := p.Start()
			if !errors.Is(err, buildErr) {
				t.Fatalf("Start() error = %v, want errors.Is(..., buildErr)", err)
			}
			wantEvents := []string{"core:start", "core:close"}
			if !reflect.DeepEqual(events, wantEvents) {
				t.Fatalf("events = %#v, want %#v", events, wantEvents)
			}
			assertPanelUnpublished(t, p)
		})
	}
}

func TestPanelLifecycleSeamsFallBackToDefaults(t *testing.T) {
	p := &Panel{
		panelConfig: &Config{},
		logger:      New(&Config{}).logger,
	}
	ops := p.lifecycleOps()
	if ops.loadCore == nil || ops.startCore == nil || ops.closeCore == nil ||
		ops.buildRuntimePlan == nil || ops.buildStaticModules == nil || ops.buildMachineModule == nil {
		t.Fatal("lifecycleOps() left a nil operation")
	}
}

func TestPanelStartRollsBackEarlierServicesWhenLaterServiceFails(t *testing.T) {
	startErr := errors.New("second service failed")
	events := []string{}
	first := &lifecycleTestService{name: "first", events: &events}
	second := &lifecycleTestService{name: "second", events: &events, startErr: startErr}
	third := &lifecycleTestService{name: "third", events: &events}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{first, second, third}, nil
	})

	err := p.Start()
	if !errors.Is(err, startErr) {
		t.Fatalf("Start() error = %v, want errors.Is(..., startErr)", err)
	}
	wantEvents := []string{"core:start", "first:start", "second:start", "first:close", "core:close"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	if first.closes != 1 {
		t.Fatalf("first close calls = %d, want 1", first.closes)
	}
	if third.starts != 0 {
		t.Fatalf("third start calls = %d, want 0", third.starts)
	}
	assertPanelUnpublished(t, p)
}

func TestPanelStartRollsBackStartedServicesInReverseOrder(t *testing.T) {
	startErr := errors.New("third service failed")
	events := []string{}
	first := &lifecycleTestService{name: "first", events: &events}
	second := &lifecycleTestService{name: "second", events: &events}
	third := &lifecycleTestService{name: "third", events: &events, startErr: startErr}
	fourth := &lifecycleTestService{name: "fourth", events: &events}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{first, second, third, fourth}, nil
	})

	err := p.Start()
	if !errors.Is(err, startErr) {
		t.Fatalf("Start() error = %v, want errors.Is(..., startErr)", err)
	}
	wantEvents := []string{
		"core:start", "first:start", "second:start", "third:start",
		"second:close", "first:close", "core:close",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	if fourth.starts != 0 {
		t.Fatalf("fourth start calls = %d, want 0", fourth.starts)
	}
	assertPanelUnpublished(t, p)
}

func TestPanelStartRollbackErrorsPreservePrimaryError(t *testing.T) {
	startErr := errors.New("service start failed")
	serviceCloseErr := errors.New("service rollback failed")
	coreCloseErr := errors.New("core rollback failed")
	events := []string{}
	first := &lifecycleTestService{name: "first", events: &events, closeErr: serviceCloseErr}
	second := &lifecycleTestService{name: "second", events: &events, startErr: startErr}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{first, second}, nil
	})
	p.lifecycle.closeCore = func(*core.Instance) error {
		events = append(events, "core:close")
		return coreCloseErr
	}

	err := p.Start()
	for _, want := range []error{startErr, serviceCloseErr, coreCloseErr} {
		if !errors.Is(err, want) {
			t.Errorf("Start() error = %v, want errors.Is(..., %v)", err, want)
		}
	}
	wantEvents := []string{"core:start", "first:start", "second:start", "first:close", "core:close"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	assertPanelUnpublished(t, p)
}

func TestPanelStartCoreFailurePreservesCloseError(t *testing.T) {
	startErr := errors.New("core start failed")
	closeErr := errors.New("core close failed")
	server := &core.Instance{}
	p := New(&Config{})
	p.lifecycle.loadCore = func(*Panel, *Config) (*core.Instance, error) { return server, nil }
	p.lifecycle.startCore = func(*core.Instance) error { return startErr }
	p.lifecycle.closeCore = func(*core.Instance) error { return closeErr }

	err := p.Start()
	for _, want := range []error{startErr, closeErr} {
		if !errors.Is(err, want) {
			t.Errorf("Start() error = %v, want errors.Is(..., %v)", err, want)
		}
	}
	assertPanelUnpublished(t, p)
}

func TestPanelStartCanRetryAfterFailedStartup(t *testing.T) {
	planErr := errors.New("first plan failed")
	events := []string{}
	servers := []*core.Instance{{}, {}}
	loadCalls := 0
	planCalls := 0
	module := &lifecycleTestService{name: "service", events: &events}
	p := New(&Config{})
	p.lifecycle.loadCore = func(*Panel, *Config) (*core.Instance, error) {
		server := servers[loadCalls]
		loadCalls++
		return server, nil
	}
	p.lifecycle.startCore = func(*core.Instance) error {
		events = append(events, "core:start")
		return nil
	}
	p.lifecycle.closeCore = func(*core.Instance) error {
		events = append(events, "core:close")
		return nil
	}
	p.lifecycle.buildRuntimePlan = func(*Config) (runtimeConfigPlan, error) {
		planCalls++
		if planCalls == 1 {
			return runtimeConfigPlan{}, planErr
		}
		return runtimeConfigPlan{mode: runtimeConfigModeStatic}, nil
	}
	p.lifecycle.buildStaticModules = func(*Panel, *core.Instance, runtimeConfigPlan) ([]service.Service, error) {
		return []service.Service{module}, nil
	}

	if err := p.Start(); !errors.Is(err, planErr) {
		t.Fatalf("first Start() error = %v, want planErr", err)
	}
	assertPanelUnpublished(t, p)
	if err := p.Start(); err != nil {
		t.Fatalf("second Start() error = %v", err)
	}
	if !p.Running || p.Server != servers[1] || len(p.Service) != 1 || p.Service[0] != module {
		t.Fatalf("successful retry published unexpected state: Running=%v Server=%p Service=%#v", p.Running, p.Server, p.Service)
	}
	wantEvents := []string{"core:start", "core:close", "core:start", "service:start"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
}

func TestPanelStartWhileRunningDoesNotDuplicateResources(t *testing.T) {
	events := []string{}
	module := &lifecycleTestService{name: "service", events: &events}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{module}, nil
	})
	if err := p.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("second Start() error = %v", err)
	}

	wantEvents := []string{"core:start", "service:start"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	if len(p.Service) != 1 || p.Service[0] != module {
		t.Fatalf("Service = %#v, want one module", p.Service)
	}
}

func TestPanelStartAfterCloseCreatesFreshResources(t *testing.T) {
	events := []string{}
	servers := []*core.Instance{{}, {}}
	services := []*lifecycleTestService{
		{name: "first", events: &events},
		{name: "second", events: &events},
	}
	loadCalls := 0
	buildCalls := 0
	p := New(&Config{})
	p.lifecycle.loadCore = func(*Panel, *Config) (*core.Instance, error) {
		server := servers[loadCalls]
		loadCalls++
		return server, nil
	}
	p.lifecycle.startCore = func(*core.Instance) error {
		events = append(events, "core:start")
		return nil
	}
	p.lifecycle.closeCore = func(*core.Instance) error {
		events = append(events, "core:close")
		return nil
	}
	p.lifecycle.buildRuntimePlan = func(*Config) (runtimeConfigPlan, error) {
		return runtimeConfigPlan{mode: runtimeConfigModeStatic}, nil
	}
	p.lifecycle.buildStaticModules = func(*Panel, *core.Instance, runtimeConfigPlan) ([]service.Service, error) {
		module := services[buildCalls]
		buildCalls++
		return []service.Service{module}, nil
	}

	if err := p.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("second Start() error = %v", err)
	}

	wantEvents := []string{
		"core:start", "first:start", "first:close", "core:close",
		"core:start", "second:start",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	if loadCalls != 2 || buildCalls != 2 {
		t.Fatalf("fresh resource calls: load=%d build=%d, want 2 each", loadCalls, buildCalls)
	}
	if !p.Running || p.Server != servers[1] || len(p.Service) != 1 || p.Service[0] != services[1] {
		t.Fatalf("restarted panel state: Running=%v Server=%p Service=%#v", p.Running, p.Server, p.Service)
	}
}

func TestPanelLifecycleUsesInternalStateWhenPublicRunningIsMutated(t *testing.T) {
	events := []string{}
	module := &lifecycleTestService{name: "service", events: &events}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{module}, nil
	})
	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	p.Running = false
	if err := p.Start(); err != nil {
		t.Fatalf("second Start() error = %v", err)
	}
	wantEvents := []string{"core:start", "service:start"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("public Running mutation duplicated resources: events=%#v", events)
	}
	if !p.Running {
		t.Fatal("Running = false after running-state no-op, want compatibility field resynchronized")
	}

	if err := p.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	p.Running = true
	if err := p.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if p.Running {
		t.Fatal("Running = true after stopped-state no-op, want compatibility field resynchronized")
	}
	wantEvents = []string{"core:start", "service:start", "service:close", "core:close"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("public Running mutation duplicated cleanup: events=%#v", events)
	}
}

func TestPanelCloseRepeatedlyClosesResourcesOnce(t *testing.T) {
	events := []string{}
	first := &lifecycleTestService{name: "first", events: &events}
	second := &lifecycleTestService{name: "second", events: &events}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{first, second}, nil
	})
	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}

	wantEvents := []string{
		"core:start", "first:start", "second:start",
		"first:close", "second:close", "core:close",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	assertPanelUnpublished(t, p)
}

func TestPanelClosePreservesCleanupErrorsAndClearsState(t *testing.T) {
	firstCloseErr := errors.New("first close failed")
	coreCloseErr := errors.New("core close failed")
	events := []string{}
	first := &lifecycleTestService{name: "first", events: &events, closeErr: firstCloseErr}
	second := &lifecycleTestService{name: "second", events: &events}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{first, second}, nil
	})
	p.lifecycle.closeCore = func(*core.Instance) error {
		events = append(events, "core:close")
		return coreCloseErr
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	err := p.Close()
	for _, want := range []error{firstCloseErr, coreCloseErr} {
		if !errors.Is(err, want) {
			t.Errorf("Close() error = %v, want errors.Is(..., %v)", err, want)
		}
	}
	wantEvents := []string{
		"core:start", "first:start", "second:start",
		"first:close", "second:close", "core:close",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	assertPanelUnpublished(t, p)
	beforeSecondClose := append([]string(nil), events...)
	if err := p.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if !reflect.DeepEqual(events, beforeSecondClose) {
		t.Fatalf("second Close() added events: before=%#v after=%#v", beforeSecondClose, events)
	}
}

func TestPanelCloseAfterPartialFailureDoesNotCloseResourcesAgain(t *testing.T) {
	startErr := errors.New("second service failed")
	events := []string{}
	first := &lifecycleTestService{name: "first", events: &events}
	second := &lifecycleTestService{name: "second", events: &events, startErr: startErr}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{first, second}, nil
	})
	if err := p.Start(); !errors.Is(err, startErr) {
		t.Fatalf("Start() error = %v, want startErr", err)
	}
	beforeClose := append([]string(nil), events...)
	if err := p.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !reflect.DeepEqual(events, beforeClose) {
		t.Fatalf("Close() added events after rollback: before=%#v after=%#v", beforeClose, events)
	}
	assertPanelUnpublished(t, p)
}

func newLifecycleTestPanel(t *testing.T, events *[]string, modules func() ([]service.Service, error)) *Panel {
	t.Helper()
	server := &core.Instance{}
	p := New(&Config{})
	p.lifecycle.loadCore = func(*Panel, *Config) (*core.Instance, error) {
		return server, nil
	}
	p.lifecycle.startCore = func(got *core.Instance) error {
		if got != server {
			t.Fatalf("startCore received unexpected server: %p", got)
		}
		*events = append(*events, "core:start")
		return nil
	}
	p.lifecycle.closeCore = func(got *core.Instance) error {
		if got != server {
			t.Fatalf("closeCore received unexpected server: %p", got)
		}
		*events = append(*events, "core:close")
		return nil
	}
	p.lifecycle.buildRuntimePlan = func(*Config) (runtimeConfigPlan, error) {
		return runtimeConfigPlan{mode: runtimeConfigModeStatic}, nil
	}
	p.lifecycle.buildStaticModules = func(*Panel, *core.Instance, runtimeConfigPlan) ([]service.Service, error) {
		return modules()
	}
	return p
}

func assertPanelUnpublished(t *testing.T, p *Panel) {
	t.Helper()
	if p.Running {
		t.Error("Running = true, want false")
	}
	if p.Server != nil {
		t.Errorf("Server = %p, want nil", p.Server)
	}
	if len(p.Service) != 0 {
		t.Errorf("Service length = %d, want 0", len(p.Service))
	}
}
