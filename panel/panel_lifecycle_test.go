package panel

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"testing"
	"time"

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

func TestPanelStartRejectsRuntimePlanBeforeConstructingCore(t *testing.T) {
	planErr := errors.New("runtime plan failed")
	p := New(&Config{})
	p.lifecycle.loadCore = func(*Config) (*core.Instance, error) {
		t.Fatal("core must not be constructed when runtime plan validation fails")
		return nil, nil
	}
	p.lifecycle.startCore = func(*core.Instance) error {
		t.Fatal("core must not be started when runtime plan validation fails")
		return nil
	}
	p.lifecycle.closeCore = func(*core.Instance) error {
		t.Fatal("core must not be closed when runtime plan validation fails")
		return nil
	}
	p.lifecycle.buildRuntimePlan = func(*Config) (runtimeConfigPlan, error) {
		return runtimeConfigPlan{}, planErr
	}

	err := p.Start()
	if !errors.Is(err, planErr) {
		t.Fatalf("Start() error = %v, want errors.Is(..., planErr)", err)
	}
	assertPanelUnpublished(t, p)
}

func TestPanelStartClosesCoreWhenCoreStartFails(t *testing.T) {
	startErr := errors.New("core start failed")
	events := []string{}
	server := &core.Instance{}
	p := New(&Config{})
	p.lifecycle.loadCore = func(*Config) (*core.Instance, error) { return server, nil }
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
	wantEvents := []string{"core:start", "first:start", "second:start", "second:close", "first:close", "core:close"}
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
		"third:close", "second:close", "first:close", "core:close",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	if fourth.starts != 0 {
		t.Fatalf("fourth start calls = %d, want 0", fourth.starts)
	}
	assertPanelUnpublished(t, p)
}

func TestPanelStartRollbackErrorsPreservePrimaryErrorAndOwnership(t *testing.T) {
	startErr := errors.New("service start failed")
	serviceCloseErr := errors.New("service rollback failed")
	coreCloseErr := errors.New("core rollback failed")
	currentCoreCloseErr := coreCloseErr
	events := []string{}
	first := &lifecycleTestService{name: "first", events: &events, closeErr: serviceCloseErr}
	second := &lifecycleTestService{name: "second", events: &events, startErr: startErr}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{first, second}, nil
	})
	p.lifecycle.closeCore = func(*core.Instance) error {
		events = append(events, "core:close")
		return currentCoreCloseErr
	}

	err := p.Start()
	for _, want := range []error{startErr, serviceCloseErr, coreCloseErr} {
		if !errors.Is(err, want) {
			t.Errorf("Start() error = %v, want errors.Is(..., %v)", err, want)
		}
	}
	wantEvents := []string{"core:start", "first:start", "second:start", "second:close", "first:close", "core:close"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	snapshot := p.publishedStateSnapshot()
	if snapshot.lifecycle != panelStateFailedOwned || snapshot.server == nil || len(snapshot.services) != 1 || snapshot.services[0] != first {
		t.Fatalf("failed rollback ownership = lifecycle:%v server:%p services:%v", snapshot.lifecycle, snapshot.server, snapshot.services)
	}
	if err := p.Start(); err == nil {
		t.Fatal("Start() error = nil, want failed-owned rejection")
	}

	first.closeErr = nil
	currentCoreCloseErr = nil
	if err := p.Close(); err != nil {
		t.Fatalf("Close() retry error = %v", err)
	}
	assertPanelUnpublished(t, p)
}
func TestPanelStartCoreFailureRetainsCoreUntilCloseRetry(t *testing.T) {
	startErr := errors.New("core start failed")
	closeErr := errors.New("core close failed")
	currentCloseErr := closeErr
	server := &core.Instance{}
	p := New(&Config{})
	p.lifecycle.loadCore = func(*Config) (*core.Instance, error) { return server, nil }
	p.lifecycle.startCore = func(*core.Instance) error { return startErr }
	p.lifecycle.closeCore = func(*core.Instance) error { return currentCloseErr }
	p.lifecycle.buildRuntimePlan = func(*Config) (runtimeConfigPlan, error) { return runtimeConfigPlan{}, nil }

	err := p.Start()
	for _, want := range []error{startErr, closeErr} {
		if !errors.Is(err, want) {
			t.Errorf("Start() error = %v, want errors.Is(..., %v)", err, want)
		}
	}
	assertPanelPublishedState(t, p, panelStateFailedOwned, server, 0)
	assertLegacyPanelState(t, p, false, server, 0)
	if err := p.Start(); err == nil {
		t.Fatal("Start() error = nil, want failed-owned rejection")
	}

	currentCloseErr = nil
	if err := p.Close(); err != nil {
		t.Fatalf("Close() retry error = %v", err)
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
	p.lifecycle.loadCore = func(*Config) (*core.Instance, error) {
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
	if !p.Running || p.Server != servers[0] || len(p.Service) != 1 || p.Service[0] != module {
		t.Fatalf("successful retry published unexpected state: Running=%v Server=%p Service=%#v", p.Running, p.Server, p.Service)
	}
	wantEvents := []string{"core:start", "service:start"}
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
	p.lifecycle.loadCore = func(*Config) (*core.Instance, error) {
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

func TestPanelLifecycleIgnoresCompatibilityFieldMutation(t *testing.T) {
	events := []string{}
	realService := &lifecycleTestService{name: "real", events: &events}
	fakeService := &lifecycleTestService{name: "fake", events: &events}
	realServer := &core.Instance{}
	fakeServer := &core.Instance{}
	var closedServer *core.Instance
	p := New(&Config{})
	p.lifecycle.loadCore = func(*Config) (*core.Instance, error) { return realServer, nil }
	p.lifecycle.startCore = func(*core.Instance) error { return nil }
	p.lifecycle.closeCore = func(server *core.Instance) error {
		closedServer = server
		return nil
	}
	p.lifecycle.buildRuntimePlan = func(*Config) (runtimeConfigPlan, error) {
		return runtimeConfigPlan{mode: runtimeConfigModeStatic}, nil
	}
	p.lifecycle.buildStaticModules = func(*Panel, *core.Instance, runtimeConfigPlan) ([]service.Service, error) {
		return []service.Service{realService}, nil
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	p.Running = false
	p.Server = fakeServer
	p.Service = []service.Service{fakeService}
	assertPanelAccessors(t, p, true, realServer, []service.Service{realService})
	if err := p.Start(); err != nil {
		t.Fatalf("second Start() error = %v", err)
	}
	if !p.Running || p.Server != realServer || len(p.Service) != 1 || p.Service[0] != realService {
		t.Errorf("compatibility fields were not restored from private state: Running=%v Server=%p Service=%#v", p.Running, p.Server, p.Service)
	}
	if wantEvents := []string{"real:start"}; !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("public Running mutation duplicated resources: events=%#v", events)
	}

	if err := p.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closedServer != realServer || realService.closes != 1 || fakeService.closes != 0 {
		t.Fatalf("cleanup used compatibility fields: closedServer=%p realCloses=%d fakeCloses=%d", closedServer, realService.closes, fakeService.closes)
	}
	p.Running = true
	p.Server = fakeServer
	p.Service = []service.Service{fakeService}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if p.Running || p.Server != nil || len(p.Service) != 0 {
		t.Fatalf("stopped-state compatibility fields were not cleared: Running=%v Server=%p Service=%#v", p.Running, p.Server, p.Service)
	}
	wantEvents := []string{"real:start", "real:close"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("public Running mutation duplicated cleanup: events=%#v", events)
	}
}

func TestPanelPublishedStateIsUnpublishedDuringSlowStartAndClose(t *testing.T) {
	server := &core.Instance{}
	module := &blockingLifecycleService{
		startEntered: make(chan struct{}),
		startRelease: make(chan struct{}),
		closeEntered: make(chan struct{}),
		closeRelease: make(chan struct{}),
	}
	defer closeSignal(module.startRelease)
	defer closeSignal(module.closeRelease)

	p := New(&Config{})
	p.lifecycle.loadCore = func(*Config) (*core.Instance, error) { return server, nil }
	p.lifecycle.startCore = func(*core.Instance) error { return nil }
	p.lifecycle.closeCore = func(*core.Instance) error { return nil }
	p.lifecycle.buildRuntimePlan = func(*Config) (runtimeConfigPlan, error) {
		return runtimeConfigPlan{mode: runtimeConfigModeStatic}, nil
	}
	p.lifecycle.buildStaticModules = func(*Panel, *core.Instance, runtimeConfigPlan) ([]service.Service, error) {
		return []service.Service{module}, nil
	}

	startResult := make(chan error, 1)
	go func() { startResult <- p.Start() }()
	waitForLifecycleSignal(t, module.startEntered, "service Start")
	assertPanelPublishedState(t, p, panelStateStarting, nil, 0)
	assertLegacyPanelState(t, p, false, nil, 0)
	assertPanelAccessors(t, p, false, nil, nil)
	closeSignal(module.startRelease)
	if err := waitForLifecycleResult(t, startResult, "Panel.Start"); err != nil {
		t.Fatal(err)
	}
	assertPanelPublishedState(t, p, panelStateRunning, server, 1)
	assertLegacyPanelState(t, p, true, server, 1)
	assertPanelAccessors(t, p, true, server, []service.Service{module})

	closeResult := make(chan error, 1)
	go func() { closeResult <- p.Close() }()
	waitForLifecycleSignal(t, module.closeEntered, "service Close")
	assertPanelPublishedState(t, p, panelStateStopping, server, 1)
	assertLegacyPanelState(t, p, false, server, 1)
	assertPanelAccessors(t, p, false, server, []service.Service{module})
	closeSignal(module.closeRelease)
	if err := waitForLifecycleResult(t, closeResult, "Panel.Close"); err != nil {
		t.Fatal(err)
	}
	assertPanelPublishedState(t, p, panelStateStopped, nil, 0)
	assertLegacyPanelState(t, p, false, nil, 0)
	assertPanelAccessors(t, p, false, nil, nil)
}

func TestPanelPublishedServiceSlicesDoNotAliasCompatibilityOrSnapshots(t *testing.T) {
	events := []string{}
	first := &lifecycleTestService{name: "first", events: &events}
	second := &lifecycleTestService{name: "second", events: &events}
	replacement := &lifecycleTestService{name: "replacement", events: &events}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{first, second}, nil
	})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	snapshot := p.publishedStateSnapshot()
	snapshot.services[0] = replacement
	p.Service[0] = replacement
	publicSnapshot := p.ServicesSnapshot()
	publicSnapshot[0] = replacement
	fresh := p.publishedStateSnapshot()
	if fresh.services[0] != first {
		t.Fatalf("private services aliased a returned or compatibility slice: %#v", fresh.services)
	}
	freshPublic := p.ServicesSnapshot()
	if freshPublic[0] != first {
		t.Fatalf("read-only service snapshot aliased a previous result: %#v", freshPublic)
	}

	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if first.closes != 1 || second.closes != 1 || replacement.closes != 0 {
		t.Fatalf("cleanup used aliased service slice: first=%d second=%d replacement=%d", first.closes, second.closes, replacement.closes)
	}
}

func TestPanelPublishedStateSnapshotStaysConsistentUnderRepeatedScheduling(t *testing.T) {
	p := New(&Config{})
	p.lifecycle.loadCore = func(*Config) (*core.Instance, error) { return &core.Instance{}, nil }
	p.lifecycle.startCore = func(*core.Instance) error { return nil }
	p.lifecycle.closeCore = func(*core.Instance) error { return nil }
	p.lifecycle.buildRuntimePlan = func(*Config) (runtimeConfigPlan, error) {
		return runtimeConfigPlan{mode: runtimeConfigModeStatic}, nil
	}
	p.lifecycle.buildStaticModules = func(*Panel, *core.Instance, runtimeConfigPlan) ([]service.Service, error) {
		return []service.Service{noopLifecycleService{}}, nil
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	ready := make(chan struct{})
	observedRunning := make(chan struct{})
	observedNonRunningAfterStart := make(chan struct{})
	snapshotErrors := make(chan error, 1)
	defer closeSignal(stop)
	go func() {
		defer close(done)
		firstObservation := true
		seenRunning := false
		reportedNonRunning := false
		for {
			snapshot := p.publishedStateSnapshot()
			if firstObservation {
				close(ready)
				firstObservation = false
			}
			if err := validatePanelPublishedState(snapshot); err != nil {
				select {
				case snapshotErrors <- err:
				default:
				}
				return
			}
			if snapshot.lifecycle == panelStateRunning && !seenRunning {
				close(observedRunning)
				seenRunning = true
			}
			if seenRunning && snapshot.lifecycle != panelStateRunning && !reportedNonRunning {
				close(observedNonRunningAfterStart)
				reportedNonRunning = true
			}
			select {
			case <-stop:
				return
			default:
				runtime.Gosched()
			}
		}
	}()
	waitForLifecycleSignal(t, ready, "snapshot observer readiness")

	for i := 0; i < 200; i++ {
		if err := p.Start(); err != nil {
			t.Fatalf("Start iteration %d: %v", i, err)
		}
		if i == 0 {
			waitForLifecycleSignal(t, observedRunning, "observer running snapshot")
		}
		if err := p.Close(); err != nil {
			t.Fatalf("Close iteration %d: %v", i, err)
		}
		if i == 0 {
			waitForLifecycleSignal(t, observedNonRunningAfterStart, "observer non-running snapshot")
		}
	}
	closeSignal(stop)
	waitForLifecycleSignal(t, done, "snapshot observer")
	select {
	case err := <-snapshotErrors:
		t.Fatal(err)
	default:
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

func TestPanelClosePreservesCleanupErrorsRetainsOwnershipAndRetries(t *testing.T) {
	firstCloseErr := errors.New("first close failed")
	coreCloseErr := errors.New("core close failed")
	currentCoreCloseErr := coreCloseErr
	events := []string{}
	first := &lifecycleTestService{name: "first", events: &events, closeErr: firstCloseErr}
	second := &lifecycleTestService{name: "second", events: &events}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{first, second}, nil
	})
	p.lifecycle.closeCore = func(*core.Instance) error {
		events = append(events, "core:close")
		return currentCoreCloseErr
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
	snapshot := p.publishedStateSnapshot()
	if snapshot.lifecycle != panelStateFailedOwned || snapshot.server == nil || len(snapshot.services) != 1 || snapshot.services[0] != first {
		t.Fatalf("failed Close ownership = lifecycle:%v server:%p services:%v", snapshot.lifecycle, snapshot.server, snapshot.services)
	}
	if err := p.Start(); err == nil {
		t.Fatal("Start() error = nil, want failed-owned rejection")
	}

	first.closeErr = nil
	currentCoreCloseErr = nil
	if err := p.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	wantEvents = append(wantEvents, "first:close", "core:close")
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("retry Close events = %#v, want %#v", events, wantEvents)
	}
	assertPanelUnpublished(t, p)
	beforeThirdClose := append([]string(nil), events...)
	if err := p.Close(); err != nil {
		t.Fatalf("third Close() error = %v", err)
	}
	if !reflect.DeepEqual(events, beforeThirdClose) {
		t.Fatalf("idempotent Close added events: before=%#v after=%#v", beforeThirdClose, events)
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
	p.lifecycle.loadCore = func(*Config) (*core.Instance, error) {
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
	assertPanelPublishedState(t, p, panelStateStopped, nil, 0)
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

type blockingLifecycleService struct {
	startEntered chan struct{}
	startRelease chan struct{}
	closeEntered chan struct{}
	closeRelease chan struct{}
}

func (s *blockingLifecycleService) Start() error {
	close(s.startEntered)
	<-s.startRelease
	return nil
}

func (s *blockingLifecycleService) Close() error {
	close(s.closeEntered)
	<-s.closeRelease
	return nil
}

type noopLifecycleService struct{}

func (noopLifecycleService) Start() error { return nil }
func (noopLifecycleService) Close() error { return nil }

type deadlineLifecycleService struct {
	waitStart     bool
	waitClose     bool
	startDeadline chan bool
	closeDeadline chan bool
}

func (s *deadlineLifecycleService) Start() error {
	return s.StartContext(context.Background())
}

func (s *deadlineLifecycleService) StartContext(ctx context.Context) error {
	_, hasDeadline := ctx.Deadline()
	if s.startDeadline != nil {
		s.startDeadline <- hasDeadline
	}
	if s.waitStart {
		<-ctx.Done()
		return ctx.Err()
	}
	return ctx.Err()
}

func (s *deadlineLifecycleService) Close() error {
	return s.CloseContext(context.Background())
}

func (s *deadlineLifecycleService) CloseContext(ctx context.Context) error {
	_, hasDeadline := ctx.Deadline()
	if s.closeDeadline != nil {
		s.closeDeadline <- hasDeadline
	}
	if s.waitClose {
		<-ctx.Done()
		return ctx.Err()
	}
	return ctx.Err()
}

func TestPanelStartContextPropagatesDeadlineAndRejectsLatePublication(t *testing.T) {
	events := []string{}
	runtimeService := &deadlineLifecycleService{
		waitStart:     true,
		startDeadline: make(chan bool, 1),
	}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{runtimeService}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := p.StartContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("StartContext() error = %v, want deadline exceeded", err)
	}
	if hasDeadline := <-runtimeService.startDeadline; !hasDeadline {
		t.Fatal("service StartContext did not receive a deadline")
	}
	assertPanelUnpublished(t, p)
}

func TestPanelCloseContextPropagatesDeadlineAndRetainsOwnership(t *testing.T) {
	events := []string{}
	runtimeService := &deadlineLifecycleService{
		closeDeadline: make(chan bool, 2),
	}
	p := newLifecycleTestPanel(t, &events, func() ([]service.Service, error) {
		return []service.Service{runtimeService}, nil
	})
	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	runtimeService.waitClose = true
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := p.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext() error = %v, want deadline exceeded", err)
	}
	if hasDeadline := <-runtimeService.closeDeadline; !hasDeadline {
		t.Fatal("service CloseContext did not receive a deadline")
	}
	state := p.publishedStateSnapshot()
	if state.lifecycle != panelStateFailedOwned || state.server == nil || len(state.services) != 1 {
		t.Fatalf("deadline cleanup lost ownership: lifecycle=%v server=%v services=%d", state.lifecycle, state.server, len(state.services))
	}
	assertPanelAccessors(t, p, false, state.server, state.services)

	runtimeService.waitClose = false
	if err := p.Close(); err != nil {
		t.Fatalf("Close() cleanup retry error = %v", err)
	}
}

func assertPanelPublishedState(t *testing.T, p *Panel, wantLifecycle panelLifecycleState, wantServer *core.Instance, wantServices int) {
	t.Helper()
	snapshot := p.publishedStateSnapshot()
	if snapshot.lifecycle != wantLifecycle || snapshot.server != wantServer || len(snapshot.services) != wantServices {
		t.Fatalf(
			"published state = {lifecycle:%d server:%p services:%d}, want {%d %p %d}",
			snapshot.lifecycle,
			snapshot.server,
			len(snapshot.services),
			wantLifecycle,
			wantServer,
			wantServices,
		)
	}
}

func assertLegacyPanelState(t *testing.T, p *Panel, wantRunning bool, wantServer *core.Instance, wantServices int) {
	t.Helper()
	if p.Running != wantRunning || p.Server != wantServer || len(p.Service) != wantServices {
		t.Fatalf(
			"legacy state = {Running:%v Server:%p Service:%d}, want {%v %p %d}",
			p.Running,
			p.Server,
			len(p.Service),
			wantRunning,
			wantServer,
			wantServices,
		)
	}
}

func assertPanelAccessors(t *testing.T, p *Panel, wantRunning bool, wantServer *core.Instance, wantServices []service.Service) {
	t.Helper()
	if got := p.IsRunning(); got != wantRunning {
		t.Fatalf("IsRunning() = %v, want %v", got, wantRunning)
	}
	if got := p.ServerInstance(); got != wantServer {
		t.Fatalf("ServerInstance() = %p, want %p", got, wantServer)
	}
	if got := p.ServicesSnapshot(); !reflect.DeepEqual(got, wantServices) {
		t.Fatalf("ServicesSnapshot() = %#v, want %#v", got, wantServices)
	}
}

func validatePanelPublishedState(snapshot panelPublishedState) error {
	switch snapshot.lifecycle {
	case panelStateRunning:
		if snapshot.server == nil {
			return fmt.Errorf("running snapshot has nil server")
		}
		return nil
	case panelStateStopping, panelStateFailedOwned:
		return nil
	case panelStateStopped, panelStateStarting:
		if snapshot.server != nil || len(snapshot.services) != 0 {
			return fmt.Errorf(
				"unowned snapshot has resources: lifecycle=%d server=%p services=%d",
				snapshot.lifecycle,
				snapshot.server,
				len(snapshot.services),
			)
		}
		return nil
	default:
		return fmt.Errorf("unknown panel lifecycle state %d", snapshot.lifecycle)
	}
}

func waitForLifecycleSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func waitForLifecycleResult(t *testing.T, result <-chan error, operation string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
		return nil
	}
}

func closeSignal(signal chan struct{}) {
	select {
	case <-signal:
	default:
		close(signal)
	}
}
