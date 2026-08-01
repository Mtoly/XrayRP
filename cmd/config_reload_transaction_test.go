package cmd

import (
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/panel"
)

func TestPanelReloadModulePublishesCandidateOnlyAfterStart(t *testing.T) {
	initialTime := time.Unix(500, 0)
	times := []time.Time{initialTime.Add(4 * time.Second), initialTime.Add(5 * time.Second)}
	events := make([]string, 0, 6)
	initialConfig := reloadTestPanelConfig("initial")
	candidateConfig := reloadTestPanelConfig("candidate")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
	startEntered := make(chan struct{})
	startRelease := make(chan struct{})
	candidateRuntime := &reloadTestRuntime{
		name:         "candidate",
		events:       &events,
		startEntered: startEntered,
		startRelease: startRelease,
	}
	var processApplied atomic.Bool

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			events = append(events, "load")
			return candidateConfig, nil
		},
		buildRuntime: func(config *panel.Config) panelRuntime {
			if config != candidateConfig {
				t.Fatal("buildRuntime received non-candidate config")
			}
			events = append(events, "build-candidate")
			return candidateRuntime
		},
		applyProcessConfig: func(config *panel.Config) {
			if config != candidateConfig {
				t.Fatal("applyProcessConfig received non-candidate config")
			}
			events = append(events, "apply-process")
			processApplied.Store(true)
		},
		collectGarbage: func() {
			events = append(events, "gc")
		},
		now: func() time.Time {
			next := times[0]
			times = times[1:]
			return next
		},
	})

	reloadDone := make(chan error, 1)
	go func() {
		reloadDone <- module.Reload("changed.yml")
	}()

	<-startEntered
	inFlight := module.stateSnapshot()
	if inFlight.config != initialConfig || inFlight.runtime != nil {
		t.Fatal("closed old runtime or candidate state was published during candidate Start")
	}
	if inFlight.status != panelReloadStatusReloading {
		t.Fatalf("in-flight status = %v, want reloading", inFlight.status)
	}
	if processApplied.Load() {
		t.Fatal("candidate process state published before Start completed")
	}

	close(startRelease)
	if err := <-reloadDone; err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	applied := module.stateSnapshot()
	if applied.config != candidateConfig || applied.runtime != candidateRuntime {
		t.Fatal("successful candidate was not published after Start")
	}
	if applied.status != panelReloadStatusReady || applied.failure != nil {
		t.Fatalf("successful state = status %v, failure %v; want ready without failure", applied.status, applied.failure)
	}
	if !processApplied.Load() {
		t.Fatal("successful candidate process state was not published")
	}
	wantEvents := []string{
		"load",
		"initial.close",
		"gc",
		"build-candidate",
		"candidate.start",
		"apply-process",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
}

func TestPanelReloadModuleRestoresLastKnownGoodAfterCandidateStartFailure(t *testing.T) {
	startErr := errors.New("start candidate")
	initialTime := time.Unix(600, 0)
	events := make([]string, 0, 8)
	initialConfig := reloadTestPanelConfig("initial")
	candidateConfig := reloadTestPanelConfig("candidate")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
	candidateRuntime := &reloadTestRuntime{name: "candidate", events: &events, startErr: startErr}
	restoredRuntime := &reloadTestRuntime{name: "restored", events: &events}
	var buildCalls int
	var processApplied atomic.Bool

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			events = append(events, "load")
			return candidateConfig, nil
		},
		buildRuntime: func(config *panel.Config) panelRuntime {
			buildCalls++
			switch buildCalls {
			case 1:
				if config != candidateConfig {
					t.Fatal("first build did not receive candidate config")
				}
				events = append(events, "build-candidate")
				return candidateRuntime
			case 2:
				if config != initialConfig {
					t.Fatal("restore build did not receive initial config")
				}
				events = append(events, "build-restore")
				return restoredRuntime
			default:
				t.Fatalf("unexpected build call %d", buildCalls)
				return nil
			}
		},
		applyProcessConfig: func(*panel.Config) {
			processApplied.Store(true)
		},
		collectGarbage: func() {
			events = append(events, "gc")
		},
		now: func() time.Time {
			return initialTime.Add(4 * time.Second)
		},
	})

	err := module.Reload("changed.yml")
	if !errors.Is(err, startErr) {
		t.Fatalf("Reload() error = %v, want candidate start error", err)
	}
	applied := module.stateSnapshot()
	if applied.config != initialConfig || applied.runtime != restoredRuntime {
		t.Fatal("candidate Start failure did not publish restored last-known-good runtime")
	}
	if applied.status != panelReloadStatusReady || applied.failure != nil {
		t.Fatalf("restored state = status %v, failure %v; want ready without failure", applied.status, applied.failure)
	}
	if processApplied.Load() {
		t.Fatal("candidate process state applied after candidate Start failure")
	}
	wantEvents := []string{
		"load",
		"initial.close",
		"gc",
		"build-candidate",
		"candidate.start",
		"candidate.close",
		"build-restore",
		"restored.start",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
}

func TestPanelReloadModuleCandidateCleanupFailureBlocksLastKnownGoodRestore(t *testing.T) {
	startErr := errors.New("start candidate")
	candidateCleanupErr := errors.New("cleanup candidate")
	initialTime := time.Unix(700, 0)
	events := make([]string, 0, 4)
	initialConfig := reloadTestPanelConfig("initial")
	candidateConfig := reloadTestPanelConfig("candidate")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
	candidateRuntime := &reloadTestRuntime{
		name:     "candidate",
		events:   &events,
		startErr: startErr,
		closeErr: candidateCleanupErr,
	}
	buildCalls := 0

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			return candidateConfig, nil
		},
		buildRuntime: func(config *panel.Config) panelRuntime {
			buildCalls++
			if buildCalls != 1 || config != candidateConfig {
				t.Fatalf("unexpected build call %d for config %p", buildCalls, config)
			}
			return candidateRuntime
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("candidate process state applied after failed Start")
		},
		collectGarbage: func() {
			events = append(events, "gc")
		},
		now: func() time.Time {
			return initialTime.Add(4 * time.Second)
		},
	})

	err := module.Reload("changed.yml")
	for _, wantErr := range []error{startErr, candidateCleanupErr} {
		if !errors.Is(err, wantErr) {
			t.Fatalf("Reload() error = %v, want joined error %v", err, wantErr)
		}
	}
	failed := module.stateSnapshot()
	if failed.config != initialConfig || failed.runtime != candidateRuntime || failed.status != panelReloadStatusFailedOwned {
		t.Fatalf("candidate cleanup failure state = config:%p runtime:%v status:%v", failed.config, failed.runtime, failed.status)
	}
	for _, wantErr := range []error{startErr, candidateCleanupErr} {
		if !errors.Is(failed.failure, wantErr) {
			t.Fatalf("stored failure = %v, want joined error %v", failed.failure, wantErr)
		}
	}
	if got, want := events, []string{"initial.close", "gc", "candidate.start", "candidate.close"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
	if err := module.Reload("again.yml"); !errors.Is(err, errPanelReloadFailedOwned) {
		t.Fatalf("second Reload() error = %v, want failed-owned rejection", err)
	}

	candidateRuntime.closeErr = nil
	if err := module.Close(); err != nil {
		t.Fatalf("Close() cleanup retry error = %v", err)
	}
}
func TestPanelReloadModuleRestoresLastKnownGoodWhenCandidateBuildReturnsNil(t *testing.T) {
	initialTime := time.Unix(750, 0)
	events := make([]string, 0, 3)
	initialConfig := reloadTestPanelConfig("initial")
	candidateConfig := reloadTestPanelConfig("candidate")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
	restoredRuntime := &reloadTestRuntime{name: "restored", events: &events}
	buildCalls := 0

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			return candidateConfig, nil
		},
		buildRuntime: func(config *panel.Config) panelRuntime {
			buildCalls++
			switch buildCalls {
			case 1:
				if config != candidateConfig {
					t.Fatal("candidate build received wrong config")
				}
				return nil
			case 2:
				if config != initialConfig {
					t.Fatal("restore build received wrong config")
				}
				return restoredRuntime
			default:
				t.Fatalf("unexpected build call %d", buildCalls)
				return nil
			}
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("candidate process state applied after nil build")
		},
		collectGarbage: func() {
			events = append(events, "gc")
		},
		now: func() time.Time {
			return initialTime.Add(4 * time.Second)
		},
	})

	if err := module.Reload("changed.yml"); err == nil {
		t.Fatal("Reload() error = nil, want candidate build error")
	}
	applied := module.stateSnapshot()
	if applied.config != initialConfig || applied.runtime != restoredRuntime || applied.status != panelReloadStatusReady {
		t.Fatalf("nil candidate build restore state = config:%p runtime:%v status:%v", applied.config, applied.runtime, applied.status)
	}
	if got, want := events, []string{"initial.close", "gc", "restored.start"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
}
func TestPanelReloadModuleOldCloseFailureDoesNotBuildCandidateOrRestore(t *testing.T) {
	closeErr := errors.New("close initial")
	initialTime := time.Unix(800, 0)
	events := make([]string, 0, 2)
	initialConfig := reloadTestPanelConfig("initial")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events, closeErr: closeErr}
	buildCalls := 0

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			return reloadTestPanelConfig("candidate"), nil
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			buildCalls++
			return &reloadTestRuntime{name: "candidate", events: &events}
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("candidate process state applied after old Close failure")
		},
		collectGarbage: func() {
			t.Fatal("garbage collection ran after old Close failure")
		},
		now: func() time.Time {
			return initialTime.Add(4 * time.Second)
		},
	})

	err := module.Reload("changed.yml")
	if !errors.Is(err, closeErr) {
		t.Fatalf("Reload() error = %v, want %v", err, closeErr)
	}
	applied := module.stateSnapshot()
	if applied.config != initialConfig || applied.runtime != initialRuntime || applied.status != panelReloadStatusFailedOwned {
		t.Fatalf("old Close failure state = config:%p runtime:%v status:%v", applied.config, applied.runtime, applied.status)
	}
	if buildCalls != 0 {
		t.Fatalf("runtime builds = %d, want 0", buildCalls)
	}
	if got, want := events, []string{"initial.close"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}

	initialRuntime.closeErr = nil
	if err := module.Close(); err != nil {
		t.Fatalf("Close() cleanup retry error = %v", err)
	}
}
func TestPanelReloadModuleSerializesConcurrentReloads(t *testing.T) {
	initialTime := time.Unix(900, 0)
	times := []time.Time{
		initialTime.Add(4 * time.Second),
		initialTime.Add(5 * time.Second),
		initialTime.Add(9 * time.Second),
		initialTime.Add(10 * time.Second),
	}
	events := make([]string, 0, 5)
	firstStartEntered := make(chan struct{})
	firstStartRelease := make(chan struct{})
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
	firstRuntime := &reloadTestRuntime{
		name:         "first",
		events:       &events,
		startEntered: firstStartEntered,
		startRelease: firstStartRelease,
	}
	secondRuntime := &reloadTestRuntime{name: "second", events: &events}
	attempted := make(chan panelReloadOperation, 2)
	var active atomic.Int32
	var maxActive atomic.Int32
	var loadCalls int

	module := newPanelReloadModule(reloadTestPanelConfig("initial"), initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			loadCalls++
			return reloadTestPanelConfig("candidate"), nil
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			if loadCalls == 1 {
				return firstRuntime
			}
			return secondRuntime
		},
		applyProcessConfig: func(*panel.Config) {},
		collectGarbage:     func() {},
		now: func() time.Time {
			next := times[0]
			times = times[1:]
			return next
		},
		observeOperation: func(operation panelReloadOperation, phase panelReloadOperationPhase) {
			switch phase {
			case panelReloadOperationAttempted:
				attempted <- operation
			case panelReloadOperationEntered:
				current := active.Add(1)
				for {
					observed := maxActive.Load()
					if current <= observed || maxActive.CompareAndSwap(observed, current) {
						break
					}
				}
			case panelReloadOperationExited:
				active.Add(-1)
			}
		},
	})

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- module.Reload("first.yml")
	}()
	if operation := <-attempted; operation != panelReloadOperationReload {
		t.Fatalf("first operation = %v, want reload", operation)
	}
	<-firstStartEntered

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- module.Reload("second.yml")
	}()
	if operation := <-attempted; operation != panelReloadOperationReload {
		t.Fatalf("second operation = %v, want reload", operation)
	}

	close(firstStartRelease)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Reload() error = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second Reload() error = %v", err)
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent reload operations = %d, want 1", got)
	}
	if module.stateSnapshot().runtime != secondRuntime {
		t.Fatal("second serialized reload was not the final applied runtime")
	}
}

func TestPanelReloadModuleSerializesCloseWithReload(t *testing.T) {
	initialTime := time.Unix(1000, 0)
	times := []time.Time{initialTime.Add(4 * time.Second), initialTime.Add(5 * time.Second)}
	events := make([]string, 0, 3)
	startEntered := make(chan struct{})
	startRelease := make(chan struct{})
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
	candidateRuntime := &reloadTestRuntime{
		name:         "candidate",
		events:       &events,
		startEntered: startEntered,
		startRelease: startRelease,
	}
	attempted := make(chan panelReloadOperation, 2)

	module := newPanelReloadModule(reloadTestPanelConfig("initial"), initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			return reloadTestPanelConfig("candidate"), nil
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			return candidateRuntime
		},
		applyProcessConfig: func(*panel.Config) {},
		collectGarbage:     func() {},
		now: func() time.Time {
			next := times[0]
			times = times[1:]
			return next
		},
		observeOperation: func(operation panelReloadOperation, phase panelReloadOperationPhase) {
			if phase == panelReloadOperationAttempted {
				attempted <- operation
			}
		},
	})

	reloadDone := make(chan error, 1)
	go func() {
		reloadDone <- module.Reload("changed.yml")
	}()
	if operation := <-attempted; operation != panelReloadOperationReload {
		t.Fatalf("first operation = %v, want reload", operation)
	}
	<-startEntered

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- module.Close()
	}()
	if operation := <-attempted; operation != panelReloadOperationClose {
		t.Fatalf("second operation = %v, want close", operation)
	}

	close(startRelease)
	if err := <-reloadDone; err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	wantEvents := []string{"initial.close", "candidate.start", "candidate.close"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	closed := module.stateSnapshot()
	if closed.runtime != nil {
		t.Fatal("Close() left a runtime published")
	}
	if closed.status != panelReloadStatusClosed {
		t.Fatalf("Close() status = %v, want closed", closed.status)
	}
}

func TestPanelReloadModuleCloseIsIdempotentAndRejectsReload(t *testing.T) {
	initialTime := time.Unix(1100, 0)
	events := make([]string, 0, 1)
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
	loadCalls := 0

	module := newPanelReloadModule(reloadTestPanelConfig("initial"), initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			loadCalls++
			return reloadTestPanelConfig("candidate"), nil
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			t.Fatal("buildRuntime called after Close")
			return nil
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("applyProcessConfig called after Close")
		},
		collectGarbage: func() {
			t.Fatal("collectGarbage called after Close")
		},
		now: func() time.Time {
			return initialTime.Add(4 * time.Second)
		},
	})

	if err := module.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := module.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err := module.Reload("changed.yml"); !errors.Is(err, errPanelReloadClosed) {
		t.Fatalf("Reload() error = %v, want errPanelReloadClosed", err)
	}
	if loadCalls != 0 {
		t.Fatalf("loadCandidate calls after Close = %d, want 0", loadCalls)
	}
	if got, want := events, []string{"initial.close"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
}
