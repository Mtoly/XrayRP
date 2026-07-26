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
	if inFlight.config != initialConfig || inFlight.runtime != initialRuntime {
		t.Fatal("candidate state published before Start completed")
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
		"build-candidate",
		"initial.close",
		"gc",
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
		"build-candidate",
		"initial.close",
		"gc",
		"candidate.start",
		"candidate.close",
		"build-restore",
		"restored.start",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
}

func TestPanelReloadModuleJoinsCandidateCleanupAndRestoreFailures(t *testing.T) {
	startErr := errors.New("start candidate")
	candidateCleanupErr := errors.New("cleanup candidate")
	restoreErr := errors.New("start restored")
	restoreCleanupErr := errors.New("cleanup restored")
	initialTime := time.Unix(700, 0)
	events := make([]string, 0, 9)
	initialConfig := reloadTestPanelConfig("initial")
	candidateConfig := reloadTestPanelConfig("candidate")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
	candidateRuntime := &reloadTestRuntime{
		name:     "candidate",
		events:   &events,
		startErr: startErr,
		closeErr: candidateCleanupErr,
	}
	restoredRuntime := &reloadTestRuntime{
		name:     "restored",
		events:   &events,
		startErr: restoreErr,
		closeErr: restoreCleanupErr,
	}
	buildCalls := 0

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			return candidateConfig, nil
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			buildCalls++
			if buildCalls == 1 {
				return candidateRuntime
			}
			return restoredRuntime
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("candidate process state applied after failed Start")
		},
		collectGarbage: func() {},
		now: func() time.Time {
			return initialTime.Add(4 * time.Second)
		},
	})

	err := module.Reload("changed.yml")
	for _, wantErr := range []error{startErr, candidateCleanupErr, restoreErr, restoreCleanupErr} {
		if !errors.Is(err, wantErr) {
			t.Fatalf("Reload() error = %v, want joined error %v", err, wantErr)
		}
	}
	failed := module.stateSnapshot()
	if failed.config != initialConfig || failed.runtime != nil {
		t.Fatal("restore failure claimed a runtime was applied")
	}
	if failed.status != panelReloadStatusFailed {
		t.Fatalf("restore failure status = %v, want failed", failed.status)
	}
	for _, wantErr := range []error{startErr, candidateCleanupErr, restoreErr, restoreCleanupErr} {
		if !errors.Is(failed.failure, wantErr) {
			t.Fatalf("stored failure = %v, want joined error %v", failed.failure, wantErr)
		}
	}
}

func TestPanelReloadModuleKeepsOldRuntimeWhenCandidateBuildReturnsNil(t *testing.T) {
	initialTime := time.Unix(750, 0)
	events := make([]string, 0)
	initialConfig := reloadTestPanelConfig("initial")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			return reloadTestPanelConfig("candidate"), nil
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			return nil
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("candidate process state applied after nil build")
		},
		collectGarbage: func() {
			t.Fatal("garbage collection ran before a runtime was replaced")
		},
		now: func() time.Time {
			return initialTime.Add(4 * time.Second)
		},
	})

	if err := module.Reload("changed.yml"); err == nil {
		t.Fatal("Reload() error = nil, want candidate build error")
	}
	applied := module.stateSnapshot()
	if applied.config != initialConfig || applied.runtime != initialRuntime {
		t.Fatal("nil candidate build changed the applied runtime")
	}
	if applied.status != panelReloadStatusReady || applied.failure != nil {
		t.Fatalf("state = status %v, failure %v; want unchanged ready state", applied.status, applied.failure)
	}
	if len(events) != 0 {
		t.Fatalf("nil candidate build produced lifecycle events: %#v", events)
	}
}

func TestPanelReloadModuleRestoresOldRuntimeAfterCloseFailure(t *testing.T) {
	closeErr := errors.New("close initial")
	candidateCleanupErr := errors.New("cleanup candidate")
	initialTime := time.Unix(800, 0)
	events := make([]string, 0, 6)
	initialConfig := reloadTestPanelConfig("initial")
	candidateConfig := reloadTestPanelConfig("candidate")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events, closeErr: closeErr}
	candidateRuntime := &reloadTestRuntime{name: "candidate", events: &events, closeErr: candidateCleanupErr}
	restoredRuntime := &reloadTestRuntime{name: "restored", events: &events}
	buildCalls := 0

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			return candidateConfig, nil
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			buildCalls++
			if buildCalls == 1 {
				events = append(events, "build-candidate")
				return candidateRuntime
			}
			events = append(events, "build-restore")
			return restoredRuntime
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("candidate process state applied after old Close failure")
		},
		collectGarbage: func() {},
		now: func() time.Time {
			return initialTime.Add(4 * time.Second)
		},
	})

	err := module.Reload("changed.yml")
	for _, wantErr := range []error{closeErr, candidateCleanupErr} {
		if !errors.Is(err, wantErr) {
			t.Fatalf("Reload() error = %v, want joined error %v", err, wantErr)
		}
	}
	applied := module.stateSnapshot()
	if applied.config != initialConfig || applied.runtime != restoredRuntime {
		t.Fatal("old Close failure did not retain restored last-known-good state")
	}
	if applied.status != panelReloadStatusReady || applied.failure != nil {
		t.Fatalf("restored state = status %v, failure %v; want ready without failure", applied.status, applied.failure)
	}
	wantEvents := []string{
		"build-candidate",
		"initial.close",
		"candidate.close",
		"build-restore",
		"restored.start",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
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
