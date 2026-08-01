package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/panel"
)

type reloadTestRuntime struct {
	name         string
	events       *[]string
	startErr     error
	closeErr     error
	startEntered chan struct{}
	startRelease <-chan struct{}
}

func (r *reloadTestRuntime) Start() error {
	*r.events = append(*r.events, r.name+".start")
	if r.startEntered != nil {
		close(r.startEntered)
	}
	if r.startRelease != nil {
		<-r.startRelease
	}
	return r.startErr
}

func (r *reloadTestRuntime) Close() error {
	*r.events = append(*r.events, r.name+".close")
	return r.closeErr
}

type deadlineReloadRuntime struct {
	name          string
	events        *[]string
	waitStart     bool
	waitClose     bool
	startDeadline chan bool
	closeDeadline chan bool
}

func (r *deadlineReloadRuntime) Start() error {
	return r.StartContext(context.Background())
}

func (r *deadlineReloadRuntime) StartContext(ctx context.Context) error {
	*r.events = append(*r.events, r.name+".start")
	_, hasDeadline := ctx.Deadline()
	if r.startDeadline != nil {
		r.startDeadline <- hasDeadline
	}
	if r.waitStart {
		<-ctx.Done()
		return ctx.Err()
	}
	return ctx.Err()
}

func (r *deadlineReloadRuntime) Close() error {
	return r.CloseContext(context.Background())
}

func (r *deadlineReloadRuntime) CloseContext(ctx context.Context) error {
	*r.events = append(*r.events, r.name+".close")
	_, hasDeadline := ctx.Deadline()
	if r.closeDeadline != nil {
		r.closeDeadline <- hasDeadline
	}
	if r.waitClose {
		<-ctx.Done()
		return ctx.Err()
	}
	return ctx.Err()
}

func TestPanelReloadContextPropagatesStartDeadlineAndRestoresLastKnownGood(t *testing.T) {
	initialTime := time.Unix(425, 0)
	events := make([]string, 0, 4)
	initialConfig := reloadTestPanelConfig("initial")
	candidateConfig := reloadTestPanelConfig("candidate")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
	candidateRuntime := &deadlineReloadRuntime{
		name:          "candidate",
		events:        &events,
		waitStart:     true,
		startDeadline: make(chan bool, 1),
		closeDeadline: make(chan bool, 1),
	}
	restoredRuntime := &deadlineReloadRuntime{name: "restored", events: &events}
	buildCalls := 0
	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			return candidateConfig, nil
		},
		buildRuntime: func(config *panel.Config) panelRuntime {
			buildCalls++
			if buildCalls == 1 {
				return candidateRuntime
			}
			if config != initialConfig {
				t.Fatal("restore used a non-LKG config")
			}
			return restoredRuntime
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("canceled candidate process config was published")
		},
		collectGarbage: func() {},
		now:            func() time.Time { return initialTime.Add(4 * time.Second) },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := module.ReloadContext(ctx, "changed.yml"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReloadContext() error = %v, want deadline exceeded", err)
	}
	if hasDeadline := <-candidateRuntime.startDeadline; !hasDeadline {
		t.Fatal("candidate StartContext did not receive a deadline")
	}
	if hasDeadline := <-candidateRuntime.closeDeadline; !hasDeadline {
		t.Fatal("candidate cleanup CloseContext did not receive a deadline")
	}
	state := module.stateSnapshot()
	if state.status != panelReloadStatusReady || state.config != initialConfig || state.runtime != restoredRuntime {
		t.Fatalf("deadline restore state = status:%v config:%p runtime:%v", state.status, state.config, state.runtime)
	}
}

func TestPanelReloadCloseContextPropagatesDeadlineAndRetainsOwnership(t *testing.T) {
	initialTime := time.Unix(450, 0)
	events := make([]string, 0, 2)
	runtime := &deadlineReloadRuntime{
		name:          "initial",
		events:        &events,
		waitClose:     true,
		closeDeadline: make(chan bool, 2),
	}
	module := newPanelReloadModule(reloadTestPanelConfig("initial"), runtime, panelReloadOptions{
		lastAppliedAt: initialTime,
		now:           func() time.Time { return initialTime },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := module.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext() error = %v, want deadline exceeded", err)
	}
	if hasDeadline := <-runtime.closeDeadline; !hasDeadline {
		t.Fatal("runtime CloseContext did not receive a deadline")
	}
	state := module.stateSnapshot()
	if state.status != panelReloadStatusFailedOwned || state.runtime != runtime {
		t.Fatalf("deadline close lost ownership: status=%v runtime=%v", state.status, state.runtime)
	}

	runtime.waitClose = false
	if err := module.Close(); err != nil {
		t.Fatalf("Close() cleanup retry error = %v", err)
	}
}

func TestPanelReloadModuleKeepsAppliedRuntimeOnCandidateLoadFailure(t *testing.T) {
	loadErr := errors.New("read candidate")
	initialTime := time.Unix(100, 0)
	events := make([]string, 0)
	initialConfig := reloadTestPanelConfig("initial")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		configFile:    "config.yml",
		lastAppliedAt: initialTime,
		loadCandidate: func(eventName, configuredFile string) (*panel.Config, error) {
			events = append(events, "load:"+eventName+":"+configuredFile)
			return nil, loadErr
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			t.Fatal("buildRuntime called after candidate load failure")
			return nil
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("applyProcessConfig called after candidate load failure")
		},
		collectGarbage: func() {
			t.Fatal("collectGarbage called after candidate load failure")
		},
		now: func() time.Time {
			return initialTime.Add(4 * time.Second)
		},
	})

	err := module.Reload("changed.yml")
	if !errors.Is(err, loadErr) {
		t.Fatalf("Reload() error = %v, want wrapped load error", err)
	}
	if got, want := events, []string{"load:changed.yml:config.yml"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
	if module.applied.config != initialConfig || module.applied.runtime != initialRuntime {
		t.Fatal("candidate load failure changed applied state")
	}
	if !module.lastAppliedAt.Equal(initialTime) {
		t.Fatalf("lastAppliedAt = %s, want %s", module.lastAppliedAt, initialTime)
	}
}

func TestPanelReloadModuleKeepsAppliedRuntimeOnEmptyCandidate(t *testing.T) {
	initialTime := time.Unix(200, 0)
	events := make([]string, 0)
	initialConfig := reloadTestPanelConfig("initial")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			events = append(events, "load")
			return &panel.Config{}, nil
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			t.Fatal("buildRuntime called for empty candidate")
			return nil
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("applyProcessConfig called for empty candidate")
		},
		collectGarbage: func() {
			t.Fatal("collectGarbage called for empty candidate")
		},
		now: func() time.Time {
			return initialTime.Add(4 * time.Second)
		},
	})

	err := module.Reload("changed.yml")
	if !errors.Is(err, errPanelReloadEmptyNodes) {
		t.Fatalf("Reload() error = %v, want errPanelReloadEmptyNodes", err)
	}
	if got, want := events, []string{"load"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
	if module.applied.config != initialConfig || module.applied.runtime != initialRuntime {
		t.Fatal("empty candidate changed applied state")
	}
	if !module.lastAppliedAt.Equal(initialTime) {
		t.Fatalf("lastAppliedAt = %s, want %s", module.lastAppliedAt, initialTime)
	}
}

func TestPanelReloadModuleSupportsSameModeReloads(t *testing.T) {
	tests := []struct {
		name      string
		initial   *panel.Config
		candidate *panel.Config
	}{
		{
			name:      "static to static",
			initial:   reloadStaticTestPanelConfig("initial"),
			candidate: reloadStaticTestPanelConfig("candidate"),
		},
		{
			name:      "machine to machine with empty nodes",
			initial:   reloadMachineTestPanelConfig("initial"),
			candidate: reloadMachineTestPanelConfig("candidate"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initialTime := time.Unix(225, 0)
			events := make([]string, 0, 2)
			initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
			candidateRuntime := &reloadTestRuntime{name: "candidate", events: &events}
			module := newPanelReloadModule(tt.initial, initialRuntime, panelReloadOptions{
				lastAppliedAt: initialTime,
				loadCandidate: func(string, string) (*panel.Config, error) {
					return tt.candidate, nil
				},
				buildRuntime: func(config *panel.Config) panelRuntime {
					if config != tt.candidate {
						t.Fatal("buildRuntime received non-candidate config")
					}
					return candidateRuntime
				},
				applyProcessConfig: func(*panel.Config) {},
				collectGarbage:     func() {},
				now:                func() time.Time { return initialTime.Add(4 * time.Second) },
			})

			if err := module.Reload("changed.yml"); err != nil {
				t.Fatalf("Reload() error = %v", err)
			}
			state := module.stateSnapshot()
			if state.config != tt.candidate || state.runtime != candidateRuntime || state.status != panelReloadStatusReady {
				t.Fatalf("applied state = config:%p runtime:%v status:%v", state.config, state.runtime, state.status)
			}
			if got, want := events, []string{"initial.close", "candidate.start"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("events = %#v, want %#v", got, want)
			}
		})
	}
}

func TestPanelReloadModuleRestoresLastKnownGoodForSameModeStartFailures(t *testing.T) {
	startErr := errors.New("start candidate")
	tests := []struct {
		name      string
		initial   *panel.Config
		candidate *panel.Config
	}{
		{
			name:      "static to static",
			initial:   reloadStaticTestPanelConfig("initial"),
			candidate: reloadStaticTestPanelConfig("candidate"),
		},
		{
			name:      "machine to machine",
			initial:   reloadMachineTestPanelConfig("initial"),
			candidate: reloadMachineTestPanelConfig("candidate"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initialTime := time.Unix(235, 0)
			events := make([]string, 0, 4)
			initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
			candidateRuntime := &reloadTestRuntime{name: "candidate", events: &events, startErr: startErr}
			restoredRuntime := &reloadTestRuntime{name: "restored", events: &events}
			buildCalls := 0
			module := newPanelReloadModule(tt.initial, initialRuntime, panelReloadOptions{
				lastAppliedAt: initialTime,
				loadCandidate: func(string, string) (*panel.Config, error) {
					return tt.candidate, nil
				},
				buildRuntime: func(config *panel.Config) panelRuntime {
					buildCalls++
					if buildCalls == 1 {
						if config != tt.candidate {
							t.Fatal("candidate build received wrong config")
						}
						return candidateRuntime
					}
					if config != tt.initial {
						t.Fatal("restore build received non-LKG config")
					}
					return restoredRuntime
				},
				applyProcessConfig: func(*panel.Config) {
					t.Fatal("failed candidate process config was published")
				},
				collectGarbage: func() {},
				now:            func() time.Time { return initialTime.Add(4 * time.Second) },
			})

			if err := module.Reload("changed.yml"); !errors.Is(err, startErr) {
				t.Fatalf("Reload() error = %v, want %v", err, startErr)
			}
			state := module.stateSnapshot()
			if state.config != tt.initial || state.runtime != restoredRuntime || state.status != panelReloadStatusReady {
				t.Fatalf("LKG state = config:%p runtime:%v status:%v", state.config, state.runtime, state.status)
			}
			wantEvents := []string{"initial.close", "candidate.start", "candidate.close", "restored.start"}
			if !reflect.DeepEqual(events, wantEvents) {
				t.Fatalf("events = %#v, want %#v", events, wantEvents)
			}
		})
	}
}

func TestPanelReloadModuleRejectsModeChangesBeforeClosingCurrentRuntime(t *testing.T) {
	tests := []struct {
		name      string
		initial   *panel.Config
		candidate *panel.Config
	}{
		{
			name:      "static to machine",
			initial:   reloadStaticTestPanelConfig("initial"),
			candidate: reloadMachineTestPanelConfig("candidate"),
		},
		{
			name:      "machine to static",
			initial:   reloadMachineTestPanelConfig("initial"),
			candidate: reloadStaticTestPanelConfig("candidate"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initialTime := time.Unix(245, 0)
			events := make([]string, 0)
			initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
			module := newPanelReloadModule(tt.initial, initialRuntime, panelReloadOptions{
				lastAppliedAt: initialTime,
				loadCandidate: func(string, string) (*panel.Config, error) {
					return tt.candidate, nil
				},
				buildRuntime: func(*panel.Config) panelRuntime {
					t.Fatal("buildRuntime called for unsupported mode change")
					return nil
				},
				applyProcessConfig: func(*panel.Config) {
					t.Fatal("mode-changing process config was published")
				},
				collectGarbage: func() {
					t.Fatal("garbage collection ran for unsupported mode change")
				},
				now: func() time.Time { return initialTime.Add(4 * time.Second) },
			})

			if err := module.Reload("changed.yml"); !errors.Is(err, panel.ErrRuntimeConfigModeChange) {
				t.Fatalf("Reload() error = %v, want %v", err, panel.ErrRuntimeConfigModeChange)
			}
			state := module.stateSnapshot()
			if state.config != tt.initial || state.runtime != initialRuntime || state.status != panelReloadStatusReady {
				t.Fatalf("mode rejection changed LKG state = config:%p runtime:%v status:%v", state.config, state.runtime, state.status)
			}
			if len(events) != 0 {
				t.Fatalf("mode rejection touched current runtime: %#v", events)
			}
		})
	}
}

func TestPanelReloadModuleRejectsNilCandidate(t *testing.T) {
	initialTime := time.Unix(250, 0)
	events := make([]string, 0)
	initialConfig := reloadTestPanelConfig("initial")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			return nil, nil
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			t.Fatal("buildRuntime called for nil candidate")
			return nil
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("applyProcessConfig called for nil candidate")
		},
		collectGarbage: func() {
			t.Fatal("collectGarbage called for nil candidate")
		},
		now: func() time.Time {
			return initialTime.Add(4 * time.Second)
		},
	})

	err := module.Reload("changed.yml")
	if err == nil {
		t.Fatal("Reload() error = nil, want nil candidate error")
	}
	if module.applied.config != initialConfig || module.applied.runtime != initialRuntime {
		t.Fatal("nil candidate changed applied state")
	}
	if len(events) != 0 {
		t.Fatalf("nil candidate produced lifecycle events: %#v", events)
	}
}

func TestPanelReloadModulePreservesSuccessfulReloadOrder(t *testing.T) {
	initialTime := time.Unix(300, 0)
	commitTime := initialTime.Add(5 * time.Second)
	times := []time.Time{initialTime.Add(4 * time.Second), commitTime}
	events := make([]string, 0, 6)
	initialConfig := reloadTestPanelConfig("initial")
	candidateConfig := reloadTestPanelConfig("candidate")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
	candidateRuntime := &reloadTestRuntime{name: "candidate", events: &events}

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		configFile:    "config.yml",
		lastAppliedAt: initialTime,
		loadCandidate: func(eventName, configuredFile string) (*panel.Config, error) {
			events = append(events, "load:"+eventName+":"+configuredFile)
			return candidateConfig, nil
		},
		buildRuntime: func(config *panel.Config) panelRuntime {
			if config != candidateConfig {
				t.Fatal("buildRuntime received the wrong candidate config")
			}
			events = append(events, "build")
			return candidateRuntime
		},
		applyProcessConfig: func(config *panel.Config) {
			if config != candidateConfig {
				t.Fatal("applyProcessConfig received the wrong candidate config")
			}
			events = append(events, "apply-process")
		},
		collectGarbage: func() {
			events = append(events, "gc")
		},
		now: func() time.Time {
			if len(times) == 0 {
				t.Fatal("now called more times than expected")
			}
			next := times[0]
			times = times[1:]
			return next
		},
	})

	if err := module.Reload("changed.yml"); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	wantEvents := []string{
		"load:changed.yml:config.yml",
		"initial.close",
		"gc",
		"build",
		"candidate.start",
		"apply-process",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	if module.applied.config != candidateConfig || module.applied.runtime != candidateRuntime {
		t.Fatal("successful reload did not publish the candidate state")
	}
	if !module.lastAppliedAt.Equal(commitTime) {
		t.Fatalf("lastAppliedAt = %s, want %s", module.lastAppliedAt, commitTime)
	}
}

func TestPanelReloadModuleOldCloseFailureRetainsRuntimeAndBlocksReload(t *testing.T) {
	closeErr := errors.New("close initial")
	initialTime := time.Unix(350, 0)
	events := make([]string, 0, 2)
	initialConfig := reloadTestPanelConfig("initial")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events, closeErr: closeErr}
	loadCalls := 0
	buildCalls := 0

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			loadCalls++
			return reloadTestPanelConfig("candidate"), nil
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			buildCalls++
			return &reloadTestRuntime{name: "candidate", events: &events}
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("candidate process config applied after old Close failure")
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
		t.Fatalf("Reload() error = %v, want wrapped close error", err)
	}
	failed := module.stateSnapshot()
	if failed.config != initialConfig || failed.runtime != initialRuntime || failed.status != panelReloadStatusFailedOwned {
		t.Fatalf("old Close failure state = config:%p runtime:%v status:%v", failed.config, failed.runtime, failed.status)
	}
	if buildCalls != 0 {
		t.Fatalf("candidate builds = %d, want 0 before old runtime release", buildCalls)
	}
	if err := module.Reload("again.yml"); !errors.Is(err, errPanelReloadFailedOwned) {
		t.Fatalf("second Reload() error = %v, want failed-owned rejection", err)
	}
	if loadCalls != 1 || buildCalls != 0 {
		t.Fatalf("failed-owned Reload performed work: loads=%d builds=%d", loadCalls, buildCalls)
	}

	initialRuntime.closeErr = nil
	if err := module.Close(); err != nil {
		t.Fatalf("Close() cleanup retry error = %v", err)
	}
	closed := module.stateSnapshot()
	if closed.status != panelReloadStatusClosed || closed.runtime != nil {
		t.Fatalf("cleanup retry state = runtime:%v status:%v", closed.runtime, closed.status)
	}
	if got, want := events, []string{"initial.close", "initial.close"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
}
func TestPanelReloadModuleCloseClosesCurrentRuntime(t *testing.T) {
	initialTime := time.Unix(375, 0)
	times := []time.Time{initialTime.Add(4 * time.Second), initialTime.Add(5 * time.Second)}
	events := make([]string, 0, 4)
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
	candidateRuntime := &reloadTestRuntime{name: "candidate", events: &events}

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
	})

	if err := module.Reload("changed.yml"); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if err := module.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got, want := events, []string{"initial.close", "candidate.start", "candidate.close"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
}

func TestPanelReloadModuleDoesNotAdvanceDebounceAfterStartFailure(t *testing.T) {
	startErr := errors.New("start candidate")
	initialTime := time.Unix(390, 0)
	events := make([]string, 0, 2)
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}
	candidateRuntime := &reloadTestRuntime{name: "candidate", events: &events, startErr: startErr}
	restoredRuntime := &reloadTestRuntime{name: "restored", events: &events}
	buildCalls := 0

	module := newPanelReloadModule(reloadTestPanelConfig("initial"), initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			return reloadTestPanelConfig("candidate"), nil
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			buildCalls++
			if buildCalls == 1 {
				return candidateRuntime
			}
			return restoredRuntime
		},
		applyProcessConfig: func(*panel.Config) {},
		collectGarbage:     func() {},
		now: func() time.Time {
			return initialTime.Add(4 * time.Second)
		},
	})

	err := module.Reload("changed.yml")
	if !errors.Is(err, startErr) {
		t.Fatalf("Reload() error = %v, want wrapped start error", err)
	}
	if !module.lastAppliedAt.Equal(initialTime) {
		t.Fatalf("lastAppliedAt = %s, want unchanged %s", module.lastAppliedAt, initialTime)
	}
}

func TestPanelReloadModuleDebouncesBeforeLoadingCandidate(t *testing.T) {
	initialTime := time.Unix(400, 0)
	events := make([]string, 0)
	initialConfig := reloadTestPanelConfig("initial")
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events}

	module := newPanelReloadModule(initialConfig, initialRuntime, panelReloadOptions{
		lastAppliedAt: initialTime,
		loadCandidate: func(string, string) (*panel.Config, error) {
			t.Fatal("loadCandidate called inside debounce interval")
			return nil, nil
		},
		buildRuntime: func(*panel.Config) panelRuntime {
			t.Fatal("buildRuntime called inside debounce interval")
			return nil
		},
		applyProcessConfig: func(*panel.Config) {
			t.Fatal("applyProcessConfig called inside debounce interval")
		},
		collectGarbage: func() {
			t.Fatal("collectGarbage called inside debounce interval")
		},
		now: func() time.Time {
			return initialTime.Add(3 * time.Second)
		},
	})

	if err := module.Reload("changed.yml"); err != nil {
		t.Fatalf("Reload() error = %v, want nil for a debounced event", err)
	}
	if len(events) != 0 {
		t.Fatalf("debounced reload produced events: %#v", events)
	}
	if module.applied.config != initialConfig || module.applied.runtime != initialRuntime {
		t.Fatal("debounced reload changed applied state")
	}
}

func TestLoadPanelReloadCandidateReportsReadFailure(t *testing.T) {
	missingFile := filepath.Join(t.TempDir(), "missing.yml")

	_, err := loadPanelReloadCandidate(missingFile, "")
	if err == nil {
		t.Fatal("loadPanelReloadCandidate() error = nil, want read error")
	}
	if !strings.Contains(err.Error(), "failed to read new config file") {
		t.Fatalf("loadPanelReloadCandidate() error = %q, want read classification", err)
	}
}

func TestLoadPanelReloadCandidateReportsParseFailure(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "invalid.yml")
	configData := []byte("Nodes:\n  - PanelType:\n      nested: value\n")
	if err := os.WriteFile(configFile, configData, 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}

	_, err := loadPanelReloadCandidate(configFile, "")
	if err == nil {
		t.Fatal("loadPanelReloadCandidate() error = nil, want parse error")
	}
	if !strings.Contains(err.Error(), "failed to parse new config file") {
		t.Fatalf("loadPanelReloadCandidate() error = %q, want parse classification", err)
	}
}

func reloadTestPanelConfig(name string) *panel.Config {
	return reloadStaticTestPanelConfig(name)
}

func reloadStaticTestPanelConfig(name string) *panel.Config {
	return &panel.Config{
		NodesConfig: []*panel.NodesConfig{{
			PanelType: "SSPanel",
			ApiConfig: &api.Config{
				APIHost:  "https://" + name + ".example.com",
				NodeType: "Vless",
			},
		}},
	}
}

func reloadMachineTestPanelConfig(name string) *panel.Config {
	return &panel.Config{
		MachineConfig: &panel.MachineConfig{
			Enable:    true,
			PanelType: "NewV2board",
			ApiHost:   "https://" + name + ".example.com",
			MachineID: 7,
			Token:     name + "-token",
		},
	}
}
