package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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
		"build",
		"initial.close",
		"gc",
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

func TestPanelReloadModuleReportsCloseErrorAfterRestoringOldRuntime(t *testing.T) {
	closeErr := errors.New("close initial")
	initialTime := time.Unix(350, 0)
	events := make([]string, 0, 3)
	initialRuntime := &reloadTestRuntime{name: "initial", events: &events, closeErr: closeErr}
	candidateRuntime := &reloadTestRuntime{name: "candidate", events: &events}
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
	if !errors.Is(err, closeErr) {
		t.Fatalf("Reload() error = %v, want wrapped close error", err)
	}
	if module.applied.runtime != restoredRuntime {
		t.Fatal("old Close error did not publish restored runtime")
	}
	if got, want := events, []string{"initial.close", "candidate.close", "restored.start"}; !reflect.DeepEqual(got, want) {
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
	return &panel.Config{
		NodesConfig: []*panel.NodesConfig{{
			PanelType: name,
		}},
	}
}
