package cmd

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/panel"
	"github.com/Mtoly/XrayRP/service"
)

type reloadObservationClock struct {
	times []time.Time
	last  time.Time
}

func (c *reloadObservationClock) Now() time.Time {
	if len(c.times) != 0 {
		c.last = c.times[0]
		c.times = c.times[1:]
	}
	return c.last
}

func TestPanelReloadObservabilityMeasuresSuccessfulPhasesAndInterruption(t *testing.T) {
	base := time.Unix(2000, 0)
	clock := &reloadObservationClock{times: []time.Time{
		base,
		base.Add(100 * time.Millisecond),
		base.Add(300 * time.Millisecond),
		base.Add(350 * time.Millisecond),
		base.Add(500 * time.Millisecond),
	}}
	events := make([]string, 0, 2)
	initialConfig := reloadTestPanelConfig("initial")
	candidateConfig := reloadTestPanelConfig("candidate")
	module := newPanelReloadModule(initialConfig, &reloadTestRuntime{name: "initial", events: &events}, panelReloadOptions{
		lastAppliedAt: initialTimeForReloadObservation(base),
		loadCandidate: func(string, string) (*panel.Config, error) {
			return candidateConfig, nil
		},
		validateCandidate: func(*panel.Config, *panel.Config) error { return nil },
		buildRuntime: func(config *panel.Config) panelRuntime {
			if config != candidateConfig {
				t.Fatalf("buildRuntime received config %p, want candidate %p", config, candidateConfig)
			}
			return &reloadTestRuntime{name: "candidate", events: &events}
		},
		applyProcessConfig: func(*panel.Config) {},
		collectGarbage:     func() {},
		now:                func() time.Time { return base.Add(4 * time.Second) },
		reloadClock:        clock.Now,
	})

	if err := module.Reload("changed.yml"); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	got := module.ObservabilitySnapshot().Reload
	want := service.ReloadSnapshot{
		Phase:                    service.ReloadPhaseNone,
		Attempts:                 1,
		Successes:                1,
		LastCandidateDuration:    100 * time.Millisecond,
		LastStopDuration:         200 * time.Millisecond,
		LastStartDuration:        50 * time.Millisecond,
		LastCommitDuration:       150 * time.Millisecond,
		LastInterruptionDuration: 400 * time.Millisecond,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reload observability = %#v, want %#v", got, want)
	}
}

func TestPanelReloadObservabilityReportsActiveStartPhase(t *testing.T) {
	base := time.Unix(2050, 0)
	clock := &reloadObservationClock{times: []time.Time{base}}
	startEntered := make(chan struct{})
	startRelease := make(chan struct{})
	events := make([]string, 0, 2)
	initialConfig := reloadTestPanelConfig("initial")
	candidateConfig := reloadTestPanelConfig("candidate")
	module := newPanelReloadModule(initialConfig, &reloadTestRuntime{name: "initial", events: &events}, panelReloadOptions{
		lastAppliedAt: initialTimeForReloadObservation(base),
		loadCandidate: func(string, string) (*panel.Config, error) { return candidateConfig, nil },
		validateCandidate: func(*panel.Config, *panel.Config) error {
			return nil
		},
		buildRuntime: func(config *panel.Config) panelRuntime {
			if config != candidateConfig {
				t.Fatalf("buildRuntime received config %p, want %p", config, candidateConfig)
			}
			return &reloadTestRuntime{
				name:         "candidate",
				events:       &events,
				startEntered: startEntered,
				startRelease: startRelease,
			}
		},
		applyProcessConfig: func(*panel.Config) {},
		collectGarbage:     func() {},
		now:                func() time.Time { return base.Add(4 * time.Second) },
		reloadClock:        clock.Now,
	})

	done := make(chan error, 1)
	go func() { done <- module.Reload("changed.yml") }()
	<-startEntered
	if got := module.ObservabilitySnapshot().Reload.Phase; got != service.ReloadPhaseStart {
		t.Fatalf("active reload phase = %q, want %q", got, service.ReloadPhaseStart)
	}
	close(startRelease)
	if err := <-done; err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
}

func TestPanelReloadObservabilityMeasuresRollbackAndKeepsLastKnownGood(t *testing.T) {
	base := time.Unix(2100, 0)
	clock := &reloadObservationClock{times: []time.Time{
		base,
		base.Add(100 * time.Millisecond),
		base.Add(300 * time.Millisecond),
		base.Add(350 * time.Millisecond),
		base.Add(800 * time.Millisecond),
	}}
	startErr := errors.New("candidate start")
	events := make([]string, 0, 4)
	initialConfig := reloadTestPanelConfig("initial")
	candidateConfig := reloadTestPanelConfig("candidate")
	restoredRuntime := &reloadTestRuntime{name: "restored", events: &events}
	buildCalls := 0
	module := newPanelReloadModule(initialConfig, &reloadTestRuntime{name: "initial", events: &events}, panelReloadOptions{
		lastAppliedAt: initialTimeForReloadObservation(base),
		loadCandidate: func(string, string) (*panel.Config, error) { return candidateConfig, nil },
		validateCandidate: func(*panel.Config, *panel.Config) error {
			return nil
		},
		buildRuntime: func(config *panel.Config) panelRuntime {
			buildCalls++
			if buildCalls == 1 {
				if config != candidateConfig {
					t.Fatalf("candidate build received config %p, want %p", config, candidateConfig)
				}
				return &reloadTestRuntime{name: "candidate", events: &events, startErr: startErr}
			}
			if config != initialConfig {
				t.Fatalf("restore build received config %p, want %p", config, initialConfig)
			}
			return restoredRuntime
		},
		applyProcessConfig: func(*panel.Config) { t.Fatal("failed candidate process config was applied") },
		collectGarbage:     func() {},
		now:                func() time.Time { return base.Add(4 * time.Second) },
		reloadClock:        clock.Now,
	})

	if err := module.Reload("changed.yml"); !errors.Is(err, startErr) {
		t.Fatalf("Reload() error = %v, want %v", err, startErr)
	}
	state := module.stateSnapshot()
	if state.config != initialConfig || state.runtime != restoredRuntime || state.status != panelReloadStatusReady {
		t.Fatalf("last-known-good state = config:%p runtime:%v status:%v", state.config, state.runtime, state.status)
	}

	got := module.ObservabilitySnapshot().Reload
	want := service.ReloadSnapshot{
		Phase:                    service.ReloadPhaseNone,
		Attempts:                 1,
		Failures:                 1,
		LastCandidateDuration:    100 * time.Millisecond,
		LastStopDuration:         200 * time.Millisecond,
		LastStartDuration:        50 * time.Millisecond,
		LastRollbackDuration:     450 * time.Millisecond,
		LastInterruptionDuration: 700 * time.Millisecond,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reload rollback observability = %#v, want %#v", got, want)
	}
}

func initialTimeForReloadObservation(base time.Time) time.Time {
	return base.Add(-time.Hour)
}
