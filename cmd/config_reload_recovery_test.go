package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/panel"
)

type reloadRecoverySteps struct {
	waiting chan struct{}
	release chan struct{}
}

func newReloadRecoverySteps() reloadRecoverySteps {
	return reloadRecoverySteps{waiting: make(chan struct{}), release: make(chan struct{})}
}

func (s reloadRecoverySteps) wait(ctx context.Context, _ time.Duration) error {
	select {
	case s.waiting <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s reloadRecoverySteps) awaitWaiting(t *testing.T) {
	t.Helper()
	select {
	case <-s.waiting:
	case <-time.After(2 * time.Second):
		t.Fatal("recovery did not wait for its retry delay")
	}
}

func awaitPanelReloadRecoveryExit(t *testing.T, module *panelReloadModule) {
	t.Helper()
	module.recoveryMu.Lock()
	done := module.recoveryDone
	module.recoveryMu.Unlock()
	if done == nil {
		t.Fatal("no recovery was started")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("recovery did not exit")
	}
}

// newDoubleFailureReloadModule fails the candidate start and the first
// last-known-good restore; later builds come from next.
func newDoubleFailureReloadModule(t *testing.T, steps reloadRecoverySteps, next func(*panel.Config) panelRuntime) (*panelReloadModule, *panel.Config) {
	t.Helper()
	startErr := errors.New("panel unavailable")
	events := make([]string, 0, 16)
	initialConfig := reloadTestPanelConfig("initial")
	candidateConfig := reloadTestPanelConfig("candidate")
	var buildCalls int
	module := newPanelReloadModule(initialConfig, &reloadTestRuntime{name: "initial", events: &events}, panelReloadOptions{
		lastAppliedAt: time.Unix(600, 0),
		loadCandidate: func(string, string) (*panel.Config, error) {
			return candidateConfig, nil
		},
		buildRuntime: func(config *panel.Config) panelRuntime {
			buildCalls++
			switch buildCalls {
			case 1:
				return &reloadTestRuntime{name: "candidate", events: &events, startErr: startErr}
			case 2:
				if config != initialConfig {
					t.Errorf("restore build config = %v, want initial config", config)
				}
				return &reloadTestRuntime{name: "restore-1", events: &events, startErr: startErr}
			default:
				return next(config)
			}
		},
		applyProcessConfig: func(*panel.Config) {},
		collectGarbage:     func() {},
		now:                func() time.Time { return time.Unix(700, 0) },
		waitRecovery:       steps.wait,
	})

	if err := module.Reload("changed.yml"); !errors.Is(err, startErr) {
		t.Fatalf("Reload() error = %v, want %v", err, startErr)
	}
	if state := module.stateSnapshot(); state.status != panelReloadStatusFailed || state.runtime != nil {
		t.Fatalf("state after double failure = status %v runtime %v, want failed without runtime", state.status, state.runtime)
	}
	return module, initialConfig
}

func TestPanelReloadModuleRetriesLastKnownGoodAfterRestoreFailure(t *testing.T) {
	steps := newReloadRecoverySteps()
	var restored *reloadTestRuntime
	var restoredConfig *panel.Config
	module, initialConfig := newDoubleFailureReloadModule(t, steps, func(config *panel.Config) panelRuntime {
		restoredConfig = config
		restored = &reloadTestRuntime{name: "restore-2", events: new([]string)}
		return restored
	})
	t.Cleanup(func() { _ = module.Close() })

	steps.awaitWaiting(t)
	steps.release <- struct{}{}
	awaitPanelReloadRecoveryExit(t, module)

	state := module.stateSnapshot()
	if state.status != panelReloadStatusReady || state.runtime != restored || state.config != initialConfig {
		t.Fatalf("state after recovery = status %v runtime %v config %v, want ready restored last-known-good", state.status, state.runtime, state.config)
	}
	if restoredConfig != initialConfig {
		t.Fatalf("recovery build config = %v, want initial config", restoredConfig)
	}
}

func TestPanelReloadModuleCloseStopsPendingRecovery(t *testing.T) {
	steps := newReloadRecoverySteps()
	module, _ := newDoubleFailureReloadModule(t, steps, func(*panel.Config) panelRuntime {
		t.Error("recovery built a runtime after Close")
		return nil
	})

	steps.awaitWaiting(t)
	if err := module.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	awaitPanelReloadRecoveryExit(t, module)
	if state := module.stateSnapshot(); state.status != panelReloadStatusClosed {
		t.Fatalf("state after Close = %v, want closed", state.status)
	}
}

func TestPanelReloadModuleSuccessfulReloadSupersedesRecovery(t *testing.T) {
	steps := newReloadRecoverySteps()
	var builds []*panel.Config
	var reloaded *reloadTestRuntime
	module, _ := newDoubleFailureReloadModule(t, steps, func(config *panel.Config) panelRuntime {
		builds = append(builds, config)
		reloaded = &reloadTestRuntime{name: "reloaded", events: new([]string)}
		return reloaded
	})
	t.Cleanup(func() { _ = module.Close() })

	steps.awaitWaiting(t)
	if err := module.Reload("changed-again.yml"); err != nil {
		t.Fatalf("second Reload() error = %v", err)
	}
	steps.release <- struct{}{}
	awaitPanelReloadRecoveryExit(t, module)

	if len(builds) != 1 {
		t.Fatalf("builds after superseded recovery = %d, want only the reload candidate", len(builds))
	}
	if state := module.stateSnapshot(); state.status != panelReloadStatusReady || state.runtime != reloaded {
		t.Fatalf("state = status %v runtime %v, want the reloaded runtime", state.status, state.runtime)
	}
}
