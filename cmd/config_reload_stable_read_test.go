package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/panel"
)

const (
	// candidateValidMachineConfig is a complete, valid machine-mode config.
	candidateValidMachineConfig = `Log:
  Level: warning
  ShowErrorDetails: false
MachineConfig:
  Enable: true
  PanelType: "NewV2board"
  ApiHost: "https://panel.example.com"
  MachineID: 23
  Token: "test-machine-token"
  ControllerConfig:
    UpdatePeriodic: 60
    WebSocketConfig:
      Enable: true
      Endpoint: "wss://panel.example.com/ws"
      HeartbeatInterval: 30
      ReconnectBackoff: 5
      ResyncOnReconnect: true
`
	// candidatePartialMachineConfig is YAML-valid but fails runtime validation:
	// MachineID and Token are still missing because the writer is paused.
	candidatePartialMachineConfig = `MachineConfig:
  Enable: true
  PanelType: "NewV2board"
  ApiHost: "https://panel.example.com"
`
	// candidateStillPartialMachineConfig is a second partial shape that also
	// fails validation, used to keep the writer "changing" without ever becoming
	// valid.
	candidateStillPartialMachineConfig = `MachineConfig:
  Enable: true
  PanelType: "NewV2board"
  ApiHost: "https://panel.example.com"
  MachineID: 23
`
	// candidateStaticConfig is a valid config in a different runtime mode.
	candidateStaticConfig = `Nodes:
  - PanelType: "SSPanel"
    ApiConfig:
      ApiHost: "http://127.0.0.1:667"
      NodeID: 41
`
)

// scriptedSnapshots returns one scripted file snapshot per observation. Once
// the script is exhausted the last snapshot is returned. The script advances
// through an injected barrier rather than a sleep, so ordering is deterministic.
type scriptedSnapshots struct {
	snapshots [][]byte
	readErr   error
	reads     int
}

func (s *scriptedSnapshots) read(string) ([]byte, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	index := s.reads
	if index >= len(s.snapshots) {
		index = len(s.snapshots) - 1
	}
	s.reads++
	return s.snapshots[index], nil
}

// noWait advances the observation timeline without sleeping.
func noWait(ctx context.Context, _ time.Duration) error { return ctx.Err() }

func machineConfigFromString(t *testing.T, content string) *panel.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := loadPanelReloadCandidate(path, "")
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return config
}

func newObservingModule(t *testing.T, reader func(string) ([]byte, error), previous *panel.Config) *panelReloadModule {
	t.Helper()
	initialTime := time.Unix(15000, 0)
	return newPanelReloadModule(previous, &reloadTestRuntime{name: "initial", events: &[]string{}}, panelReloadOptions{
		configFile:         "config.yml",
		lastAppliedAt:      initialTime,
		readCandidateFile:  reader,
		waitCandidate:      noWait,
		buildRuntime:       func(*panel.Config) panelRuntime { return &reloadTestRuntime{name: "candidate", events: &[]string{}} },
		applyProcessConfig: func(*panel.Config) {},
		collectGarbage:     func() {},
		now:                func() time.Time { return initialTime.Add(4 * time.Second) },
	})
}

// TestReloadDoesNotRejectTemporarilyStablePartialCandidate is the key PR A
// regression: a partial write that pauses long enough to be read twice
// identically must NOT be reported as the final invalid candidate while the
// bounded window is still open. Once the writer finishes, the reload succeeds.
func TestReloadDoesNotRejectTemporarilyStablePartialCandidate(t *testing.T) {
	previous := machineConfigFromString(t, candidateValidMachineConfig)
	reader := &scriptedSnapshots{snapshots: [][]byte{
		[]byte(""),                            // truncate
		[]byte(candidatePartialMachineConfig), // partial write begins
		[]byte(candidatePartialMachineConfig), // PAUSED: identical twice
		[]byte(candidatePartialMachineConfig), // still paused
		[]byte(candidateValidMachineConfig),   // writer finishes late
		[]byte(candidateValidMachineConfig),   // stable and valid
	}}
	module := newObservingModule(t, reader.read, previous)

	if err := module.Reload("config.yml"); err != nil {
		t.Fatalf("Reload() error = %v, want the final valid config to be accepted", err)
	}
	if reader.reads < 4 {
		t.Fatalf("loader stopped after %d observation(s); it must keep observing a stable-but-invalid candidate", reader.reads)
	}
	applied := module.stateSnapshot()
	if applied.status != panelReloadStatusReady {
		t.Fatalf("applied status = %v, want ready", applied.status)
	}
	if applied.config == nil || applied.config.MachineConfig == nil || applied.config.MachineConfig.MachineID != 23 {
		t.Fatal("the final valid config was not applied")
	}
}

// Outcome A: a transient non-atomic write that ends in a valid config.
func TestReloadAcceptsValidConfigAfterTransientWrite(t *testing.T) {
	previous := machineConfigFromString(t, candidateValidMachineConfig)
	reader := &scriptedSnapshots{snapshots: [][]byte{
		[]byte(""),
		[]byte(candidatePartialMachineConfig),
		[]byte(candidateValidMachineConfig),
		[]byte(candidateValidMachineConfig),
	}}
	module := newObservingModule(t, reader.read, previous)
	if err := module.Reload("config.yml"); err != nil {
		t.Fatalf("Reload() error = %v, want success", err)
	}
	if applied := module.stateSnapshot(); applied.config == nil || applied.config.MachineConfig == nil {
		t.Fatal("valid config was not applied")
	}
}

// Outcome B: a snapshot that stays unchanged and invalid for the whole window
// is a genuine invalid candidate: the original validation error is returned and
// the last-known-good configuration is preserved.
func TestReloadReportsStableInvalidCandidateWithOriginalError(t *testing.T) {
	previous := machineConfigFromString(t, candidateValidMachineConfig)
	reader := &scriptedSnapshots{snapshots: [][]byte{
		[]byte(candidatePartialMachineConfig),
		[]byte(candidatePartialMachineConfig),
	}}
	module := newObservingModule(t, reader.read, previous)

	err := module.Reload("config.yml")
	if err == nil {
		t.Fatal("stable invalid candidate was accepted")
	}
	if !errors.Is(err, errPanelReloadCandidateInvalid) {
		t.Fatalf("error = %v, want errPanelReloadCandidateInvalid", err)
	}
	if !strings.Contains(err.Error(), "MachineID") {
		t.Fatalf("error = %v, want the original validation reason", err)
	}
	if applied := module.stateSnapshot(); applied.config != previous {
		t.Fatal("last-known-good configuration was replaced")
	}
}

// Outcome C: a file that never repeats a snapshot is reported as unstable
// rather than being classified as invalid.
func TestReloadReportsNeverStabilisingCandidate(t *testing.T) {
	previous := machineConfigFromString(t, candidateValidMachineConfig)
	sequence := make([][]byte, 0, 8)
	for index := 0; index < 8; index++ {
		// Every snapshot differs from the previous one AND is invalid (Token is
		// always missing), so the file never becomes classifiable.
		sequence = append(sequence, []byte(
			"MachineConfig:\n  Enable: true\n  PanelType: \"NewV2board\"\n  ApiHost: \"https://panel.example.com\"\n  MachineID: "+string(rune('1'+index))+"\n",
		))
	}
	module := newObservingModule(t, (&scriptedSnapshots{snapshots: sequence}).read, previous)

	err := module.Reload("config.yml")
	if !errors.Is(err, errPanelReloadUnstableCandidate) {
		t.Fatalf("error = %v, want errPanelReloadUnstableCandidate", err)
	}
	if applied := module.stateSnapshot(); applied.config != previous {
		t.Fatal("last-known-good configuration was replaced")
	}
}

// A candidate that was briefly stable early but kept changing afterwards must
// be reported as unstable, not as a genuine invalid candidate: the early
// stability signal is not a verdict.
func TestReloadReportsEarlyStabilityThenFurtherChangesAsUnstable(t *testing.T) {
	previous := machineConfigFromString(t, candidateValidMachineConfig)
	module := newObservingModule(t, (&scriptedSnapshots{snapshots: [][]byte{
		[]byte(candidatePartialMachineConfig),
		[]byte(candidatePartialMachineConfig), // briefly stable
		[]byte(candidateStillPartialMachineConfig),
		[]byte(candidateStillPartialMachineConfig),
		[]byte("MachineConfig:\n  Enable: true\n  PanelType: \"NewV2board\"\n  ApiHost: \"https://panel.example.com\"\n  MachineID: 24\n"), // changed again
	}}).read, previous)

	err := module.Reload("config.yml")
	if !errors.Is(err, errPanelReloadUnstableCandidate) {
		t.Fatalf("error = %v, want errPanelReloadUnstableCandidate", err)
	}
	if applied := module.stateSnapshot(); applied.config != previous {
		t.Fatal("last-known-good configuration was replaced")
	}
}

// A runtime-mode change is still rejected once the file is stable.
func TestReloadRejectsStableModeChange(t *testing.T) {
	previous := machineConfigFromString(t, candidateValidMachineConfig)
	module := newObservingModule(t, (&scriptedSnapshots{snapshots: [][]byte{
		[]byte(candidateStaticConfig),
		[]byte(candidateStaticConfig),
	}}).read, previous)

	err := module.Reload("config.yml")
	if !errors.Is(err, panel.ErrRuntimeConfigModeChange) {
		t.Fatalf("error = %v, want ErrRuntimeConfigModeChange", err)
	}
	if applied := module.stateSnapshot(); applied.config != previous {
		t.Fatal("mode change replaced the last-known-good configuration")
	}
}

// Candidate contents and the machine token must never reach the returned error.
func TestReloadCandidateErrorsDoNotLeakContents(t *testing.T) {
	previous := machineConfigFromString(t, candidateValidMachineConfig)
	secret := "top-secret-token"
	sequence := make([][]byte, 0, 8)
	for index := 0; index < 8; index++ {
		// Every snapshot differs from the previous one, is invalid (ApiHost is
		// always missing), and nevertheless embeds the secret.
		sequence = append(sequence, []byte(
			"MachineConfig:\n  Enable: true\n  PanelType: \"NewV2board\"\n  MachineID: "+string(rune('1'+index))+"\n  Token: \""+secret+"-"+string(rune('a'+index))+"\"\n",
		))
	}
	module := newObservingModule(t, (&scriptedSnapshots{snapshots: sequence}).read, previous)
	err := module.Reload("config.yml")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked candidate contents: %v", err)
	}
}

// The observation loop must stay inside the caller's deadline.
func TestReloadObservationHonorsContextDeadline(t *testing.T) {
	previous := machineConfigFromString(t, candidateValidMachineConfig)
	var observations int
	reader := func(string) ([]byte, error) {
		observations++
		return []byte("MachineConfig:\n  Enable: true\n  ApiHost: \"https://panel.example.com\"\n  MachineID: " + string(rune('0'+observations)) + "\n"), nil
	}
	initialTime := time.Unix(15000, 0)
	module := newPanelReloadModule(previous, &reloadTestRuntime{name: "initial", events: &[]string{}}, panelReloadOptions{
		configFile:        "config.yml",
		lastAppliedAt:     initialTime,
		readCandidateFile: reader,
		waitCandidate: func(ctx context.Context, _ time.Duration) error {
			<-ctx.Done()
			return ctx.Err()
		},
		buildRuntime:       func(*panel.Config) panelRuntime { return &reloadTestRuntime{name: "candidate", events: &[]string{}} },
		applyProcessConfig: func(*panel.Config) {},
		collectGarbage:     func() {},
		now:                func() time.Time { return initialTime.Add(4 * time.Second) },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := module.ReloadContext(ctx, "config.yml"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
}

// A read failure is still surfaced with the historical classification.
func TestReloadStillReportsReadFailures(t *testing.T) {
	previous := machineConfigFromString(t, candidateValidMachineConfig)
	module := newObservingModule(t, (&scriptedSnapshots{readErr: os.ErrNotExist}).read, previous)
	err := module.Reload("config.yml")
	if err == nil || !strings.Contains(err.Error(), "failed to read new config file") {
		t.Fatalf("error = %v, want the read classification", err)
	}
}

// The production loader wrapper still parses a complete file.
func TestLoadPanelReloadCandidateStillParsesCompleteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(candidateValidMachineConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := loadPanelReloadCandidate(path, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if config.MachineConfig == nil || config.MachineConfig.MachineID != 23 {
		t.Fatalf("unexpected config: %#v", config.MachineConfig)
	}
}
