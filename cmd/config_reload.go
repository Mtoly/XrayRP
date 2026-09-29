package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/internal/operation"
	"github.com/Mtoly/XrayRP/panel"
	"github.com/Mtoly/XrayRP/service"
)

var (
	errPanelReloadNilCandidate = errors.New("panel reload candidate is nil")
	errPanelReloadEmptyNodes   = errors.New("panel reload candidate contains no nodes")
	errPanelReloadClosed       = errors.New("panel reload module is closed")
	errPanelReloadFailedOwned  = errors.New("panel reload cleanup ownership remains")
	// errPanelReloadCandidateInvalid marks a candidate that failed runtime
	// validation so the reload keeps its historical warning classification while
	// the wrapped error still carries the specific reason.
	errPanelReloadCandidateInvalid = errors.New("panel reload candidate is invalid")
	// errPanelReloadUnstableCandidate reports that the configuration file never
	// stayed readable and unchanged long enough to be classified. The applied
	// configuration is kept and the next change event retries.
	errPanelReloadUnstableCandidate = errors.New("config file is still being modified")
)

const (
	// panelReloadCandidateObservations bounds how many snapshots of the
	// configuration file are inspected before a candidate is classified. With
	// panelReloadCandidateObservationDelay this bounds the added reload latency;
	// the reload context deadline remains the hard upper bound.
	panelReloadCandidateObservations = 5
	// panelReloadCandidateObservationDelay separates snapshots so a writer that
	// truncates and rewrites the file has time to finish.
	panelReloadCandidateObservationDelay = 50 * time.Millisecond
)

type panelRuntime interface {
	Start() error
	Close() error
}

func startPanelRuntimeContext(ctx context.Context, runtime panelRuntime) error {
	if runtime == nil {
		return nil
	}
	if contextual, ok := runtime.(interface{ StartContext(context.Context) error }); ok {
		return contextual.StartContext(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return runtime.Start()
}

func closePanelRuntimeContext(ctx context.Context, runtime panelRuntime) error {
	if runtime == nil {
		return nil
	}
	if contextual, ok := runtime.(interface{ CloseContext(context.Context) error }); ok {
		return contextual.CloseContext(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return runtime.Close()
}

type panelReloadOperation uint8

const (
	panelReloadOperationReload panelReloadOperation = iota
	panelReloadOperationClose
)

type panelReloadOperationPhase uint8

const (
	panelReloadOperationAttempted panelReloadOperationPhase = iota
	panelReloadOperationEntered
	panelReloadOperationExited
)

type panelReloadStatus uint8

const (
	panelReloadStatusReady panelReloadStatus = iota
	panelReloadStatusReloading
	panelReloadStatusFailed
	panelReloadStatusFailedOwned
	panelReloadStatusClosed
)

type panelReloadState struct {
	config  *panel.Config
	runtime panelRuntime
	status  panelReloadStatus
	failure error
}

type panelReloadOptions struct {
	configFile    string
	lastAppliedAt time.Time
	debounce      time.Duration
	loadCandidate func(eventName, configuredFile string) (*panel.Config, error)
	// readCandidateFile and waitCandidate are the deterministic seams for the
	// bounded candidate observation loop. Both default to production behaviour.
	readCandidateFile  func(string) ([]byte, error)
	waitCandidate      func(context.Context, time.Duration) error
	validateCandidate  func(current, candidate *panel.Config) error
	buildRuntime       func(*panel.Config) panelRuntime
	applyProcessConfig func(*panel.Config)
	collectGarbage     func()
	now                func() time.Time
	reloadClock        func() time.Time
	observeOperation   func(panelReloadOperation, panelReloadOperationPhase)
}

type panelReloadObservation struct {
	snapshot              service.ReloadSnapshot
	phaseStartedAt        time.Time
	interruptionStartedAt time.Time
}

type panelReloadModule struct {
	operationMu       operation.Gate
	stateMu           sync.RWMutex
	reloadMu          sync.RWMutex
	applied           panelReloadState
	configFile        string
	lastAppliedAt     time.Time
	debounce          time.Duration
	loadCandidate     func(eventName, configuredFile string) (*panel.Config, error)
	readCandidateFile func(string) ([]byte, error)
	waitCandidate     func(context.Context, time.Duration) error
	validate          func(current, candidate *panel.Config) error
	buildRuntime      func(*panel.Config) panelRuntime
	applyProcess      func(*panel.Config)
	collect           func()
	now               func() time.Time
	reloadClock       func() time.Time
	observeOp         func(panelReloadOperation, panelReloadOperationPhase)
	reload            panelReloadObservation
}

func newPanelReloadModule(initialConfig *panel.Config, initialRuntime panelRuntime, options panelReloadOptions) *panelReloadModule {
	if options.debounce == 0 {
		options.debounce = 3 * time.Second
	}
	if options.readCandidateFile == nil {
		options.readCandidateFile = os.ReadFile
	}
	if options.waitCandidate == nil {
		options.waitCandidate = waitForPanelReloadObservation
	}
	if options.validateCandidate == nil {
		options.validateCandidate = validatePanelReloadCandidate
	}
	if options.buildRuntime == nil {
		options.buildRuntime = func(config *panel.Config) panelRuntime {
			return panel.New(config)
		}
	}
	if options.applyProcessConfig == nil {
		options.applyProcessConfig = applyPanelProcessConfig
	}
	if options.collectGarbage == nil {
		options.collectGarbage = runtime.GC
	}
	if options.now == nil {
		options.now = time.Now
	}
	if options.reloadClock == nil {
		options.reloadClock = time.Now
	}
	if options.lastAppliedAt.IsZero() {
		options.lastAppliedAt = options.now()
	}

	return &panelReloadModule{
		applied: panelReloadState{
			config:  initialConfig,
			runtime: initialRuntime,
			status:  panelReloadStatusReady,
		},
		reload: panelReloadObservation{
			snapshot: service.ReloadSnapshot{Phase: service.ReloadPhaseNone},
		},
		configFile:        options.configFile,
		lastAppliedAt:     options.lastAppliedAt,
		debounce:          options.debounce,
		loadCandidate:     options.loadCandidate,
		readCandidateFile: options.readCandidateFile,
		waitCandidate:     options.waitCandidate,
		validate:          options.validateCandidate,
		buildRuntime:      options.buildRuntime,
		applyProcess:      options.applyProcessConfig,
		collect:           options.collectGarbage,
		now:               options.now,
		reloadClock:       options.reloadClock,
		observeOp:         options.observeOperation,
	}
}

func (m *panelReloadModule) Reload(eventName string) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return m.ReloadContext(ctx, eventName)
}

func (m *panelReloadModule) ReloadContext(parent context.Context, eventName string) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultSyncTimeout)
	defer cancel()
	if err := m.beginOperationContext(ctx, panelReloadOperationReload); err != nil {
		return err
	}
	defer m.endOperation(panelReloadOperationReload)

	current := m.stateSnapshot()
	if current.status == panelReloadStatusClosed {
		return errPanelReloadClosed
	}
	if current.status == panelReloadStatusFailedOwned {
		return errors.Join(errPanelReloadFailedOwned, current.failure)
	}
	if !m.now().After(m.lastAppliedAt.Add(m.debounce)) {
		return nil
	}

	fmt.Println("Config file changed:", eventName)
	m.beginReloadObservation()
	reloadSucceeded := false
	defer func() {
		m.finishReloadObservation(reloadSucceeded)
	}()

	candidateConfig, err := m.observeCandidate(ctx, eventName, current.config)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		if errors.Is(err, errPanelReloadCandidateInvalid) {
			log.Warnf("Hot reload: candidate config validation failed; keeping existing configuration")
		} else {
			log.Errorf("Hot reload: %v; keeping existing configuration", err)
		}
		return err
	}
	if candidateConfig == nil {
		log.Errorf("Hot reload: %v; keeping existing configuration", errPanelReloadNilCandidate)
		return errPanelReloadNilCandidate
	}

	m.publishState(panelReloadState{
		config:  current.config,
		runtime: current.runtime,
		status:  panelReloadStatusReloading,
	})
	m.transitionReloadPhase(service.ReloadPhaseStop)

	if current.runtime != nil {
		if closeErr := closePanelRuntimeContext(ctx, current.runtime); closeErr != nil {
			joined := fmt.Errorf("close old panel: %w", closeErr)
			log.Error("Hot reload: failed to close old panel")
			m.publishState(panelReloadState{
				config:  current.config,
				runtime: current.runtime,
				status:  panelReloadStatusFailedOwned,
				failure: joined,
			})
			m.transitionReloadPhase(service.ReloadPhaseRollback)
			return joined
		}
	}
	m.publishState(panelReloadState{
		config: current.config,
		status: panelReloadStatusReloading,
	})
	m.collect()
	m.transitionReloadPhase(service.ReloadPhaseStart)

	candidateRuntime := m.buildRuntime(candidateConfig)
	if candidateRuntime == nil {
		err := errors.New("build new panel: nil runtime")
		log.Error("Hot reload: failed to build new panel")
		m.transitionReloadPhase(service.ReloadPhaseRollback)
		return m.restoreLastKnownGoodContext(ctx, current, []error{err})
	}

	if err := startPanelRuntimeContext(ctx, candidateRuntime); err != nil {
		log.Error("Hot reload: failed to start new panel")
		errs := []error{fmt.Errorf("start new panel: %w", err)}
		m.transitionReloadPhase(service.ReloadPhaseRollback)
		cleanupCtx, cleanupCancel := service.CleanupContext(ctx)
		cleanupErr := closePanelRuntimeContext(cleanupCtx, candidateRuntime)
		cleanupCancel()
		if cleanupErr != nil {
			log.Error("Hot reload: failed to clean candidate panel")
			errs = append(errs, fmt.Errorf("clean failed candidate panel: %w", cleanupErr))
			joined := errors.Join(errs...)
			m.publishState(panelReloadState{
				config:  current.config,
				runtime: candidateRuntime,
				status:  panelReloadStatusFailedOwned,
				failure: joined,
			})
			return joined
		}
		return m.restoreLastKnownGoodContext(ctx, current, errs)
	}

	if err := ctx.Err(); err != nil {
		m.transitionReloadPhase(service.ReloadPhaseRollback)
		cleanupCtx, cleanupCancel := service.CleanupContext(ctx)
		cleanupErr := closePanelRuntimeContext(cleanupCtx, candidateRuntime)
		cleanupCancel()
		if cleanupErr != nil {
			joined := errors.Join(err, cleanupErr)
			m.publishState(panelReloadState{config: current.config, runtime: candidateRuntime, status: panelReloadStatusFailedOwned, failure: joined})
			return joined
		}
		return m.restoreLastKnownGoodContext(ctx, current, []error{err})
	}
	m.transitionReloadPhase(service.ReloadPhaseCommit)
	m.applyProcess(candidateConfig)
	m.publishState(panelReloadState{
		config:  candidateConfig,
		runtime: candidateRuntime,
		status:  panelReloadStatusReady,
	})
	m.lastAppliedAt = m.now()
	reloadSucceeded = true
	return nil
}
func (m *panelReloadModule) Close() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return m.CloseContext(ctx)
}

func (m *panelReloadModule) CloseContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultCloseTimeout)
	defer cancel()
	if m == nil {
		return nil
	}

	if err := m.beginOperationContext(ctx, panelReloadOperationClose); err != nil {
		return err
	}
	defer m.endOperation(panelReloadOperationClose)

	current := m.stateSnapshot()
	if current.status == panelReloadStatusClosed {
		return nil
	}

	var closeErr error
	if current.runtime != nil {
		closeErr = closePanelRuntimeContext(ctx, current.runtime)
	}
	if closeErr != nil {
		joined := errors.Join(current.failure, closeErr)
		m.publishState(panelReloadState{
			config:  current.config,
			runtime: current.runtime,
			status:  panelReloadStatusFailedOwned,
			failure: joined,
		})
		return closeErr
	}
	m.publishState(panelReloadState{
		config: current.config,
		status: panelReloadStatusClosed,
	})
	return nil
}
func (m *panelReloadModule) restoreLastKnownGood(previous panelReloadState, errs []error) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return m.restoreLastKnownGoodContext(ctx, previous, errs)
}

func (m *panelReloadModule) restoreLastKnownGoodContext(parent context.Context, previous panelReloadState, errs []error) error {
	ctx, cancel := service.WithDefaultTimeout(context.WithoutCancel(parent), service.DefaultStartTimeout)
	defer cancel()
	restoredRuntime := m.buildRuntime(previous.config)
	if restoredRuntime == nil {
		errs = append(errs, errors.New("restore old panel: nil runtime"))
		joined := errors.Join(errs...)
		m.publishState(panelReloadState{
			config:  previous.config,
			status:  panelReloadStatusFailed,
			failure: joined,
		})
		log.Error("Hot reload: failed to restore old panel")
		return joined
	}

	if err := startPanelRuntimeContext(ctx, restoredRuntime); err != nil {
		errs = append(errs, fmt.Errorf("restore old panel: %w", err))
		cleanupCtx, cleanupCancel := service.CleanupContext(ctx)
		cleanupErr := closePanelRuntimeContext(cleanupCtx, restoredRuntime)
		cleanupCancel()
		if cleanupErr != nil {
			errs = append(errs, fmt.Errorf("clean failed restored panel: %w", cleanupErr))
			joined := errors.Join(errs...)
			m.publishState(panelReloadState{
				config:  previous.config,
				runtime: restoredRuntime,
				status:  panelReloadStatusFailedOwned,
				failure: joined,
			})
			log.Error("Hot reload: failed to restore old panel")
			return joined
		}
		joined := errors.Join(errs...)
		m.publishState(panelReloadState{
			config:  previous.config,
			status:  panelReloadStatusFailed,
			failure: joined,
		})
		log.Error("Hot reload: failed to restore old panel")
		return joined
	}

	m.publishState(panelReloadState{
		config:  previous.config,
		runtime: restoredRuntime,
		status:  panelReloadStatusReady,
	})
	return errors.Join(errs...)
}
func (m *panelReloadModule) beginOperation(operation panelReloadOperation) {
	_ = m.beginOperationContext(context.Background(), operation)
}

func (m *panelReloadModule) beginOperationContext(ctx context.Context, operation panelReloadOperation) error {
	if m.observeOp != nil {
		m.observeOp(operation, panelReloadOperationAttempted)
	}
	if err := m.operationMu.Lock(ctx); err != nil {
		return err
	}
	if m.observeOp != nil {
		m.observeOp(operation, panelReloadOperationEntered)
	}
	return nil
}

func (m *panelReloadModule) endOperation(operation panelReloadOperation) {
	if m.observeOp != nil {
		m.observeOp(operation, panelReloadOperationExited)
	}
	m.operationMu.Unlock()
}
func (m *panelReloadModule) stateSnapshot() panelReloadState {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.applied
}

func (m *panelReloadModule) ObservabilitySnapshot() service.RuntimeSnapshot {
	if m == nil {
		return service.RuntimeSnapshot{Kind: service.RuntimeKindPanel, Lifecycle: service.RuntimeLifecycleClosed, WebSocket: service.WebSocketDisabled}
	}
	state := m.stateSnapshot()
	reload := m.reloadSnapshot()
	snapshot := service.RuntimeSnapshot{
		Kind:      service.RuntimeKindPanel,
		Lifecycle: service.RuntimeLifecycleStopped,
		WebSocket: service.WebSocketDisabled,
	}
	if provider, ok := state.runtime.(service.RuntimeSnapshotProvider); ok {
		snapshot = provider.ObservabilitySnapshot()
	}
	snapshot.Reload = reload
	switch state.status {
	case panelReloadStatusReady:
	case panelReloadStatusReloading:
		if state.runtime == nil || snapshot.Lifecycle != service.RuntimeLifecycleRunning {
			snapshot.Lifecycle = service.RuntimeLifecycleStarting
		} else {
			snapshot.Lifecycle = service.RuntimeLifecycleReloading
		}
	case panelReloadStatusFailed:
		snapshot.Lifecycle = service.RuntimeLifecycleFailed
		snapshot.LastFailureStage = service.FailureStageStart
	case panelReloadStatusFailedOwned:
		snapshot.Lifecycle = service.RuntimeLifecycleFailedOwned
		snapshot.CleanupPending = true
		snapshot.LastFailureStage = service.FailureStageCleanup
	case panelReloadStatusClosed:
		snapshot.Lifecycle = service.RuntimeLifecycleClosed
		snapshot.Children = nil
	}
	return snapshot
}

func (m *panelReloadModule) beginReloadObservation() {
	now := m.reloadNow()
	m.reloadMu.Lock()
	m.reload.snapshot.Attempts++
	m.reload.snapshot.Phase = service.ReloadPhaseCandidate
	m.reload.snapshot.LastCandidateDuration = 0
	m.reload.snapshot.LastStopDuration = 0
	m.reload.snapshot.LastStartDuration = 0
	m.reload.snapshot.LastCommitDuration = 0
	m.reload.snapshot.LastRollbackDuration = 0
	m.reload.snapshot.LastInterruptionDuration = 0
	m.reload.phaseStartedAt = now
	m.reload.interruptionStartedAt = time.Time{}
	m.reloadMu.Unlock()
}

func (m *panelReloadModule) transitionReloadPhase(next service.ReloadPhase) {
	now := m.reloadNow()
	m.reloadMu.Lock()
	m.finishReloadPhaseLocked(now)
	if next == service.ReloadPhaseNone {
		m.reload.snapshot.Phase = service.ReloadPhaseNone
		m.reload.phaseStartedAt = time.Time{}
		m.reloadMu.Unlock()
		return
	}
	m.reload.snapshot.Phase = next
	m.reload.phaseStartedAt = now
	if next == service.ReloadPhaseStop {
		m.reload.interruptionStartedAt = now
	}
	m.reloadMu.Unlock()
}

func (m *panelReloadModule) finishReloadPhaseLocked(now time.Time) {
	phase := m.reload.snapshot.Phase
	if phase == service.ReloadPhaseNone || m.reload.phaseStartedAt.IsZero() {
		return
	}
	duration := nonNegativeDuration(now.Sub(m.reload.phaseStartedAt))
	switch phase {
	case service.ReloadPhaseCandidate:
		m.reload.snapshot.LastCandidateDuration = duration
	case service.ReloadPhaseStop:
		m.reload.snapshot.LastStopDuration = duration
	case service.ReloadPhaseStart:
		m.reload.snapshot.LastStartDuration = duration
	case service.ReloadPhaseCommit:
		m.reload.snapshot.LastCommitDuration = duration
	case service.ReloadPhaseRollback:
		m.reload.snapshot.LastRollbackDuration = duration
	}
}

func (m *panelReloadModule) finishReloadObservation(success bool) {
	now := m.reloadNow()
	m.reloadMu.Lock()
	m.finishReloadPhaseLocked(now)
	if !m.reload.interruptionStartedAt.IsZero() {
		m.reload.snapshot.LastInterruptionDuration = nonNegativeDuration(now.Sub(m.reload.interruptionStartedAt))
	}
	if success {
		m.reload.snapshot.Successes++
	} else {
		m.reload.snapshot.Failures++
	}
	m.reload.snapshot.Phase = service.ReloadPhaseNone
	m.reload.phaseStartedAt = time.Time{}
	m.reload.interruptionStartedAt = time.Time{}
	m.reloadMu.Unlock()
}

func (m *panelReloadModule) reloadSnapshot() service.ReloadSnapshot {
	m.reloadMu.RLock()
	defer m.reloadMu.RUnlock()
	return m.reload.snapshot
}

func (m *panelReloadModule) reloadNow() time.Time {
	now := m.reloadClock()
	if now.IsZero() {
		return time.Now()
	}
	return now
}

func nonNegativeDuration(value time.Duration) time.Duration {
	if value < 0 {
		return 0
	}
	return value
}

func (m *panelReloadModule) publishState(state panelReloadState) {
	m.stateMu.Lock()
	m.applied = state
	m.stateMu.Unlock()
}

func loadPanelReloadCandidate(eventName, configuredFile string) (*panel.Config, error) {
	candidateViper := viper.New()
	if eventName != "" {
		candidateViper.SetConfigFile(eventName)
	} else if configuredFile != "" {
		candidateViper.SetConfigFile(configuredFile)
	} else {
		candidateViper.SetConfigName("config")
		candidateViper.SetConfigType("yml")
		candidateViper.AddConfigPath(".")
	}

	if err := candidateViper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read new config file %s: %w", eventName, err)
	}

	candidateConfig := &panel.Config{}
	if err := candidateViper.Unmarshal(candidateConfig); err != nil {
		return nil, fmt.Errorf("failed to parse new config file %s: %w", eventName, err)
	}
	return candidateConfig, nil
}

// observeCandidate loads the candidate within the caller's deadline instead of
// trusting a single read of the configuration file.
//
// Two matching consecutive snapshots are a stability signal, not proof that the
// writer finished: a writer can pause mid-write. A stable snapshot that fails
// validation therefore does not end the observation by itself. Bounded outcomes:
//
//   - a snapshot that decodes and validates is accepted immediately (a healthy
//     reload adds no latency);
//   - a snapshot that stays unchanged for the whole window but never validates
//     returns its original read/parse/validation error (LKG preserved);
//   - a file that never stays readable and unchanged returns
//     errPanelReloadUnstableCandidate.
//
// This is best-effort resilience against transient non-atomic writes, not an
// integrity guarantee. Writing the file atomically (write a temporary file,
// fsync where appropriate, then rename/replace) remains the strong
// operator-side guarantee.
func (m *panelReloadModule) observeCandidate(ctx context.Context, eventName string, current *panel.Config) (*panel.Config, error) {
	path := strings.TrimSpace(eventName)
	if path == "" {
		path = strings.TrimSpace(m.configFile)
	}
	// An injected loader keeps its historical single-read contract, and a run
	// with no explicit path keeps the historical viper discovery behaviour.
	if m.loadCandidate != nil {
		candidate, err := m.loadCandidate(eventName, m.configFile)
		return candidate, m.classifySingle(current, candidate, err)
	}
	if path == "" {
		candidate, err := loadPanelReloadCandidate(eventName, m.configFile)
		return candidate, m.classifySingle(current, candidate, err)
	}

	var (
		previous  []byte
		havePrev  bool
		sawBytes  bool
		lastRead  error
		lastIssue error
	)
	for observation := 0; observation < panelReloadCandidateObservations; observation++ {
		if observation > 0 {
			if err := m.waitCandidate(ctx, panelReloadCandidateObservationDelay); err != nil {
				return nil, err
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		snapshot, readErr := m.readCandidateFile(path)
		if readErr != nil {
			// A rename-based writer can briefly remove the file; keep observing
			// within the deadline instead of failing the reload outright.
			lastRead = fmt.Errorf("failed to read new config file %s: %w", path, readErr)
			previous, havePrev, lastIssue = nil, false, nil
			continue
		}
		sawBytes = true
		if candidate, classifyErr := m.decodeCandidate(snapshot, path, current); classifyErr == nil {
			return candidate, nil
		} else if havePrev && bytes.Equal(previous, snapshot) {
			// Unchanged but still unusable: remember why and keep observing so a
			// writer that finishes later in the window can still be accepted.
			lastIssue = classifyErr
		} else {
			// The pair no longer matches, so an earlier "stable but invalid"
			// verdict is stale: only a repeat at the end of the window may be
			// reported as a genuine invalid candidate.
			lastIssue = nil
		}
		previous, havePrev = snapshot, true
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lastIssue != nil {
		return nil, lastIssue
	}
	if !sawBytes && lastRead != nil {
		return nil, lastRead
	}
	return nil, fmt.Errorf("%w: %s", errPanelReloadUnstableCandidate, path)
}

// classifySingle applies validation to a single-read candidate and marks a
// validation failure so the caller keeps the historical reload log wording.
func (m *panelReloadModule) classifySingle(current, candidate *panel.Config, err error) error {
	if err != nil || candidate == nil {
		return err
	}
	if err := m.validate(current, candidate); err != nil {
		return errors.Join(errPanelReloadCandidateInvalid, err)
	}
	return nil
}

// decodeCandidate decodes one snapshot and validates it against the applied
// configuration without publishing anything. Candidate contents never appear in
// returned errors.
func (m *panelReloadModule) decodeCandidate(snapshot []byte, path string, current *panel.Config) (*panel.Config, error) {
	candidateViper := viper.New()
	// SetConfigFile reuses viper's own extension-based type inference and its
	// unsupported-extension error; no discovery logic is duplicated here.
	candidateViper.SetConfigFile(path)
	if err := candidateViper.ReadConfig(bytes.NewReader(snapshot)); err != nil {
		// ReadConfig mirrors the historical ReadInConfig classification: a
		// read/decode failure is reported as a read failure.
		return nil, fmt.Errorf("failed to read new config file %s: %w", path, err)
	}
	candidate := &panel.Config{}
	if err := candidateViper.Unmarshal(candidate); err != nil {
		return nil, fmt.Errorf("failed to parse new config file %s: %w", path, err)
	}
	if err := m.validate(current, candidate); err != nil {
		return nil, errors.Join(errPanelReloadCandidateInvalid, err)
	}
	return candidate, nil
}

func waitForPanelReloadObservation(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func applyPanelProcessConfig(config *panel.Config) {
	if config != nil && config.LogConfig != nil && config.LogConfig.Level == "debug" {
		log.SetReportCaller(true)
	} else {
		log.SetReportCaller(false)
	}
	common.SetShowErrorDetails(config.ShowErrorDetails())
}

func validatePanelReloadCandidate(current, candidate *panel.Config) error {
	err := panel.ValidateRuntimeConfigReload(current, candidate)
	if errors.Is(err, panel.ErrStaticRuntimeConfigEmptyNodes) {
		return errors.Join(errPanelReloadEmptyNodes, err)
	}
	return err
}
