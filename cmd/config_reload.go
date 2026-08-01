package cmd

import (
	"context"
	"errors"
	"fmt"
	"runtime"
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
	configFile         string
	lastAppliedAt      time.Time
	debounce           time.Duration
	loadCandidate      func(eventName, configuredFile string) (*panel.Config, error)
	validateCandidate  func(current, candidate *panel.Config) error
	buildRuntime       func(*panel.Config) panelRuntime
	applyProcessConfig func(*panel.Config)
	collectGarbage     func()
	now                func() time.Time
	observeOperation   func(panelReloadOperation, panelReloadOperationPhase)
}

type panelReloadModule struct {
	operationMu   operation.Gate
	stateMu       sync.RWMutex
	applied       panelReloadState
	configFile    string
	lastAppliedAt time.Time
	debounce      time.Duration
	loadCandidate func(eventName, configuredFile string) (*panel.Config, error)
	validate      func(current, candidate *panel.Config) error
	buildRuntime  func(*panel.Config) panelRuntime
	applyProcess  func(*panel.Config)
	collect       func()
	now           func() time.Time
	observeOp     func(panelReloadOperation, panelReloadOperationPhase)
}

func newPanelReloadModule(initialConfig *panel.Config, initialRuntime panelRuntime, options panelReloadOptions) *panelReloadModule {
	if options.debounce == 0 {
		options.debounce = 3 * time.Second
	}
	if options.loadCandidate == nil {
		options.loadCandidate = loadPanelReloadCandidate
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
	if options.lastAppliedAt.IsZero() {
		options.lastAppliedAt = options.now()
	}

	return &panelReloadModule{
		applied: panelReloadState{
			config:  initialConfig,
			runtime: initialRuntime,
			status:  panelReloadStatusReady,
		},
		configFile:    options.configFile,
		lastAppliedAt: options.lastAppliedAt,
		debounce:      options.debounce,
		loadCandidate: options.loadCandidate,
		validate:      options.validateCandidate,
		buildRuntime:  options.buildRuntime,
		applyProcess:  options.applyProcessConfig,
		collect:       options.collectGarbage,
		now:           options.now,
		observeOp:     options.observeOperation,
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
	candidateConfig, err := m.loadCandidate(eventName, m.configFile)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		log.Errorf("Hot reload: %v; keeping existing configuration", err)
		return err
	}
	if candidateConfig == nil {
		log.Errorf("Hot reload: %v; keeping existing configuration", errPanelReloadNilCandidate)
		return errPanelReloadNilCandidate
	}
	if err := m.validate(current.config, candidateConfig); err != nil {
		log.Warnf("Hot reload: candidate config validation failed; keeping existing configuration")
		return err
	}

	m.publishState(panelReloadState{
		config:  current.config,
		runtime: current.runtime,
		status:  panelReloadStatusReloading,
	})

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
			return joined
		}
	}
	m.publishState(panelReloadState{
		config: current.config,
		status: panelReloadStatusReloading,
	})
	m.collect()

	candidateRuntime := m.buildRuntime(candidateConfig)
	if candidateRuntime == nil {
		err := errors.New("build new panel: nil runtime")
		log.Error("Hot reload: failed to build new panel")
		return m.restoreLastKnownGoodContext(ctx, current, []error{err})
	}

	if err := startPanelRuntimeContext(ctx, candidateRuntime); err != nil {
		log.Error("Hot reload: failed to start new panel")
		errs := []error{fmt.Errorf("start new panel: %w", err)}
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
	m.applyProcess(candidateConfig)
	m.publishState(panelReloadState{
		config:  candidateConfig,
		runtime: candidateRuntime,
		status:  panelReloadStatusReady,
	})
	m.lastAppliedAt = m.now()
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
	snapshot := service.RuntimeSnapshot{
		Kind:      service.RuntimeKindPanel,
		Lifecycle: service.RuntimeLifecycleStopped,
		WebSocket: service.WebSocketDisabled,
	}
	if provider, ok := state.runtime.(service.RuntimeSnapshotProvider); ok {
		snapshot = provider.ObservabilitySnapshot()
	}
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
