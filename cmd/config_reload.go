package cmd

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/panel"
)

var (
	errPanelReloadNilCandidate = errors.New("panel reload candidate is nil")
	errPanelReloadEmptyNodes   = errors.New("panel reload candidate contains no nodes")
	errPanelReloadClosed       = errors.New("panel reload module is closed")
)

type panelRuntime interface {
	Start() error
	Close() error
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
	buildRuntime       func(*panel.Config) panelRuntime
	applyProcessConfig func(*panel.Config)
	collectGarbage     func()
	now                func() time.Time
	observeOperation   func(panelReloadOperation, panelReloadOperationPhase)
}

type panelReloadModule struct {
	operationMu   sync.Mutex
	stateMu       sync.RWMutex
	applied       panelReloadState
	configFile    string
	lastAppliedAt time.Time
	debounce      time.Duration
	loadCandidate func(eventName, configuredFile string) (*panel.Config, error)
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
		buildRuntime:  options.buildRuntime,
		applyProcess:  options.applyProcessConfig,
		collect:       options.collectGarbage,
		now:           options.now,
		observeOp:     options.observeOperation,
	}
}

func (m *panelReloadModule) Reload(eventName string) error {
	m.beginOperation(panelReloadOperationReload)
	defer m.endOperation(panelReloadOperationReload)

	current := m.stateSnapshot()
	if current.status == panelReloadStatusClosed {
		return errPanelReloadClosed
	}
	if !m.now().After(m.lastAppliedAt.Add(m.debounce)) {
		return nil
	}

	fmt.Println("Config file changed:", eventName)
	candidateConfig, err := m.loadCandidate(eventName, m.configFile)
	if err != nil {
		log.Errorf("Hot reload: %v; keeping existing configuration", err)
		return err
	}
	if candidateConfig == nil {
		log.Errorf("Hot reload: %v; keeping existing configuration", errPanelReloadNilCandidate)
		return errPanelReloadNilCandidate
	}
	if len(candidateConfig.NodesConfig) == 0 {
		log.Warnf("Hot reload: new config file %s contains no Nodes; ignoring reload to avoid stopping running services", eventName)
		return fmt.Errorf("%w: %s", errPanelReloadEmptyNodes, eventName)
	}
	candidateRuntime := m.buildRuntime(candidateConfig)
	if candidateRuntime == nil {
		err := errors.New("build new panel: nil runtime")
		log.Error("Hot reload: failed to build new panel")
		return err
	}

	m.publishState(panelReloadState{
		config:  current.config,
		runtime: current.runtime,
		status:  panelReloadStatusReloading,
	})

	var errs []error
	if current.runtime != nil {
		if err := current.runtime.Close(); err != nil {
			log.Error("Hot reload: failed to close old panel")
			errs = append(errs, fmt.Errorf("close old panel: %w", err))
			if cleanupErr := candidateRuntime.Close(); cleanupErr != nil {
				log.Error("Hot reload: failed to clean candidate panel")
				errs = append(errs, fmt.Errorf("clean candidate panel after old close failure: %w", cleanupErr))
			}
			return m.restoreLastKnownGood(current, errs)
		}
	}
	m.collect()

	if err := candidateRuntime.Start(); err != nil {
		log.Error("Hot reload: failed to start new panel")
		errs = append(errs, fmt.Errorf("start new panel: %w", err))
		if cleanupErr := candidateRuntime.Close(); cleanupErr != nil {
			log.Error("Hot reload: failed to clean candidate panel")
			errs = append(errs, fmt.Errorf("clean failed candidate panel: %w", cleanupErr))
		}
		return m.restoreLastKnownGood(current, errs)
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
	if m == nil {
		return nil
	}

	m.beginOperation(panelReloadOperationClose)
	defer m.endOperation(panelReloadOperationClose)

	current := m.stateSnapshot()
	if current.status == panelReloadStatusClosed {
		return nil
	}

	var closeErr error
	if current.runtime != nil {
		closeErr = current.runtime.Close()
	}
	m.publishState(panelReloadState{
		config:  current.config,
		status:  panelReloadStatusClosed,
		failure: closeErr,
	})
	return closeErr
}

func (m *panelReloadModule) restoreLastKnownGood(previous panelReloadState, errs []error) error {
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

	if err := restoredRuntime.Start(); err != nil {
		errs = append(errs, fmt.Errorf("restore old panel: %w", err))
		if cleanupErr := restoredRuntime.Close(); cleanupErr != nil {
			errs = append(errs, fmt.Errorf("clean failed restored panel: %w", cleanupErr))
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
	if m.observeOp != nil {
		m.observeOp(operation, panelReloadOperationAttempted)
	}
	m.operationMu.Lock()
	if m.observeOp != nil {
		m.observeOp(operation, panelReloadOperationEntered)
	}
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
