package cmd

import (
	"errors"
	"fmt"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/panel"
)

var (
	errPanelReloadNilCandidate = errors.New("panel reload candidate is nil")
	errPanelReloadEmptyNodes   = errors.New("panel reload candidate contains no nodes")
)

type panelRuntime interface {
	Start() error
	Close() error
}

type panelReloadState struct {
	config  *panel.Config
	runtime panelRuntime
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
}

type panelReloadModule struct {
	applied       panelReloadState
	configFile    string
	lastAppliedAt time.Time
	debounce      time.Duration
	loadCandidate func(eventName, configuredFile string) (*panel.Config, error)
	buildRuntime  func(*panel.Config) panelRuntime
	applyProcess  func(*panel.Config)
	collect       func()
	now           func() time.Time
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
		},
		configFile:    options.configFile,
		lastAppliedAt: options.lastAppliedAt,
		debounce:      options.debounce,
		loadCandidate: options.loadCandidate,
		buildRuntime:  options.buildRuntime,
		applyProcess:  options.applyProcessConfig,
		collect:       options.collectGarbage,
		now:           options.now,
	}
}

func (m *panelReloadModule) Reload(eventName string) error {
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

	var errs []error
	if err := m.applied.runtime.Close(); err != nil {
		log.Error("Hot reload: failed to close old panel")
		errs = append(errs, fmt.Errorf("close old panel: %w", err))
	}
	m.collect()

	m.applyProcess(candidateConfig)
	candidateRuntime := m.buildRuntime(candidateConfig)
	m.applied = panelReloadState{
		config:  candidateConfig,
		runtime: candidateRuntime,
	}
	if candidateRuntime == nil {
		errs = append(errs, errors.New("start new panel: nil runtime"))
		log.Error("Hot reload: failed to start new panel")
		return errors.Join(errs...)
	}
	if err := candidateRuntime.Start(); err != nil {
		log.Error("Hot reload: failed to start new panel")
		errs = append(errs, fmt.Errorf("start new panel: %w", err))
		return errors.Join(errs...)
	}

	m.lastAppliedAt = m.now()
	return errors.Join(errs...)
}

func (m *panelReloadModule) Close() error {
	if m == nil || m.applied.runtime == nil {
		return nil
	}
	return m.applied.runtime.Close()
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
