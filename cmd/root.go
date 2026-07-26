package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/panel"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use: "XrayR",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(); err != nil {
				if common.ShowErrorDetails() {
					log.Errorf("XrayR failed to start: %v", err)
				} else {
					log.Error("XrayR failed to start; error details omitted because they may contain credentials")
				}
				os.Exit(1)
			}
		},
	}
)

func init() {
	// Configure global logger time format.
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006/01/02 15:04:05.000000",
	})

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file for XrayR.")
}

func getConfig() (*viper.Viper, error) {
	config := viper.New()

	// Set custom path and name
	if cfgFile != "" {
		configName := path.Base(cfgFile)
		configFileExt := path.Ext(cfgFile)
		configNameOnly := strings.TrimSuffix(configName, configFileExt)
		configPath := path.Dir(cfgFile)
		config.SetConfigName(configNameOnly)
		config.SetConfigType(strings.TrimPrefix(configFileExt, "."))
		config.AddConfigPath(configPath)
		// Set ASSET Path and Config Path for XrayR
		os.Setenv("XRAY_LOCATION_ASSET", configPath)
		os.Setenv("XRAY_LOCATION_CONFIG", configPath)
	} else {
		// Set default config path
		config.SetConfigName("config")
		config.SetConfigType("yml")
		config.AddConfigPath(".")

	}

	if err := config.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config file error: %w", err)
	}

	config.WatchConfig() // Watch the config

	return config, nil
}

func run() error {
	showVersion()

	config, err := getConfig()
	if err != nil {
		return err
	}
	panelConfig := &panel.Config{}
	if err := config.Unmarshal(panelConfig); err != nil {
		return fmt.Errorf("Parse config file %v failed: %s \n", cfgFile, err)
	}

	applyPanelProcessConfig(panelConfig)

	// Create initial panel instance.
	initialPanel := panel.New(panelConfig)
	reloader := newPanelReloadModule(panelConfig, initialPanel, panelReloadOptions{
		configFile:    cfgFile,
		lastAppliedAt: time.Now(),
	})
	config.OnConfigChange(func(e fsnotify.Event) {
		_ = reloader.Reload(e.Name)
	})

	if err := initialPanel.Start(); err != nil {
		return fmt.Errorf("failed to start panel: %w", err)
	}
	defer func() {
		if err := reloader.Close(); err != nil {
			log.Error("Failed to close panel")
		}
	}()

	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()
	// Running backend
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	<-osSignals

	return nil
}

func Execute() error {
	return rootCmd.Execute()
}
