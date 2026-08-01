package cmd

import (
	"context"
	"errors"
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
	"github.com/Mtoly/XrayRP/service"
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runContext(ctx)
}

func runContext(ctx context.Context) error {
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

	initialPanel := panel.New(panelConfig)
	reloader := newPanelReloadModule(panelConfig, initialPanel, panelReloadOptions{
		configFile:    cfgFile,
		lastAppliedAt: time.Now(),
	})
	observability, err := newObservabilityServer(panelConfig.Observability, reloader)
	if err != nil {
		return err
	}
	config.OnConfigChange(func(e fsnotify.Event) {
		if err := reloader.ReloadContext(ctx, e.Name); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("Hot reload failed")
		}
	})

	startCtx, startCancel := service.WithDefaultTimeout(ctx, service.DefaultStartTimeout)
	err = initialPanel.StartContext(startCtx)
	startCancel()
	if err != nil {
		cleanupCtx, cleanupCancel := service.CleanupContext(ctx)
		cleanupErr := reloader.CloseContext(cleanupCtx)
		cleanupCancel()
		return errors.Join(fmt.Errorf("failed to start panel: %w", err), cleanupErr)
	}
	if err := observability.StartContext(ctx); err != nil {
		cleanupCtx, cleanupCancel := service.CleanupContext(ctx)
		cleanupErr := reloader.CloseContext(cleanupCtx)
		cleanupCancel()
		return errors.Join(fmt.Errorf("failed to start observability server: %w", err), cleanupErr)
	}

	runtime.GC()
	<-ctx.Done()
	observability.BeginShutdown()

	shutdownCtx, shutdownCancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer shutdownCancel()
	panelCloseErr := reloader.CloseContext(shutdownCtx)
	observabilityCloseErr := observability.CloseContext(shutdownCtx)
	if panelCloseErr != nil {
		panelCloseErr = fmt.Errorf("failed to close panel: %w", panelCloseErr)
	}
	if observabilityCloseErr != nil {
		observabilityCloseErr = fmt.Errorf("failed to close observability server: %w", observabilityCloseErr)
	}
	return errors.Join(panelCloseErr, observabilityCloseErr)
}
func Execute() error {
	return rootCmd.Execute()
}
