package controller

import (
	"errors"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
)

type recordingPeriodic struct {
	interval time.Duration
	execute  func() error
	started  int
	closed   int
	closeErr error
}

func (p *recordingPeriodic) Start() error {
	p.started++
	return nil
}

func (p *recordingPeriodic) Close() error {
	p.closed++
	return p.closeErr
}

func TestNormalizeBaseConfigInterval(t *testing.T) {
	tests := []struct {
		name    string
		seconds int
		min     int
		want    int
	}{
		{name: "zero", seconds: 0, min: 30, want: 0},
		{name: "negative", seconds: -1, min: 30, want: 0},
		{name: "clamped", seconds: 5, min: 30, want: 30},
		{name: "unchanged", seconds: 60, min: 30, want: 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeBaseConfigInterval(tt.seconds, tt.min); got != tt.want {
				t.Fatalf("normalizeBaseConfigInterval(%d, %d) = %d, want %d", tt.seconds, tt.min, got, tt.want)
			}
		})
	}
}

func TestControllerApplyBaseConfigStartsAndReplacesIntervals(t *testing.T) {
	created := make([]*recordingPeriodic, 0)
	controller := &Controller{
		config: &Config{UpdatePeriodic: 60},
	}
	controller.newPeriodicTask = func(interval time.Duration, execute func() error) periodicRunner {
		periodic := &recordingPeriodic{interval: interval, execute: execute}
		created = append(created, periodic)
		return periodic
	}

	if err := controller.applyBaseConfig(apiBaseConfig(15, 45)); err != nil {
		t.Fatalf("applyBaseConfig returned error: %v", err)
	}
	if len(created) != 2 {
		t.Fatalf("expected two periodic tasks, got %d", len(created))
	}
	if created[0].interval != 45*time.Second || created[1].interval != 15*time.Second {
		t.Fatalf("unexpected intervals: pull=%s push=%s", created[0].interval, created[1].interval)
	}
	if created[0].started != 1 || created[1].started != 1 {
		t.Fatalf("expected both tasks to start once, got %d/%d", created[0].started, created[1].started)
	}

	if err := controller.applyBaseConfig(apiBaseConfig(3, 4)); err != nil {
		t.Fatalf("second applyBaseConfig returned error: %v", err)
	}
	if len(created) != 4 {
		t.Fatalf("expected replacement tasks, got %d", len(created))
	}
	if created[0].closed != 1 || created[1].closed != 1 {
		t.Fatalf("expected old tasks to close once, got %d/%d", created[0].closed, created[1].closed)
	}
	if created[2].interval != minBaseConfigPullInterval*time.Second || created[3].interval != minBaseConfigPushInterval*time.Second {
		t.Fatalf("unexpected clamped intervals: pull=%s push=%s", created[2].interval, created[3].interval)
	}
}

func TestControllerApplyBaseConfigIgnoresMissingIntervals(t *testing.T) {
	created := 0
	controller := &Controller{}
	controller.newPeriodicTask = func(interval time.Duration, execute func() error) periodicRunner {
		created++
		return &recordingPeriodic{interval: interval, execute: execute}
	}

	if err := controller.applyBaseConfig(nil); err != nil {
		t.Fatalf("nil applyBaseConfig returned error: %v", err)
	}
	if err := controller.applyBaseConfig(apiBaseConfig(0, 0)); err != nil {
		t.Fatalf("zero applyBaseConfig returned error: %v", err)
	}
	if created != 0 {
		t.Fatalf("expected no periodic tasks, got %d", created)
	}
}

func TestControllerApplyBaseConfigReturnsCloseError(t *testing.T) {
	closeErr := errors.New("close failed")
	created := make([]*recordingPeriodic, 0)
	controller := &Controller{}
	controller.newPeriodicTask = func(interval time.Duration, execute func() error) periodicRunner {
		periodic := &recordingPeriodic{interval: interval, execute: execute}
		created = append(created, periodic)
		return periodic
	}

	if err := controller.applyBaseConfig(apiBaseConfig(15, 45)); err != nil {
		t.Fatalf("initial applyBaseConfig returned error: %v", err)
	}
	created[0].closeErr = closeErr

	err := controller.applyBaseConfig(apiBaseConfig(20, 50))
	if !errors.Is(err, closeErr) {
		t.Fatalf("expected close error, got %v", err)
	}
}

func TestControllerStartPeriodicTasksUsesBaseConfigBeforeFallback(t *testing.T) {
	created := make([]*recordingPeriodic, 0)
	controller := &Controller{config: &Config{UpdatePeriodic: 60}}
	controller.newPeriodicTask = func(interval time.Duration, execute func() error) periodicRunner {
		periodic := &recordingPeriodic{interval: interval, execute: execute}
		created = append(created, periodic)
		return periodic
	}
	controller.apiClient = baseConfigAPI{BaseConfig: api.BaseConfig{PushInterval: 15, PullInterval: 45}}

	if err := controller.startControllerPeriodicTasks(&api.NodeInfo{}); err != nil {
		t.Fatalf("startControllerPeriodicTasks returned error: %v", err)
	}
	if len(created) != 2 {
		t.Fatalf("expected two periodic tasks, got %d", len(created))
	}
	if created[0].interval != 45*time.Second || created[1].interval != 15*time.Second {
		t.Fatalf("unexpected intervals: pull=%s push=%s", created[0].interval, created[1].interval)
	}
}

func TestControllerStartPeriodicTasksFallsBackToLocalUpdatePeriodic(t *testing.T) {
	created := make([]*recordingPeriodic, 0)
	controller := &Controller{config: &Config{UpdatePeriodic: 60}}
	controller.newPeriodicTask = func(interval time.Duration, execute func() error) periodicRunner {
		periodic := &recordingPeriodic{interval: interval, execute: execute}
		created = append(created, periodic)
		return periodic
	}

	if err := controller.startControllerPeriodicTasks(&api.NodeInfo{}); err != nil {
		t.Fatalf("startControllerPeriodicTasks returned error: %v", err)
	}
	if len(created) != 2 {
		t.Fatalf("expected two periodic tasks, got %d", len(created))
	}
	if created[0].interval != 60*time.Second || created[1].interval != 60*time.Second {
		t.Fatalf("unexpected fallback intervals: pull=%s push=%s", created[0].interval, created[1].interval)
	}
}

type baseConfigAPI struct {
	api.API
	api.BaseConfig
}

func (a baseConfigAPI) GetBaseConfig() *api.BaseConfig {
	baseConfig := a.BaseConfig
	return &baseConfig
}

func apiBaseConfig(push, pull int) *api.BaseConfig {
	return &api.BaseConfig{PushInterval: push, PullInterval: pull}
}
