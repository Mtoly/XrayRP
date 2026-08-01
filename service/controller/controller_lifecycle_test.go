package controller

import (
	"errors"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/limiter"
)

func TestControllerStartUserFailureRollsBackRuntimeWithoutPublishingState(t *testing.T) {
	userErr := errors.New("add users failed")
	controller := newLifecycleTestController(newFakeControllerAPI(), false)
	var (
		activeTag    string
		cleanupCalls int
	)
	controller.syncApplyHooks.runtime.addTag = func(_ *api.NodeInfo, tag string, _ *Config) error {
		activeTag = tag
		return nil
	}
	controller.syncApplyHooks.runtime.addUsers = func(*[]api.UserInfo, *api.NodeInfo, string, *Config) error {
		return userErr
	}
	controller.syncApplyHooks.runtime.cleanupTag = func(_ *api.NodeInfo, tag string) error {
		cleanupCalls++
		if activeTag == tag {
			activeTag = ""
		}
		return nil
	}
	controller.syncCoordinatorFactory = func(syncActionExecutor) syncCoordinatorLifecycle {
		t.Fatal("sync coordinator must not start after user application failure")
		return nil
	}

	err := controller.Start()
	if !errors.Is(err, userErr) {
		t.Fatalf("Start() error = %v, want %v", err, userErr)
	}
	if cleanupCalls != 1 || activeTag != "" {
		t.Fatalf("runtime cleanup = calls:%d active:%q, want one cleanup and no active tag", cleanupCalls, activeTag)
	}
	nodeInfo, tag, users := controller.getStateSnapshot()
	if nodeInfo != nil || tag != "" || users != nil {
		t.Fatalf("failed Start published Node runtime state: node=%#v tag=%q users=%#v", nodeInfo, tag, users)
	}
}

func TestControllerStartCleanupFailureRetainsOwnershipUntilCloseRetry(t *testing.T) {
	userErr := errors.New("add users failed")
	cleanupErr := errors.New("runtime cleanup failed")
	controller := newLifecycleTestController(newFakeControllerAPI(), false)
	var (
		addCalls     int
		cleanupCalls int
	)
	controller.syncApplyHooks.runtime.addTag = func(*api.NodeInfo, string, *Config) error {
		addCalls++
		return nil
	}
	controller.syncApplyHooks.runtime.addUsers = func(*[]api.UserInfo, *api.NodeInfo, string, *Config) error {
		return userErr
	}
	controller.syncApplyHooks.runtime.cleanupTag = func(*api.NodeInfo, string) error {
		cleanupCalls++
		if cleanupCalls == 1 {
			return cleanupErr
		}
		return nil
	}

	err := controller.Start()
	if !errors.Is(err, userErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("Start() error = %v, want user and cleanup errors", err)
	}
	if err := controller.Start(); err == nil {
		t.Fatal("second Start() error = nil, want failed-owned rejection")
	}
	if addCalls != 1 || cleanupCalls != 1 {
		t.Fatalf("duplicate Start touched resources: add=%d cleanup=%d", addCalls, cleanupCalls)
	}
	if err := controller.Close(); err != nil {
		t.Fatalf("Close() retry error = %v", err)
	}
	if cleanupCalls != 2 {
		t.Fatalf("Close() cleanup calls = %d, want retry", cleanupCalls)
	}
	if err := controller.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if cleanupCalls != 2 {
		t.Fatalf("second Close() repeated cleanup: calls=%d", cleanupCalls)
	}
}

func TestControllerStartLimiterFailureRollsBackLimiterAndRuntime(t *testing.T) {
	limiterErr := errors.New("add limiter failed")
	controller := newLifecycleTestController(newFakeControllerAPI(), false)
	var (
		deleteLimiterCalls  int
		cleanupRuntimeCalls int
	)
	controller.syncApplyHooks.limiter.addInbound = func(string, uint64, *[]api.UserInfo, *limiter.GlobalDeviceLimitConfig) error {
		return limiterErr
	}
	controller.syncApplyHooks.limiter.deleteInbound = func(string) error {
		deleteLimiterCalls++
		return nil
	}
	controller.syncApplyHooks.runtime.cleanupTag = func(*api.NodeInfo, string) error {
		cleanupRuntimeCalls++
		return nil
	}
	controller.syncCoordinatorFactory = func(syncActionExecutor) syncCoordinatorLifecycle {
		t.Fatal("sync coordinator must not start after limiter failure")
		return nil
	}

	err := controller.Start()
	if !errors.Is(err, limiterErr) {
		t.Fatalf("Start() error = %v, want %v", err, limiterErr)
	}
	if deleteLimiterCalls != 1 || cleanupRuntimeCalls != 1 {
		t.Fatalf("cleanup calls = limiter:%d runtime:%d, want 1/1", deleteLimiterCalls, cleanupRuntimeCalls)
	}
}

func TestControllerStartRuleFailureRollsBackRulesLimiterAndRuntime(t *testing.T) {
	ruleErr := errors.New("apply rules failed")
	controller := newLifecycleTestController(newFakeControllerAPI(), false)
	controller.config.DisableGetRule = false
	var (
		ruleCalls           int
		deleteLimiterCalls  int
		cleanupRuntimeCalls int
	)
	controller.syncApplyHooks.updateRule = func(string, []api.DetectRule) error {
		ruleCalls++
		if ruleCalls == 1 {
			return ruleErr
		}
		return nil
	}
	controller.syncApplyHooks.limiter.deleteInbound = func(string) error {
		deleteLimiterCalls++
		return nil
	}
	controller.syncApplyHooks.runtime.cleanupTag = func(*api.NodeInfo, string) error {
		cleanupRuntimeCalls++
		return nil
	}
	controller.syncCoordinatorFactory = func(syncActionExecutor) syncCoordinatorLifecycle {
		t.Fatal("sync coordinator must not start after rule failure")
		return nil
	}

	err := controller.Start()
	if !errors.Is(err, ruleErr) {
		t.Fatalf("Start() error = %v, want %v", err, ruleErr)
	}
	if ruleCalls != 2 || deleteLimiterCalls != 1 || cleanupRuntimeCalls != 1 {
		t.Fatalf("cleanup calls = rules:%d limiter:%d runtime:%d, want 2/1/1", ruleCalls, deleteLimiterCalls, cleanupRuntimeCalls)
	}
}

func TestControllerStartPeriodicFailureRollsBackControlPlaneAndResources(t *testing.T) {
	periodicErr := errors.New("periodic start failed")
	controller := newLifecycleTestController(newFakeControllerAPI(), false)
	coordinator := &fakeLifecycleCoordinator{}
	controller.syncCoordinatorFactory = func(syncActionExecutor) syncCoordinatorLifecycle {
		return coordinator
	}
	controller.newPeriodicTask = func(time.Duration, func() error) periodicRunner {
		return failingPeriodic{err: periodicErr}
	}
	var (
		deleteLimiterCalls  int
		cleanupRuntimeCalls int
	)
	controller.syncApplyHooks.limiter.deleteInbound = func(string) error {
		deleteLimiterCalls++
		return nil
	}
	controller.syncApplyHooks.runtime.cleanupTag = func(*api.NodeInfo, string) error {
		cleanupRuntimeCalls++
		return nil
	}

	err := controller.Start()
	if !errors.Is(err, periodicErr) {
		t.Fatalf("Start() error = %v, want %v", err, periodicErr)
	}
	if !coordinator.stopped {
		t.Fatal("periodic failure did not stop sync coordinator")
	}
	if deleteLimiterCalls != 1 || cleanupRuntimeCalls != 1 {
		t.Fatalf("cleanup calls = limiter:%d runtime:%d, want 1/1", deleteLimiterCalls, cleanupRuntimeCalls)
	}
	nodeInfo, tag, users := controller.getStateSnapshot()
	if nodeInfo != nil || tag != "" || users != nil {
		t.Fatalf("periodic failure published Node runtime state: node=%#v tag=%q users=%#v", nodeInfo, tag, users)
	}
}
