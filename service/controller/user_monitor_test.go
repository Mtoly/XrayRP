package controller

import (
	"reflect"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/app/mydispatcher"
	"github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/common/rule"
)

func TestUserInfoMonitorHoldsReloadLockWhileApplyingAutoLimitChanges(t *testing.T) {
	controller, _ := newTestSyncApplyController(&fakeSyncApplyAPI{})
	controller.config.AutoSpeedLimitConfig = &AutoSpeedLimitConfig{
		Limit:         1,
		LimitSpeed:    8,
		LimitDuration: 1,
	}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	emptyUsers := []api.UserInfo{}
	controller.setUserList(&emptyUsers)

	expired := api.UserInfo{UID: 1, Email: "expired@example.test", SpeedLimit: 100}
	panelLimiter := limiter.New()
	if err := panelLimiter.AddInboundLimiter(tag, 0, &[]api.UserInfo{expired}, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	t.Cleanup(func() {
		if err := panelLimiter.Close(); err != nil {
			t.Errorf("Limiter.Close() error = %v", err)
		}
	})
	controller.dispatcher = &mydispatcher.DefaultDispatcher{
		Limiter:     panelLimiter,
		RuleManager: rule.New(),
	}
	controller.limitedUsers = map[api.UserInfo]LimitInfo{
		expired: {
			end:               time.Now().Add(-time.Minute).Unix(),
			currentSpeedLimit: 8,
			originSpeedLimit:  expired.SpeedLimit,
		},
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	monitorDone := make(chan error, 1)
	controller.beforeUserMonitorLimiterUpdate = func() {
		close(entered)
		<-release
	}
	go func() {
		monitorDone <- controller.userInfoMonitor()
	}()
	<-entered

	reloadLockWasFree := controller.reloadMu.TryLock()
	if reloadLockWasFree {
		controller.reloadMu.Unlock()
	}
	close(release)
	if err := <-monitorDone; err != nil {
		t.Fatalf("userInfoMonitor() error = %v", err)
	}
	if reloadLockWasFree {
		t.Fatal("user monitor applied an auto-limit change without holding reloadMu")
	}
}

func TestUserInfoMonitorLimiterFailurePreservesAppliedAutoLimitOverlay(t *testing.T) {
	controller, _ := newTestSyncApplyController(&fakeSyncApplyAPI{})
	controller.config.AutoSpeedLimitConfig = &AutoSpeedLimitConfig{
		Limit:         1,
		LimitSpeed:    8,
		LimitDuration: 1,
	}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	emptyUsers := []api.UserInfo{}
	controller.setUserList(&emptyUsers)

	expired := api.UserInfo{UID: 1, Email: "expired@example.test", SpeedLimit: 100}
	appliedLimited := map[api.UserInfo]LimitInfo{
		expired: {
			end:               time.Now().Add(-time.Minute).Unix(),
			currentSpeedLimit: 8,
			originSpeedLimit:  expired.SpeedLimit,
		},
	}
	controller.limitedUsers = cloneMap(appliedLimited)
	controller.dispatcher = &mydispatcher.DefaultDispatcher{
		Limiter:     limiter.New(),
		RuleManager: rule.New(),
	}
	t.Cleanup(func() {
		if err := controller.dispatcher.Limiter.Close(); err != nil {
			t.Errorf("Limiter.Close() error = %v", err)
		}
	})

	err := controller.userInfoMonitor()
	if err == nil {
		t.Fatal("userInfoMonitor() returned nil after limiter update failure")
	}
	if !reflect.DeepEqual(controller.limitedUsers, appliedLimited) {
		t.Fatalf("limiter failure changed applied auto-limit state:\n got: %#v\nwant: %#v", controller.limitedUsers, appliedLimited)
	}
}
