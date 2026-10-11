package controller

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/stats"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/app/mydispatcher"
	"github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/common/rule"
)

type trafficReportAPI struct {
	fakeSyncApplyAPI
	reported []api.UserTraffic
	onReport func()
}

func (f *trafficReportAPI) ReportUserTraffic(traffic *[]api.UserTraffic) error {
	f.reported = append(f.reported, *traffic...)
	f.onReport()
	return nil
}

func TestUserInfoMonitorKeepsTrafficAddedDuringReport(t *testing.T) {
	panel := &trafficReportAPI{}
	controller, _ := newTestSyncApplyController(panel)
	controller.config.AutoSpeedLimitConfig = &AutoSpeedLimitConfig{}
	statsManager, err := stats.NewManager(context.Background(), &stats.Config{})
	if err != nil {
		t.Fatalf("stats.NewManager() error = %v", err)
	}
	controller.stm = statsManager
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	user := api.UserInfo{UID: 1, Email: "user@example.test"}
	controller.setUserList(&[]api.UserInfo{user})

	userTag := controller.buildUserTagFrom(user, tag)
	upCounter, err := statsManager.RegisterCounter("user>>>" + userTag + ">>>traffic>>>uplink")
	if err != nil {
		t.Fatalf("RegisterCounter(uplink) error = %v", err)
	}
	downCounter, err := statsManager.RegisterCounter("user>>>" + userTag + ">>>traffic>>>downlink")
	if err != nil {
		t.Fatalf("RegisterCounter(downlink) error = %v", err)
	}
	upCounter.Add(100)
	downCounter.Add(200)
	// Traffic keeps flowing while the report request is in flight.
	panel.onReport = func() {
		upCounter.Add(7)
		downCounter.Add(11)
	}

	panelLimiter := limiter.New()
	if err := panelLimiter.AddInboundLimiter(tag, 0, &[]api.UserInfo{user}, nil); err != nil {
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

	if err := controller.userInfoMonitor(); err != nil {
		t.Fatalf("userInfoMonitor() error = %v", err)
	}

	want := []api.UserTraffic{{UID: 1, Email: "user@example.test", Upload: 100, Download: 200}}
	if !reflect.DeepEqual(panel.reported, want) {
		t.Fatalf("reported traffic = %#v, want %#v", panel.reported, want)
	}
	if up, down := upCounter.Value(), downCounter.Value(); up != 7 || down != 11 {
		t.Fatalf("counters after report = up %d, down %d; want traffic added during report (7, 11)", up, down)
	}
}

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
