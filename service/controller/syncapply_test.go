package controller

import (
	"context"
	"regexp"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/common/mylego"
)

type fakeSyncApplyAPI struct {
	nodeInfo   *api.NodeInfo
	userList   *[]api.UserInfo
	ruleList   *[]api.DetectRule
	certConfig *api.XrayRCertConfig
	aliveList  map[int][]string

	nodeErr error
	userErr error
	ruleErr error
	certErr error

	getNodeInfoCalls int
	getUserListCalls int
	getNodeRuleCalls int
	getCertCfgCalls  int
}

func (f *fakeSyncApplyAPI) GetNodeInfo() (*api.NodeInfo, error) {
	f.getNodeInfoCalls++
	return f.nodeInfo, f.nodeErr
}

func (f *fakeSyncApplyAPI) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	f.getCertCfgCalls++
	return f.certConfig, f.certErr
}

func (f *fakeSyncApplyAPI) GetUserList() (*[]api.UserInfo, error) {
	f.getUserListCalls++
	return f.userList, f.userErr
}

func (f *fakeSyncApplyAPI) GetAliveList() (map[int][]string, error) { return f.aliveList, nil }
func (f *fakeSyncApplyAPI) ReportNodeStatus(*api.NodeStatus) error  { return nil }
func (f *fakeSyncApplyAPI) ReportNodeOnlineUsers(*[]api.OnlineUser) error {
	return nil
}
func (f *fakeSyncApplyAPI) ReportUserTraffic(*[]api.UserTraffic) error { return nil }
func (f *fakeSyncApplyAPI) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: "https://panel.example", NodeID: 1, NodeType: "V2ray"}
}
func (f *fakeSyncApplyAPI) GetNodeRule() (*[]api.DetectRule, error) {
	f.getNodeRuleCalls++
	return f.ruleList, f.ruleErr
}
func (f *fakeSyncApplyAPI) ReportIllegal(*[]api.DetectResult) error { return nil }
func (f *fakeSyncApplyAPI) Debug()                                  {}

type syncApplyRecorder struct {
	appliedSnapshots    []syncApplySnapshot
	removedTags         []string
	addedTags           []string
	addUserCalls        int
	addLimiterCalls     int
	deleteLimiterCalls  int
	updateLimiterCalls  int
	rebuildInboundCalls int
	removedUsers        [][]string
	updateRuleCalls     int
	lastRuleTag         string
	lastRules           []api.DetectRule
	appliedCertConfigs  []*api.XrayRCertConfig
}

func newTestSyncApplyController(apiClient api.API) (*Controller, *syncApplyRecorder) {
	logger := log.NewEntry(log.New())
	recorder := &syncApplyRecorder{}
	controller := &Controller{
		config: &Config{
			ListenIP:       "127.0.0.1",
			UpdatePeriodic: 1,
			CertConfig: &mylego.CertConfig{
				CertMode: "dns",
			},
		},
		apiClient: apiClient,
		logger:    logger,
		startAt:   time.Now().Add(-time.Minute),
	}
	controller.syncApplyHooks = syncApplyHooks{
		removeOldTag: func(tag string) error {
			recorder.removedTags = append(recorder.removedTags, tag)
			return nil
		},
		addNewTag: func(_ *api.NodeInfo, tag string) error {
			recorder.addedTags = append(recorder.addedTags, tag)
			return nil
		},
		addNewUser: func(_ *[]api.UserInfo, _ *api.NodeInfo, _ string) error {
			recorder.addUserCalls++
			return nil
		},
		addInboundLimiter: func(string, uint64, *[]api.UserInfo, *limiter.GlobalDeviceLimitConfig) error {
			recorder.addLimiterCalls++
			return nil
		},
		deleteInboundLimiter: func(string) error {
			recorder.deleteLimiterCalls++
			return nil
		},
		updateInboundLimiter: func(string, *[]api.UserInfo) error {
			recorder.updateLimiterCalls++
			return nil
		},
		rebuildInboundWithUsers: func(*[]api.UserInfo, *api.NodeInfo, string) error {
			recorder.rebuildInboundCalls++
			return nil
		},
		removeUsers: func(users []string, _ string) error {
			copied := append([]string(nil), users...)
			recorder.removedUsers = append(recorder.removedUsers, copied)
			return nil
		},
		updateRule: func(tag string, rules []api.DetectRule) error {
			recorder.updateRuleCalls++
			recorder.lastRuleTag = tag
			recorder.lastRules = append([]api.DetectRule(nil), rules...)
			return nil
		},
		onSnapshotApplied: func(snapshot syncApplySnapshot) {
			recorder.appliedSnapshots = append(recorder.appliedSnapshots, snapshot)
		},
		onCertConfigApplied: func(cert *api.XrayRCertConfig) {
			recorder.appliedCertConfigs = append(recorder.appliedCertConfigs, clonePanelCertConfig(cert))
		},
	}
	return controller, recorder
}

func routePolicyWithCandidate(candidate string) *api.PanelRoutePolicy {
	return &api.PanelRoutePolicy{
		HasDirectBypass: true,
		Outbound: api.OutboundFilterPolicy{
			Candidates: []string{candidate},
			Include:    []string{candidate},
			Fallback:   []string{"direct"},
		},
	}
}

func TestSyncApply_WSTriggeredFetchUsesUnifiedApplyPipeline(t *testing.T) {
	restUsers := []api.UserInfo{{UID: 1, Email: "rest@example.com"}}
	restRules := []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("rest.example")}}
	fakeAPI := &fakeSyncApplyAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:    "V2ray",
			NodeID:      1,
			Port:        8443,
			SpeedLimit:  100,
			RoutePolicy: routePolicyWithCandidate("rest-candidate"),
		},
		userList: &restUsers,
		ruleList: &restRules,
	}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	currentNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, SpeedLimit: 10, RoutePolicy: routePolicyWithCandidate("old-candidate")}
	currentUsers := []api.UserInfo{{UID: 1, Email: "old@example.com"}}
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	controller.setUserList(&currentUsers)

	action, ok := syncActionFromWSEvent("resync_all", time.Now())
	if !ok {
		t.Fatal("expected websocket event to map to a sync action")
	}
	if err := controller.ExecuteSyncAction(context.Background(), action); err != nil {
		t.Fatalf("ExecuteSyncAction returned error: %v", err)
	}
	if len(recorder.appliedSnapshots) != 1 {
		t.Fatalf("expected ws-triggered sync to enter apply pipeline once, got %d", len(recorder.appliedSnapshots))
	}
	if recorder.appliedSnapshots[0].Action.Source != syncActionSourceWS {
		t.Fatalf("expected ws-triggered apply source, got %q", recorder.appliedSnapshots[0].Action.Source)
	}

	if err := controller.nodeInfoMonitor(); err != nil {
		t.Fatalf("nodeInfoMonitor returned error: %v", err)
	}
	if len(recorder.appliedSnapshots) != 2 {
		t.Fatalf("expected polling sync to reuse same apply pipeline, got %d entries", len(recorder.appliedSnapshots))
	}
	if recorder.appliedSnapshots[1].Action.Source != syncActionSourcePolling {
		t.Fatalf("expected polling apply source, got %q", recorder.appliedSnapshots[1].Action.Source)
	}
	if fakeAPI.getNodeInfoCalls != 2 || fakeAPI.getUserListCalls != 2 || fakeAPI.getNodeRuleCalls != 2 {
		t.Fatalf("expected both ws and polling paths to fetch REST snapshots, got node=%d users=%d rules=%d", fakeAPI.getNodeInfoCalls, fakeAPI.getUserListCalls, fakeAPI.getNodeRuleCalls)
	}
}

func TestSyncApply_CompareAndApplyNodeRouteAndCertChanges(t *testing.T) {
	restUsers := []api.UserInfo{{UID: 1, Email: "rest@example.com"}}
	restRules := []api.DetectRule{{ID: 2, Pattern: regexp.MustCompile("new.example")}}
	fakeAPI := &fakeSyncApplyAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:    "V2ray",
			NodeID:      1,
			Port:        443,
			SpeedLimit:  200,
			RoutePolicy: routePolicyWithCandidate("new-candidate"),
		},
		userList: &restUsers,
		ruleList: &restRules,
		certConfig: &api.XrayRCertConfig{
			Provider: "cloudflare",
			Email:    "ops@example.com",
			DNSEnv:   map[string]string{"CF_API_TOKEN": "token"},
		},
	}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	currentNode := &api.NodeInfo{
		NodeType:    "V2ray",
		NodeID:      1,
		Port:        443,
		SpeedLimit:  100,
		RoutePolicy: routePolicyWithCandidate("old-candidate"),
	}
	currentUsers := []api.UserInfo{{UID: 1, Email: "rest@example.com"}}
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	controller.setUserList(&currentUsers)
	controller.setAppliedRuleList([]api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("old.example")}})
	controller.config.CertConfig = &mylego.CertConfig{
		CertMode: "dns",
		Provider: "alidns",
		Email:    "old@example.com",
		DNSEnv:   map[string]string{"ALICLOUD_ACCESS_KEY": "old"},
	}

	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeResyncAll, syncActionSourceWS, syncActionMetadata{Trigger: "resync_all"})); err != nil {
		t.Fatalf("ExecuteSyncAction returned error: %v", err)
	}

	if len(recorder.removedTags) != 1 || len(recorder.addedTags) != 1 {
		t.Fatalf("expected compare-and-apply to rebuild node runtime once, got removed=%d added=%d", len(recorder.removedTags), len(recorder.addedTags))
	}
	if recorder.addUserCalls != 1 || recorder.addLimiterCalls != 1 || recorder.deleteLimiterCalls != 1 {
		t.Fatalf("expected node re-apply to re-add users and limiter once, got addUsers=%d addLimiter=%d deleteLimiter=%d", recorder.addUserCalls, recorder.addLimiterCalls, recorder.deleteLimiterCalls)
	}
	if recorder.updateRuleCalls != 1 {
		t.Fatalf("expected route/rule compare-and-apply once, got %d", recorder.updateRuleCalls)
	}
	if len(recorder.appliedCertConfigs) != 1 {
		t.Fatalf("expected cert compare-and-apply once, got %d", len(recorder.appliedCertConfigs))
	}
	if controller.config.CertConfig.Provider != "cloudflare" || controller.config.CertConfig.Email != "ops@example.com" {
		t.Fatalf("expected controller cert config to be updated from REST snapshot, got provider=%q email=%q", controller.config.CertConfig.Provider, controller.config.CertConfig.Email)
	}
	if got := controller.config.CertConfig.DNSEnv["CF_API_TOKEN"]; got != "token" {
		t.Fatalf("expected DNS env to be updated from REST snapshot, got %q", got)
	}
}

func TestSyncApply_UnchangedObjectsDoNotReapply(t *testing.T) {
	users := []api.UserInfo{{UID: 1, Email: "same@example.com"}}
	rules := []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("same.example")}}
	cert := &api.XrayRCertConfig{
		Provider: "cloudflare",
		Email:    "ops@example.com",
		DNSEnv:   map[string]string{"CF_API_TOKEN": "same-token"},
	}
	node := &api.NodeInfo{
		NodeType:    "V2ray",
		NodeID:      1,
		Port:        443,
		SpeedLimit:  100,
		RoutePolicy: routePolicyWithCandidate("same-candidate"),
	}
	fakeAPI := &fakeSyncApplyAPI{
		nodeInfo:   node,
		userList:   &users,
		ruleList:   &rules,
		certConfig: cert,
	}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	controller.setNodeState(node, controller.buildNodeTagFrom(node))
	controller.setUserList(&users)
	controller.setAppliedRuleList(rules)
	controller.config.CertConfig = &mylego.CertConfig{
		CertMode: "dns",
		Provider: cert.Provider,
		Email:    cert.Email,
		DNSEnv:   map[string]string{"CF_API_TOKEN": "same-token"},
	}

	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeResyncAll, syncActionSourceWS, syncActionMetadata{Trigger: "resync_all"})); err != nil {
		t.Fatalf("ExecuteSyncAction returned error: %v", err)
	}

	if len(recorder.removedTags) != 0 || len(recorder.addedTags) != 0 {
		t.Fatalf("expected unchanged node snapshot to skip rebuild, got removed=%d added=%d", len(recorder.removedTags), len(recorder.addedTags))
	}
	if recorder.addUserCalls != 0 || recorder.addLimiterCalls != 0 || recorder.deleteLimiterCalls != 0 || recorder.updateLimiterCalls != 0 || recorder.rebuildInboundCalls != 0 {
		t.Fatalf("expected unchanged user snapshot to skip apply, got addUsers=%d addLimiter=%d deleteLimiter=%d updateLimiter=%d rebuild=%d", recorder.addUserCalls, recorder.addLimiterCalls, recorder.deleteLimiterCalls, recorder.updateLimiterCalls, recorder.rebuildInboundCalls)
	}
	if len(recorder.removedUsers) != 0 {
		t.Fatalf("expected unchanged user snapshot to skip removals, got %d removal batches", len(recorder.removedUsers))
	}
	if recorder.updateRuleCalls != 0 {
		t.Fatalf("expected unchanged rule snapshot to skip apply, got %d", recorder.updateRuleCalls)
	}
	if len(recorder.appliedCertConfigs) != 0 {
		t.Fatalf("expected unchanged cert snapshot to skip apply, got %d", len(recorder.appliedCertConfigs))
	}
}

func TestSyncApply_WSComplexObjectsUseRestSnapshot(t *testing.T) {
	restUsers := []api.UserInfo{{UID: 1, Email: "rest@example.com"}}
	restRules := []api.DetectRule{{ID: 7, Pattern: regexp.MustCompile("rest.example")}}
	fakeAPI := &fakeSyncApplyAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:    "V2ray",
			NodeID:      1,
			Port:        8443,
			SpeedLimit:  100,
			RoutePolicy: routePolicyWithCandidate("rest-candidate"),
		},
		userList: &restUsers,
		ruleList: &restRules,
	}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	currentNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443, SpeedLimit: 10, RoutePolicy: routePolicyWithCandidate("old-candidate")}
	currentUsers := []api.UserInfo{{UID: 1, Email: "old@example.com"}}
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	controller.setUserList(&currentUsers)

	action := newSyncAction(syncActionTypeSyncRoutesAndOutbounds, syncActionSourceWS, syncActionMetadata{
		Trigger: "routes_changed",
		Reason:  "ws payload could be stale, complex objects must come from REST",
	})
	if err := controller.ExecuteSyncAction(context.Background(), action); err != nil {
		t.Fatalf("ExecuteSyncAction returned error: %v", err)
	}
	if fakeAPI.getNodeInfoCalls != 1 || fakeAPI.getNodeRuleCalls != 1 {
		t.Fatalf("expected ws-triggered sync to fetch complex objects from REST, got node=%d rules=%d", fakeAPI.getNodeInfoCalls, fakeAPI.getNodeRuleCalls)
	}
	if len(recorder.appliedSnapshots) != 1 || recorder.appliedSnapshots[0].NodeInfo == nil || recorder.appliedSnapshots[0].NodeInfo.RoutePolicy == nil {
		t.Fatal("expected apply pipeline to receive REST node snapshot with route policy")
	}
	if got := recorder.appliedSnapshots[0].NodeInfo.RoutePolicy.Outbound.Candidates[0]; got != "rest-candidate" {
		t.Fatalf("expected REST route policy candidate to drive apply pipeline, got %q", got)
	}
	if len(recorder.lastRules) != 1 || recorder.lastRules[0].Pattern.String() != "rest.example" {
		t.Fatalf("expected REST rule snapshot to drive apply pipeline, got %#v", recorder.lastRules)
	}
}
