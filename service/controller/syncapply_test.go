package controller

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/app/mydispatcher"
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
	appliedSnapshotsMu      sync.Mutex
	appliedSnapshots        []syncApplySnapshot
	removedTags             []string
	addedTags               []string
	addedNodeInfos          []*api.NodeInfo
	addedUserTags           []string
	addedUserPayloads       [][]api.UserInfo
	updatedLimiterTags      []string
	updatedLimiterPayloads  [][]api.UserInfo
	addUserCalls            int
	addLimiterCalls         int
	deleteLimiterCalls      int
	updateLimiterCalls      int
	snapshotLimiterCalls    int
	restoreLimiterCalls     int
	applyGlobalDevicesCalls int
	removedUsers            [][]string
	updateRuleCalls         int
	lastRuleTag             string
	lastRules               []api.DetectRule
	updatedGlobalDeviceTags []string
	updatedGlobalDevices    []map[int][]string
	clearedGlobalDeviceTags []string
	addTagErr               error
	updateLimiterErr        error
	removeUsersErr          error
	addTagErrAtCall         int
	addTagCalls             int
	activeRuntimes          map[string]*api.NodeInfo
	activeLimiterTags       map[string]bool
}

func (r *syncApplyRecorder) recordAppliedSnapshot(snapshot syncApplySnapshot) {
	r.appliedSnapshotsMu.Lock()
	defer r.appliedSnapshotsMu.Unlock()
	r.appliedSnapshots = append(r.appliedSnapshots, snapshot)
}

func (r *syncApplyRecorder) appliedSnapshotCount() int {
	r.appliedSnapshotsMu.Lock()
	defer r.appliedSnapshotsMu.Unlock()
	return len(r.appliedSnapshots)
}

func (r *syncApplyRecorder) appliedSnapshotAt(index int) (syncApplySnapshot, bool) {
	r.appliedSnapshotsMu.Lock()
	defer r.appliedSnapshotsMu.Unlock()
	if index < 0 || index >= len(r.appliedSnapshots) {
		return syncApplySnapshot{}, false
	}
	return r.appliedSnapshots[index], true
}

func (r *syncApplyRecorder) recordAddNewUser(tag string, users *[]api.UserInfo) {
	r.addUserCalls++
	r.addedUserTags = append(r.addedUserTags, tag)
	r.addedUserPayloads = append(r.addedUserPayloads, cloneRecordedUsers(users))
}

func (r *syncApplyRecorder) recordUpdateInboundLimiter(tag string, users *[]api.UserInfo) {
	r.updateLimiterCalls++
	r.updatedLimiterTags = append(r.updatedLimiterTags, tag)
	r.updatedLimiterPayloads = append(r.updatedLimiterPayloads, cloneRecordedUsers(users))
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
		runtime: syncApplyRuntimeHooks{
			cleanupTag: func(_ *api.NodeInfo, tag string) error {
				recorder.removedTags = append(recorder.removedTags, tag)
				if recorder.activeRuntimes != nil {
					delete(recorder.activeRuntimes, tag)
				}
				return nil
			},
			addTag: func(nodeInfo *api.NodeInfo, tag string) error {
				recorder.addTagCalls++
				recorder.addedTags = append(recorder.addedTags, tag)
				recorder.addedNodeInfos = append(recorder.addedNodeInfos, cloneRecordedNodeInfo(nodeInfo))
				if recorder.addTagErr != nil && (recorder.addTagErrAtCall == 0 || recorder.addTagErrAtCall == recorder.addTagCalls) {
					return recorder.addTagErr
				}
				if recorder.activeRuntimes == nil {
					recorder.activeRuntimes = make(map[string]*api.NodeInfo)
				}
				recorder.activeRuntimes[tag] = cloneRecordedNodeInfo(nodeInfo)
				return nil
			},
			addUsers: func(users *[]api.UserInfo, _ *api.NodeInfo, tag string) error {
				recorder.recordAddNewUser(tag, users)
				return nil
			},
			removeUsers: func(users []string, _ string) error {
				copied := append([]string(nil), users...)
				recorder.removedUsers = append(recorder.removedUsers, copied)
				return recorder.removeUsersErr
			},
		},
		limiter: syncApplyLimiterHooks{
			addInbound: func(tag string, _ uint64, _ *[]api.UserInfo, _ *limiter.GlobalDeviceLimitConfig) error {
				recorder.addLimiterCalls++
				if recorder.activeLimiterTags == nil {
					recorder.activeLimiterTags = make(map[string]bool)
				}
				recorder.activeLimiterTags[tag] = true
				return nil
			},
			deleteInbound: func(tag string) error {
				recorder.deleteLimiterCalls++
				if recorder.activeLimiterTags != nil {
					delete(recorder.activeLimiterTags, tag)
				}
				return nil
			},
			updateInbound: func(tag string, users *[]api.UserInfo) error {
				recorder.recordUpdateInboundLimiter(tag, users)
				if recorder.updateLimiterErr != nil {
					return recorder.updateLimiterErr
				}
				if recorder.activeLimiterTags == nil {
					recorder.activeLimiterTags = make(map[string]bool)
				}
				recorder.activeLimiterTags[tag] = true
				return nil
			},
			snapshotInbound: func(string) (*limiter.InboundLimiterStateSnapshot, error) {
				recorder.snapshotLimiterCalls++
				return &limiter.InboundLimiterStateSnapshot{}, nil
			},
			restoreInbound: func(string, *limiter.InboundLimiterStateSnapshot) error {
				recorder.restoreLimiterCalls++
				return nil
			},
			applyGlobalDevices: func(tag string, apply globalDeviceApply) error {
				recorder.applyGlobalDevicesCalls++
				if apply.Clear {
					recorder.clearedGlobalDeviceTags = append(recorder.clearedGlobalDeviceTags, tag)
					return nil
				}
				recorder.updatedGlobalDeviceTags = append(recorder.updatedGlobalDeviceTags, tag)
				recorder.updatedGlobalDevices = append(recorder.updatedGlobalDevices, cloneRecordedGlobalDevices(apply.Devices))
				return nil
			},
		},
		updateRule: func(tag string, rules []api.DetectRule) error {
			recorder.updateRuleCalls++
			recorder.lastRuleTag = tag
			recorder.lastRules = append([]api.DetectRule(nil), rules...)
			return nil
		},
		onSnapshotApplied: func(snapshot syncApplySnapshot) {
			recorder.recordAppliedSnapshot(snapshot)
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

func cloneRecordedNodeInfo(nodeInfo *api.NodeInfo) *api.NodeInfo {
	if nodeInfo == nil {
		return nil
	}
	cloned := *nodeInfo
	if nodeInfo.RoutePolicy != nil {
		routePolicy := *nodeInfo.RoutePolicy
		routePolicy.DirectDomains = append([]string(nil), nodeInfo.RoutePolicy.DirectDomains...)
		routePolicy.Outbound = api.OutboundFilterPolicy{
			Candidates: append([]string(nil), nodeInfo.RoutePolicy.Outbound.Candidates...),
			Include:    append([]string(nil), nodeInfo.RoutePolicy.Outbound.Include...),
			Exclude:    append([]string(nil), nodeInfo.RoutePolicy.Outbound.Exclude...),
			Fallback:   append([]string(nil), nodeInfo.RoutePolicy.Outbound.Fallback...),
		}
		cloned.RoutePolicy = &routePolicy
	}
	return &cloned
}

func cloneRecordedUsers(users *[]api.UserInfo) []api.UserInfo {
	if users == nil {
		return nil
	}
	return append([]api.UserInfo(nil), (*users)...)
}

func cloneRecordedGlobalDevices(devices map[int][]string) map[int][]string {
	if devices == nil {
		return nil
	}
	cloned := make(map[int][]string, len(devices))
	for uid, ips := range devices {
		cloned[uid] = append([]string(nil), ips...)
	}
	return cloned
}

func assertUserPayload(t *testing.T, got, want []api.UserInfo) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected user payload:\n got: %#v\nwant: %#v", got, want)
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
			CertMode:   "file",
			CertDomain: "node.example.com",
			CertFile:   "/tmp/new.crt",
			KeyFile:    "/tmp/new.key",
			Provider:   "cloudflare",
			Email:      "ops@example.com",
			DNSEnv:     map[string]string{"CF_API_TOKEN": "token"},
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
		CertMode:   "dns",
		CertDomain: "old.example.com",
		Provider:   "alidns",
		Email:      "old@example.com",
		DNSEnv:     map[string]string{"ALICLOUD_ACCESS_KEY": "old"},
	}

	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeResyncAll, syncActionSourceWS, syncActionMetadata{Trigger: "resync_all"})); err != nil {
		t.Fatalf("ExecuteSyncAction returned error: %v", err)
	}

	if len(recorder.removedTags) != 1 || len(recorder.addedTags) != 1 {
		t.Fatalf("expected compare-and-apply to rebuild node runtime once, got removed=%d added=%d", len(recorder.removedTags), len(recorder.addedTags))
	}
	if len(recorder.addedNodeInfos) != 1 || recorder.addedNodeInfos[0] == nil || recorder.addedNodeInfos[0].RoutePolicy == nil {
		t.Fatal("expected rebuilt node apply to carry route policy into addNewTag")
	}
	if got := recorder.addedNodeInfos[0].RoutePolicy.Outbound.Candidates[0]; got != "new-candidate" {
		t.Fatalf("expected addNewTag to receive updated route policy candidate, got %q", got)
	}
	if recorder.addUserCalls != 1 || recorder.addLimiterCalls != 1 || recorder.deleteLimiterCalls != 1 {
		t.Fatalf("expected node re-apply to re-add users and limiter once, got addUsers=%d addLimiter=%d deleteLimiter=%d", recorder.addUserCalls, recorder.addLimiterCalls, recorder.deleteLimiterCalls)
	}
	if recorder.updateRuleCalls != 1 {
		t.Fatalf("expected route/rule compare-and-apply once, got %d", recorder.updateRuleCalls)
	}
	if controller.config.CertConfig.CertMode != "file" || controller.config.CertConfig.CertDomain != "node.example.com" {
		t.Fatalf("expected controller cert mode/domain to be updated from REST snapshot, got mode=%q domain=%q", controller.config.CertConfig.CertMode, controller.config.CertConfig.CertDomain)
	}
	if controller.config.CertConfig.CertFile != "/tmp/new.crt" || controller.config.CertConfig.KeyFile != "/tmp/new.key" {
		t.Fatalf("expected controller cert files to be updated from REST snapshot, got cert=%q key=%q", controller.config.CertConfig.CertFile, controller.config.CertConfig.KeyFile)
	}
	if controller.config.CertConfig.Provider != "cloudflare" || controller.config.CertConfig.Email != "ops@example.com" {
		t.Fatalf("expected controller cert config to be updated from REST snapshot, got provider=%q email=%q", controller.config.CertConfig.Provider, controller.config.CertConfig.Email)
	}
	if got := controller.config.CertConfig.DNSEnv["CF_API_TOKEN"]; got != "token" {
		t.Fatalf("expected DNS env to be updated from REST snapshot, got %q", got)
	}
}

func TestSyncApply_RoutePolicyOnlyChangeRebuildsThroughUnifiedApply(t *testing.T) {
	restUsers := []api.UserInfo{{UID: 1, Email: "same@example.com"}}
	currentRoutePolicy := routePolicyWithCandidate("old-candidate")
	nextRoutePolicy := routePolicyWithCandidate("route-only-candidate")
	fakeAPI := &fakeSyncApplyAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:    "V2ray",
			NodeID:      1,
			Port:        443,
			SpeedLimit:  100,
			RoutePolicy: nextRoutePolicy,
		},
		ruleList: &[]api.DetectRule{},
	}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	currentNode := &api.NodeInfo{
		NodeType:    "V2ray",
		NodeID:      1,
		Port:        443,
		SpeedLimit:  100,
		RoutePolicy: currentRoutePolicy,
	}
	currentUsers := append([]api.UserInfo(nil), restUsers...)
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	controller.setUserList(&currentUsers)

	action := newSyncAction(syncActionTypeSyncRoutesAndOutbounds, syncActionSourceWS, syncActionMetadata{Trigger: "routes_changed"})
	if err := controller.ExecuteSyncAction(context.Background(), action); err != nil {
		t.Fatalf("ExecuteSyncAction returned error: %v", err)
	}

	if fakeAPI.getNodeInfoCalls != 1 {
		t.Fatalf("expected route policy sync to fetch node info once, got %d", fakeAPI.getNodeInfoCalls)
	}
	if fakeAPI.getUserListCalls != 0 {
		t.Fatalf("expected route policy only sync to skip user fetch, got %d", fakeAPI.getUserListCalls)
	}
	if len(recorder.removedTags) != 1 || len(recorder.addedTags) != 1 {
		t.Fatalf("expected route policy only change to rebuild node runtime once, got removed=%d added=%d", len(recorder.removedTags), len(recorder.addedTags))
	}
	if recorder.addUserCalls != 1 || recorder.addLimiterCalls != 1 || recorder.deleteLimiterCalls != 1 {
		t.Fatalf("expected route policy only rebuild to re-apply users and limiter once, got addUsers=%d addLimiter=%d deleteLimiter=%d", recorder.addUserCalls, recorder.addLimiterCalls, recorder.deleteLimiterCalls)
	}
	if recorder.updateRuleCalls != 0 {
		t.Fatalf("expected no rule update when fetched rules are unchanged/empty, got %d", recorder.updateRuleCalls)
	}
	if len(recorder.addedNodeInfos) != 1 || recorder.addedNodeInfos[0] == nil || recorder.addedNodeInfos[0].RoutePolicy == nil {
		t.Fatal("expected route policy only rebuild to carry route policy into addNewTag")
	}
	if got := recorder.addedNodeInfos[0].RoutePolicy.Outbound.Candidates[0]; got != "route-only-candidate" {
		t.Fatalf("expected addNewTag to receive route-only candidate, got %q", got)
	}
	if len(recorder.appliedSnapshots) != 1 || recorder.appliedSnapshots[0].NodeInfo == nil || recorder.appliedSnapshots[0].NodeInfo.RoutePolicy == nil {
		t.Fatal("expected unified apply snapshot to include updated route policy")
	}
	if got := recorder.appliedSnapshots[0].NodeInfo.RoutePolicy.Outbound.Candidates[0]; got != "route-only-candidate" {
		t.Fatalf("expected unified apply snapshot to carry route-only candidate, got %q", got)
	}
	if got := controller.nodeInfo.RoutePolicy.Outbound.Candidates[0]; got != "route-only-candidate" {
		t.Fatalf("expected controller node state to persist updated route policy, got %q", got)
	}
}

func TestSyncApply_TagChangeWithSameRulesReappliesRulesThroughUnifiedApply(t *testing.T) {
	rules := []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("same.example")}}
	fakeAPI := &fakeSyncApplyAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:    "V2ray",
			NodeID:      2,
			Port:        443,
			SpeedLimit:  100,
			RoutePolicy: routePolicyWithCandidate("same-candidate"),
		},
		ruleList: &rules,
	}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	currentNode := &api.NodeInfo{
		NodeType:    "V2ray",
		NodeID:      1,
		Port:        443,
		SpeedLimit:  100,
		RoutePolicy: routePolicyWithCandidate("same-candidate"),
	}
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	controller.setAppliedRuleList(rules)

	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncRoutesAndOutbounds, syncActionSourceWS, syncActionMetadata{Trigger: "routes_changed"})); err != nil {
		t.Fatalf("ExecuteSyncAction returned error: %v", err)
	}

	if len(recorder.removedTags) != 1 || len(recorder.addedTags) != 1 {
		t.Fatalf("expected tag-changing route sync to rebuild node runtime once, got removed=%d added=%d", len(recorder.removedTags), len(recorder.addedTags))
	}
	if recorder.updateRuleCalls != 1 {
		t.Fatalf("expected same rules to re-apply once when tag changes, got %d", recorder.updateRuleCalls)
	}
	if recorder.lastRuleTag != recorder.addedTags[0] {
		t.Fatalf("expected rule re-apply to bind to new runtime tag %q, got %q", recorder.addedTags[0], recorder.lastRuleTag)
	}
	if recorder.lastRuleTag == recorder.removedTags[0] {
		t.Fatalf("expected rule re-apply to avoid stale runtime tag %q", recorder.removedTags[0])
	}
	if got := controller.getAppliedRuleTag(); got != recorder.addedTags[0] {
		t.Fatalf("expected controller rule state to track new runtime tag %q, got %q", recorder.addedTags[0], got)
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
	if recorder.addUserCalls != 0 || recorder.addLimiterCalls != 0 || recorder.deleteLimiterCalls != 0 || recorder.updateLimiterCalls != 0 {
		t.Fatalf("expected unchanged user snapshot to skip apply, got addUsers=%d addLimiter=%d deleteLimiter=%d updateLimiter=%d", recorder.addUserCalls, recorder.addLimiterCalls, recorder.deleteLimiterCalls, recorder.updateLimiterCalls)
	}
	if recorder.snapshotLimiterCalls != 0 || recorder.restoreLimiterCalls != 0 {
		t.Fatalf("expected unchanged user snapshot to skip limiter snapshot/restore, got snapshot=%d restore=%d", recorder.snapshotLimiterCalls, recorder.restoreLimiterCalls)
	}
	if len(recorder.removedUsers) != 0 {
		t.Fatalf("expected unchanged user snapshot to skip removals, got %d removal batches", len(recorder.removedUsers))
	}
	if recorder.updateRuleCalls != 0 {
		t.Fatalf("expected unchanged rule snapshot to skip apply, got %d", recorder.updateRuleCalls)
	}
	if controller.config.CertConfig == nil || controller.config.CertConfig.Provider != "cloudflare" || controller.config.CertConfig.Email != "ops@example.com" || controller.config.CertConfig.DNSEnv["CF_API_TOKEN"] != "same-token" {
		t.Fatalf("expected unchanged cert snapshot to keep existing cert config, got %#v", controller.config.CertConfig)
	}
}

func TestSyncApply_ClearFetchedCertConfig(t *testing.T) {
	fakeAPI := &fakeSyncApplyAPI{}
	controller, _ := newTestSyncApplyController(fakeAPI)
	controller.panelType = "SSPanel"
	controller.config.CertConfig = &mylego.CertConfig{
		CertMode: "dns",
		Provider: "cloudflare",
		Email:    "ops@example.com",
		DNSEnv:   map[string]string{"CF_API_TOKEN": "stale-token"},
	}

	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncCertConfig, syncActionSourceWS, syncActionMetadata{Trigger: "cert_changed"})); err != nil {
		t.Fatalf("ExecuteSyncAction returned error: %v", err)
	}

	if fakeAPI.getCertCfgCalls != 1 {
		t.Fatalf("expected cert sync to fetch cert config once, got %d", fakeAPI.getCertCfgCalls)
	}
	if controller.config.CertConfig != nil {
		t.Fatalf("expected fetched nil cert config to clear controller cert config, got %#v", controller.config.CertConfig)
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

func TestSyncApply_SyncDevicesUpdatesGlobalDeviceState(t *testing.T) {
	fakeAPI := &fakeSyncApplyAPI{}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	action := newSyncAction(syncActionTypeSyncDevices, syncActionSourceWS, syncActionMetadata{Trigger: newV2board.WSEventXboardSyncDevices})
	action.Payload.Devices = map[int][]string{1: []string{"192.0.2.1"}}
	if err := controller.ExecuteSyncAction(context.Background(), action); err != nil {
		t.Fatalf("ExecuteSyncAction: %v", err)
	}
	if recorder.applyGlobalDevicesCalls != 1 {
		t.Fatalf("global device apply calls=%d", recorder.applyGlobalDevicesCalls)
	}
	if recorder.updatedGlobalDeviceTags[0] != tag {
		t.Fatalf("bad update tag: got %q want %q", recorder.updatedGlobalDeviceTags[0], tag)
	}
	if recorder.updatedGlobalDevices[0][1][0] != "192.0.2.1" {
		t.Fatalf("bad devices: %#v", recorder.updatedGlobalDevices)
	}
	if fakeAPI.getNodeInfoCalls != 0 || fakeAPI.getUserListCalls != 0 {
		t.Fatalf("unexpected REST calls")
	}
}

func TestSyncApply_ClearGlobalDevicesClearsWithoutRestFetch(t *testing.T) {
	fakeAPI := &fakeSyncApplyAPI{}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	action := newSyncAction(syncActionTypeClearGlobalDevices, syncActionSourceReconnect, syncActionMetadata{Trigger: "ws_disconnect"})
	if err := controller.ExecuteSyncAction(context.Background(), action); err != nil {
		t.Fatalf("ExecuteSyncAction: %v", err)
	}
	if recorder.applyGlobalDevicesCalls != 1 {
		t.Fatalf("global device apply calls=%d", recorder.applyGlobalDevicesCalls)
	}
	if recorder.clearedGlobalDeviceTags[0] != tag {
		t.Fatalf("bad clear tag: got %q want %q", recorder.clearedGlobalDeviceTags[0], tag)
	}
	if fakeAPI.getNodeInfoCalls != 0 || fakeAPI.getUserListCalls != 0 {
		t.Fatalf("unexpected REST calls")
	}
}

func TestSyncApply_GlobalDeviceActionsNoopWithoutCurrentTag(t *testing.T) {
	fakeAPI := &fakeSyncApplyAPI{}
	controller, recorder := newTestSyncApplyController(fakeAPI)

	action := newSyncAction(syncActionTypeSyncDevices, syncActionSourceWS, syncActionMetadata{Trigger: newV2board.WSEventXboardSyncDevices})
	action.Payload.Devices = map[int][]string{1: []string{"192.0.2.1"}}
	if err := controller.ExecuteSyncAction(context.Background(), action); err != nil {
		t.Fatalf("ExecuteSyncAction sync devices without current tag: %v", err)
	}
	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeClearGlobalDevices, syncActionSourceReconnect, syncActionMetadata{Trigger: "ws_disconnect"})); err != nil {
		t.Fatalf("ExecuteSyncAction clear without current tag: %v", err)
	}
	if recorder.applyGlobalDevicesCalls != 0 {
		t.Fatalf("expected no global-device hook without current tag, got calls=%d", recorder.applyGlobalDevicesCalls)
	}
	if fakeAPI.getNodeInfoCalls != 0 || fakeAPI.getUserListCalls != 0 {
		t.Fatalf("unexpected REST calls")
	}
}

func TestSyncApply_GlobalDeviceActionsNoopWithoutRuntimeLimiter(t *testing.T) {
	fakeAPI := &fakeSyncApplyAPI{}
	controller, _ := newTestSyncApplyController(fakeAPI)
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	controller.setNodeState(node, controller.buildNodeTagFrom(node))
	controller.syncApplyHooks = syncApplyHooks{}

	action := newSyncAction(syncActionTypeSyncDevices, syncActionSourceWS, syncActionMetadata{Trigger: newV2board.WSEventXboardSyncDevices})
	action.Payload.Devices = map[int][]string{1: []string{"192.0.2.1"}}
	if err := controller.ExecuteSyncAction(context.Background(), action); err != nil {
		t.Fatalf("ExecuteSyncAction sync devices without dispatcher: %v", err)
	}
	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeClearGlobalDevices, syncActionSourceReconnect, syncActionMetadata{Trigger: "ws_disconnect"})); err != nil {
		t.Fatalf("ExecuteSyncAction clear without dispatcher: %v", err)
	}
	controller.dispatcher = &mydispatcher.DefaultDispatcher{}
	if err := controller.ExecuteSyncAction(context.Background(), action); err != nil {
		t.Fatalf("ExecuteSyncAction sync devices without limiter: %v", err)
	}
	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeClearGlobalDevices, syncActionSourceReconnect, syncActionMetadata{Trigger: "ws_disconnect"})); err != nil {
		t.Fatalf("ExecuteSyncAction clear without limiter: %v", err)
	}
	if fakeAPI.getNodeInfoCalls != 0 || fakeAPI.getUserListCalls != 0 {
		t.Fatalf("unexpected REST calls")
	}
}

func TestSyncApply_UserLimitOnlyChangeUpdatesInboundLimiter(t *testing.T) {
	currentUsers := []api.UserInfo{{UID: 1, Email: "user@example.com", UUID: "uuid-1", SpeedLimit: 100, DeviceLimit: 1}}
	nextUsers := []api.UserInfo{{UID: 1, Email: "user@example.com", UUID: "uuid-1", SpeedLimit: 200, DeviceLimit: 2}}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	fakeAPI := &fakeSyncApplyAPI{userList: &nextUsers}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	controller.setUserList(&currentUsers)

	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"})); err != nil {
		t.Fatalf("ExecuteSyncAction returned error: %v", err)
	}

	if len(recorder.removedUsers) != 0 || recorder.addUserCalls != 0 {
		t.Fatalf("expected limit-only change to skip runtime users, got removed=%d addUsers=%d", len(recorder.removedUsers), recorder.addUserCalls)
	}
	if recorder.updateLimiterCalls != 1 {
		t.Fatalf("expected one limiter update, got %d", recorder.updateLimiterCalls)
	}
	if len(recorder.updatedLimiterTags) != 1 || recorder.updatedLimiterTags[0] != tag {
		t.Fatalf("expected limiter update for tag %q, got %#v", tag, recorder.updatedLimiterTags)
	}
	if len(recorder.updatedLimiterPayloads) != 1 {
		t.Fatalf("expected one limiter update payload, got %d", len(recorder.updatedLimiterPayloads))
	}
	assertUserPayload(t, recorder.updatedLimiterPayloads[0], []api.UserInfo{nextUsers[0]})
	if len(recorder.addedUserPayloads) != 0 {
		t.Fatalf("expected no runtime add payloads, got %#v", recorder.addedUserPayloads)
	}
	if recorder.snapshotLimiterCalls != 1 || recorder.restoreLimiterCalls != 0 {
		t.Fatalf("expected limiter snapshot without restore, got snapshot=%d restore=%d", recorder.snapshotLimiterCalls, recorder.restoreLimiterCalls)
	}
	_, _, appliedUsers := controller.getStateSnapshot()
	if appliedUsers == nil || len(*appliedUsers) != 1 || (*appliedUsers)[0].SpeedLimit != 200 || (*appliedUsers)[0].DeviceLimit != 2 {
		t.Fatalf("expected committed user limits to be updated, got %#v", appliedUsers)
	}
}

func TestSyncApply_UUIDChangeIsRuntimeAffecting(t *testing.T) {
	currentUsers := []api.UserInfo{{UID: 1, Email: "user@example.com", UUID: "uuid-1", SpeedLimit: 100, DeviceLimit: 1}}
	nextUsers := []api.UserInfo{{UID: 1, Email: "user@example.com", UUID: "uuid-2", SpeedLimit: 100, DeviceLimit: 1}}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	fakeAPI := &fakeSyncApplyAPI{userList: &nextUsers}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	controller.setUserList(&currentUsers)

	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"})); err != nil {
		t.Fatalf("ExecuteSyncAction returned error: %v", err)
	}

	if recorder.updateLimiterCalls != 1 || recorder.addUserCalls != 1 {
		t.Fatalf("expected limiter update and runtime add, got updateLimiter=%d addUsers=%d", recorder.updateLimiterCalls, recorder.addUserCalls)
	}
	if len(recorder.updatedLimiterTags) != 1 || recorder.updatedLimiterTags[0] != tag {
		t.Fatalf("expected limiter update for tag %q, got %#v", tag, recorder.updatedLimiterTags)
	}
	if len(recorder.updatedLimiterPayloads) != 1 {
		t.Fatalf("expected one limiter update payload, got %d", len(recorder.updatedLimiterPayloads))
	}
	assertUserPayload(t, recorder.updatedLimiterPayloads[0], []api.UserInfo{nextUsers[0]})
	if len(recorder.addedUserTags) != 1 || recorder.addedUserTags[0] != tag {
		t.Fatalf("expected runtime add for tag %q, got %#v", tag, recorder.addedUserTags)
	}
	if len(recorder.addedUserPayloads) != 1 {
		t.Fatalf("expected one runtime add payload, got %d", len(recorder.addedUserPayloads))
	}
	assertUserPayload(t, recorder.addedUserPayloads[0], []api.UserInfo{nextUsers[0]})
	if len(recorder.removedUsers) != 1 || len(recorder.removedUsers[0]) != 1 || recorder.removedUsers[0][0] != tag+"|user@example.com|1" {
		t.Fatalf("expected old runtime user removal key, got %#v", recorder.removedUsers)
	}
	if recorder.snapshotLimiterCalls != 1 || recorder.restoreLimiterCalls != 0 {
		t.Fatalf("expected limiter snapshot without restore, got snapshot=%d restore=%d", recorder.snapshotLimiterCalls, recorder.restoreLimiterCalls)
	}
	_, _, appliedUsers := controller.getStateSnapshot()
	if appliedUsers == nil || len(*appliedUsers) != 1 || (*appliedUsers)[0].UUID != "uuid-2" {
		t.Fatalf("expected committed user UUID to be updated, got %#v", appliedUsers)
	}
}

func TestSyncApply_UserLimitOnlyUpdateFailureRestoresLimiterAndDoesNotCommitUserState(t *testing.T) {
	currentUsers := []api.UserInfo{{UID: 1, Email: "user@example.com", UUID: "uuid-1", SpeedLimit: 100, DeviceLimit: 1}}
	nextUsers := []api.UserInfo{{UID: 1, Email: "user@example.com", UUID: "uuid-1", SpeedLimit: 200, DeviceLimit: 2}}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	fakeAPI := &fakeSyncApplyAPI{userList: &nextUsers}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	recorder.updateLimiterErr = errors.New("limiter update failed")
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	controller.setUserList(&currentUsers)

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"}))
	if !errors.Is(err, recorder.updateLimiterErr) {
		t.Fatalf("expected limiter update failure, got %v", err)
	}
	if recorder.snapshotLimiterCalls != 1 || recorder.restoreLimiterCalls != 1 {
		t.Fatalf("expected limiter snapshot and restore once, got snapshot=%d restore=%d", recorder.snapshotLimiterCalls, recorder.restoreLimiterCalls)
	}
	if len(recorder.removedUsers) != 0 || recorder.addUserCalls != 0 {
		t.Fatalf("expected limiter failure to stop before runtime users, got removed=%d addUsers=%d", len(recorder.removedUsers), recorder.addUserCalls)
	}
	if len(recorder.updatedLimiterTags) != 1 || recorder.updatedLimiterTags[0] != tag {
		t.Fatalf("expected limiter update attempt for tag %q, got %#v", tag, recorder.updatedLimiterTags)
	}
	if len(recorder.updatedLimiterPayloads) != 1 {
		t.Fatalf("expected one limiter update payload, got %d", len(recorder.updatedLimiterPayloads))
	}
	assertUserPayload(t, recorder.updatedLimiterPayloads[0], []api.UserInfo{nextUsers[0]})
	if len(recorder.addedUserPayloads) != 0 {
		t.Fatalf("expected no runtime add payloads, got %#v", recorder.addedUserPayloads)
	}
	_, _, appliedUsers := controller.getStateSnapshot()
	if appliedUsers != &currentUsers || (*appliedUsers)[0].SpeedLimit != 100 || (*appliedUsers)[0].DeviceLimit != 1 {
		t.Fatalf("expected committed user state to retain old limits, got %#v", appliedUsers)
	}
}

func TestSyncApply_RuntimeAddFailureRestoresLimiterAndDoesNotCommitUserState(t *testing.T) {
	currentUsers := []api.UserInfo{{UID: 1, Email: "user@example.com", UUID: "uuid-1", SpeedLimit: 100, DeviceLimit: 1}}
	nextUsers := []api.UserInfo{{UID: 1, Email: "user@example.com", UUID: "uuid-2", SpeedLimit: 200, DeviceLimit: 2}}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	fakeAPI := &fakeSyncApplyAPI{userList: &nextUsers}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	tag := controller.buildNodeTagFrom(node)
	addUserErr := errors.New("add user failed")
	controller.syncApplyHooks.runtime.addUsers = func(users *[]api.UserInfo, _ *api.NodeInfo, tag string) error {
		recorder.recordAddNewUser(tag, users)
		return addUserErr
	}
	controller.setNodeState(node, tag)
	controller.setUserList(&currentUsers)

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"}))
	if !errors.Is(err, addUserErr) {
		t.Fatalf("expected runtime add failure, got %v", err)
	}
	if recorder.snapshotLimiterCalls != 1 || recorder.restoreLimiterCalls != 1 {
		t.Fatalf("expected limiter snapshot and restore once, got snapshot=%d restore=%d", recorder.snapshotLimiterCalls, recorder.restoreLimiterCalls)
	}
	if recorder.updateLimiterCalls != 1 || recorder.addUserCalls != 2 {
		t.Fatalf("expected limiter update, runtime add attempt, and rollback restore, got updateLimiter=%d addUsers=%d", recorder.updateLimiterCalls, recorder.addUserCalls)
	}
	if len(recorder.updatedLimiterTags) != 1 || recorder.updatedLimiterTags[0] != tag {
		t.Fatalf("expected limiter update for tag %q, got %#v", tag, recorder.updatedLimiterTags)
	}
	if len(recorder.updatedLimiterPayloads) != 1 {
		t.Fatalf("expected one limiter update payload, got %d", len(recorder.updatedLimiterPayloads))
	}
	assertUserPayload(t, recorder.updatedLimiterPayloads[0], []api.UserInfo{nextUsers[0]})
	if len(recorder.addedUserTags) != 2 || recorder.addedUserTags[0] != tag || recorder.addedUserTags[1] != tag {
		t.Fatalf("expected runtime add attempt and rollback restore for tag %q, got %#v", tag, recorder.addedUserTags)
	}
	if len(recorder.addedUserPayloads) != 2 {
		t.Fatalf("expected runtime add attempt plus old-user restore, got %d payloads", len(recorder.addedUserPayloads))
	}
	assertUserPayload(t, recorder.addedUserPayloads[0], []api.UserInfo{nextUsers[0]})
	assertUserPayload(t, recorder.addedUserPayloads[1], []api.UserInfo{currentUsers[0]})
	if len(recorder.removedUsers) != 2 || len(recorder.removedUsers[0]) != 1 || recorder.removedUsers[0][0] != tag+"|user@example.com|1" || len(recorder.removedUsers[1]) != 1 || recorder.removedUsers[1][0] != tag+"|user@example.com|1" {
		t.Fatalf("expected runtime update to remove old user then roll back partially added user, got %#v", recorder.removedUsers)
	}
	_, _, appliedUsers := controller.getStateSnapshot()
	if appliedUsers != &currentUsers || (*appliedUsers)[0].UUID != "uuid-1" || (*appliedUsers)[0].SpeedLimit != 100 || (*appliedUsers)[0].DeviceLimit != 1 {
		t.Fatalf("expected committed user state to retain old UUID and limits, got %#v", appliedUsers)
	}
}

func TestSyncApply_RuntimeRemoveFailureRestoresLimiterAndDoesNotCommitUserState(t *testing.T) {
	currentUsers := []api.UserInfo{{UID: 1, Email: "user@example.com", UUID: "uuid-1", SpeedLimit: 100, DeviceLimit: 1}}
	nextUsers := []api.UserInfo{{UID: 1, Email: "user@example.com", UUID: "uuid-2", SpeedLimit: 200, DeviceLimit: 2}}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	fakeAPI := &fakeSyncApplyAPI{userList: &nextUsers}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	tag := controller.buildNodeTagFrom(node)
	recorder.removeUsersErr = errors.New("remove user failed")
	controller.setNodeState(node, tag)
	controller.setUserList(&currentUsers)

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"}))
	if !errors.Is(err, recorder.removeUsersErr) {
		t.Fatalf("expected runtime remove failure, got %v", err)
	}
	if recorder.snapshotLimiterCalls != 1 || recorder.restoreLimiterCalls != 1 {
		t.Fatalf("expected limiter snapshot and restore once, got snapshot=%d restore=%d", recorder.snapshotLimiterCalls, recorder.restoreLimiterCalls)
	}
	if recorder.updateLimiterCalls != 1 || recorder.addUserCalls != 1 {
		t.Fatalf("expected limiter update and rollback restore after remove failure, got updateLimiter=%d addUsers=%d", recorder.updateLimiterCalls, recorder.addUserCalls)
	}
	if len(recorder.updatedLimiterTags) != 1 || recorder.updatedLimiterTags[0] != tag {
		t.Fatalf("expected limiter update for tag %q, got %#v", tag, recorder.updatedLimiterTags)
	}
	if len(recorder.updatedLimiterPayloads) != 1 {
		t.Fatalf("expected one limiter update payload, got %d", len(recorder.updatedLimiterPayloads))
	}
	assertUserPayload(t, recorder.updatedLimiterPayloads[0], []api.UserInfo{nextUsers[0]})
	if len(recorder.addedUserPayloads) != 1 {
		t.Fatalf("expected runtime restore payload after remove failure, got %#v", recorder.addedUserPayloads)
	}
	assertUserPayload(t, recorder.addedUserPayloads[0], []api.UserInfo{currentUsers[0]})
	if len(recorder.removedUsers) != 1 || len(recorder.removedUsers[0]) != 1 || recorder.removedUsers[0][0] != tag+"|user@example.com|1" {
		t.Fatalf("expected runtime update to attempt old user removal, got %#v", recorder.removedUsers)
	}
	_, _, appliedUsers := controller.getStateSnapshot()
	if appliedUsers != &currentUsers || (*appliedUsers)[0].UUID != "uuid-1" || (*appliedUsers)[0].SpeedLimit != 100 || (*appliedUsers)[0].DeviceLimit != 1 {
		t.Fatalf("expected committed user state to retain old UUID and limits, got %#v", appliedUsers)
	}
}

func TestSyncApply_UserDiffPayloadOrder(t *testing.T) {
	deletedUser := api.UserInfo{UID: 1, Email: "deleted@example.com", UUID: "uuid-deleted", SpeedLimit: 10, DeviceLimit: 1}
	runtimeCurrent := api.UserInfo{UID: 2, Email: "runtime@example.com", UUID: "uuid-runtime-old", SpeedLimit: 20, DeviceLimit: 1}
	limitCurrent := api.UserInfo{UID: 3, Email: "limit@example.com", UUID: "uuid-limit", SpeedLimit: 30, DeviceLimit: 1}
	addedUser := api.UserInfo{UID: 4, Email: "added@example.com", UUID: "uuid-added", SpeedLimit: 40, DeviceLimit: 1}
	runtimeNext := runtimeCurrent
	runtimeNext.UUID = "uuid-runtime-new"
	runtimeNext.SpeedLimit = 25
	limitNext := limitCurrent
	limitNext.SpeedLimit = 300
	limitNext.DeviceLimit = 3

	currentUsers := []api.UserInfo{deletedUser, runtimeCurrent, limitCurrent}
	nextUsers := []api.UserInfo{limitNext, addedUser, runtimeNext}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	fakeAPI := &fakeSyncApplyAPI{userList: &nextUsers}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	controller.setUserList(&currentUsers)

	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"})); err != nil {
		t.Fatalf("ExecuteSyncAction returned error: %v", err)
	}

	if recorder.updateLimiterCalls != 1 || recorder.addUserCalls != 1 {
		t.Fatalf("expected limiter update and runtime add once, got updateLimiter=%d addUsers=%d", recorder.updateLimiterCalls, recorder.addUserCalls)
	}
	if len(recorder.updatedLimiterPayloads) != 1 {
		t.Fatalf("expected one limiter update payload, got %d", len(recorder.updatedLimiterPayloads))
	}
	assertUserPayload(t, recorder.updatedLimiterPayloads[0], []api.UserInfo{addedUser, runtimeNext, limitNext})
	if len(recorder.removedUsers) != 1 {
		t.Fatalf("expected one runtime remove batch, got %#v", recorder.removedUsers)
	}
	wantRemovedUsers := []string{tag + "|deleted@example.com|1", tag + "|runtime@example.com|2"}
	if !reflect.DeepEqual(recorder.removedUsers[0], wantRemovedUsers) {
		t.Fatalf("unexpected runtime remove payload:\n got: %#v\nwant: %#v", recorder.removedUsers[0], wantRemovedUsers)
	}
	if len(recorder.addedUserPayloads) != 1 {
		t.Fatalf("expected one runtime add payload, got %d", len(recorder.addedUserPayloads))
	}
	assertUserPayload(t, recorder.addedUserPayloads[0], []api.UserInfo{addedUser, runtimeNext})
}

func TestSyncApply_NodeRebuildAddFailureKeepsOldRuntimeState(t *testing.T) {
	restUsers := []api.UserInfo{{UID: 1, Email: "rest@example.com"}}
	restRules := []api.DetectRule{{ID: 8, Pattern: regexp.MustCompile("new.example")}}
	fakeAPI := &fakeSyncApplyAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:    "V2ray",
			NodeID:      2,
			Port:        8443,
			SpeedLimit:  100,
			RoutePolicy: routePolicyWithCandidate("new-candidate"),
		},
		userList: &restUsers,
		ruleList: &restRules,
	}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	recorder.addTagErr = errors.New("add new tag failed")

	currentNode := &api.NodeInfo{
		NodeType:    "V2ray",
		NodeID:      1,
		Port:        443,
		SpeedLimit:  100,
		RoutePolicy: routePolicyWithCandidate("old-candidate"),
	}
	currentTag := controller.buildNodeTagFrom(currentNode)
	controller.setNodeState(currentNode, currentTag)
	controller.setUserList(&restUsers)
	controller.setAppliedRuleList([]api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("old.example")}})
	recorder.activeRuntimes = map[string]*api.NodeInfo{currentTag: cloneRecordedNodeInfo(currentNode)}
	recorder.activeLimiterTags = map[string]bool{currentTag: true}

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeResyncAll, syncActionSourceWS, syncActionMetadata{Trigger: "resync_all"}))
	if !errors.Is(err, recorder.addTagErr) {
		t.Fatalf("expected addNewTag failure to be returned, got %v", err)
	}
	if len(recorder.addedTags) != 1 {
		t.Fatalf("expected one addNewTag attempt before aborting, got %d", len(recorder.addedTags))
	}
	if len(recorder.removedTags) != 0 {
		t.Fatalf("expected old runtime tag to remain when addNewTag fails, got removed=%v", recorder.removedTags)
	}
	if recorder.deleteLimiterCalls != 0 {
		t.Fatalf("expected old limiter to remain untouched on addNewTag failure, got %d deletions", recorder.deleteLimiterCalls)
	}
	if recorder.addUserCalls != 0 || recorder.addLimiterCalls != 0 || recorder.updateRuleCalls != 0 {
		t.Fatalf("expected pipeline to stop before user/rule apply, got addUsers=%d addLimiter=%d updateRule=%d", recorder.addUserCalls, recorder.addLimiterCalls, recorder.updateRuleCalls)
	}
	if len(recorder.appliedSnapshots) != 0 {
		t.Fatalf("expected failed apply not to publish applied snapshot, got %d", len(recorder.appliedSnapshots))
	}
	if runtime := recorder.activeRuntimes[currentTag]; runtime == nil || runtime.NodeID != currentNode.NodeID || runtime.Port != currentNode.Port {
		t.Fatalf("expected old runtime to stay active after add failure, got %#v", runtime)
	}
	if len(recorder.activeRuntimes) != 1 {
		t.Fatalf("expected only old runtime to remain active, got %d runtimes", len(recorder.activeRuntimes))
	}
	if !recorder.activeLimiterTags[currentTag] || len(recorder.activeLimiterTags) != 1 {
		t.Fatalf("expected old limiter to stay active after add failure, got %#v", recorder.activeLimiterTags)
	}

	appliedNode, appliedTag, appliedUsers := controller.getStateSnapshot()
	if appliedNode != currentNode {
		t.Fatalf("expected controller node state to remain on old node, got %#v", appliedNode)
	}
	if appliedTag != currentTag {
		t.Fatalf("expected controller tag to remain %q, got %q", currentTag, appliedTag)
	}
	if appliedUsers != &restUsers {
		t.Fatalf("expected controller user state to remain unchanged, got %#v", appliedUsers)
	}
	if got := controller.getAppliedRuleTag(); got != currentTag {
		t.Fatalf("expected rule state to remain bound to old tag %q, got %q", currentTag, got)
	}
}

func TestSyncApply_SameTagRebuildAddFailureRestoresOldRuntimeState(t *testing.T) {
	restUsers := []api.UserInfo{{UID: 1, Email: "same@example.com"}}
	restRules := []api.DetectRule{{ID: 9, Pattern: regexp.MustCompile("same-tag.example")}}
	currentNode := &api.NodeInfo{
		NodeType:    "V2ray",
		NodeID:      1,
		Port:        443,
		SpeedLimit:  100,
		RoutePolicy: routePolicyWithCandidate("old-candidate"),
	}
	nextNode := &api.NodeInfo{
		NodeType:    "V2ray",
		NodeID:      1,
		Port:        443,
		SpeedLimit:  200,
		RoutePolicy: routePolicyWithCandidate("new-candidate"),
	}
	fakeAPI := &fakeSyncApplyAPI{
		nodeInfo: nextNode,
		userList: &restUsers,
		ruleList: &restRules,
	}
	controller, recorder := newTestSyncApplyController(fakeAPI)
	recorder.addTagErr = errors.New("same tag rebuild add failed")
	recorder.addTagErrAtCall = 1

	currentTag := controller.buildNodeTagFrom(currentNode)
	controller.setNodeState(currentNode, currentTag)
	controller.setUserList(&restUsers)
	controller.setAppliedRuleList([]api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("old.example")}})
	recorder.activeRuntimes = map[string]*api.NodeInfo{currentTag: cloneRecordedNodeInfo(currentNode)}
	recorder.activeLimiterTags = map[string]bool{currentTag: true}

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeResyncAll, syncActionSourceWS, syncActionMetadata{Trigger: "resync_all"}))
	if !errors.Is(err, recorder.addTagErr) {
		t.Fatalf("expected same-tag addNewTag failure to be returned, got %v", err)
	}
	if recorder.addTagCalls != 2 {
		t.Fatalf("expected same-tag rebuild failure to attempt add then restore, got %d add calls", recorder.addTagCalls)
	}
	if len(recorder.removedTags) != 2 || recorder.removedTags[0] != currentTag || recorder.removedTags[1] != currentTag {
		t.Fatalf("expected same-tag rebuild to remove old runtime and cleanup failed replacement, got %v", recorder.removedTags)
	}
	if runtime := recorder.activeRuntimes[currentTag]; runtime == nil || runtime.NodeID != currentNode.NodeID || runtime.SpeedLimit != currentNode.SpeedLimit {
		t.Fatalf("expected old runtime to be restored after same-tag add failure, got %#v", runtime)
	}
	if len(recorder.activeRuntimes) != 1 {
		t.Fatalf("expected only restored old runtime to remain active, got %d runtimes", len(recorder.activeRuntimes))
	}
	if recorder.deleteLimiterCalls != 0 {
		t.Fatalf("expected old limiter to remain untouched during failed same-tag rebuild, got %d deletions", recorder.deleteLimiterCalls)
	}
	if !recorder.activeLimiterTags[currentTag] || len(recorder.activeLimiterTags) != 1 {
		t.Fatalf("expected old limiter to stay active after same-tag add failure, got %#v", recorder.activeLimiterTags)
	}
	if recorder.addUserCalls != 1 || recorder.addLimiterCalls != 0 || recorder.updateRuleCalls != 0 {
		t.Fatalf("expected only rollback user restore before aborting downstream apply on same-tag failure, got addUsers=%d addLimiter=%d updateRule=%d", recorder.addUserCalls, recorder.addLimiterCalls, recorder.updateRuleCalls)
	}
	if len(recorder.appliedSnapshots) != 0 {
		t.Fatalf("expected failed same-tag apply not to publish applied snapshot, got %d", len(recorder.appliedSnapshots))
	}

	appliedNode, appliedTag, appliedUsers := controller.getStateSnapshot()
	if appliedNode != currentNode {
		t.Fatalf("expected controller node state to remain on old node after same-tag failure, got %#v", appliedNode)
	}
	if appliedTag != currentTag {
		t.Fatalf("expected controller tag to remain %q after same-tag failure, got %q", currentTag, appliedTag)
	}
	if appliedUsers != &restUsers {
		t.Fatalf("expected controller user state to remain unchanged after same-tag failure, got %#v", appliedUsers)
	}
	if got := controller.getAppliedRuleTag(); got != currentTag {
		t.Fatalf("expected rule state to remain bound to old tag %q after same-tag failure, got %q", currentTag, got)
	}
}
