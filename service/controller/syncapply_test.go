package controller

import (
	"context"
	"errors"
	"fmt"
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

func TestFetchSyncApplySnapshotUsesCurrentStateForWrappedNotModifiedErrors(t *testing.T) {
	currentNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	currentUsers := []api.UserInfo{{UID: 1, Email: "current@example.com"}}
	currentRules := []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("current.example")}}

	tests := []struct {
		name      string
		configure func(*fakeSyncApplyAPI)
		action    syncAction
		assert    func(*testing.T, syncApplySnapshot)
	}{
		{
			name: "node",
			configure: func(client *fakeSyncApplyAPI) {
				client.nodeErr = fmt.Errorf("fetch node: %w", api.ErrNodeNotModified)
				client.ruleList = &currentRules
			},
			action: newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourcePolling, syncActionMetadata{}),
			assert: func(t *testing.T, snapshot syncApplySnapshot) {
				if snapshot.NodeInfo == currentNode || !reflect.DeepEqual(snapshot.NodeInfo, currentNode) {
					t.Fatalf("expected an owned copy of current node state, got %#v", snapshot.NodeInfo)
				}
			},
		},
		{
			name: "user",
			configure: func(client *fakeSyncApplyAPI) {
				client.userErr = fmt.Errorf("fetch users: %w", api.ErrUserNotModified)
			},
			action: newSyncAction(syncActionTypeSyncUsers, syncActionSourcePolling, syncActionMetadata{}),
			assert: func(t *testing.T, snapshot syncApplySnapshot) {
				if snapshot.UserList == &currentUsers || snapshot.UserList == nil || !reflect.DeepEqual(*snapshot.UserList, currentUsers) {
					t.Fatalf("expected an owned copy of current user state, got %#v", snapshot.UserList)
				}
			},
		},
		{
			name: "rule",
			configure: func(client *fakeSyncApplyAPI) {
				client.nodeInfo = currentNode
				client.ruleErr = fmt.Errorf("fetch rules: %w", api.ErrRuleNotModified)
			},
			action: newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourcePolling, syncActionMetadata{}),
			assert: func(t *testing.T, snapshot syncApplySnapshot) {
				if snapshot.RuleList == nil || !reflect.DeepEqual(*snapshot.RuleList, currentRules) {
					t.Fatalf("expected current rule state, got %#v", snapshot.RuleList)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeSyncApplyAPI{}
			test.configure(client)
			controller, _ := newTestSyncApplyController(client)
			controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
			controller.setUserList(&currentUsers)
			controller.setAppliedRuleList(currentRules)

			snapshot, err := newNodeRuntimeStateApplyModule(controller).fetchSyncApplySnapshot(test.action)
			if err != nil {
				t.Fatalf("fetchSyncApplySnapshot returned wrapped not-modified error: %v", err)
			}
			test.assert(t, snapshot)
		})
	}
}

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
	addedCertConfigs        []*mylego.CertConfig
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
	activeRules             map[string][]api.DetectRule
	updatedGlobalDeviceTags []string
	updatedGlobalDevices    []map[int][]string
	clearedGlobalDeviceTags []string
	addTagErr               error
	updateLimiterErr        error
	removeUsersErr          error
	cleanupTagErr           error
	cleanupTagErrAtCall     int
	cleanupTagCalls         int
	addTagErrAtCall         int
	addTagCalls             int
	onAddTag                func(*Config)
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

func newTestSyncApplyController(apiClient PanelClient) (*Controller, *syncApplyRecorder) {
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
				recorder.cleanupTagCalls++
				recorder.removedTags = append(recorder.removedTags, tag)
				if recorder.activeRuntimes != nil {
					delete(recorder.activeRuntimes, tag)
				}
				if recorder.cleanupTagErr != nil &&
					(recorder.cleanupTagErrAtCall == 0 || recorder.cleanupTagErrAtCall == recorder.cleanupTagCalls) {
					return recorder.cleanupTagErr
				}
				return nil
			},
			addTag: func(nodeInfo *api.NodeInfo, tag string, config *Config) error {
				recorder.addTagCalls++
				recorder.addedTags = append(recorder.addedTags, tag)
				recorder.addedNodeInfos = append(recorder.addedNodeInfos, cloneRecordedNodeInfo(nodeInfo))
				recorder.addedCertConfigs = append(recorder.addedCertConfigs, cloneRuntimeCertConfig(config.CertConfig))
				if recorder.onAddTag != nil {
					recorder.onAddTag(config)
				}
				if recorder.addTagErr != nil && (recorder.addTagErrAtCall == 0 || recorder.addTagErrAtCall == recorder.addTagCalls) {
					return recorder.addTagErr
				}
				if recorder.activeRuntimes == nil {
					recorder.activeRuntimes = make(map[string]*api.NodeInfo)
				}
				recorder.activeRuntimes[tag] = cloneRecordedNodeInfo(nodeInfo)
				return nil
			},
			addUsers: func(users *[]api.UserInfo, _ *api.NodeInfo, tag string, _ *Config) error {
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
			replaceInbound: func(tag string, users *[]api.UserInfo) error {
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
			restoreInbound: func(tag string, _ *limiter.InboundLimiterStateSnapshot) error {
				recorder.restoreLimiterCalls++
				if recorder.activeLimiterTags == nil {
					recorder.activeLimiterTags = make(map[string]bool)
				}
				recorder.activeLimiterTags[tag] = true
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
			if recorder.activeRules == nil {
				recorder.activeRules = make(map[string][]api.DetectRule)
			}
			if len(rules) == 0 {
				delete(recorder.activeRules, tag)
			} else {
				recorder.activeRules[tag] = cloneDetectRules(rules)
			}
			return nil
		},
		retireRuleTag: func(oldTag, replacementTag string) {
			if recorder.activeRules == nil {
				return
			}
			delete(recorder.activeRules, oldTag)
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
	if len(recorder.addedCertConfigs) != 1 ||
		recorder.addedCertConfigs[0] == nil ||
		recorder.addedCertConfigs[0].CertFile != "/tmp/new.crt" ||
		recorder.addedCertConfigs[0].KeyFile != "/tmp/new.key" {
		t.Fatalf("expected node runtime build to receive the same snapshot's certificate config, got %#v", recorder.addedCertConfigs)
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
	if got := controller.runtimeStateSnapshot().node.snapshot().RoutePolicy.Outbound.Candidates[0]; got != "route-only-candidate" {
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
	currentTag := controller.buildNodeTagFrom(currentNode)
	controller.setNodeState(currentNode, currentTag)
	controller.setAppliedRuleList(rules)
	recorder.activeRules = map[string][]api.DetectRule{
		currentTag: cloneDetectRules(rules),
	}

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
	if _, retained := recorder.activeRules[currentTag]; retained {
		t.Fatalf("successful tag change retained rules for old tag %q", currentTag)
	}
	if got := recorder.activeRules[recorder.addedTags[0]]; !reflect.DeepEqual(got, rules) {
		t.Fatalf("rules for new tag = %#v, want %#v", got, rules)
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

func TestSyncApply_CertOnlyBuildFailurePreservesAppliedConfigAndRuntime(t *testing.T) {
	buildErr := errors.New("candidate TLS runtime build failed")
	nextCert := &api.XrayRCertConfig{
		CertMode:   "file",
		CertDomain: "new.example.com",
		CertFile:   "/candidate/new.crt",
		KeyFile:    "/candidate/new.key",
	}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{certConfig: nextCert})
	currentNode := &api.NodeInfo{
		NodeType:  "V2ray",
		NodeID:    1,
		Port:      443,
		EnableTLS: true,
	}
	currentUsers := []api.UserInfo{}
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	controller.setUserList(&currentUsers)
	oldCert := &mylego.CertConfig{
		CertMode:   "file",
		CertDomain: "old.example.com",
		CertFile:   "/applied/old.crt",
		KeyFile:    "/applied/old.key",
	}
	controller.config.CertConfig = oldCert
	recorder.addTagErr = buildErr
	recorder.addTagErrAtCall = 1

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncCertConfig, syncActionSourceWS, syncActionMetadata{Trigger: "cert_changed"}))

	if !errors.Is(err, buildErr) {
		t.Fatalf("ExecuteSyncAction() error = %v, want %v", err, buildErr)
	}
	if controller.config.CertConfig != oldCert {
		t.Fatalf("failed certificate runtime build published config %#v", controller.config.CertConfig)
	}
	appliedNode, appliedTag, _ := controller.getStateSnapshot()
	if !reflect.DeepEqual(appliedNode, currentNode) || appliedTag != controller.buildNodeTagFrom(currentNode) {
		t.Fatalf("failed certificate runtime build changed applied node: node=%v tag=%q", appliedNode, appliedTag)
	}
	if len(recorder.removedTags) != 2 || recorder.addTagCalls != 2 {
		t.Fatalf("candidate failure did not restore same-tag runtime: removed=%d addCalls=%d", len(recorder.removedTags), recorder.addTagCalls)
	}
}

func TestSyncApply_CertOnlyCleanupFailureAttemptsLastKnownGoodRestore(t *testing.T) {
	cleanupErr := errors.New("old TLS runtime cleanup failed")
	restoreErr := errors.New("last-known-good TLS runtime restore failed")
	nextCert := &api.XrayRCertConfig{
		CertMode:   "file",
		CertDomain: "new.example.com",
		CertFile:   "/candidate/new.crt",
		KeyFile:    "/candidate/new.key",
	}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{certConfig: nextCert})
	currentNode := &api.NodeInfo{
		NodeType:  "V2ray",
		NodeID:    1,
		Port:      443,
		EnableTLS: true,
	}
	currentUsers := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	controller.setUserList(&currentUsers)
	oldCert := &mylego.CertConfig{
		CertMode:   "file",
		CertDomain: "old.example.com",
		CertFile:   "/applied/old.crt",
		KeyFile:    "/applied/old.key",
	}
	controller.config.CertConfig = oldCert
	recorder.cleanupTagErr = cleanupErr
	recorder.cleanupTagErrAtCall = 1
	recorder.addTagErr = restoreErr
	recorder.addTagErrAtCall = 1

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncCertConfig, syncActionSourceWS, syncActionMetadata{Trigger: "cert_changed"}))

	if !errors.Is(err, cleanupErr) || !errors.Is(err, restoreErr) {
		t.Fatalf("ExecuteSyncAction() error = %v, want cleanup %v and restore %v", err, cleanupErr, restoreErr)
	}
	if recorder.addTagCalls != 1 {
		t.Fatalf("last-known-good runtime restore attempts = %d, want 1", recorder.addTagCalls)
	}
	if controller.config.CertConfig != oldCert {
		t.Fatalf("cleanup failure published candidate config: %#v", controller.config.CertConfig)
	}
}

func TestSyncApply_CertOnlyUserReadinessFailureRestoresRuntimeAndLimiter(t *testing.T) {
	userErr := errors.New("candidate TLS runtime user readiness failed")
	nextCert := &api.XrayRCertConfig{
		CertMode:   "file",
		CertDomain: "new.example.com",
		CertFile:   "/candidate/new.crt",
		KeyFile:    "/candidate/new.key",
	}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{certConfig: nextCert})
	currentNode := &api.NodeInfo{
		NodeType:  "V2ray",
		NodeID:    1,
		Port:      443,
		EnableTLS: true,
	}
	currentUsers := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	currentTag := controller.buildNodeTagFrom(currentNode)
	controller.setNodeState(currentNode, currentTag)
	controller.setUserList(&currentUsers)
	oldCert := &mylego.CertConfig{
		CertMode:   "file",
		CertDomain: "old.example.com",
		CertFile:   "/applied/old.crt",
		KeyFile:    "/applied/old.key",
	}
	controller.config.CertConfig = oldCert
	recorder.activeRuntimes = map[string]*api.NodeInfo{currentTag: cloneRecordedNodeInfo(currentNode)}
	recorder.activeLimiterTags = map[string]bool{currentTag: true}
	controller.syncApplyHooks.runtime.addUsers = func(users *[]api.UserInfo, _ *api.NodeInfo, tag string, _ *Config) error {
		recorder.recordAddNewUser(tag, users)
		if recorder.addUserCalls == 1 {
			return userErr
		}
		return nil
	}

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncCertConfig, syncActionSourceWS, syncActionMetadata{Trigger: "cert_changed"}))

	if !errors.Is(err, userErr) {
		t.Fatalf("ExecuteSyncAction() error = %v, want %v", err, userErr)
	}
	if controller.config.CertConfig != oldCert {
		t.Fatalf("user readiness failure published candidate config: %#v", controller.config.CertConfig)
	}
	if recorder.addTagCalls != 2 || recorder.cleanupTagCalls != 2 || recorder.addUserCalls != 2 {
		t.Fatalf("candidate rollback ownership = addTag:%d cleanup:%d addUsers:%d, want 2/2/2", recorder.addTagCalls, recorder.cleanupTagCalls, recorder.addUserCalls)
	}
	if runtime := recorder.activeRuntimes[currentTag]; runtime == nil || !reflect.DeepEqual(runtime, currentNode) {
		t.Fatalf("last-known-good runtime was not restored: %#v", runtime)
	}
	if recorder.deleteLimiterCalls != 0 || recorder.addLimiterCalls != 0 ||
		!recorder.activeLimiterTags[currentTag] || len(recorder.activeLimiterTags) != 1 {
		t.Fatalf("certificate-only replacement changed the applied limiter: deletes=%d adds=%d active=%#v", recorder.deleteLimiterCalls, recorder.addLimiterCalls, recorder.activeLimiterTags)
	}
}

func TestSyncApply_NodeAndCertUserReadinessFailureRestoresLastKnownGoodSnapshot(t *testing.T) {
	userErr := errors.New("candidate node users not ready")
	users := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	nextNode := &api.NodeInfo{
		NodeType:   "V2ray",
		NodeID:     1,
		Port:       443,
		EnableTLS:  true,
		SpeedLimit: 200,
	}
	nextCert := &api.XrayRCertConfig{
		CertMode:   "file",
		CertDomain: "new.example.com",
		CertFile:   "/candidate/new.crt",
		KeyFile:    "/candidate/new.key",
	}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{
		nodeInfo:   nextNode,
		userList:   &users,
		certConfig: nextCert,
	})
	currentNode := &api.NodeInfo{
		NodeType:   "V2ray",
		NodeID:     1,
		Port:       443,
		EnableTLS:  true,
		SpeedLimit: 100,
	}
	currentTag := controller.buildNodeTagFrom(currentNode)
	controller.setNodeState(currentNode, currentTag)
	controller.setUserList(&users)
	oldCert := &mylego.CertConfig{
		CertMode:   "file",
		CertDomain: "old.example.com",
		CertFile:   "/applied/old.crt",
		KeyFile:    "/applied/old.key",
	}
	controller.config.CertConfig = oldCert
	recorder.activeRuntimes = map[string]*api.NodeInfo{currentTag: cloneRecordedNodeInfo(currentNode)}
	recorder.activeLimiterTags = map[string]bool{currentTag: true}
	controller.syncApplyHooks.runtime.addUsers = func(payload *[]api.UserInfo, _ *api.NodeInfo, tag string, _ *Config) error {
		recorder.recordAddNewUser(tag, payload)
		if recorder.addUserCalls == 1 {
			return userErr
		}
		return nil
	}

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeResyncAll, syncActionSourceWS, syncActionMetadata{Trigger: "resync_all"}))

	if !errors.Is(err, userErr) {
		t.Fatalf("ExecuteSyncAction() error = %v, want %v", err, userErr)
	}
	if controller.config.CertConfig != oldCert {
		t.Fatalf("user readiness failure published candidate certificate config: %#v", controller.config.CertConfig)
	}
	appliedNode, appliedTag, appliedUsers := controller.getStateSnapshot()
	if !reflect.DeepEqual(appliedNode, currentNode) || appliedTag != currentTag || !reflect.DeepEqual(appliedUsers, &users) {
		t.Fatalf("user readiness failure published candidate state: node=%#v tag=%q users=%#v", appliedNode, appliedTag, appliedUsers)
	}
	if runtime := recorder.activeRuntimes[currentTag]; runtime == nil || !reflect.DeepEqual(runtime, currentNode) {
		t.Fatalf("last-known-good runtime was not restored: %#v", runtime)
	}
	if len(recorder.activeRuntimes) != 1 {
		t.Fatalf("candidate runtime remained active: %#v", recorder.activeRuntimes)
	}
	if !recorder.activeLimiterTags[currentTag] || len(recorder.activeLimiterTags) != 1 {
		t.Fatalf("last-known-good limiter was not restored: %#v", recorder.activeLimiterTags)
	}
	if recorder.addTagCalls != 2 || recorder.cleanupTagCalls != 2 || recorder.addUserCalls != 2 {
		t.Fatalf("runtime rollback ownership = addTag:%d cleanup:%d addUsers:%d, want 2/2/2", recorder.addTagCalls, recorder.cleanupTagCalls, recorder.addUserCalls)
	}
}

func TestSyncApply_NodeFailureClearsCandidateTagRulesBeforeRestoringAppliedRules(t *testing.T) {
	userErr := errors.New("candidate users not ready")
	oldUsers := []api.UserInfo{{UID: 1, Email: "old@example.com"}}
	oldRules := []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("old.example")}}
	nextRules := []api.DetectRule{{ID: 2, Pattern: regexp.MustCompile("next.example")}}
	nextNode := &api.NodeInfo{
		NodeType: "V2ray",
		NodeID:   2,
		Port:     8443,
	}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{
		nodeInfo: nextNode,
		ruleList: &nextRules,
	})
	oldNode := &api.NodeInfo{
		NodeType: "V2ray",
		NodeID:   1,
		Port:     443,
	}
	oldTag := controller.buildNodeTagFrom(oldNode)
	nextTag := controller.buildNodeTagFrom(nextNode)
	controller.setNodeState(oldNode, oldTag)
	controller.setUserList(&oldUsers)
	controller.setAppliedRuleState(oldTag, oldRules)
	recorder.activeRuntimes = map[string]*api.NodeInfo{oldTag: cloneRecordedNodeInfo(oldNode)}
	recorder.activeLimiterTags = map[string]bool{oldTag: true}
	recorder.activeRules = map[string][]api.DetectRule{oldTag: cloneDetectRules(oldRules)}
	controller.syncApplyHooks.runtime.addUsers = func(users *[]api.UserInfo, _ *api.NodeInfo, tag string, _ *Config) error {
		recorder.recordAddNewUser(tag, users)
		if recorder.addUserCalls == 1 {
			return userErr
		}
		return nil
	}

	err := controller.ExecuteSyncAction(
		context.Background(),
		newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourceWS, syncActionMetadata{Trigger: "node_changed"}),
	)

	if !errors.Is(err, userErr) {
		t.Fatalf("ExecuteSyncAction() error = %v, want %v", err, userErr)
	}
	if _, exists := recorder.activeRules[nextTag]; exists {
		t.Fatalf("failed candidate retained audit rules for tag %q: %#v", nextTag, recorder.activeRules[nextTag])
	}
	if got := recorder.activeRules[oldTag]; !reflect.DeepEqual(got, oldRules) {
		t.Fatalf("last-known-good audit rules = %#v, want %#v", got, oldRules)
	}
}

func TestSyncApply_NodeAndCertKeepsAppliedStatePrivateUntilUserReadiness(t *testing.T) {
	oldUsers := []api.UserInfo{{UID: 1, Email: "old@example.com"}}
	nextUsers := []api.UserInfo{{UID: 2, Email: "next@example.com"}}
	oldRules := []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("old.example")}}
	nextRules := []api.DetectRule{{ID: 2, Pattern: regexp.MustCompile("next.example")}}
	nextNode := &api.NodeInfo{
		NodeType:   "V2ray",
		NodeID:     1,
		Port:       443,
		EnableTLS:  true,
		SpeedLimit: 200,
	}
	nextCert := &api.XrayRCertConfig{
		CertMode:   "file",
		CertDomain: "next.example.com",
		CertFile:   "/candidate/next.crt",
		KeyFile:    "/candidate/next.key",
	}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{
		nodeInfo:   nextNode,
		userList:   &nextUsers,
		ruleList:   &nextRules,
		certConfig: nextCert,
	})
	oldNode := &api.NodeInfo{
		NodeType:   "V2ray",
		NodeID:     1,
		Port:       443,
		EnableTLS:  true,
		SpeedLimit: 100,
	}
	oldTag := controller.buildNodeTagFrom(oldNode)
	controller.setNodeState(oldNode, oldTag)
	controller.setUserList(&oldUsers)
	controller.setAppliedRuleState(oldTag, oldRules)
	controller.config.CertConfig = &mylego.CertConfig{
		CertMode:   "file",
		CertDomain: "old.example.com",
		CertFile:   "/applied/old.crt",
		KeyFile:    "/applied/old.key",
	}

	userReadinessEntered := make(chan struct{})
	releaseUserReadiness := make(chan struct{})
	controller.syncApplyHooks.runtime.addUsers = func(users *[]api.UserInfo, _ *api.NodeInfo, tag string, _ *Config) error {
		recorder.recordAddNewUser(tag, users)
		close(userReadinessEntered)
		<-releaseUserReadiness
		return nil
	}

	applyDone := make(chan error, 1)
	go func() {
		applyDone <- controller.ExecuteSyncAction(
			context.Background(),
			newSyncAction(syncActionTypeResyncAll, syncActionSourceWS, syncActionMetadata{Trigger: "resync_all"}),
		)
	}()

	select {
	case <-userReadinessEntered:
	case err := <-applyDone:
		t.Fatalf("ExecuteSyncAction() completed before user readiness was released: %v", err)
	}

	duringReadiness := controller.runtimeStateSnapshot()
	close(releaseUserReadiness)
	if err := <-applyDone; err != nil {
		t.Fatalf("ExecuteSyncAction() error = %v", err)
	}

	if appliedNode := duringReadiness.nodeInfoSnapshot(); !reflect.DeepEqual(appliedNode, oldNode) ||
		duringReadiness.tag != oldTag ||
		!reflect.DeepEqual(duringReadiness.userListSnapshot(), &oldUsers) ||
		duringReadiness.appliedRuleTag != oldTag ||
		!reflect.DeepEqual(duringReadiness.appliedRuleList, oldRules) {
		t.Fatalf("candidate state became visible before user readiness: %#v", duringReadiness)
	}

	applied := controller.runtimeStateSnapshot()
	if appliedNode := applied.nodeInfoSnapshot(); !reflect.DeepEqual(appliedNode, nextNode) ||
		applied.tag != controller.buildNodeTagFrom(nextNode) ||
		!reflect.DeepEqual(applied.userListSnapshot(), &nextUsers) ||
		applied.appliedRuleTag != controller.buildNodeTagFrom(nextNode) ||
		!reflect.DeepEqual(applied.appliedRuleList, nextRules) {
		t.Fatalf("successful apply did not publish one complete candidate state: %#v", applied)
	}
}

func TestSyncApply_NodeOnlyKeepsAppliedStatePrivateUntilUserReadiness(t *testing.T) {
	oldUsers := []api.UserInfo{{UID: 1, Email: "old@example.com"}}
	oldRules := []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("old.example")}}
	nextRules := []api.DetectRule{{ID: 2, Pattern: regexp.MustCompile("next.example")}}
	nextNode := &api.NodeInfo{
		NodeType:   "V2ray",
		NodeID:     1,
		Port:       443,
		SpeedLimit: 200,
	}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{
		nodeInfo: nextNode,
		ruleList: &nextRules,
	})
	oldNode := &api.NodeInfo{
		NodeType:   "V2ray",
		NodeID:     1,
		Port:       443,
		SpeedLimit: 100,
	}
	oldTag := controller.buildNodeTagFrom(oldNode)
	controller.setNodeState(oldNode, oldTag)
	controller.setUserList(&oldUsers)
	controller.setAppliedRuleState(oldTag, oldRules)

	userReadinessEntered := make(chan struct{})
	releaseUserReadiness := make(chan struct{})
	controller.syncApplyHooks.runtime.addUsers = func(users *[]api.UserInfo, _ *api.NodeInfo, tag string, _ *Config) error {
		recorder.recordAddNewUser(tag, users)
		close(userReadinessEntered)
		<-releaseUserReadiness
		return nil
	}

	applyDone := make(chan error, 1)
	go func() {
		applyDone <- controller.ExecuteSyncAction(
			context.Background(),
			newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourceWS, syncActionMetadata{Trigger: "node_changed"}),
		)
	}()

	select {
	case <-userReadinessEntered:
	case err := <-applyDone:
		t.Fatalf("ExecuteSyncAction() completed before user readiness was released: %v", err)
	}

	duringReadiness := controller.runtimeStateSnapshot()
	close(releaseUserReadiness)
	if err := <-applyDone; err != nil {
		t.Fatalf("ExecuteSyncAction() error = %v", err)
	}

	if appliedNode := duringReadiness.nodeInfoSnapshot(); !reflect.DeepEqual(appliedNode, oldNode) ||
		duringReadiness.tag != oldTag ||
		!reflect.DeepEqual(duringReadiness.userListSnapshot(), &oldUsers) ||
		duringReadiness.appliedRuleTag != oldTag ||
		!reflect.DeepEqual(duringReadiness.appliedRuleList, oldRules) {
		t.Fatalf("node-only candidate state became visible before user readiness: %#v", duringReadiness)
	}

	applied := controller.runtimeStateSnapshot()
	if appliedNode := applied.nodeInfoSnapshot(); !reflect.DeepEqual(appliedNode, nextNode) ||
		applied.tag != controller.buildNodeTagFrom(nextNode) ||
		!reflect.DeepEqual(applied.userListSnapshot(), &oldUsers) ||
		applied.appliedRuleTag != controller.buildNodeTagFrom(nextNode) ||
		!reflect.DeepEqual(applied.appliedRuleList, nextRules) {
		t.Fatalf("successful node-only apply did not publish one complete candidate state: %#v", applied)
	}
}

func TestSyncApply_CertOnlyBuildKeepsCandidatePrivateUntilRuntimeReady(t *testing.T) {
	nextCert := &api.XrayRCertConfig{
		CertMode:   "file",
		CertDomain: "new.example.com",
		CertFile:   "/candidate/new.crt",
		KeyFile:    "/candidate/new.key",
	}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{certConfig: nextCert})
	currentNode := &api.NodeInfo{
		NodeType:  "V2ray",
		NodeID:    1,
		Port:      443,
		EnableTLS: true,
	}
	currentUsers := []api.UserInfo{}
	controller.setNodeState(currentNode, controller.buildNodeTagFrom(currentNode))
	controller.setUserList(&currentUsers)
	oldCert := &mylego.CertConfig{
		CertMode:   "file",
		CertDomain: "old.example.com",
		CertFile:   "/applied/old.crt",
		KeyFile:    "/applied/old.key",
	}
	controller.config.CertConfig = oldCert
	recorder.onAddTag = func(candidate *Config) {
		if controller.config.CertConfig != oldCert {
			t.Fatal("candidate certificate config published before runtime readiness")
		}
		if candidate == controller.config || candidate.CertConfig == oldCert {
			t.Fatal("runtime build did not receive an isolated candidate config")
		}
		if candidate.CertConfig.CertFile != nextCert.CertFile || candidate.CertConfig.KeyFile != nextCert.KeyFile {
			t.Fatalf("runtime candidate certificate = %#v", candidate.CertConfig)
		}
	}

	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncCertConfig, syncActionSourceWS, syncActionMetadata{Trigger: "cert_changed"})); err != nil {
		t.Fatalf("ExecuteSyncAction() error = %v", err)
	}

	if len(recorder.removedTags) != 1 || recorder.addTagCalls != 1 {
		t.Fatalf("certificate-only update rebuilds = removed:%d added:%d, want 1/1", len(recorder.removedTags), recorder.addTagCalls)
	}
	if controller.config.CertConfig == oldCert ||
		controller.config.CertConfig.CertFile != nextCert.CertFile ||
		controller.config.CertConfig.KeyFile != nextCert.KeyFile {
		t.Fatalf("successful certificate runtime did not publish candidate config: %#v", controller.config.CertConfig)
	}
}

func TestCandidateCertConfigMaterializesNormalizedMode(t *testing.T) {
	tests := []struct {
		name string
		next *api.XrayRCertConfig
		want string
	}{
		{
			name: "implicit DNS",
			next: &api.XrayRCertConfig{
				Provider: "cloudflare",
				DNSEnv:   map[string]string{"CF_API_TOKEN": "candidate-token"},
			},
			want: "dns",
		},
		{
			name: "trimmed lowercase DNS",
			next: &api.XrayRCertConfig{
				CertMode: " DNS ",
				Provider: "cloudflare",
			},
			want: "dns",
		},
		{
			name: "lowercase file",
			next: &api.XrayRCertConfig{
				CertMode: "FILE",
				CertFile: "/candidate/node.crt",
				KeyFile:  "/candidate/node.key",
			},
			want: "file",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := candidateCertConfig(
				&mylego.CertConfig{CertMode: "file"},
				test.next,
			)
			if candidate == nil || candidate.CertMode != test.want {
				t.Fatalf("candidateCertConfig() mode = %q, want %q", candidate.CertMode, test.want)
			}
		})
	}
}

func TestSyncApply_SocksCertOnlyUserBuildReceivesCandidateConfig(t *testing.T) {
	nextCert := &api.XrayRCertConfig{
		CertMode:   "file",
		CertDomain: "next.example.com",
		CertFile:   "/candidate/next.crt",
		KeyFile:    "/candidate/next.key",
	}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{certConfig: nextCert})
	currentNode := &api.NodeInfo{
		NodeType:  "Socks",
		NodeID:    1,
		Port:      443,
		EnableTLS: true,
	}
	currentUsers := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	currentTag := controller.buildNodeTagFrom(currentNode)
	controller.setNodeState(currentNode, currentTag)
	controller.setUserList(&currentUsers)
	controller.config.CertConfig = &mylego.CertConfig{
		CertMode:   "file",
		CertDomain: "old.example.com",
		CertFile:   "/applied/old.crt",
		KeyFile:    "/applied/old.key",
	}

	var userBuildCert *mylego.CertConfig
	controller.syncApplyHooks.runtime.addUsers = func(users *[]api.UserInfo, _ *api.NodeInfo, tag string, config *Config) error {
		recorder.recordAddNewUser(tag, users)
		userBuildCert = cloneRuntimeCertConfig(config.CertConfig)
		return nil
	}

	if err := controller.ExecuteSyncAction(
		context.Background(),
		newSyncAction(syncActionTypeSyncCertConfig, syncActionSourceWS, syncActionMetadata{Trigger: "cert_changed"}),
	); err != nil {
		t.Fatalf("ExecuteSyncAction() error = %v", err)
	}

	if userBuildCert == nil ||
		userBuildCert.CertFile != nextCert.CertFile ||
		userBuildCert.KeyFile != nextCert.KeyFile {
		t.Fatalf("Socks user-embedded candidate runtime received certificate config %#v, want %#v", userBuildCert, nextCert)
	}
}

func TestSyncApply_MissingCertCapabilityIsNoOp(t *testing.T) {
	controller, _ := newTestSyncApplyController(panelClientWithoutDebug{})
	original := &mylego.CertConfig{CertMode: "file", CertFile: "/existing/cert.crt", KeyFile: "/existing/cert.key"}
	controller.config.CertConfig = original

	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncCertConfig, syncActionSourceWS, syncActionMetadata{Trigger: "cert_changed"})); err != nil {
		t.Fatalf("ExecuteSyncAction returned error without cert capability: %v", err)
	}
	if controller.config.CertConfig != original {
		t.Fatalf("expected missing cert capability to preserve existing config, got %#v", controller.config.CertConfig)
	}
}

func TestSyncApply_SupportedAbsentCertConfigClearsWithoutPanelTypeKnowledge(t *testing.T) {
	fakeAPI := &fakeSyncApplyAPI{}
	controller, _ := newTestSyncApplyController(fakeAPI)
	controller.panelType = "FuturePanel"
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
	if appliedUsers == &currentUsers || appliedUsers == nil || (*appliedUsers)[0].SpeedLimit != 100 || (*appliedUsers)[0].DeviceLimit != 1 {
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
	controller.syncApplyHooks.runtime.addUsers = func(users *[]api.UserInfo, _ *api.NodeInfo, tag string, _ *Config) error {
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
	if recorder.updateLimiterCalls != 0 || recorder.addUserCalls != 2 {
		t.Fatalf("expected runtime add attempt and rollback restore without limiter publication, got updateLimiter=%d addUsers=%d", recorder.updateLimiterCalls, recorder.addUserCalls)
	}
	if len(recorder.updatedLimiterTags) != 0 || len(recorder.updatedLimiterPayloads) != 0 {
		t.Fatalf("runtime failure published candidate limiter: tags=%#v payloads=%#v", recorder.updatedLimiterTags, recorder.updatedLimiterPayloads)
	}
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
	if appliedUsers == &currentUsers || appliedUsers == nil || (*appliedUsers)[0].UUID != "uuid-1" || (*appliedUsers)[0].SpeedLimit != 100 || (*appliedUsers)[0].DeviceLimit != 1 {
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
	if recorder.updateLimiterCalls != 0 || recorder.addUserCalls != 1 {
		t.Fatalf("expected rollback restore after remove failure without limiter publication, got updateLimiter=%d addUsers=%d", recorder.updateLimiterCalls, recorder.addUserCalls)
	}
	if len(recorder.updatedLimiterTags) != 0 || len(recorder.updatedLimiterPayloads) != 0 {
		t.Fatalf("runtime failure published candidate limiter: tags=%#v payloads=%#v", recorder.updatedLimiterTags, recorder.updatedLimiterPayloads)
	}
	if len(recorder.addedUserPayloads) != 1 {
		t.Fatalf("expected runtime restore payload after remove failure, got %#v", recorder.addedUserPayloads)
	}
	assertUserPayload(t, recorder.addedUserPayloads[0], []api.UserInfo{currentUsers[0]})
	if len(recorder.removedUsers) != 1 || len(recorder.removedUsers[0]) != 1 || recorder.removedUsers[0][0] != tag+"|user@example.com|1" {
		t.Fatalf("expected runtime update to attempt old user removal, got %#v", recorder.removedUsers)
	}
	_, _, appliedUsers := controller.getStateSnapshot()
	if appliedUsers == &currentUsers || appliedUsers == nil || (*appliedUsers)[0].UUID != "uuid-1" || (*appliedUsers)[0].SpeedLimit != 100 || (*appliedUsers)[0].DeviceLimit != 1 {
		t.Fatalf("expected committed user state to retain old UUID and limits, got %#v", appliedUsers)
	}
}

func TestSyncApply_RuntimeRemoveDoesNotPublishCandidateLimiter(t *testing.T) {
	kept := api.UserInfo{UID: 1, Email: "kept@example.test", UUID: "kept-uuid"}
	removed := api.UserInfo{UID: 2, Email: "removed@example.test", UUID: "removed-uuid"}
	currentUsers := []api.UserInfo{kept, removed}
	nextUsers := []api.UserInfo{kept}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	controller, _ := newTestSyncApplyController(&fakeSyncApplyAPI{userList: &nextUsers})
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	controller.setUserList(&currentUsers)

	panelLimiter := limiter.New()
	t.Cleanup(func() {
		if err := panelLimiter.Close(); err != nil {
			t.Errorf("Limiter.Close() error = %v", err)
		}
	})
	if err := panelLimiter.AddInboundLimiter(tag, node.SpeedLimit, &currentUsers, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	controller.syncApplyHooks.limiter.replaceInbound = panelLimiter.ReplaceInboundUsers
	controller.syncApplyHooks.limiter.snapshotInbound = panelLimiter.SnapshotInboundLimiterState
	controller.syncApplyHooks.limiter.restoreInbound = panelLimiter.RestoreInboundLimiterState

	removeEntered := make(chan struct{})
	releaseRemove := make(chan struct{})
	runtimeErr := errors.New("remove user failed")
	controller.syncApplyHooks.runtime.removeUsers = func([]string, string) error {
		close(removeEntered)
		<-releaseRemove
		return runtimeErr
	}

	applyDone := make(chan error, 1)
	go func() {
		applyDone <- controller.ExecuteSyncAction(
			context.Background(),
			newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"}),
		)
	}()

	<-removeEntered
	removedKey := fmt.Sprintf("%s|%s|%d", tag, removed.Email, removed.UID)
	_, _, rejectedDuringApply := panelLimiter.Admit(tag, removedKey, "192.0.2.2", nil, nil)
	close(releaseRemove)
	err := <-applyDone

	if rejectedDuringApply {
		t.Fatal("candidate limiter was published before the runtime user transaction completed")
	}
	if !errors.Is(err, runtimeErr) {
		t.Fatalf("ExecuteSyncAction() error = %v, want runtime remove failure", err)
	}
	if _, _, rejected := panelLimiter.Admit(tag, removedKey, "192.0.2.2", nil, nil); rejected {
		t.Fatal("runtime failure did not preserve the last-known-good limiter")
	}
}

func TestSyncApply_EmbeddedRuntimeRebuildFailureRestoresAppliedUsers(t *testing.T) {
	for _, nodeType := range []string{"Socks", "HTTP"} {
		t.Run(nodeType, func(t *testing.T) {
			currentUsers := []api.UserInfo{{UID: 1, Email: "current@example.test", UUID: "current-uuid"}}
			nextUsers := []api.UserInfo{{UID: 2, Email: "next@example.test", UUID: "next-uuid"}}
			node := &api.NodeInfo{NodeType: nodeType, NodeID: 1, Port: 1080}
			controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{userList: &nextUsers})
			tag := controller.buildNodeTagFrom(node)
			controller.setNodeState(node, tag)
			controller.setUserList(&currentUsers)

			rebuildErr := errors.New("rebuild embedded inbound failed")
			controller.syncApplyHooks.runtime.addUsers = func(users *[]api.UserInfo, _ *api.NodeInfo, tag string, _ *Config) error {
				recorder.recordAddNewUser(tag, users)
				if recorder.addUserCalls == 1 {
					return rebuildErr
				}
				return nil
			}

			err := controller.ExecuteSyncAction(
				context.Background(),
				newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"}),
			)
			if !errors.Is(err, rebuildErr) {
				t.Fatalf("ExecuteSyncAction() error = %v, want runtime rebuild failure", err)
			}
			if recorder.addUserCalls != 2 {
				t.Fatalf("runtime rebuild calls = %d, want candidate attempt and applied restore", recorder.addUserCalls)
			}
			assertUserPayload(t, recorder.addedUserPayloads[0], nextUsers)
			assertUserPayload(t, recorder.addedUserPayloads[1], currentUsers)
			if recorder.addLimiterCalls != 0 || recorder.updateLimiterCalls != 0 {
				t.Fatalf("runtime failure published limiter: add=%d replace=%d", recorder.addLimiterCalls, recorder.updateLimiterCalls)
			}
			_, _, appliedUsers := controller.getStateSnapshot()
			if appliedUsers == nil || !reflect.DeepEqual(*appliedUsers, currentUsers) {
				t.Fatalf("runtime failure changed applied users: %#v", appliedUsers)
			}
		})
	}
}

func TestSyncApply_EmbeddedLimiterFailureRestoresRuntimeAndLimiter(t *testing.T) {
	for _, nodeType := range []string{"Socks", "HTTP"} {
		t.Run(nodeType, func(t *testing.T) {
			currentUsers := []api.UserInfo{{UID: 1, Email: "current@example.test", UUID: "current-uuid"}}
			nextUsers := []api.UserInfo{{UID: 2, Email: "next@example.test", UUID: "next-uuid"}}
			node := &api.NodeInfo{NodeType: nodeType, NodeID: 1, Port: 1080}
			controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{userList: &nextUsers})
			tag := controller.buildNodeTagFrom(node)
			controller.setNodeState(node, tag)
			controller.setUserList(&currentUsers)

			controller.syncApplyHooks.runtime.addUsers = func(users *[]api.UserInfo, _ *api.NodeInfo, tag string, _ *Config) error {
				recorder.recordAddNewUser(tag, users)
				return nil
			}
			limiterErr := errors.New("replace embedded limiter failed")
			controller.syncApplyHooks.limiter.addInbound = func(string, uint64, *[]api.UserInfo, *limiter.GlobalDeviceLimitConfig) error {
				recorder.addLimiterCalls++
				return limiterErr
			}
			controller.syncApplyHooks.limiter.replaceInbound = func(tag string, users *[]api.UserInfo) error {
				recorder.recordUpdateInboundLimiter(tag, users)
				return limiterErr
			}

			err := controller.ExecuteSyncAction(
				context.Background(),
				newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"}),
			)
			if !errors.Is(err, limiterErr) {
				t.Fatalf("ExecuteSyncAction() error = %v, want limiter replacement failure", err)
			}
			if recorder.addUserCalls != 2 {
				t.Fatalf("runtime rebuild calls = %d, want candidate apply and applied restore", recorder.addUserCalls)
			}
			assertUserPayload(t, recorder.addedUserPayloads[0], nextUsers)
			assertUserPayload(t, recorder.addedUserPayloads[1], currentUsers)
			if recorder.addLimiterCalls != 0 || recorder.updateLimiterCalls != 1 {
				t.Fatalf("limiter publication calls = add:%d replace:%d, want authoritative replacement", recorder.addLimiterCalls, recorder.updateLimiterCalls)
			}
			if recorder.snapshotLimiterCalls != 1 || recorder.restoreLimiterCalls != 1 {
				t.Fatalf("limiter transaction calls = snapshot:%d restore:%d, want 1/1", recorder.snapshotLimiterCalls, recorder.restoreLimiterCalls)
			}
			_, _, appliedUsers := controller.getStateSnapshot()
			if appliedUsers == nil || !reflect.DeepEqual(*appliedUsers, currentUsers) {
				t.Fatalf("limiter failure changed applied users: %#v", appliedUsers)
			}
		})
	}
}

func TestSyncApply_InitialUserLimiterFailureRemovesCandidateRuntimeUsers(t *testing.T) {
	for _, nodeType := range []string{"V2ray", "Socks", "HTTP"} {
		t.Run(nodeType, func(t *testing.T) {
			nextUsers := []api.UserInfo{{UID: 2, Email: "next@example.test", UUID: "next-uuid"}}
			node := &api.NodeInfo{NodeType: nodeType, NodeID: 1, Port: 1080}
			controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{userList: &nextUsers})
			tag := controller.buildNodeTagFrom(node)
			controller.setNodeState(node, tag)

			controller.syncApplyHooks.runtime.addUsers = func(users *[]api.UserInfo, _ *api.NodeInfo, tag string, _ *Config) error {
				recorder.recordAddNewUser(tag, users)
				return nil
			}
			limiterErr := errors.New("create initial limiter failed")
			controller.syncApplyHooks.limiter.addInbound = func(tag string, _ uint64, _ *[]api.UserInfo, _ *limiter.GlobalDeviceLimitConfig) error {
				recorder.addLimiterCalls++
				if recorder.activeLimiterTags == nil {
					recorder.activeLimiterTags = make(map[string]bool)
				}
				recorder.activeLimiterTags[tag] = true
				return limiterErr
			}

			err := controller.ExecuteSyncAction(
				context.Background(),
				newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"}),
			)
			if !errors.Is(err, limiterErr) {
				t.Fatalf("ExecuteSyncAction() error = %v, want initial limiter failure", err)
			}
			if recorder.addLimiterCalls != 1 || recorder.deleteLimiterCalls != 1 {
				t.Fatalf("limiter transaction calls = add:%d delete:%d, want 1/1", recorder.addLimiterCalls, recorder.deleteLimiterCalls)
			}
			if recorder.activeLimiterTags[tag] {
				t.Fatal("failed initial limiter remained published")
			}
			if nodeType == "V2ray" {
				wantKey := tag + "|next@example.test|2"
				if len(recorder.removedUsers) != 1 || !reflect.DeepEqual(recorder.removedUsers[0], []string{wantKey}) {
					t.Fatalf("candidate runtime removals = %#v, want %q", recorder.removedUsers, wantKey)
				}
			} else {
				if recorder.addUserCalls != 2 {
					t.Fatalf("embedded runtime rebuild calls = %d, want candidate and empty restore", recorder.addUserCalls)
				}
				if len(recorder.addedUserPayloads[1]) != 0 {
					t.Fatalf("embedded runtime restore users = %#v, want empty", recorder.addedUserPayloads[1])
				}
			}
			_, _, appliedUsers := controller.getStateSnapshot()
			if appliedUsers != nil {
				t.Fatalf("failed initial user sync published applied users: %#v", appliedUsers)
			}
		})
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
	assertUserPayload(t, recorder.updatedLimiterPayloads[0], nextUsers)
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
	nextTag := controller.buildNodeTagFrom(fakeAPI.nodeInfo)
	if len(recorder.removedTags) != 1 || recorder.removedTags[0] != nextTag {
		t.Fatalf("expected only the partial candidate tag %q to be cleaned when addNewTag fails, got removed=%v", nextTag, recorder.removedTags)
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
	if appliedNode == currentNode || !reflect.DeepEqual(appliedNode, currentNode) {
		t.Fatalf("expected controller node state to remain on an owned copy of the old node, got %#v", appliedNode)
	}
	if appliedTag != currentTag {
		t.Fatalf("expected controller tag to remain %q, got %q", currentTag, appliedTag)
	}
	if appliedUsers == &restUsers || appliedUsers == nil || !reflect.DeepEqual(*appliedUsers, restUsers) {
		t.Fatalf("expected controller user state to remain an owned copy of the prior values, got %#v", appliedUsers)
	}
	if got := controller.getAppliedRuleTag(); got != currentTag {
		t.Fatalf("expected rule state to remain bound to old tag %q, got %q", currentTag, got)
	}
}

func TestSyncApply_TagChangeCleanupFailureRemovesCandidateAndRestoresOldRuntime(t *testing.T) {
	cleanupErr := errors.New("old runtime cleanup failed")
	users := []api.UserInfo{{UID: 1, Email: "rest@example.com"}}
	nextNode := &api.NodeInfo{
		NodeType: "V2ray",
		NodeID:   2,
		Port:     8443,
	}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{
		nodeInfo: nextNode,
		userList: &users,
	})
	currentNode := &api.NodeInfo{
		NodeType: "V2ray",
		NodeID:   1,
		Port:     443,
	}
	currentTag := controller.buildNodeTagFrom(currentNode)
	nextTag := controller.buildNodeTagFrom(nextNode)
	controller.setNodeState(currentNode, currentTag)
	controller.setUserList(&users)
	recorder.activeRuntimes = map[string]*api.NodeInfo{currentTag: cloneRecordedNodeInfo(currentNode)}
	recorder.activeLimiterTags = map[string]bool{currentTag: true}
	recorder.cleanupTagErr = cleanupErr
	recorder.cleanupTagErrAtCall = 1

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeResyncAll, syncActionSourceWS, syncActionMetadata{Trigger: "resync_all"}))

	if !errors.Is(err, cleanupErr) {
		t.Fatalf("ExecuteSyncAction() error = %v, want %v", err, cleanupErr)
	}
	if recorder.addTagCalls != 2 {
		t.Fatalf("runtime add attempts = %d, want candidate plus old-runtime restore", recorder.addTagCalls)
	}
	if recorder.cleanupTagCalls != 2 ||
		len(recorder.removedTags) != 2 ||
		recorder.removedTags[0] != currentTag ||
		recorder.removedTags[1] != nextTag {
		t.Fatalf("runtime cleanup ownership = calls:%d tags:%v, want old then candidate", recorder.cleanupTagCalls, recorder.removedTags)
	}
	if runtime := recorder.activeRuntimes[currentTag]; runtime == nil || !reflect.DeepEqual(runtime, currentNode) {
		t.Fatalf("last-known-good runtime was not restored: %#v", runtime)
	}
	if _, exists := recorder.activeRuntimes[nextTag]; exists || len(recorder.activeRuntimes) != 1 {
		t.Fatalf("failed tag-change candidate remained active: %#v", recorder.activeRuntimes)
	}
	if !recorder.activeLimiterTags[currentTag] || len(recorder.activeLimiterTags) != 1 || recorder.deleteLimiterCalls != 0 {
		t.Fatalf("failed tag change modified applied limiter: deletes=%d active=%#v", recorder.deleteLimiterCalls, recorder.activeLimiterTags)
	}
	appliedNode, appliedTag, _ := controller.getStateSnapshot()
	if !reflect.DeepEqual(appliedNode, currentNode) || appliedTag != currentTag {
		t.Fatalf("failed tag change published node state: node=%#v tag=%q", appliedNode, appliedTag)
	}
}

func TestSyncApply_TagChangeBuildFailureCleansPartialCandidateAndJoinsCleanupError(t *testing.T) {
	buildErr := errors.New("candidate outbound build failed")
	cleanupErr := errors.New("partial candidate cleanup failed")
	nextNode := &api.NodeInfo{
		NodeType: "V2ray",
		NodeID:   2,
		Port:     8443,
	}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{
		nodeInfo: nextNode,
	})
	currentNode := &api.NodeInfo{
		NodeType: "V2ray",
		NodeID:   1,
		Port:     443,
	}
	currentTag := controller.buildNodeTagFrom(currentNode)
	nextTag := controller.buildNodeTagFrom(nextNode)
	controller.setNodeState(currentNode, currentTag)
	recorder.activeRuntimes = map[string]*api.NodeInfo{currentTag: cloneRecordedNodeInfo(currentNode)}
	recorder.cleanupTagErr = cleanupErr
	recorder.cleanupTagErrAtCall = 1
	controller.syncApplyHooks.runtime.addTag = func(nodeInfo *api.NodeInfo, tag string, config *Config) error {
		recorder.addTagCalls++
		recorder.addedTags = append(recorder.addedTags, tag)
		recorder.addedNodeInfos = append(recorder.addedNodeInfos, cloneRecordedNodeInfo(nodeInfo))
		recorder.addedCertConfigs = append(recorder.addedCertConfigs, cloneRuntimeCertConfig(config.CertConfig))
		if recorder.activeRuntimes == nil {
			recorder.activeRuntimes = make(map[string]*api.NodeInfo)
		}
		recorder.activeRuntimes[tag] = cloneRecordedNodeInfo(nodeInfo)
		return buildErr
	}

	err := controller.ExecuteSyncAction(
		context.Background(),
		newSyncAction(syncActionTypeSyncNodeConfig, syncActionSourceWS, syncActionMetadata{Trigger: "node_changed"}),
	)

	if !errors.Is(err, buildErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("ExecuteSyncAction() error = %v, want build %v and cleanup %v", err, buildErr, cleanupErr)
	}
	if recorder.cleanupTagCalls != 1 ||
		len(recorder.removedTags) != 1 ||
		recorder.removedTags[0] != nextTag {
		t.Fatalf("partial candidate cleanup = calls:%d tags:%#v, want one cleanup for %q", recorder.cleanupTagCalls, recorder.removedTags, nextTag)
	}
	if _, exists := recorder.activeRuntimes[nextTag]; exists {
		t.Fatalf("partial candidate remained active for tag %q: %#v", nextTag, recorder.activeRuntimes)
	}
	if runtime := recorder.activeRuntimes[currentTag]; runtime == nil || !reflect.DeepEqual(runtime, currentNode) {
		t.Fatalf("last-known-good runtime changed after candidate build failure: %#v", runtime)
	}
	appliedNode, appliedTag, _ := controller.getStateSnapshot()
	if !reflect.DeepEqual(appliedNode, currentNode) || appliedTag != currentTag {
		t.Fatalf("candidate build failure published state: node=%#v tag=%q", appliedNode, appliedTag)
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
	if appliedNode == currentNode || !reflect.DeepEqual(appliedNode, currentNode) {
		t.Fatalf("expected controller node state to remain on an owned copy after same-tag failure, got %#v", appliedNode)
	}
	if appliedTag != currentTag {
		t.Fatalf("expected controller tag to remain %q after same-tag failure, got %q", currentTag, appliedTag)
	}
	if appliedUsers == &restUsers || appliedUsers == nil || !reflect.DeepEqual(*appliedUsers, restUsers) {
		t.Fatalf("expected controller user state to remain an owned copy after same-tag failure, got %#v", appliedUsers)
	}
	if got := controller.getAppliedRuleTag(); got != currentTag {
		t.Fatalf("expected rule state to remain bound to old tag %q after same-tag failure, got %q", currentTag, got)
	}
}

func TestSyncApply_NodeUserReadinessFailureRestoresRealLimiterAdmission(t *testing.T) {
	oldUser := api.UserInfo{UID: 1, Email: "old@example.test", UUID: "old-uuid", SpeedLimit: 100, DeviceLimit: 2}
	newUser := api.UserInfo{UID: 2, Email: "new@example.test", UUID: "new-uuid", SpeedLimit: 200, DeviceLimit: 2}
	oldUsers := []api.UserInfo{oldUser}
	newUsers := []api.UserInfo{newUser}
	oldNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	newNode := &api.NodeInfo{NodeType: "V2ray", NodeID: 2, Port: 8443}
	client := &fakeSyncApplyAPI{nodeInfo: newNode, userList: &newUsers}
	controller, recorder := newTestSyncApplyController(client)
	controller.config.CertConfig = nil
	controller.config.DisableGetRule = true
	oldTag := controller.buildNodeTagFrom(oldNode)
	newTag := controller.buildNodeTagFrom(newNode)
	controller.setNodeState(oldNode, oldTag)
	controller.setUserList(&oldUsers)
	recorder.activeRuntimes = map[string]*api.NodeInfo{oldTag: cloneRecordedNodeInfo(oldNode)}

	panelLimiter := limiter.New()
	if err := panelLimiter.AddInboundLimiter(oldTag, oldNode.SpeedLimit, &oldUsers, nil); err != nil {
		t.Fatalf("AddInboundLimiter() error = %v", err)
	}
	t.Cleanup(func() {
		if err := panelLimiter.Close(); err != nil {
			t.Errorf("Limiter.Close() error = %v", err)
		}
	})
	controller.dispatcher = &mydispatcher.DefaultDispatcher{Limiter: panelLimiter}
	controller.syncApplyHooks.limiter = syncApplyLimiterHooks{}

	readinessErr := errors.New("candidate users are not ready")
	addUserCalls := 0
	controller.syncApplyHooks.runtime.addUsers = func(users *[]api.UserInfo, _ *api.NodeInfo, tag string, _ *Config) error {
		addUserCalls++
		recorder.recordAddNewUser(tag, users)
		if addUserCalls == 1 {
			return readinessErr
		}
		return nil
	}

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeResyncAll, syncActionSourceWS, syncActionMetadata{Trigger: "resync_all"}))
	if !errors.Is(err, readinessErr) {
		t.Fatalf("ExecuteSyncAction() error = %v, want readiness failure", err)
	}
	if _, _, rejected := panelLimiter.Admit(oldTag, oldTag+"|old@example.test|1", "192.0.2.1", nil, nil); rejected {
		t.Fatal("restored last-known-good limiter rejected the applied user")
	}
	if _, _, rejected := panelLimiter.Admit(oldTag, oldTag+"|new@example.test|2", "192.0.2.2", nil, nil); !rejected {
		t.Fatal("restored last-known-good limiter admitted a candidate user")
	}
	if _, _, rejected := panelLimiter.Admit(newTag, newTag+"|new@example.test|2", "192.0.2.2", nil, nil); !rejected {
		t.Fatal("failed candidate limiter remained published")
	}
	appliedNode, appliedTag, appliedUsers := controller.getStateSnapshot()
	if !reflect.DeepEqual(appliedNode, oldNode) || appliedTag != oldTag || appliedUsers == nil || !reflect.DeepEqual(*appliedUsers, oldUsers) {
		t.Fatalf("failed node apply changed controller state: node=%#v tag=%q users=%#v", appliedNode, appliedTag, appliedUsers)
	}
}

func TestSyncApply_AuthoritativeLimiterUsersPreserveActiveAutoLimitOverlay(t *testing.T) {
	limitedUser := api.UserInfo{UID: 1, Email: "limited@example.com", UUID: "limited-uuid", SpeedLimit: 100}
	removedUser := api.UserInfo{UID: 2, Email: "removed@example.com", UUID: "removed-uuid", SpeedLimit: 200}
	addedUser := api.UserInfo{UID: 3, Email: "added@example.com", UUID: "added-uuid", SpeedLimit: 300}
	currentUsers := []api.UserInfo{limitedUser, removedUser}
	nextUsers := []api.UserInfo{limitedUser, addedUser}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{userList: &nextUsers})
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	controller.setUserList(&currentUsers)
	controller.limitedUsers = map[api.UserInfo]LimitInfo{
		limitedUser: {
			end:               time.Now().Add(time.Minute).Unix(),
			currentSpeedLimit: 8,
			originSpeedLimit:  limitedUser.SpeedLimit,
		},
	}

	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"})); err != nil {
		t.Fatalf("ExecuteSyncAction() error = %v", err)
	}
	if len(recorder.updatedLimiterPayloads) != 1 {
		t.Fatalf("limiter replacement payloads = %d, want 1", len(recorder.updatedLimiterPayloads))
	}
	wantLimited := limitedUser
	wantLimited.SpeedLimit = 1_000_000
	assertUserPayload(t, recorder.updatedLimiterPayloads[0], []api.UserInfo{wantLimited, addedUser})
	if info, exists := controller.limitedUsers[limitedUser]; !exists || info.currentSpeedLimit != 8 {
		t.Fatalf("active auto-limit overlay changed during user replacement: %#v", controller.limitedUsers)
	}
}

func TestSyncApply_RuntimeRemoveFailurePreservesAppliedAutoLimitOverlay(t *testing.T) {
	kept := api.UserInfo{UID: 1, Email: "kept@example.com", UUID: "kept-uuid", SpeedLimit: 100}
	removed := api.UserInfo{UID: 2, Email: "removed@example.com", UUID: "removed-uuid", SpeedLimit: 200}
	keptNext := kept
	keptNext.SpeedLimit = 300
	currentUsers := []api.UserInfo{kept, removed}
	nextUsers := []api.UserInfo{keptNext}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{userList: &nextUsers})
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	controller.setUserList(&currentUsers)
	recorder.removeUsersErr = errors.New("remove user failed")
	appliedLimited := map[api.UserInfo]LimitInfo{
		kept:    {end: 1000, currentSpeedLimit: 8, originSpeedLimit: kept.SpeedLimit},
		removed: {end: 2000, currentSpeedLimit: 16, originSpeedLimit: removed.SpeedLimit},
	}
	appliedWarned := map[api.UserInfo]int{kept: 1, removed: 2}
	controller.limitedUsers = cloneMap(appliedLimited)
	controller.warnedUsers = cloneMap(appliedWarned)

	err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"}))
	if !errors.Is(err, recorder.removeUsersErr) {
		t.Fatalf("ExecuteSyncAction() error = %v, want runtime remove failure", err)
	}
	if !reflect.DeepEqual(controller.limitedUsers, appliedLimited) {
		t.Fatalf("failed apply changed active auto-limit state:\n got: %#v\nwant: %#v", controller.limitedUsers, appliedLimited)
	}
	if !reflect.DeepEqual(controller.warnedUsers, appliedWarned) {
		t.Fatalf("failed apply changed warning state:\n got: %#v\nwant: %#v", controller.warnedUsers, appliedWarned)
	}
}

func TestSyncApply_UserDeletionReplacesLimiterWithAuthoritativeUsers(t *testing.T) {
	kept := api.UserInfo{UID: 1, Email: "kept@example.test", UUID: "kept-uuid", SpeedLimit: 100}
	removed := api.UserInfo{UID: 2, Email: "removed@example.test", UUID: "removed-uuid", SpeedLimit: 200}
	currentUsers := []api.UserInfo{kept, removed}
	nextUsers := []api.UserInfo{kept}
	node := &api.NodeInfo{NodeType: "V2ray", NodeID: 1, Port: 443}
	controller, recorder := newTestSyncApplyController(&fakeSyncApplyAPI{userList: &nextUsers})
	tag := controller.buildNodeTagFrom(node)
	controller.setNodeState(node, tag)
	controller.setUserList(&currentUsers)

	if err := controller.ExecuteSyncAction(context.Background(), newSyncAction(syncActionTypeSyncUsers, syncActionSourceWS, syncActionMetadata{Trigger: "users_changed"})); err != nil {
		t.Fatalf("ExecuteSyncAction() error = %v", err)
	}

	if recorder.updateLimiterCalls != 1 || len(recorder.updatedLimiterPayloads) != 1 {
		t.Fatalf("limiter replacements = calls:%d payloads:%d, want one", recorder.updateLimiterCalls, len(recorder.updatedLimiterPayloads))
	}
	assertUserPayload(t, recorder.updatedLimiterPayloads[0], nextUsers)
}
