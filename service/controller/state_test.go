package controller

import (
	"encoding/json"
	"net"
	"regexp"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

func TestNodeRuntimeStateCloneAddressPreservesFamilyAndValue(t *testing.T) {
	tests := []struct {
		name    string
		address xraynet.Address
		family  xraynet.AddressFamily
	}{
		{name: "numeric domain", address: xraynet.DomainAddress("1.1.1.1"), family: xraynet.AddressFamilyDomain},
		{name: "IPv4", address: xraynet.IPAddress(net.IPv4(192, 0, 2, 1).To4()), family: xraynet.AddressFamilyIPv4},
		{name: "IPv6", address: xraynet.IPAddress(net.ParseIP("2001:db8::1")), family: xraynet.AddressFamilyIPv6},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cloned := cloneAddress(&conf.Address{Address: test.address})
			if cloned == nil || cloned.Address == nil {
				t.Fatalf("expected cloned address, got %#v", cloned)
			}
			if cloned.Address.Family() != test.family {
				t.Fatalf("expected family %d, got %d", test.family, cloned.Address.Family())
			}
			if cloned.Address.String() != test.address.String() {
				t.Fatalf("expected value %q, got %q", test.address.String(), cloned.Address.String())
			}
			if test.family.IsIP() {
				originalIP := test.address.IP()
				clonedIP := cloned.Address.IP()
				if len(originalIP) == 0 || len(clonedIP) == 0 || &originalIP[0] == &clonedIP[0] {
					t.Fatalf("expected independent IP bytes, original=%v cloned=%v", originalIP, clonedIP)
				}
			}
		})
	}
}

func TestNodeRuntimeStateUpdatePreservesOneGeneration(t *testing.T) {
	controller := &Controller{}
	node := &api.NodeInfo{NodeID: 1, NodeType: "Vless"}
	users := &[]api.UserInfo{{UID: 1, Email: "user@example.test"}}
	controller.commitRuntimeState(nodeRuntimeState{
		nodeInfoSet: true,
		nodeInfo:    *node,
		tag:         "node-tag",
		userListSet: true,
		userList:    *users,
	})

	controller.setAppliedRuleState("node-tag", []api.DetectRule{{ID: 3, Pattern: regexp.MustCompile("ads")}})

	snapshot := controller.runtimeStateSnapshot()
	if !snapshot.nodeInfoSet || snapshot.nodeInfo.NodeID != node.NodeID || snapshot.nodeInfo.NodeType != node.NodeType || snapshot.tag != "node-tag" {
		t.Fatalf("expected rule update to preserve node generation values, got %#v", snapshot)
	}
	if !snapshot.userListSet || len(snapshot.userList) != 1 || snapshot.userList[0] != (*users)[0] {
		t.Fatalf("expected rule update to preserve owned users, got %#v", snapshot)
	}
	if snapshot.appliedRuleTag != "node-tag" || len(snapshot.appliedRuleList) != 1 || snapshot.appliedRuleList[0].ID != 3 {
		t.Fatalf("expected rule update in committed generation, got %#v", snapshot)
	}
}

func TestNodeRuntimeStateCommitIsAtomic(t *testing.T) {
	controller := &Controller{}
	oldNode := &api.NodeInfo{NodeID: 1, NodeType: "Vless"}
	oldUsers := &[]api.UserInfo{{UID: 1, Email: "old@example.test"}}
	controller.commitRuntimeState(nodeRuntimeState{
		nodeInfoSet:    true,
		nodeInfo:       *oldNode,
		tag:            "old-tag",
		userListSet:    true,
		userList:       *oldUsers,
		appliedRuleTag: "old-tag",
		appliedRuleList: []api.DetectRule{{
			ID:      1,
			Pattern: regexp.MustCompile("old"),
		}},
	})

	nextNode := &api.NodeInfo{NodeID: 2, NodeType: "Trojan"}
	nextUsers := &[]api.UserInfo{{UID: 2, Email: "new@example.test"}}
	controller.commitRuntimeState(nodeRuntimeState{
		nodeInfoSet:    true,
		nodeInfo:       *nextNode,
		tag:            "new-tag",
		userListSet:    true,
		userList:       *nextUsers,
		appliedRuleTag: "new-tag",
		appliedRuleList: []api.DetectRule{{
			ID:      2,
			Pattern: regexp.MustCompile("new"),
		}},
	})

	snapshot := controller.runtimeStateSnapshot()
	if !snapshot.nodeInfoSet || snapshot.nodeInfo.NodeID != nextNode.NodeID || snapshot.nodeInfo.NodeType != nextNode.NodeType || snapshot.tag != "new-tag" {
		t.Fatalf("expected one committed node generation value, got %#v", snapshot)
	}
	if !snapshot.userListSet || len(snapshot.userList) != 1 || snapshot.userList[0] != (*nextUsers)[0] {
		t.Fatalf("expected one committed owned user generation, got %#v", snapshot)
	}
	if snapshot.appliedRuleTag != "new-tag" || len(snapshot.appliedRuleList) != 1 || snapshot.appliedRuleList[0].ID != 2 {
		t.Fatalf("expected matching committed rule generation, got %#v", snapshot)
	}
}

func TestNodeRuntimeStateSnapshotRuleListIsIndependent(t *testing.T) {
	controller := &Controller{}
	controller.setAppliedRuleState("node-tag", []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("blocked")}})

	snapshot := controller.runtimeStateSnapshot()
	snapshot.appliedRuleList[0].ID = 99

	next := controller.runtimeStateSnapshot()
	if next.appliedRuleList[0].ID != 1 {
		t.Fatalf("expected state snapshot rules to be independent, got %#v", next.appliedRuleList)
	}
}

func TestNodeRuntimeStateSnapshot(t *testing.T) {
	controller := &Controller{}
	nodeInfo := &api.NodeInfo{NodeID: 42, NodeType: "Vless"}
	userList := &[]api.UserInfo{{UID: 7, Email: "user@example.test"}}

	controller.setNodeState(nodeInfo, "Vless_127.0.0.1_443_42")
	controller.setUserList(userList)

	gotNodeInfo, gotTag, gotUserList := controller.getStateSnapshot()
	if gotNodeInfo == nodeInfo || gotNodeInfo.NodeID != nodeInfo.NodeID || gotNodeInfo.NodeType != nodeInfo.NodeType {
		t.Fatalf("expected an independent node info copy, got %#v", gotNodeInfo)
	}
	if gotTag != "Vless_127.0.0.1_443_42" {
		t.Fatalf("expected tag %q, got %q", "Vless_127.0.0.1_443_42", gotTag)
	}
	if gotUserList == userList || len(*gotUserList) != 1 || (*gotUserList)[0] != (*userList)[0] {
		t.Fatalf("expected an independent user list copy, got %#v", gotUserList)
	}
}

func TestNodeRuntimeStateCommitOwnsMutableInputs(t *testing.T) {
	controller := &Controller{}
	nodeInfo := testMutableNodeInfo(t)
	userList := []api.UserInfo{{UID: 7, Email: "user@example.test"}}
	rules := []api.DetectRule{{ID: 3, Pattern: regexp.MustCompile("ads")}}

	controller.commitRuntimeState(nodeRuntimeState{
		nodeInfoSet:     true,
		nodeInfo:        *nodeInfo,
		tag:             "node-tag",
		userListSet:     true,
		userList:        userList,
		appliedRuleTag:  "node-tag",
		appliedRuleList: rules,
	})

	mutateNodeInfo(nodeInfo)
	userList[0].Email = "mutated@example.test"
	rules[0].ID = 99
	rules[0].Pattern.Longest()

	assertMutableStateUnchanged(t, controller.runtimeStateSnapshot())
}

func TestNodeRuntimeStateSettersOwnMutableInputs(t *testing.T) {
	controller := &Controller{}
	nodeInfo := testMutableNodeInfo(t)
	users := []api.UserInfo{{UID: 7, Email: "user@example.test"}}
	rules := []api.DetectRule{{ID: 3, Pattern: regexp.MustCompile("ads")}}

	controller.setNodeState(nodeInfo, "node-tag")
	controller.setUserList(&users)
	controller.setAppliedRuleState("node-tag", rules)

	mutateNodeInfo(nodeInfo)
	users[0].Email = "mutated@example.test"
	rules[0].ID = 99
	rules[0].Pattern.Longest()

	assertMutableStateUnchanged(t, controller.runtimeStateSnapshot())
}

func TestNodeRuntimeStateSnapshotOwnsReturnedData(t *testing.T) {
	controller := &Controller{}
	users := []api.UserInfo{{UID: 7, Email: "user@example.test"}}
	nodeInfo := testMutableNodeInfo(t)
	controller.commitRuntimeState(nodeRuntimeState{
		nodeInfoSet:     true,
		nodeInfo:        *nodeInfo,
		tag:             "node-tag",
		userListSet:     true,
		userList:        users,
		appliedRuleTag:  "node-tag",
		appliedRuleList: []api.DetectRule{{ID: 3, Pattern: regexp.MustCompile("ads")}},
	})

	snapshot := controller.runtimeStateSnapshot()
	mutateNodeInfo(&snapshot.nodeInfo)
	snapshot.userList[0].Email = "mutated@example.test"
	snapshot.appliedRuleList[0].ID = 99
	snapshot.appliedRuleList[0].Pattern.Longest()

	assertMutableStateUnchanged(t, controller.runtimeStateSnapshot())
}

func TestNodeRuntimeStateGettersOwnReturnedData(t *testing.T) {
	controller := &Controller{}
	users := []api.UserInfo{{UID: 7, Email: "user@example.test"}}
	nodeInfo := testMutableNodeInfo(t)
	controller.commitRuntimeState(nodeRuntimeState{
		nodeInfoSet:     true,
		nodeInfo:        *nodeInfo,
		tag:             "node-tag",
		userListSet:     true,
		userList:        users,
		appliedRuleTag:  "node-tag",
		appliedRuleList: []api.DetectRule{{ID: 3, Pattern: regexp.MustCompile("ads")}},
	})

	nodeInfo, _, userList := controller.getStateSnapshot()
	rules := controller.getAppliedRuleList()
	mutateNodeInfo(nodeInfo)
	(*userList)[0].Email = "mutated@example.test"
	rules[0].ID = 99
	rules[0].Pattern.Longest()

	assertMutableStateUnchanged(t, controller.runtimeStateSnapshot())
}

func TestNodeRuntimeStatePreservesNilAndEmptyCollections(t *testing.T) {
	controller := &Controller{}
	emptyUsers := make([]api.UserInfo, 0)
	emptyRules := make([]api.DetectRule, 0)
	emptyStringList := conf.StringList(make([]string, 0))
	emptyNodeInfo := &api.NodeInfo{
		Header:      make(json.RawMessage, 0),
		HttpHeaders: make(map[string]*conf.StringList),
		Headers:     make(map[string]string),
		NameServerConfig: []*conf.NameServerConfig{{
			Domains:       make([]string, 0),
			ExpectedIPs:   emptyStringList,
			ExpectIPs:     conf.StringList(make([]string, 0)),
			UnexpectedIPs: conf.StringList(make([]string, 0)),
		}},
		REALITYConfig: &api.REALITYConfig{
			ServerNames: make([]string, 0),
			ShortIds:    make([]string, 0),
		},
		ServerNames:  make([]string, 0),
		ShortIds:     make([]string, 0),
		AnyTLSConfig: &api.AnyTLSConfig{PaddingScheme: make([]string, 0)},
		TuicConfig:   &api.TuicConfig{ALPN: make([]string, 0)},
		RoutePolicy: &api.PanelRoutePolicy{
			DirectDomains: make([]string, 0),
			Outbound: api.OutboundFilterPolicy{
				Candidates: make([]string, 0),
				Include:    make([]string, 0),
				Exclude:    make([]string, 0),
				Fallback:   make([]string, 0),
			},
		},
		XHTTPExtra:            make(json.RawMessage, 0),
		XHTTPDownloadSettings: make(json.RawMessage, 0),
	}

	controller.commitRuntimeState(nodeRuntimeState{
		nodeInfoSet:     true,
		nodeInfo:        *emptyNodeInfo,
		userListSet:     true,
		userList:        emptyUsers,
		appliedRuleList: emptyRules,
	})

	snapshot := controller.runtimeStateSnapshot()
	if !snapshot.nodeInfoSet || snapshot.nodeInfo.Header == nil || snapshot.nodeInfo.HttpHeaders == nil || snapshot.nodeInfo.Headers == nil || snapshot.nodeInfo.ServerNames == nil || snapshot.nodeInfo.ShortIds == nil || snapshot.nodeInfo.XHTTPExtra == nil || snapshot.nodeInfo.XHTTPDownloadSettings == nil {
		t.Fatalf("expected empty node collections to remain non-nil, got %#v", snapshot.nodeInfo)
	}
	nameServer := snapshot.nodeInfo.NameServerConfig[0]
	if snapshot.nodeInfo.NameServerConfig == nil || nameServer == nil || nameServer.Domains == nil || nameServer.ExpectedIPs == nil || nameServer.ExpectIPs == nil || nameServer.UnexpectedIPs == nil {
		t.Fatalf("expected empty name server collections to remain non-nil, got %#v", snapshot.nodeInfo.NameServerConfig)
	}
	if snapshot.nodeInfo.REALITYConfig == nil || snapshot.nodeInfo.REALITYConfig.ServerNames == nil || snapshot.nodeInfo.REALITYConfig.ShortIds == nil {
		t.Fatalf("expected empty REALITY collections to remain non-nil, got %#v", snapshot.nodeInfo.REALITYConfig)
	}
	if snapshot.nodeInfo.AnyTLSConfig == nil || snapshot.nodeInfo.AnyTLSConfig.PaddingScheme == nil || snapshot.nodeInfo.TuicConfig == nil || snapshot.nodeInfo.TuicConfig.ALPN == nil {
		t.Fatalf("expected empty protocol collections to remain non-nil, got AnyTLS=%#v TUIC=%#v", snapshot.nodeInfo.AnyTLSConfig, snapshot.nodeInfo.TuicConfig)
	}
	policy := snapshot.nodeInfo.RoutePolicy
	if policy == nil || policy.DirectDomains == nil || policy.Outbound.Candidates == nil || policy.Outbound.Include == nil || policy.Outbound.Exclude == nil || policy.Outbound.Fallback == nil {
		t.Fatalf("expected empty route policy collections to remain non-nil, got %#v", policy)
	}
	if !snapshot.userListSet || snapshot.userList == nil {
		t.Fatalf("expected empty user list to remain non-nil, got %#v", snapshot.userList)
	}
	if snapshot.appliedRuleList == nil {
		t.Fatalf("expected empty applied rule list to remain non-nil")
	}

	controller.commitRuntimeState(nodeRuntimeState{})
	nilSnapshot := controller.runtimeStateSnapshot()
	if nilSnapshot.nodeInfoSet || nilSnapshot.userListSet || nilSnapshot.appliedRuleList != nil {
		t.Fatalf("expected nil state collections to remain nil, got %#v", nilSnapshot)
	}
}

func testMutableNodeInfo(t *testing.T) *api.NodeInfo {
	t.Helper()
	var nameServers []conf.NameServerConfig
	if err := json.Unmarshal([]byte(`[{
		"address":"1.1.1.1",
		"clientIp":"192.0.2.1",
		"domains":["domain:example.test"],
		"expectedIPs":["geoip:private"],
		"expectIPs":["geoip:us"],
		"unexpectedIPs":["geoip:cn"],
		"disableCache":true,
		"serveStale":true,
		"serveExpiredTTL":60
	},null]`), &nameServers); err != nil {
		t.Fatalf("unmarshal name server config: %v", err)
	}
	nameServerPointers := make([]*conf.NameServerConfig, len(nameServers))
	for index := range nameServers {
		nameServerPointers[index] = &nameServers[index]
	}
	nameServerPointers[1] = nil
	return &api.NodeInfo{
		NodeID: 42,
		Header: json.RawMessage(`{"type":"http"}`),
		HttpHeaders: map[string]*conf.StringList{
			"Host":  conf.NewStringList([]string{"origin.example.test"}),
			"Empty": conf.NewStringList(make([]string, 0)),
			"Nil":   nil,
		},
		Headers:          map[string]string{"X-Test": "original"},
		NameServerConfig: nameServerPointers,
		REALITYConfig: &api.REALITYConfig{
			ServerNames: []string{"reality.example.test"},
			ShortIds:    []string{"abcd"},
		},
		ServerNames:     []string{"server.example.test"},
		ShortIds:        []string{"1234"},
		Hysteria2Config: &api.Hysteria2Config{Obfs: "salamander"},
		AnyTLSConfig:    &api.AnyTLSConfig{PaddingScheme: []string{"stop=8"}},
		TuicConfig:      &api.TuicConfig{ALPN: []string{"h3"}},
		RoutePolicy: &api.PanelRoutePolicy{
			DirectDomains: []string{"direct.example.test"},
			Outbound: api.OutboundFilterPolicy{
				Candidates: []string{"candidate-a"},
				Include:    []string{"include-a"},
				Exclude:    []string{"exclude-a"},
				Fallback:   []string{"fallback-a"},
			},
		},
		XHTTPExtra:            json.RawMessage(`{"downloadSettings":{"address":"download.example.test"}}`),
		XPaddingBytes:         &[2]int32{1, 2},
		ScMaxEachPostBytes:    &[2]int32{3, 4},
		ScMinPostsIntervalMs:  &[2]int32{5, 6},
		ScStreamUpServerSecs:  &[2]int32{7, 8},
		XmuxMaxConcurrency:    &[2]int32{9, 10},
		XmuxMaxConnections:    &[2]int32{11, 12},
		XmuxCMaxReuseTimes:    &[2]int32{13, 14},
		XmuxHMaxRequestTimes:  &[2]int32{15, 16},
		XmuxHMaxReusableSecs:  &[2]int32{17, 18},
		XHTTPDownloadSettings: json.RawMessage(`{"network":"tcp"}`),
	}
}

func mutateNodeInfo(nodeInfo *api.NodeInfo) {
	nodeInfo.NodeID = 99
	nodeInfo.Header[0] = '['
	(*nodeInfo.HttpHeaders["Host"])[0] = "mutated.example.test"
	nodeInfo.Headers["X-Test"] = "mutated"
	nodeInfo.NameServerConfig[0].Address.Address = xraynet.ParseAddress("mutated.example.test")
	nodeInfo.NameServerConfig[0].ClientIP.Address = xraynet.ParseAddress("198.51.100.1")
	nodeInfo.NameServerConfig[0].Domains[0] = "domain:mutated.example.test"
	nodeInfo.NameServerConfig[0].ExpectedIPs[0] = "geoip:cn"
	nodeInfo.NameServerConfig[0].ExpectIPs[0] = "geoip:de"
	nodeInfo.NameServerConfig[0].UnexpectedIPs[0] = "geoip:private"
	*nodeInfo.NameServerConfig[0].DisableCache = false
	*nodeInfo.NameServerConfig[0].ServeStale = false
	*nodeInfo.NameServerConfig[0].ServeExpiredTTL = 1
	nodeInfo.REALITYConfig.ServerNames[0] = "mutated-reality.example.test"
	nodeInfo.REALITYConfig.ShortIds[0] = "ffff"
	nodeInfo.ServerNames[0] = "mutated-server.example.test"
	nodeInfo.ShortIds[0] = "ffff"
	nodeInfo.Hysteria2Config.Obfs = "mutated"
	nodeInfo.AnyTLSConfig.PaddingScheme[0] = "stop=99"
	nodeInfo.TuicConfig.ALPN[0] = "mutated"
	nodeInfo.RoutePolicy.DirectDomains[0] = "mutated-direct.example.test"
	nodeInfo.RoutePolicy.Outbound.Candidates[0] = "mutated-candidate"
	nodeInfo.RoutePolicy.Outbound.Include[0] = "mutated-include"
	nodeInfo.RoutePolicy.Outbound.Exclude[0] = "mutated-exclude"
	nodeInfo.RoutePolicy.Outbound.Fallback[0] = "mutated-fallback"
	nodeInfo.XHTTPExtra[0] = '['
	nodeInfo.XPaddingBytes[0] = 99
	nodeInfo.ScMaxEachPostBytes[0] = 99
	nodeInfo.ScMinPostsIntervalMs[0] = 99
	nodeInfo.ScStreamUpServerSecs[0] = 99
	nodeInfo.XmuxMaxConcurrency[0] = 99
	nodeInfo.XmuxMaxConnections[0] = 99
	nodeInfo.XmuxCMaxReuseTimes[0] = 99
	nodeInfo.XmuxHMaxRequestTimes[0] = 99
	nodeInfo.XmuxHMaxReusableSecs[0] = 99
	nodeInfo.XHTTPDownloadSettings[0] = '['
}

func assertMutableStateUnchanged(t *testing.T, snapshot nodeRuntimeState) {
	t.Helper()
	if !snapshot.nodeInfoSet || snapshot.nodeInfo.NodeID != 42 {
		t.Fatalf("expected owned node info, got %#v", snapshot.nodeInfo)
	}
	if string(snapshot.nodeInfo.Header) != `{"type":"http"}` || string(snapshot.nodeInfo.XHTTPExtra) != `{"downloadSettings":{"address":"download.example.test"}}` || string(snapshot.nodeInfo.XHTTPDownloadSettings) != `{"network":"tcp"}` {
		t.Fatalf("expected owned raw JSON fields, got %#v", snapshot.nodeInfo)
	}
	if (*snapshot.nodeInfo.HttpHeaders["Host"])[0] != "origin.example.test" || snapshot.nodeInfo.HttpHeaders["Empty"] == nil || *snapshot.nodeInfo.HttpHeaders["Empty"] == nil || snapshot.nodeInfo.HttpHeaders["Nil"] != nil || snapshot.nodeInfo.Headers["X-Test"] != "original" {
		t.Fatalf("expected owned header maps with nil and empty values preserved, got %#v", snapshot.nodeInfo)
	}
	nameServer := snapshot.nodeInfo.NameServerConfig[0]
	if len(snapshot.nodeInfo.NameServerConfig) != 2 || snapshot.nodeInfo.NameServerConfig[1] != nil || nameServer.Address.String() != "1.1.1.1" || nameServer.ClientIP.String() != "192.0.2.1" || nameServer.Domains[0] != "domain:example.test" || nameServer.ExpectedIPs[0] != "geoip:private" || nameServer.ExpectIPs[0] != "geoip:us" || nameServer.UnexpectedIPs[0] != "geoip:cn" || !*nameServer.DisableCache || !*nameServer.ServeStale || *nameServer.ServeExpiredTTL != 60 {
		t.Fatalf("expected owned nested name server config, got %#v", snapshot.nodeInfo.NameServerConfig)
	}
	if snapshot.nodeInfo.REALITYConfig.ServerNames[0] != "reality.example.test" || snapshot.nodeInfo.REALITYConfig.ShortIds[0] != "abcd" || snapshot.nodeInfo.ServerNames[0] != "server.example.test" || snapshot.nodeInfo.ShortIds[0] != "1234" {
		t.Fatalf("expected owned server name and short ID slices, got %#v", snapshot.nodeInfo)
	}
	if snapshot.nodeInfo.Hysteria2Config.Obfs != "salamander" || snapshot.nodeInfo.AnyTLSConfig.PaddingScheme[0] != "stop=8" || snapshot.nodeInfo.TuicConfig.ALPN[0] != "h3" {
		t.Fatalf("expected owned protocol configs, got %#v", snapshot.nodeInfo)
	}
	policy := snapshot.nodeInfo.RoutePolicy
	if policy.DirectDomains[0] != "direct.example.test" || policy.Outbound.Candidates[0] != "candidate-a" || policy.Outbound.Include[0] != "include-a" || policy.Outbound.Exclude[0] != "exclude-a" || policy.Outbound.Fallback[0] != "fallback-a" {
		t.Fatalf("expected owned route policy, got %#v", policy)
	}
	if snapshot.nodeInfo.XPaddingBytes[0] != 1 || snapshot.nodeInfo.ScMaxEachPostBytes[0] != 3 || snapshot.nodeInfo.ScMinPostsIntervalMs[0] != 5 || snapshot.nodeInfo.ScStreamUpServerSecs[0] != 7 || snapshot.nodeInfo.XmuxMaxConcurrency[0] != 9 || snapshot.nodeInfo.XmuxMaxConnections[0] != 11 || snapshot.nodeInfo.XmuxCMaxReuseTimes[0] != 13 || snapshot.nodeInfo.XmuxHMaxRequestTimes[0] != 15 || snapshot.nodeInfo.XmuxHMaxReusableSecs[0] != 17 {
		t.Fatalf("expected owned range pointers, got %#v", snapshot.nodeInfo)
	}
	if !snapshot.userListSet || snapshot.userList[0].Email != "user@example.test" {
		t.Fatalf("expected owned user list, got %#v", snapshot.userList)
	}
	if len(snapshot.appliedRuleList) != 1 || snapshot.appliedRuleList[0].ID != 3 || snapshot.appliedRuleList[0].Pattern == nil || snapshot.appliedRuleList[0].Pattern.String() != "ads" {
		t.Fatalf("expected owned applied rules, got %#v", snapshot.appliedRuleList)
	}
}

func TestNodeRuntimeStateAppliedRuleListIsCopied(t *testing.T) {
	controller := &Controller{}
	rules := []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("blocked")}}

	controller.setAppliedRuleState("node-tag", rules)
	rules[0].ID = 99

	got := controller.getAppliedRuleList()
	if len(got) != 1 {
		t.Fatalf("expected one applied rule, got %d", len(got))
	}
	if got[0].ID != 1 {
		t.Fatalf("expected stored rule ID to stay 1 after source mutation, got %d", got[0].ID)
	}

	got[0].ID = 100
	gotAgain := controller.getAppliedRuleList()
	if gotAgain[0].ID != 1 {
		t.Fatalf("expected stored rule ID to stay 1 after returned slice mutation, got %d", gotAgain[0].ID)
	}
}

func TestNodeRuntimeStateSetAppliedRuleListFallsBackToCurrentTag(t *testing.T) {
	controller := &Controller{}
	controller.setNodeState(&api.NodeInfo{NodeID: 1}, "current-node-tag")

	controller.setAppliedRuleList([]api.DetectRule{{ID: 3, Pattern: regexp.MustCompile("ads")}})

	if got := controller.getAppliedRuleTag(); got != "current-node-tag" {
		t.Fatalf("expected applied rule tag to fall back to current node tag, got %q", got)
	}
}

func TestNodeRuntimeStateSetAppliedRuleStateClearsEmptyRules(t *testing.T) {
	controller := &Controller{}
	controller.setAppliedRuleState("node-tag", []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("blocked")}})

	controller.setAppliedRuleState("node-tag", nil)

	if got := controller.getAppliedRuleList(); got != nil {
		t.Fatalf("expected empty applied rule list to be nil, got %#v", got)
	}
	if got := controller.getAppliedRuleTag(); got != "node-tag" {
		t.Fatalf("expected applied rule tag to remain node-tag, got %q", got)
	}
}
