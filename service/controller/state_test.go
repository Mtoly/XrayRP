package controller

import (
	"regexp"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestNodeRuntimeStateSnapshot(t *testing.T) {
	controller := &Controller{}
	nodeInfo := &api.NodeInfo{NodeID: 42, NodeType: "Vless"}
	userList := &[]api.UserInfo{{UID: 7, Email: "user@example.test"}}

	controller.setNodeState(nodeInfo, "Vless_127.0.0.1_443_42")
	controller.setUserList(userList)

	gotNodeInfo, gotTag, gotUserList := controller.getStateSnapshot()
	if gotNodeInfo != nodeInfo {
		t.Fatalf("expected node info pointer %p, got %p", nodeInfo, gotNodeInfo)
	}
	if gotTag != "Vless_127.0.0.1_443_42" {
		t.Fatalf("expected tag %q, got %q", "Vless_127.0.0.1_443_42", gotTag)
	}
	if gotUserList != userList {
		t.Fatalf("expected user list pointer %p, got %p", userList, gotUserList)
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
