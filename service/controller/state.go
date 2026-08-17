package controller

import (
	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/internal/managednode"
)

type nodeRuntimeState struct {
	node            nodeValue
	tag             string
	userListSet     bool
	userList        []api.UserInfo
	appliedRuleTag  string
	appliedRuleList []api.DetectRule
}

func (c *Controller) buildNodeTagFrom(nodeInfo *api.NodeInfo) string {
	return c.buildNodeTagFromSnapshot(api.NormalizeNodeInfo(nodeInfo))
}

func (c *Controller) buildNodeTagFromSnapshot(snapshot *api.NodeSnapshot) string {
	if snapshot == nil {
		return ""
	}
	// Include NodeID to avoid cross-node mixing when multiple logical nodes share
	// the same NodeType/ListenIP/Port (e.g., CDN or multi-node deployments).
	return managednode.BuildTag(snapshot.NodeType, c.config.ListenIP, snapshot.Port, snapshot.NodeID)
}

func (c *Controller) buildNodeTag() string {
	state := c.runtimeStateSnapshot()
	return c.buildNodeTagFromSnapshot(state.node.normalizedSnapshot())
}

func cloneDetectRules(rules []api.DetectRule) []api.DetectRule {
	if rules == nil {
		return nil
	}
	cloned := make([]api.DetectRule, len(rules))
	for index, rule := range rules {
		cloned[index] = rule
		if rule.Pattern != nil {
			cloned[index].Pattern = rule.Pattern.Copy()
		}
	}
	return cloned
}

func cloneNodeRuntimeState(state nodeRuntimeState) nodeRuntimeState {
	state.userList = cloneSlice(state.userList)
	state.appliedRuleList = cloneDetectRules(state.appliedRuleList)
	return state
}

func (state nodeRuntimeState) nodeInfoSnapshot() *api.NodeInfo {
	return state.node.snapshot()
}

func (state nodeRuntimeState) nodeSnapshot() *api.NodeSnapshot {
	return state.node.normalizedSnapshot()
}

func (state nodeRuntimeState) userListSnapshot() *[]api.UserInfo {
	if !state.userListSet {
		return nil
	}
	cloned := cloneSlice(state.userList)
	return &cloned
}

func (c *Controller) runtimeStateSnapshot() nodeRuntimeState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return cloneNodeRuntimeState(c.runtimeState)
}

func (c *Controller) commitRuntimeState(state nodeRuntimeState) {
	c.stateMu.Lock()
	c.runtimeState = cloneNodeRuntimeState(state)
	c.stateMu.Unlock()
}

func (c *Controller) commitRuntimeStateWithUserOverlay(state nodeRuntimeState, overlay limiterUserOverlayCandidate) {
	c.stateMu.Lock()
	c.runtimeState = cloneNodeRuntimeState(state)
	c.limitedUsers = overlay.limitedUsers
	c.warnedUsers = overlay.warnedUsers
	c.stateMu.Unlock()
}

func (c *Controller) commitUserListWithOverlay(userList *[]api.UserInfo, overlay limiterUserOverlayCandidate) {
	c.stateMu.Lock()
	c.runtimeState.userListSet = userList != nil
	if userList == nil {
		c.runtimeState.userList = nil
	} else {
		c.runtimeState.userList = cloneSlice(*userList)
	}
	c.limitedUsers = overlay.limitedUsers
	c.warnedUsers = overlay.warnedUsers
	c.stateMu.Unlock()
}

func (c *Controller) getStateSnapshot() (nodeInfo *api.NodeInfo, tag string, userList *[]api.UserInfo) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.runtimeState.nodeInfoSnapshot(), c.runtimeState.tag, c.runtimeState.userListSnapshot()
}

func (c *Controller) getSnapshotState() (snapshot *api.NodeSnapshot, tag string, userList *[]api.UserInfo) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.runtimeState.nodeSnapshot(), c.runtimeState.tag, c.runtimeState.userListSnapshot()
}

func (c *Controller) setNodeState(nodeInfo *api.NodeInfo, tag string) {
	c.setNodeSnapshot(api.NormalizeNodeInfo(nodeInfo), tag)
}

func (c *Controller) setNodeSnapshot(snapshot *api.NodeSnapshot, tag string) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.runtimeState.node = normalizeNodeSnapshot(snapshot)
	c.runtimeState.tag = tag
}

func (c *Controller) setUserList(userList *[]api.UserInfo) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.runtimeState.userListSet = userList != nil
	if userList == nil {
		c.runtimeState.userList = nil
	} else {
		c.runtimeState.userList = cloneSlice(*userList)
	}
}

func (c *Controller) withStateLock(fn func()) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	fn()
}

func (c *Controller) getAppliedRuleTag() string {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.runtimeState.appliedRuleTag
}

func (c *Controller) getAppliedRuleState() (string, []api.DetectRule) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.runtimeState.appliedRuleTag, cloneDetectRules(c.runtimeState.appliedRuleList)
}

func (c *Controller) setAppliedRuleState(tag string, rules []api.DetectRule) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.runtimeState.appliedRuleTag = tag
	c.runtimeState.appliedRuleList = cloneDetectRules(rules)
}

func (c *Controller) getAppliedRuleList() []api.DetectRule {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return cloneDetectRules(c.runtimeState.appliedRuleList)
}

func (c *Controller) setAppliedRuleList(rules []api.DetectRule) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	tag := c.runtimeState.appliedRuleTag
	if tag == "" {
		tag = c.runtimeState.tag
	}
	c.runtimeState.appliedRuleTag = tag
	c.runtimeState.appliedRuleList = cloneDetectRules(rules)
}
