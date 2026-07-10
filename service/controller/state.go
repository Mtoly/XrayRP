package controller

import "github.com/Mtoly/XrayRP/api"

type nodeRuntimeState struct {
	nodeInfo        *api.NodeInfo
	tag             string
	userList        *[]api.UserInfo
	appliedRuleTag  string
	appliedRuleList []api.DetectRule
}

func cloneDetectRules(rules []api.DetectRule) []api.DetectRule {
	if len(rules) == 0 {
		return nil
	}
	cloned := make([]api.DetectRule, len(rules))
	copy(cloned, rules)
	return cloned
}

func cloneNodeRuntimeState(state nodeRuntimeState) nodeRuntimeState {
	state.appliedRuleList = cloneDetectRules(state.appliedRuleList)
	return state
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

func (c *Controller) updateRuntimeState(update func(*nodeRuntimeState)) {
	c.stateMu.Lock()
	state := cloneNodeRuntimeState(c.runtimeState)
	update(&state)
	c.runtimeState = state
	c.stateMu.Unlock()
}

func (c *Controller) getStateSnapshot() (nodeInfo *api.NodeInfo, tag string, userList *[]api.UserInfo) {
	state := c.runtimeStateSnapshot()
	return state.nodeInfo, state.tag, state.userList
}

func (c *Controller) setNodeState(nodeInfo *api.NodeInfo, tag string) {
	c.updateRuntimeState(func(state *nodeRuntimeState) {
		state.nodeInfo = nodeInfo
		state.tag = tag
	})
}

func (c *Controller) setUserList(userList *[]api.UserInfo) {
	c.updateRuntimeState(func(state *nodeRuntimeState) {
		state.userList = userList
	})
}

func (c *Controller) withStateLock(fn func()) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	fn()
}

func (c *Controller) getAppliedRuleTag() string {
	return c.runtimeStateSnapshot().appliedRuleTag
}

func (c *Controller) setAppliedRuleState(tag string, rules []api.DetectRule) {
	c.updateRuntimeState(func(state *nodeRuntimeState) {
		state.appliedRuleTag = tag
		state.appliedRuleList = cloneDetectRules(rules)
	})
}

func (c *Controller) getAppliedRuleList() []api.DetectRule {
	return c.runtimeStateSnapshot().appliedRuleList
}

func (c *Controller) setAppliedRuleList(rules []api.DetectRule) {
	c.updateRuntimeState(func(state *nodeRuntimeState) {
		tag := state.appliedRuleTag
		if tag == "" {
			tag = state.tag
		}
		state.appliedRuleTag = tag
		state.appliedRuleList = cloneDetectRules(rules)
	})
}
