package controller

import "github.com/Mtoly/XrayRP/api"

func (c *Controller) getStateSnapshot() (nodeInfo *api.NodeInfo, tag string, userList *[]api.UserInfo) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.nodeInfo, c.Tag, c.userList
}

func (c *Controller) setNodeState(nodeInfo *api.NodeInfo, tag string) {
	c.stateMu.Lock()
	c.nodeInfo = nodeInfo
	c.Tag = tag
	c.stateMu.Unlock()
}

func (c *Controller) setUserList(userList *[]api.UserInfo) {
	c.stateMu.Lock()
	c.userList = userList
	c.stateMu.Unlock()
}

func (c *Controller) withStateLock(fn func()) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	fn()
}

func (c *Controller) getAppliedRuleTag() string {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.appliedRuleTag
}

func (c *Controller) setAppliedRuleState(tag string, rules []api.DetectRule) {
	c.stateMu.Lock()
	c.appliedRuleTag = tag
	if len(rules) == 0 {
		c.appliedRuleList = nil
	} else {
		c.appliedRuleList = make([]api.DetectRule, len(rules))
		copy(c.appliedRuleList, rules)
	}
	c.stateMu.Unlock()
}

func (c *Controller) getAppliedRuleList() []api.DetectRule {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	if len(c.appliedRuleList) == 0 {
		return nil
	}
	rules := make([]api.DetectRule, len(c.appliedRuleList))
	copy(rules, c.appliedRuleList)
	return rules
}

func (c *Controller) setAppliedRuleList(rules []api.DetectRule) {
	c.stateMu.RLock()
	tag := c.appliedRuleTag
	if tag == "" {
		tag = c.Tag
	}
	c.stateMu.RUnlock()
	c.setAppliedRuleState(tag, rules)
}
