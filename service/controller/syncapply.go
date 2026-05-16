package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/common/mylego"
)

type syncApplySnapshot struct {
	Action     syncAction
	NodeInfo   *api.NodeInfo
	UserList   *[]api.UserInfo
	RuleList   *[]api.DetectRule
	CertConfig *api.XrayRCertConfig
}

type syncApplyHooks struct {
	removeOldTag            func(string) error
	addNewTag               func(*api.NodeInfo, string) error
	addNewUser              func(*[]api.UserInfo, *api.NodeInfo, string) error
	addInboundLimiter       func(string, uint64, *[]api.UserInfo, *limiter.GlobalDeviceLimitConfig) error
	deleteInboundLimiter    func(string) error
	updateInboundLimiter    func(string, *[]api.UserInfo) error
	rebuildInboundWithUsers func(*[]api.UserInfo, *api.NodeInfo, string) error
	removeUsers             func([]string, string) error
	updateRule              func(string, []api.DetectRule) error
	onSnapshotApplied       func(syncApplySnapshot)
	onCertConfigApplied     func(*api.XrayRCertConfig)
}

func (c *Controller) ExecuteSyncAction(_ context.Context, action syncAction) error {
	snapshot, err := c.fetchSyncApplySnapshot(action)
	if err != nil {
		return err
	}
	return c.applySyncSnapshot(snapshot)
}

func (c *Controller) fetchSyncApplySnapshot(action syncAction) (syncApplySnapshot, error) {
	currentNodeInfo, _, currentUserList := c.getStateSnapshot()
	snapshot := syncApplySnapshot{Action: action}

	fetchNode := false
	fetchUsers := false
	fetchRules := false
	fetchCert := false

	switch action.Type {
	case syncActionTypeSyncNodeConfig:
		fetchNode = true
		fetchRules = true
	case syncActionTypeSyncUsers:
		fetchUsers = true
	case syncActionTypeSyncCertConfig:
		fetchCert = true
	case syncActionTypeSyncRoutesAndOutbounds:
		fetchNode = true
		fetchRules = true
	case syncActionTypeResyncAll:
		fetchNode = true
		fetchUsers = true
		fetchRules = true
		fetchCert = true
	case syncActionTypeSyncAliveState:
		return snapshot, nil
	default:
		fetchNode = true
		fetchUsers = true
		fetchRules = true
		fetchCert = true
	}

	if fetchNode {
		nodeInfo, err := c.apiClient.GetNodeInfo()
		if err != nil {
			if err.Error() == api.NodeNotModified {
				snapshot.NodeInfo = currentNodeInfo
			} else {
				return snapshot, err
			}
		} else {
			if nodeInfo.Port == 0 || nodeInfo.Port > 65535 {
				return snapshot, fmt.Errorf("invalid server port: %d, must be 1-65535", nodeInfo.Port)
			}
			snapshot.NodeInfo = nodeInfo
		}
	}

	if fetchUsers {
		userList, err := c.apiClient.GetUserList()
		if err != nil {
			if err.Error() == api.UserNotModified {
				snapshot.UserList = currentUserList
			} else {
				return snapshot, err
			}
		} else {
			snapshot.UserList = userList
		}
	}

	if fetchRules && !c.config.DisableGetRule {
		ruleList, err := c.apiClient.GetNodeRule()
		if err != nil {
			if err.Error() == api.RuleNotModified {
				rules := c.getAppliedRuleList()
				snapshot.RuleList = &rules
			} else {
				return snapshot, err
			}
		} else {
			snapshot.RuleList = ruleList
		}
	}

	if fetchCert {
		certConfig, err := c.apiClient.GetXrayRCertConfig()
		if err != nil && !errors.Is(err, api.ErrUnsupportedPanelFeature) {
			return snapshot, err
		}
		snapshot.CertConfig = certConfig
	}

	return snapshot, nil
}

func (c *Controller) applySyncSnapshot(snapshot syncApplySnapshot) error {
	hooks := c.resolveSyncApplyHooks()
	currentNodeInfo, currentTag, currentUserList := c.getStateSnapshot()

	nodeChanged := false
	if snapshot.NodeInfo != nil {
		var err error
		currentNodeInfo, currentTag, nodeChanged, err = c.applyNodeSnapshot(currentNodeInfo, currentTag, snapshot.NodeInfo, hooks)
		if err != nil {
			return err
		}
	}

	if snapshot.RuleList != nil && !c.config.DisableGetRule {
		if err := c.applyRuleSnapshot(currentTag, *snapshot.RuleList, hooks); err != nil {
			return err
		}
	}

	effectiveUsers := snapshot.UserList
	if effectiveUsers == nil {
		effectiveUsers = currentUserList
	}
	if currentNodeInfo != nil && effectiveUsers != nil {
		if err := c.applyUserSnapshot(nodeChanged, currentNodeInfo, currentTag, currentUserList, effectiveUsers, hooks); err != nil {
			return err
		}
		if nodeChanged || snapshot.UserList != nil {
			c.setUserList(effectiveUsers)
		}
	}

	if snapshot.CertConfig != nil {
		if err := c.applyCertConfigSnapshot(snapshot.CertConfig, hooks); err != nil {
			return err
		}
	}

	if hooks.onSnapshotApplied != nil {
		hooks.onSnapshotApplied(snapshot)
	}
	return nil
}

func (c *Controller) applyNodeSnapshot(currentNodeInfo *api.NodeInfo, currentTag string, nextNodeInfo *api.NodeInfo, hooks syncApplyHooks) (*api.NodeInfo, string, bool, error) {
	if nextNodeInfo == nil {
		return currentNodeInfo, currentTag, false, nil
	}
	if nextNodeInfo.Port == 0 || nextNodeInfo.Port > 65535 {
		return currentNodeInfo, currentTag, false, fmt.Errorf("invalid server port: %d, must be 1-65535", nextNodeInfo.Port)
	}
	if currentNodeInfo != nil && !nodeStateChanged(currentNodeInfo, nextNodeInfo) {
		return currentNodeInfo, currentTag, false, nil
	}

	if currentNodeInfo != nil && currentTag != "" {
		if err := hooks.removeOldTag(currentTag); err != nil {
			return currentNodeInfo, currentTag, false, err
		}
		if currentNodeInfo.NodeType == "Shadowsocks-Plugin" {
			if err := hooks.removeOldTag(fmt.Sprintf("dokodemo-door_%s+1", currentTag)); err != nil {
				return currentNodeInfo, currentTag, false, err
			}
		}
	}

	newTag := c.buildNodeTagFrom(nextNodeInfo)
	if err := hooks.addNewTag(nextNodeInfo, newTag); err != nil {
		return currentNodeInfo, currentTag, false, err
	}
	if currentNodeInfo != nil && currentTag != "" {
		if err := hooks.deleteInboundLimiter(currentTag); err != nil {
			return currentNodeInfo, currentTag, false, err
		}
	}
	c.setNodeState(nextNodeInfo, newTag)
	return nextNodeInfo, newTag, true, nil
}

func (c *Controller) applyRuleSnapshot(tag string, rules []api.DetectRule, hooks syncApplyHooks) error {
	if tag == "" {
		return nil
	}
	currentRules := c.getAppliedRuleList()
	if detectRuleListsEqual(currentRules, rules) {
		return nil
	}
	if err := hooks.updateRule(tag, rules); err != nil {
		return err
	}
	c.setAppliedRuleList(rules)
	return nil
}

func (c *Controller) applyUserSnapshot(nodeChanged bool, nodeInfo *api.NodeInfo, tag string, currentUserList, nextUserList *[]api.UserInfo, hooks syncApplyHooks) error {
	if nodeInfo == nil || nextUserList == nil {
		return nil
	}
	if nodeChanged || currentUserList == nil {
		if err := hooks.addNewUser(nextUserList, nodeInfo, tag); err != nil {
			return err
		}
		return hooks.addInboundLimiter(tag, nodeInfo.SpeedLimit, nextUserList, c.config.GlobalDeviceLimitConfig)
	}
	if reflect.DeepEqual(currentUserList, nextUserList) {
		return nil
	}

	if nodeInfo.NodeType == "Socks" || nodeInfo.NodeType == "HTTP" {
		if err := hooks.rebuildInboundWithUsers(nextUserList, nodeInfo, tag); err != nil {
			return err
		}
		return hooks.addInboundLimiter(tag, nodeInfo.SpeedLimit, nextUserList, c.config.GlobalDeviceLimitConfig)
	}

	deleted, added := compareUserList(currentUserList, nextUserList)
	if len(deleted) > 0 {
		deletedEmail := make([]string, len(deleted))
		for i, u := range deleted {
			deletedEmail[i] = fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID)
		}
		if err := hooks.removeUsers(deletedEmail, tag); err != nil {
			return err
		}
	}
	if len(added) > 0 {
		if err := hooks.addNewUser(&added, nodeInfo, tag); err != nil {
			return err
		}
		if err := hooks.updateInboundLimiter(tag, &added); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) applyCertConfigSnapshot(certConfig *api.XrayRCertConfig, hooks syncApplyHooks) error {
	if certConfig == nil {
		return nil
	}
	if c.config.CertConfig != nil && panelCertConfigEqual(c.config.CertConfig, certConfig) {
		return nil
	}
	if c.config.CertConfig == nil {
		c.config.CertConfig = &mylego.CertConfig{}
	}
	c.config.CertConfig.Provider = certConfig.Provider
	c.config.CertConfig.Email = certConfig.Email
	c.config.CertConfig.DNSEnv = cloneStringMap(certConfig.DNSEnv)
	if hooks.onCertConfigApplied != nil {
		hooks.onCertConfigApplied(clonePanelCertConfig(certConfig))
	}
	return nil
}

func (c *Controller) resolveSyncApplyHooks() syncApplyHooks {
	hooks := c.syncApplyHooks
	if hooks.removeOldTag == nil {
		hooks.removeOldTag = c.removeOldTag
	}
	if hooks.addNewTag == nil {
		hooks.addNewTag = c.addNewTag
	}
	if hooks.addNewUser == nil {
		hooks.addNewUser = c.addNewUser
	}
	if hooks.addInboundLimiter == nil {
		hooks.addInboundLimiter = c.AddInboundLimiter
	}
	if hooks.deleteInboundLimiter == nil {
		hooks.deleteInboundLimiter = c.DeleteInboundLimiter
	}
	if hooks.updateInboundLimiter == nil {
		hooks.updateInboundLimiter = c.UpdateInboundLimiter
	}
	if hooks.rebuildInboundWithUsers == nil {
		hooks.rebuildInboundWithUsers = c.rebuildInboundWithUsers
	}
	if hooks.removeUsers == nil {
		hooks.removeUsers = c.removeUsers
	}
	if hooks.updateRule == nil {
		hooks.updateRule = c.UpdateRule
	}
	return hooks
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
	c.stateMu.Lock()
	if len(rules) == 0 {
		c.appliedRuleList = nil
	} else {
		c.appliedRuleList = make([]api.DetectRule, len(rules))
		copy(c.appliedRuleList, rules)
	}
	c.stateMu.Unlock()
}

func detectRuleListsEqual(current, next []api.DetectRule) bool {
	if len(current) != len(next) {
		return false
	}
	for i := range current {
		if current[i].ID != next[i].ID {
			return false
		}
		currentPattern := ""
		nextPattern := ""
		if current[i].Pattern != nil {
			currentPattern = current[i].Pattern.String()
		}
		if next[i].Pattern != nil {
			nextPattern = next[i].Pattern.String()
		}
		if currentPattern != nextPattern {
			return false
		}
	}
	return true
}

func panelCertConfigEqual(current *mylego.CertConfig, next *api.XrayRCertConfig) bool {
	if current == nil || next == nil {
		return current == nil && next == nil
	}
	return current.Provider == next.Provider && current.Email == next.Email && reflect.DeepEqual(current.DNSEnv, next.DNSEnv)
}

func clonePanelCertConfig(certConfig *api.XrayRCertConfig) *api.XrayRCertConfig {
	if certConfig == nil {
		return nil
	}
	return &api.XrayRCertConfig{
		Provider: certConfig.Provider,
		Email:    certConfig.Email,
		DNSEnv:   cloneStringMap(certConfig.DNSEnv),
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(src))
	for key, value := range src {
		cloned[key] = value
	}
	return cloned
}
