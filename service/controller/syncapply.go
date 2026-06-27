package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/limiter"
	"github.com/Mtoly/XrayRP/common/mylego"
	xraycommon "github.com/xtls/xray-core/common"
)

type syncApplySnapshot struct {
	Action            syncAction
	NodeInfo          *api.NodeInfo
	UserList          *[]api.UserInfo
	RuleList          *[]api.DetectRule
	CertConfig        *api.XrayRCertConfig
	BaseConfig        *api.BaseConfig
	CertConfigFetched bool
}

type syncApplyHooks struct {
	removeOldTag            func(string) error
	removeInboundTag        func(string) error
	removeOutboundTag       func(string) error
	addNewTag               func(*api.NodeInfo, string) error
	addNewUser              func(*[]api.UserInfo, *api.NodeInfo, string) error
	addInboundLimiter       func(string, uint64, *[]api.UserInfo, *limiter.GlobalDeviceLimitConfig) error
	deleteInboundLimiter    func(string) error
	updateInboundLimiter    func(string, *[]api.UserInfo) error
	snapshotInboundLimiter  func(string) (*limiter.InboundLimiterStateSnapshot, error)
	restoreInboundLimiter   func(string, *limiter.InboundLimiterStateSnapshot) error
	updateGlobalDevices     func(string, map[int][]string) error
	clearGlobalDevices      func(string) error
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
	case syncActionTypeSyncDevices, syncActionTypeClearGlobalDevices:
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
		snapshot.BaseConfig = c.currentBaseConfig()
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
		if err != nil {
			if !errors.Is(err, api.ErrUnsupportedPanelFeature) {
				return snapshot, err
			}
		} else {
			snapshot.CertConfig = certConfig
			snapshot.CertConfigFetched = c.shouldApplyFetchedCertConfig(certConfig)
		}
	}

	return snapshot, nil
}

func (c *Controller) applySyncSnapshot(snapshot syncApplySnapshot) error {
	hooks := c.resolveSyncApplyHooks()
	currentNodeInfo, currentTag, currentUserList := c.getStateSnapshot()

	switch snapshot.Action.Type {
	case syncActionTypeSyncDevices:
		if currentTag != "" {
			if err := hooks.updateGlobalDevices(currentTag, snapshot.Action.Payload.Devices); err != nil {
				return err
			}
		}
		if hooks.onSnapshotApplied != nil {
			hooks.onSnapshotApplied(snapshot)
		}
		return nil
	case syncActionTypeClearGlobalDevices:
		if currentTag != "" {
			if err := hooks.clearGlobalDevices(currentTag); err != nil {
				return err
			}
		}
		if hooks.onSnapshotApplied != nil {
			hooks.onSnapshotApplied(snapshot)
		}
		return nil
	}

	nodeChanged := false
	if snapshot.NodeInfo != nil {
		var err error
		currentNodeInfo, currentTag, nodeChanged, err = c.applyNodeSnapshot(currentNodeInfo, currentTag, currentUserList, snapshot.NodeInfo, hooks)
		if err != nil {
			return err
		}
	}

	if err := c.applyBaseConfig(snapshot.BaseConfig); err != nil {
		return err
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

	if snapshot.CertConfigFetched {
		if err := c.applyCertConfigSnapshot(snapshot.CertConfig, hooks); err != nil {
			return err
		}
	}

	if hooks.onSnapshotApplied != nil {
		hooks.onSnapshotApplied(snapshot)
	}
	return nil
}

func (c *Controller) applyNodeSnapshot(currentNodeInfo *api.NodeInfo, currentTag string, currentUserList *[]api.UserInfo, nextNodeInfo *api.NodeInfo, hooks syncApplyHooks) (*api.NodeInfo, string, bool, error) {
	if nextNodeInfo == nil {
		return currentNodeInfo, currentTag, false, nil
	}
	if nextNodeInfo.Port == 0 || nextNodeInfo.Port > 65535 {
		return currentNodeInfo, currentTag, false, fmt.Errorf("invalid server port: %d, must be 1-65535", nextNodeInfo.Port)
	}
	if currentNodeInfo != nil && !nodeStateChanged(currentNodeInfo, nextNodeInfo) {
		return currentNodeInfo, currentTag, false, nil
	}

	newTag := c.buildNodeTagFrom(nextNodeInfo)
	removeCurrentRuntime := func() error {
		if currentNodeInfo == nil || currentTag == "" {
			return nil
		}
		if err := hooks.removeOldTag(currentTag); err != nil {
			return err
		}
		if currentNodeInfo.NodeType == "Shadowsocks-Plugin" {
			if err := hooks.removeOldTag(fmt.Sprintf("dokodemo-door_%s+1", currentTag)); err != nil {
				return err
			}
		}
		return nil
	}
	ignoreNoClue := func(err error) error {
		if err == nil || errors.Is(err, xraycommon.ErrNoClue) {
			return nil
		}
		return err
	}
	cleanupRuntimeTag := func(nodeInfo *api.NodeInfo, tag string) error {
		if nodeInfo == nil || tag == "" {
			return nil
		}
		var cleanupErrs []error
		if err := ignoreNoClue(hooks.removeInboundTag(tag)); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("remove inbound %s: %w", tag, err))
		}
		if err := ignoreNoClue(hooks.removeOutboundTag(tag)); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("remove outbound %s: %w", tag, err))
		}
		if nodeInfo.NodeType == "Shadowsocks-Plugin" {
			dokodemoTag := fmt.Sprintf("dokodemo-door_%s+1", tag)
			if err := ignoreNoClue(hooks.removeInboundTag(dokodemoTag)); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("remove inbound %s: %w", dokodemoTag, err))
			}
			if err := ignoreNoClue(hooks.removeOutboundTag(dokodemoTag)); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("remove outbound %s: %w", dokodemoTag, err))
			}
		}
		return errors.Join(cleanupErrs...)
	}
	restoreCurrentRuntime := func() error {
		if currentNodeInfo == nil || currentTag == "" {
			return nil
		}
		if err := hooks.addNewTag(currentNodeInfo, currentTag); err != nil {
			return err
		}
		if currentUserList == nil {
			return nil
		}
		if err := hooks.addNewUser(currentUserList, currentNodeInfo, currentTag); err != nil {
			if cleanupErr := cleanupRuntimeTag(currentNodeInfo, currentTag); cleanupErr != nil {
				return errors.Join(err, fmt.Errorf("cleanup restored runtime after user restore failure: %w", cleanupErr))
			}
			return err
		}
		return nil
	}

	switch {
	case currentNodeInfo == nil || currentTag == "":
		if err := hooks.addNewTag(nextNodeInfo, newTag); err != nil {
			return currentNodeInfo, currentTag, false, err
		}
	case newTag != currentTag:
		// When the runtime tag changes, stage the new runtime before tearing down
		// the old one so add failures don't drop the currently serving node.
		if err := hooks.addNewTag(nextNodeInfo, newTag); err != nil {
			return currentNodeInfo, currentTag, false, err
		}
		if err := removeCurrentRuntime(); err != nil {
			return currentNodeInfo, currentTag, false, err
		}
	default:
		// Same-tag rebuilds cannot pre-stage another runtime without introducing
		// dual-active behavior. Remove the old runtime, then fully restore the
		// previous runtime if replacement add fails so the controller/runtime state
		// stays on the last known-good node.
		if err := removeCurrentRuntime(); err != nil {
			return currentNodeInfo, currentTag, false, err
		}
		if err := hooks.addNewTag(nextNodeInfo, newTag); err != nil {
			cleanupErr := cleanupRuntimeTag(nextNodeInfo, newTag)
			restoreErr := restoreCurrentRuntime()
			switch {
			case cleanupErr != nil && restoreErr != nil:
				return currentNodeInfo, currentTag, false, errors.Join(err, fmt.Errorf("cleanup partial same-tag rebuild runtime: %w", cleanupErr), fmt.Errorf("restore old runtime after failed same-tag rebuild: %w", restoreErr))
			case cleanupErr != nil:
				return currentNodeInfo, currentTag, false, errors.Join(err, fmt.Errorf("cleanup partial same-tag rebuild runtime: %w", cleanupErr))
			case restoreErr != nil:
				return currentNodeInfo, currentTag, false, errors.Join(err, fmt.Errorf("restore old runtime after failed same-tag rebuild: %w", restoreErr))
			default:
				return currentNodeInfo, currentTag, false, err
			}
		}
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
	currentRuleTag := c.getAppliedRuleTag()
	if detectRuleListsEqual(currentRules, rules) {
		if tag == currentRuleTag || (len(currentRules) == 0 && len(rules) == 0) {
			return nil
		}
	}
	if err := hooks.updateRule(tag, rules); err != nil {
		return err
	}
	c.setAppliedRuleState(tag, rules)
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

	diff := diffUserList(currentUserList, nextUserList)
	if len(diff.Deleted) == 0 && len(diff.Added) == 0 && len(diff.LimitOnly) == 0 && len(diff.RuntimeUpdated) == 0 {
		return nil
	}

	limiterUpdates := make([]api.UserInfo, 0, len(diff.Added)+len(diff.RuntimeUpdated)+len(diff.LimitOnly))
	limiterUpdates = append(limiterUpdates, diff.Added...)
	limiterUpdates = append(limiterUpdates, diff.RuntimeUpdated...)
	limiterUpdates = append(limiterUpdates, diff.LimitOnly...)

	limiterSnapshot, err := hooks.snapshotInboundLimiter(tag)
	if err != nil {
		return err
	}
	restoreLimiter := func(applyErr error) error {
		if restoreErr := hooks.restoreInboundLimiter(tag, limiterSnapshot); restoreErr != nil {
			return errors.Join(applyErr, fmt.Errorf("restore inbound limiter: %w", restoreErr))
		}
		return applyErr
	}

	if err := hooks.updateInboundLimiter(tag, &limiterUpdates); err != nil {
		return restoreLimiter(err)
	}

	// Task 8 restores limiter/controller state on post-limiter runtime hook
	// failures. Full Xray runtime user rollback is future hardening.
	usersToRemove := make([]api.UserInfo, 0, len(diff.Deleted)+len(diff.RuntimeUpdated))
	usersToRemove = append(usersToRemove, diff.Deleted...)
	usersToRemove = append(usersToRemove, diff.RuntimeUpdated...)
	if len(usersToRemove) > 0 {
		removedUserKeys := buildRemovedUserKeys(tag, currentUserList, usersToRemove)
		if len(removedUserKeys) > 0 {
			if err := hooks.removeUsers(removedUserKeys, tag); err != nil {
				return restoreLimiter(err)
			}
		}
	}

	usersToAdd := make([]api.UserInfo, 0, len(diff.Added)+len(diff.RuntimeUpdated))
	usersToAdd = append(usersToAdd, diff.Added...)
	usersToAdd = append(usersToAdd, diff.RuntimeUpdated...)
	if len(usersToAdd) > 0 {
		if err := hooks.addNewUser(&usersToAdd, nodeInfo, tag); err != nil {
			return restoreLimiter(err)
		}
	}
	return nil
}

func (c *Controller) applyCertConfigSnapshot(certConfig *api.XrayRCertConfig, hooks syncApplyHooks) error {
	current := c.config.CertConfig
	if panelCertConfigEqual(current, certConfig) {
		return nil
	}
	if certConfig == nil {
		c.config.CertConfig = nil
		if hooks.onCertConfigApplied != nil {
			hooks.onCertConfigApplied(nil)
		}
		return nil
	}
	if current == nil {
		current = &mylego.CertConfig{}
		c.config.CertConfig = current
	}
	current.Provider = certConfig.Provider
	current.Email = certConfig.Email
	current.DNSEnv = cloneStringMap(certConfig.DNSEnv)
	if hooks.onCertConfigApplied != nil {
		hooks.onCertConfigApplied(clonePanelCertConfig(certConfig))
	}
	return nil
}

func (c *Controller) updateLimiterGlobalDevices(tag string, devices map[int][]string) error {
	if c == nil || c.dispatcher == nil || c.dispatcher.Limiter == nil {
		return nil
	}
	return c.dispatcher.Limiter.UpdateGlobalDevices(tag, devices)
}

func (c *Controller) clearLimiterGlobalDevices(tag string) error {
	if c == nil || c.dispatcher == nil || c.dispatcher.Limiter == nil {
		return nil
	}
	return c.dispatcher.Limiter.ClearGlobalDevices(tag)
}

func (c *Controller) snapshotInboundLimiter(tag string) (*limiter.InboundLimiterStateSnapshot, error) {
	if c == nil || c.dispatcher == nil || c.dispatcher.Limiter == nil {
		return nil, nil
	}
	return c.dispatcher.Limiter.SnapshotInboundLimiterState(tag)
}

func (c *Controller) restoreInboundLimiter(tag string, snapshot *limiter.InboundLimiterStateSnapshot) error {
	if c == nil || c.dispatcher == nil || c.dispatcher.Limiter == nil || snapshot == nil {
		return nil
	}
	return c.dispatcher.Limiter.RestoreInboundLimiterState(tag, snapshot)
}

func (c *Controller) resolveSyncApplyHooks() syncApplyHooks {
	hooks := c.syncApplyHooks
	if hooks.removeOldTag == nil {
		hooks.removeOldTag = c.removeOldTag
	}
	if hooks.removeInboundTag == nil {
		hooks.removeInboundTag = c.removeInbound
	}
	if hooks.removeOutboundTag == nil {
		hooks.removeOutboundTag = c.removeOutbound
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
	if hooks.snapshotInboundLimiter == nil {
		hooks.snapshotInboundLimiter = c.snapshotInboundLimiter
	}
	if hooks.restoreInboundLimiter == nil {
		hooks.restoreInboundLimiter = c.restoreInboundLimiter
	}
	if hooks.updateGlobalDevices == nil {
		hooks.updateGlobalDevices = c.updateLimiterGlobalDevices
	}
	if hooks.clearGlobalDevices == nil {
		hooks.clearGlobalDevices = c.clearLimiterGlobalDevices
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

func (c *Controller) shouldApplyFetchedCertConfig(certConfig *api.XrayRCertConfig) bool {
	if certConfig != nil {
		return true
	}
	return panelCertConfigMayBeCleared(c.panelType)
}

func panelCertConfigMayBeCleared(panelType string) bool {
	switch strings.ToLower(panelType) {
	case "sspanel", "newv2board", "v2board":
		return true
	default:
		return false
	}
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
