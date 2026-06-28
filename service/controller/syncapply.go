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

type globalDeviceApply struct {
	Devices map[int][]string
	Clear   bool
}

type syncApplyHooks struct {
	cleanupRuntimeTag       func(*api.NodeInfo, string) error
	addNewTag               func(*api.NodeInfo, string) error
	addNewUser              func(*[]api.UserInfo, *api.NodeInfo, string) error
	addInboundLimiter       func(string, uint64, *[]api.UserInfo, *limiter.GlobalDeviceLimitConfig) error
	deleteInboundLimiter    func(string) error
	updateInboundLimiter    func(string, *[]api.UserInfo) error
	snapshotInboundLimiter  func(string) (*limiter.InboundLimiterStateSnapshot, error)
	restoreInboundLimiter   func(string, *limiter.InboundLimiterStateSnapshot) error
	applyGlobalDevices      func(string, globalDeviceApply) error
	rebuildInboundWithUsers func(*[]api.UserInfo, *api.NodeInfo, string) error
	removeUsers             func([]string, string) error
	updateRule              func(string, []api.DetectRule) error
	onSnapshotApplied       func(syncApplySnapshot)
}

type nodeRuntimeStateApplyModule struct {
	controller *Controller
	hooks      syncApplyHooks
}

func newNodeRuntimeStateApplyModule(controller *Controller) nodeRuntimeStateApplyModule {
	return nodeRuntimeStateApplyModule{
		controller: controller,
		hooks:      controller.resolveSyncApplyHooks(),
	}
}

func (c *Controller) ExecuteSyncAction(ctx context.Context, action syncAction) error {
	return newNodeRuntimeStateApplyModule(c).Apply(ctx, action)
}

func (a nodeRuntimeStateApplyModule) Apply(_ context.Context, action syncAction) error {
	snapshot, err := a.fetchSyncApplySnapshot(action)
	if err != nil {
		return err
	}
	return a.applySyncSnapshot(snapshot)
}

func (a nodeRuntimeStateApplyModule) fetchSyncApplySnapshot(action syncAction) (syncApplySnapshot, error) {
	c := a.controller
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

func (a nodeRuntimeStateApplyModule) applySyncSnapshot(snapshot syncApplySnapshot) error {
	c := a.controller
	hooks := a.hooks
	currentNodeInfo, currentTag, currentUserList := c.getStateSnapshot()

	switch snapshot.Action.Type {
	case syncActionTypeSyncDevices:
		if currentTag != "" {
			if err := hooks.applyGlobalDevices(currentTag, globalDeviceApply{Devices: snapshot.Action.Payload.Devices}); err != nil {
				return err
			}
		}
		if hooks.onSnapshotApplied != nil {
			hooks.onSnapshotApplied(snapshot)
		}
		return nil
	case syncActionTypeClearGlobalDevices:
		if currentTag != "" {
			if err := hooks.applyGlobalDevices(currentTag, globalDeviceApply{Clear: true}); err != nil {
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
		currentNodeInfo, currentTag, nodeChanged, err = a.applyNodeSnapshot(currentNodeInfo, currentTag, currentUserList, snapshot.NodeInfo)
		if err != nil {
			return err
		}
	}

	if err := c.applyBaseConfig(snapshot.BaseConfig); err != nil {
		return err
	}

	if snapshot.RuleList != nil && !c.config.DisableGetRule {
		if err := a.applyRuleSnapshot(currentTag, *snapshot.RuleList); err != nil {
			return err
		}
	}

	effectiveUsers := snapshot.UserList
	if effectiveUsers == nil {
		effectiveUsers = currentUserList
	}
	if currentNodeInfo != nil && effectiveUsers != nil {
		if err := a.applyUserSnapshot(nodeChanged, currentNodeInfo, currentTag, currentUserList, effectiveUsers); err != nil {
			return err
		}
		if nodeChanged || snapshot.UserList != nil {
			c.setUserList(effectiveUsers)
		}
	}

	if snapshot.CertConfigFetched {
		if err := a.applyCertConfigSnapshot(snapshot.CertConfig); err != nil {
			return err
		}
	}

	if hooks.onSnapshotApplied != nil {
		hooks.onSnapshotApplied(snapshot)
	}
	return nil
}

func (a nodeRuntimeStateApplyModule) applyNodeSnapshot(currentNodeInfo *api.NodeInfo, currentTag string, currentUserList *[]api.UserInfo, nextNodeInfo *api.NodeInfo) (*api.NodeInfo, string, bool, error) {
	c := a.controller
	hooks := a.hooks
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
		return a.cleanupRuntimeTag(currentNodeInfo, currentTag)
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
			cleanupErr := a.cleanupRuntimeTag(nextNodeInfo, newTag)
			restoreErr := a.restoreRuntimeAfterFailedApply(currentNodeInfo, currentTag, currentUserList)
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

func (a nodeRuntimeStateApplyModule) applyRuleSnapshot(tag string, rules []api.DetectRule) error {
	c := a.controller
	hooks := a.hooks
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

func (a nodeRuntimeStateApplyModule) applyUserSnapshot(nodeChanged bool, nodeInfo *api.NodeInfo, tag string, currentUserList, nextUserList *[]api.UserInfo) error {
	c := a.controller
	hooks := a.hooks
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

func (a nodeRuntimeStateApplyModule) applyCertConfigSnapshot(certConfig *api.XrayRCertConfig) error {
	c := a.controller
	current := c.config.CertConfig
	if panelCertConfigEqual(current, certConfig) {
		return nil
	}
	if certConfig == nil {
		c.config.CertConfig = nil
		return nil
	}
	if current == nil {
		current = &mylego.CertConfig{}
		c.config.CertConfig = current
	}
	current.CertMode = certConfig.CertMode
	current.CertDomain = certConfig.CertDomain
	current.CertFile = certConfig.CertFile
	current.KeyFile = certConfig.KeyFile
	current.CertContent = certConfig.CertContent
	current.KeyContent = certConfig.KeyContent
	current.Provider = certConfig.Provider
	current.Email = certConfig.Email
	current.DNSEnv = cloneStringMap(certConfig.DNSEnv)
	return nil
}

func ignoreNoClue(err error) error {
	if err == nil || errors.Is(err, xraycommon.ErrNoClue) {
		return nil
	}
	return err
}

func (a nodeRuntimeStateApplyModule) cleanupRuntimeTag(nodeInfo *api.NodeInfo, tag string) error {
	if nodeInfo == nil || tag == "" {
		return nil
	}
	var cleanupErrs []error
	if err := ignoreNoClue(a.hooks.cleanupRuntimeTag(nodeInfo, tag)); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	}
	if nodeInfo.NodeType == "Shadowsocks-Plugin" {
		dokodemoTag := fmt.Sprintf("dokodemo-door_%s+1", tag)
		if err := ignoreNoClue(a.hooks.cleanupRuntimeTag(nodeInfo, dokodemoTag)); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
	}
	return errors.Join(cleanupErrs...)
}

func (a nodeRuntimeStateApplyModule) restoreRuntimeAfterFailedApply(nodeInfo *api.NodeInfo, tag string, users *[]api.UserInfo) error {
	if nodeInfo == nil || tag == "" {
		return nil
	}
	if err := a.hooks.addNewTag(nodeInfo, tag); err != nil {
		return err
	}
	if users == nil {
		return nil
	}
	if err := a.hooks.addNewUser(users, nodeInfo, tag); err != nil {
		if cleanupErr := a.cleanupRuntimeTag(nodeInfo, tag); cleanupErr != nil {
			return errors.Join(err, fmt.Errorf("cleanup restored runtime after user restore failure: %w", cleanupErr))
		}
		return err
	}
	return nil
}

func (a nodeRuntimeStateApplyModule) cleanupRuntimeTagViaController(nodeInfo *api.NodeInfo, tag string) error {
	if a.controller == nil {
		return nil
	}
	var cleanupErrs []error
	if err := ignoreNoClue(a.controller.removeInbound(tag)); err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("remove inbound %s: %w", tag, err))
	}
	if err := ignoreNoClue(a.controller.removeOutbound(tag)); err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("remove outbound %s: %w", tag, err))
	}
	return errors.Join(cleanupErrs...)
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

func (c *Controller) applyGlobalDevices(tag string, apply globalDeviceApply) error {
	if apply.Clear {
		return c.clearLimiterGlobalDevices(tag)
	}
	return c.updateLimiterGlobalDevices(tag, apply.Devices)
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
	if hooks.cleanupRuntimeTag == nil {
		hooks.cleanupRuntimeTag = nodeRuntimeStateApplyModule{controller: c}.cleanupRuntimeTagViaController
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
	if hooks.applyGlobalDevices == nil {
		hooks.applyGlobalDevices = c.applyGlobalDevices
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
	return normalizeCertMode(current.CertMode, current.Provider, current.DNSEnv) == normalizeCertMode(next.CertMode, next.Provider, next.DNSEnv) &&
		current.CertDomain == next.CertDomain &&
		current.CertFile == next.CertFile &&
		current.KeyFile == next.KeyFile &&
		current.CertContent == next.CertContent &&
		current.KeyContent == next.KeyContent &&
		current.Provider == next.Provider &&
		current.Email == next.Email &&
		reflect.DeepEqual(current.DNSEnv, next.DNSEnv)
}

func normalizeCertMode(certMode, provider string, dnsEnv map[string]string) string {
	mode := strings.ToLower(strings.TrimSpace(certMode))
	if mode != "" {
		return mode
	}
	if strings.TrimSpace(provider) != "" || len(dnsEnv) > 0 {
		return "dns"
	}
	return ""
}

func clonePanelCertConfig(certConfig *api.XrayRCertConfig) *api.XrayRCertConfig {
	if certConfig == nil {
		return nil
	}
	return &api.XrayRCertConfig{
		CertMode:    certConfig.CertMode,
		CertDomain:  certConfig.CertDomain,
		CertFile:    certConfig.CertFile,
		KeyFile:     certConfig.KeyFile,
		CertContent: certConfig.CertContent,
		KeyContent:  certConfig.KeyContent,
		Provider:    certConfig.Provider,
		Email:       certConfig.Email,
		DNSEnv:      cloneStringMap(certConfig.DNSEnv),
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
