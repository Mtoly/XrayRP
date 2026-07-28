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

type syncApplyRuntimeHooks struct {
	cleanupTag  func(*api.NodeInfo, string) error
	addTag      func(*api.NodeInfo, string, *Config) error
	addUsers    func(*[]api.UserInfo, *api.NodeInfo, string, *Config) error
	removeUsers func([]string, string) error
}

type syncApplyLimiterHooks struct {
	addInbound         func(string, uint64, *[]api.UserInfo, *limiter.GlobalDeviceLimitConfig) error
	deleteInbound      func(string) error
	replaceInbound     func(string, *[]api.UserInfo) error
	snapshotInbound    func(string) (*limiter.InboundLimiterStateSnapshot, error)
	restoreInbound     func(string, *limiter.InboundLimiterStateSnapshot) error
	applyGlobalDevices func(string, globalDeviceApply) error
}

type syncApplyHooks struct {
	runtime           syncApplyRuntimeHooks
	limiter           syncApplyLimiterHooks
	updateRule        func(string, []api.DetectRule) error
	retireRuleTag     func(string, string)
	beforeReloadLock  func()
	onSnapshotApplied func(syncApplySnapshot)
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
			if errors.Is(err, api.ErrNodeNotModified) {
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
			if errors.Is(err, api.ErrUserNotModified) {
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
			if errors.Is(err, api.ErrRuleNotModified) {
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
		provider, ok := c.apiClient.(api.CertConfigProvider)
		if !ok {
			return snapshot, nil
		}
		certConfig, err := provider.GetXrayRCertConfig()
		if err != nil {
			if !errors.Is(err, api.ErrUnsupportedPanelFeature) {
				return snapshot, err
			}
		} else {
			snapshot.CertConfig = certConfig
			snapshot.CertConfigFetched = true
		}
	}

	return snapshot, nil
}

func (a nodeRuntimeStateApplyModule) applySyncSnapshot(snapshot syncApplySnapshot) error {
	c := a.controller
	hooks := a.hooks
	if hooks.beforeReloadLock != nil {
		hooks.beforeReloadLock()
	}
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()

	appliedState := c.runtimeStateSnapshot()
	currentNodeInfo := appliedState.nodeInfoSnapshot()
	currentTag := appliedState.tag
	currentUserList := appliedState.userListSnapshot()

	switch snapshot.Action.Type {
	case syncActionTypeSyncDevices:
		if currentTag != "" {
			if err := hooks.limiter.applyGlobalDevices(currentTag, globalDeviceApply{Devices: snapshot.Action.Payload.Devices}); err != nil {
				return err
			}
		}
		if hooks.onSnapshotApplied != nil {
			hooks.onSnapshotApplied(snapshot)
		}
		return nil
	case syncActionTypeClearGlobalDevices:
		if currentTag != "" {
			if err := hooks.limiter.applyGlobalDevices(currentTag, globalDeviceApply{Clear: true}); err != nil {
				return err
			}
		}
		if hooks.onSnapshotApplied != nil {
			hooks.onSnapshotApplied(snapshot)
		}
		return nil
	}

	nodeChanged := false
	certChanged := snapshot.CertConfigFetched && !panelCertConfigEqual(c.config.CertConfig, snapshot.CertConfig)
	appliedConfig := cloneControllerConfig(c.config)
	candidateConfig := cloneControllerConfig(c.config)
	if certChanged {
		candidateConfig.CertConfig = candidateCertConfig(c.config.CertConfig, snapshot.CertConfig)
	}
	nextNodeInfo := snapshot.NodeInfo
	forceCertificateRebuild := certChanged && currentNodeInfo != nil && currentNodeInfo.EnableTLS && !currentNodeInfo.EnableREALITY && !candidateConfig.EnableREALITY
	if nextNodeInfo == nil && forceCertificateRebuild {
		nextNodeInfo = currentNodeInfo
	}
	appliedNodeInfo := appliedState.nodeInfoSnapshot()
	appliedTag := appliedState.tag
	appliedUserList := appliedState.userListSnapshot()
	appliedRuleTag := appliedState.appliedRuleTag
	appliedRules := appliedState.appliedRuleList
	var appliedLimiterSnapshot *limiter.InboundLimiterStateSnapshot
	deferNodePublication := nextNodeInfo != nil &&
		(currentNodeInfo == nil || forceCertificateRebuild || nodeStateChanged(currentNodeInfo, nextNodeInfo))
	if deferNodePublication && currentTag != "" {
		var err error
		appliedLimiterSnapshot, err = hooks.limiter.snapshotInbound(currentTag)
		if err != nil {
			return err
		}
	}
	certPublishedWithRuntime := false
	certOnlyRebuild := forceCertificateRebuild &&
		currentTag != "" &&
		(snapshot.NodeInfo == nil || !nodeStateChanged(currentNodeInfo, snapshot.NodeInfo))
	if certOnlyRebuild {
		if err := a.replaceRuntimeConfig(
			currentNodeInfo,
			currentTag,
			currentUserList,
			appliedConfig,
			candidateConfig,
		); err != nil {
			return err
		}
		c.config.CertConfig = cloneRuntimeCertConfig(candidateConfig.CertConfig)
		certPublishedWithRuntime = true
	} else if nextNodeInfo != nil {
		var err error
		currentNodeInfo, currentTag, nodeChanged, err = a.applyNodeSnapshot(
			currentNodeInfo,
			currentTag,
			currentUserList,
			nextNodeInfo,
			appliedConfig,
			candidateConfig,
			forceCertificateRebuild,
			deferNodePublication,
		)
		if err != nil {
			return err
		}
	}

	pendingNodePublication := nodeChanged && deferNodePublication
	rulesAppliedToCandidate := false
	candidateRuleStateChanged := false
	rollbackPendingNode := func(primary error) error {
		if !pendingNodePublication {
			return primary
		}
		rollbackErr := a.rollbackNodeCertificateApply(
			currentNodeInfo,
			currentTag,
			appliedNodeInfo,
			appliedTag,
			appliedUserList,
			appliedConfig,
			appliedLimiterSnapshot,
			appliedRuleTag,
			appliedRules,
			rulesAppliedToCandidate,
		)
		if rollbackErr == nil {
			return primary
		}
		return errors.Join(primary, fmt.Errorf("rollback failed node and certificate apply: %w", rollbackErr))
	}
	if pendingNodePublication && appliedTag != "" {
		if err := hooks.limiter.deleteInbound(appliedTag); err != nil {
			return rollbackPendingNode(err)
		}
	}
	if err := c.applyBaseConfig(snapshot.BaseConfig); err != nil {
		return rollbackPendingNode(err)
	}

	if snapshot.RuleList != nil && !c.config.DisableGetRule {
		var err error
		candidateRuleStateChanged, err = a.applyRuleSnapshot(
			currentTag,
			*snapshot.RuleList,
			!pendingNodePublication,
		)
		if err != nil {
			return rollbackPendingNode(err)
		}
		rulesAppliedToCandidate = pendingNodePublication && candidateRuleStateChanged
	}

	effectiveUsers := snapshot.UserList
	if effectiveUsers == nil {
		effectiveUsers = currentUserList
	}
	var userOverlay limiterUserOverlayCandidate
	publishUserState := false
	if currentNodeInfo != nil && effectiveUsers != nil {
		userOverlay = c.buildLimiterUserOverlayCandidate(effectiveUsers)
		if err := a.applyUserSnapshot(nodeChanged, currentNodeInfo, currentTag, currentUserList, effectiveUsers, userOverlay.limiterUsers, candidateConfig); err != nil {
			return rollbackPendingNode(err)
		}
		publishUserState = nodeChanged || snapshot.UserList != nil
	}

	if pendingNodePublication {
		candidateState := appliedState
		candidateState.node = normalizeNodeInfo(currentNodeInfo)
		candidateState.tag = currentTag
		if nodeChanged || snapshot.UserList != nil {
			candidateState.userListSet = effectiveUsers != nil
			if effectiveUsers == nil {
				candidateState.userList = nil
			} else {
				candidateState.userList = cloneSlice(*effectiveUsers)
			}
		}
		if candidateRuleStateChanged {
			candidateState.appliedRuleTag = currentTag
			candidateState.appliedRuleList = cloneDetectRules(*snapshot.RuleList)
		}
		if certChanged {
			c.config.CertConfig = cloneRuntimeCertConfig(candidateConfig.CertConfig)
			certPublishedWithRuntime = true
		}
		if publishUserState {
			c.commitRuntimeStateWithUserOverlay(candidateState, userOverlay)
		} else {
			c.commitRuntimeState(candidateState)
		}
	} else if publishUserState {
		c.commitUserListWithOverlay(effectiveUsers, userOverlay)
	}
	if candidateRuleStateChanged &&
		appliedRuleTag != "" &&
		appliedRuleTag != currentTag {
		hooks.retireRuleTag(appliedRuleTag, currentTag)
	}
	if certChanged && !certPublishedWithRuntime {
		c.config.CertConfig = cloneRuntimeCertConfig(candidateConfig.CertConfig)
	}

	if hooks.onSnapshotApplied != nil {
		hooks.onSnapshotApplied(snapshot)
	}
	return nil
}

func (a nodeRuntimeStateApplyModule) replaceRuntimeConfig(
	nodeInfo *api.NodeInfo,
	tag string,
	users *[]api.UserInfo,
	appliedConfig *Config,
	candidateConfig *Config,
) error {
	if err := a.cleanupRuntimeTag(nodeInfo, tag); err != nil {
		if restoreErr := a.restoreRuntimeAfterFailedApply(nodeInfo, tag, users, appliedConfig); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("restore old runtime after failed certificate cleanup: %w", restoreErr))
		}
		return err
	}

	fail := func(primary error) error {
		cleanupErr := a.cleanupRuntimeTag(nodeInfo, tag)
		restoreErr := a.restoreRuntimeAfterFailedApply(nodeInfo, tag, users, appliedConfig)
		joined := []error{primary}
		if cleanupErr != nil {
			joined = append(joined, fmt.Errorf("cleanup candidate certificate runtime: %w", cleanupErr))
		}
		if restoreErr != nil {
			joined = append(joined, fmt.Errorf("restore last-known-good certificate runtime: %w", restoreErr))
		}
		return errors.Join(joined...)
	}

	if err := a.hooks.runtime.addTag(nodeInfo, tag, candidateConfig); err != nil {
		return fail(err)
	}
	if users != nil {
		if err := a.hooks.runtime.addUsers(users, nodeInfo, tag, candidateConfig); err != nil {
			return fail(err)
		}
	}
	return nil
}

func (a nodeRuntimeStateApplyModule) applyNodeSnapshot(
	currentNodeInfo *api.NodeInfo,
	currentTag string,
	currentUserList *[]api.UserInfo,
	nextNodeInfo *api.NodeInfo,
	appliedConfig *Config,
	candidateConfig *Config,
	force bool,
	deferPublication bool,
) (*api.NodeInfo, string, bool, error) {
	c := a.controller
	hooks := a.hooks
	if nextNodeInfo == nil {
		return currentNodeInfo, currentTag, false, nil
	}
	if nextNodeInfo.Port == 0 || nextNodeInfo.Port > 65535 {
		return currentNodeInfo, currentTag, false, fmt.Errorf("invalid server port: %d, must be 1-65535", nextNodeInfo.Port)
	}
	if !force && currentNodeInfo != nil && !nodeStateChanged(currentNodeInfo, nextNodeInfo) {
		return currentNodeInfo, currentTag, false, nil
	}

	newTag := c.buildNodeTagFrom(nextNodeInfo)
	removeCurrentRuntime := func() error {
		return a.cleanupRuntimeTag(currentNodeInfo, currentTag)
	}

	switch {
	case currentNodeInfo == nil || currentTag == "":
		if err := hooks.runtime.addTag(nextNodeInfo, newTag, candidateConfig); err != nil {
			if cleanupErr := a.cleanupRuntimeTag(nextNodeInfo, newTag); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("cleanup partial candidate after build failure: %w", cleanupErr))
			}
			return currentNodeInfo, currentTag, false, err
		}
	case newTag != currentTag:
		// When the runtime tag changes, stage the new runtime before tearing down
		// the old one so add failures don't drop the currently serving node.
		if err := hooks.runtime.addTag(nextNodeInfo, newTag, candidateConfig); err != nil {
			if cleanupErr := a.cleanupRuntimeTag(nextNodeInfo, newTag); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("cleanup partial candidate after build failure: %w", cleanupErr))
			}
			return currentNodeInfo, currentTag, false, err
		}
		if err := removeCurrentRuntime(); err != nil {
			cleanupErr := a.cleanupRuntimeTag(nextNodeInfo, newTag)
			restoreErr := a.restoreRuntimeAfterFailedApply(currentNodeInfo, currentTag, currentUserList, appliedConfig)
			var joined []error
			joined = append(joined, err)
			if cleanupErr != nil {
				joined = append(joined, fmt.Errorf("cleanup candidate after failed old runtime removal: %w", cleanupErr))
			}
			if restoreErr != nil {
				joined = append(joined, fmt.Errorf("restore old runtime after failed tag change: %w", restoreErr))
			}
			return currentNodeInfo, currentTag, false, errors.Join(joined...)
		}
	default:
		// Same-tag rebuilds cannot pre-stage another runtime without introducing
		// dual-active behavior. Remove the old runtime, then fully restore the
		// previous runtime if replacement add fails so the controller/runtime state
		// stays on the last known-good node.
		if err := removeCurrentRuntime(); err != nil {
			if restoreErr := a.restoreRuntimeAfterFailedApply(currentNodeInfo, currentTag, currentUserList, appliedConfig); restoreErr != nil {
				return currentNodeInfo, currentTag, false, errors.Join(err, fmt.Errorf("restore old runtime after failed same-tag cleanup: %w", restoreErr))
			}
			return currentNodeInfo, currentTag, false, err
		}
		if err := hooks.runtime.addTag(nextNodeInfo, newTag, candidateConfig); err != nil {
			cleanupErr := a.cleanupRuntimeTag(nextNodeInfo, newTag)
			restoreErr := a.restoreRuntimeAfterFailedApply(currentNodeInfo, currentTag, currentUserList, appliedConfig)
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
	if currentNodeInfo != nil && currentTag != "" && !deferPublication {
		if err := hooks.limiter.deleteInbound(currentTag); err != nil {
			return currentNodeInfo, currentTag, false, err
		}
	}
	if !deferPublication {
		c.setNodeState(nextNodeInfo, newTag)
	}
	return nextNodeInfo, newTag, true, nil
}

func (a nodeRuntimeStateApplyModule) applyRuleSnapshot(tag string, rules []api.DetectRule, publish bool) (bool, error) {
	c := a.controller
	hooks := a.hooks
	if tag == "" {
		return false, nil
	}
	currentRuleTag, currentRules := c.getAppliedRuleState()
	if detectRuleListsEqual(currentRules, rules) {
		if tag == currentRuleTag || (len(currentRules) == 0 && len(rules) == 0) {
			return false, nil
		}
	}
	if err := hooks.updateRule(tag, rules); err != nil {
		return false, err
	}
	if publish {
		c.setAppliedRuleState(tag, rules)
	}
	return true, nil
}

func (a nodeRuntimeStateApplyModule) applyUserSnapshot(
	nodeChanged bool,
	nodeInfo *api.NodeInfo,
	tag string,
	currentUserList, nextUserList *[]api.UserInfo,
	limiterUsers *[]api.UserInfo,
	config *Config,
) error {
	c := a.controller
	hooks := a.hooks
	if nodeInfo == nil || nextUserList == nil {
		return nil
	}
	if nodeChanged {
		if err := hooks.runtime.addUsers(nextUserList, nodeInfo, tag, config); err != nil {
			return err
		}
		return hooks.limiter.addInbound(tag, nodeInfo.SpeedLimit, limiterUsers, c.config.GlobalDeviceLimitConfig)
	}
	if currentUserList == nil {
		rollbackRuntime := func(applyErr error) error {
			var rollbackErr error
			if nodeInfo.NodeType == "Socks" || nodeInfo.NodeType == "HTTP" {
				emptyUsers := []api.UserInfo{}
				rollbackErr = hooks.runtime.addUsers(&emptyUsers, nodeInfo, tag, config)
			} else {
				rollbackErr = a.removeRuntimeUsersBestEffort(tag, *nextUserList)
			}
			if rollbackErr != nil {
				return errors.Join(applyErr, fmt.Errorf("remove initial candidate runtime users: %w", rollbackErr))
			}
			return applyErr
		}
		if err := hooks.runtime.addUsers(nextUserList, nodeInfo, tag, config); err != nil {
			return rollbackRuntime(err)
		}
		if err := hooks.limiter.addInbound(tag, nodeInfo.SpeedLimit, limiterUsers, c.config.GlobalDeviceLimitConfig); err != nil {
			if cleanupErr := hooks.limiter.deleteInbound(tag); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("delete failed initial limiter: %w", cleanupErr))
			}
			return rollbackRuntime(err)
		}
		return nil
	}
	if reflect.DeepEqual(currentUserList, nextUserList) {
		return nil
	}

	if nodeInfo.NodeType == "Socks" || nodeInfo.NodeType == "HTTP" {
		limiterSnapshot, err := hooks.limiter.snapshotInbound(tag)
		if err != nil {
			return err
		}
		restoreRuntime := func(applyErr error) error {
			if restoreErr := hooks.runtime.addUsers(currentUserList, nodeInfo, tag, config); restoreErr != nil {
				return errors.Join(applyErr, fmt.Errorf("restore embedded runtime users: %w", restoreErr))
			}
			return applyErr
		}
		if err := hooks.runtime.addUsers(nextUserList, nodeInfo, tag, config); err != nil {
			return restoreRuntime(err)
		}
		if err := hooks.limiter.replaceInbound(tag, limiterUsers); err != nil {
			err = restoreRuntime(err)
			if restoreErr := hooks.limiter.restoreInbound(tag, limiterSnapshot); restoreErr != nil {
				err = errors.Join(err, fmt.Errorf("restore inbound limiter: %w", restoreErr))
			}
			return err
		}
		return nil
	}

	diff := diffUserList(currentUserList, nextUserList)
	if len(diff.Deleted) == 0 && len(diff.Added) == 0 && len(diff.LimitOnly) == 0 && len(diff.RuntimeUpdated) == 0 {
		return nil
	}

	limiterSnapshot, err := hooks.limiter.snapshotInbound(tag)
	if err != nil {
		return err
	}
	restoreLimiter := func(applyErr error) error {
		if restoreErr := hooks.limiter.restoreInbound(tag, limiterSnapshot); restoreErr != nil {
			return errors.Join(applyErr, fmt.Errorf("restore inbound limiter: %w", restoreErr))
		}
		return applyErr
	}

	usersToRemove := make([]api.UserInfo, 0, len(diff.Deleted)+len(diff.RuntimeUpdated))
	usersToRemove = append(usersToRemove, diff.Deleted...)
	usersToRemove = append(usersToRemove, diff.RuntimeUpdated...)
	usersToRestore := currentRuntimeUsersForTargets(currentUserList, usersToRemove)
	if len(usersToRemove) > 0 {
		removedUserKeys := buildRemovedUserKeys(tag, currentUserList, usersToRemove)
		if len(removedUserKeys) > 0 {
			if err := hooks.runtime.removeUsers(removedUserKeys, tag); err != nil {
				if rollbackErr := a.restoreRuntimeUsersBestEffort(nodeInfo, tag, usersToRestore, config); rollbackErr != nil {
					err = errors.Join(err, fmt.Errorf("restore runtime users after remove failure: %w", rollbackErr))
				}
				return restoreLimiter(err)
			}
		}
	}

	usersToAdd := make([]api.UserInfo, 0, len(diff.Added)+len(diff.RuntimeUpdated))
	usersToAdd = append(usersToAdd, diff.Added...)
	usersToAdd = append(usersToAdd, diff.RuntimeUpdated...)
	if len(usersToAdd) > 0 {
		if err := hooks.runtime.addUsers(&usersToAdd, nodeInfo, tag, config); err != nil {
			if rollbackErr := a.rollbackRuntimeUsersAfterAddFailure(nodeInfo, tag, usersToRestore, usersToAdd, config); rollbackErr != nil {
				err = errors.Join(err, rollbackErr)
			}
			return restoreLimiter(err)
		}
	}
	if err := hooks.limiter.replaceInbound(tag, limiterUsers); err != nil {
		if rollbackErr := a.rollbackRuntimeUsersAfterAddFailure(nodeInfo, tag, usersToRestore, usersToAdd, config); rollbackErr != nil {
			err = errors.Join(err, rollbackErr)
		}
		return restoreLimiter(err)
	}
	return nil
}

func currentRuntimeUsersForTargets(currentUserList *[]api.UserInfo, targets []api.UserInfo) []api.UserInfo {
	if currentUserList == nil || len(targets) == 0 {
		return nil
	}

	currentByKey := make(map[userIdentityKey]api.UserInfo, len(*currentUserList))
	for _, user := range *currentUserList {
		currentByKey[userIdentityKey{UID: user.UID, Email: user.Email}] = user
	}

	users := make([]api.UserInfo, 0, len(targets))
	for _, target := range targets {
		if current, ok := currentByKey[userIdentityKey{UID: target.UID, Email: target.Email}]; ok {
			users = append(users, current)
		}
	}
	return users
}

func (a nodeRuntimeStateApplyModule) rollbackRuntimeUsersAfterAddFailure(
	nodeInfo *api.NodeInfo,
	tag string,
	usersToRestore, usersToRemove []api.UserInfo,
	config *Config,
) error {
	var rollbackErrs []error
	if err := a.removeRuntimeUsersBestEffort(tag, usersToRemove); err != nil {
		rollbackErrs = append(rollbackErrs, fmt.Errorf("remove partially added runtime users: %w", err))
	}
	if err := a.restoreRuntimeUsersBestEffort(nodeInfo, tag, usersToRestore, config); err != nil {
		rollbackErrs = append(rollbackErrs, fmt.Errorf("restore removed runtime users: %w", err))
	}
	return errors.Join(rollbackErrs...)
}

func (a nodeRuntimeStateApplyModule) removeRuntimeUsersBestEffort(tag string, users []api.UserInfo) error {
	var rollbackErrs []error
	for _, user := range users {
		key := fmt.Sprintf("%s|%s|%d", tag, user.Email, user.UID)
		if err := a.hooks.runtime.removeUsers([]string{key}, tag); err != nil {
			rollbackErrs = append(rollbackErrs, err)
		}
	}
	return errors.Join(rollbackErrs...)
}

func (a nodeRuntimeStateApplyModule) restoreRuntimeUsersBestEffort(nodeInfo *api.NodeInfo, tag string, users []api.UserInfo, config *Config) error {
	var rollbackErrs []error
	for _, user := range users {
		restoreUsers := []api.UserInfo{user}
		if err := a.hooks.runtime.addUsers(&restoreUsers, nodeInfo, tag, config); err != nil {
			rollbackErrs = append(rollbackErrs, err)
		}
	}
	return errors.Join(rollbackErrs...)
}

func candidateCertConfig(current *mylego.CertConfig, next *api.XrayRCertConfig) *mylego.CertConfig {
	if next == nil {
		return nil
	}
	candidate := cloneRuntimeCertConfig(current)
	if candidate == nil {
		candidate = &mylego.CertConfig{}
	}
	candidate.CertMode = normalizeCertMode(next.CertMode, next.Provider, next.DNSEnv)
	candidate.CertDomain = next.CertDomain
	candidate.CertFile = next.CertFile
	candidate.KeyFile = next.KeyFile
	candidate.CertContent = next.CertContent
	candidate.KeyContent = next.KeyContent
	candidate.Provider = next.Provider
	candidate.Email = next.Email
	candidate.DNSEnv = cloneStringMap(next.DNSEnv)
	return candidate
}

func cloneRuntimeCertConfig(certConfig *mylego.CertConfig) *mylego.CertConfig {
	if certConfig == nil {
		return nil
	}
	cloned := *certConfig
	cloned.DNSEnv = cloneStringMap(certConfig.DNSEnv)
	return &cloned
}

func cloneControllerConfig(config *Config) *Config {
	if config == nil {
		return &Config{}
	}
	cloned := *config
	cloned.CertConfig = cloneRuntimeCertConfig(config.CertConfig)
	return &cloned
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
	if err := ignoreNoClue(a.hooks.runtime.cleanupTag(nodeInfo, tag)); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	}
	if nodeInfo.NodeType == "Shadowsocks-Plugin" {
		dokodemoTag := fmt.Sprintf("dokodemo-door_%s+1", tag)
		if err := ignoreNoClue(a.hooks.runtime.cleanupTag(nodeInfo, dokodemoTag)); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
	}
	return errors.Join(cleanupErrs...)
}

func (a nodeRuntimeStateApplyModule) restoreRuntimeAfterFailedApply(nodeInfo *api.NodeInfo, tag string, users *[]api.UserInfo, config *Config) error {
	if nodeInfo == nil || tag == "" {
		return nil
	}
	if err := a.hooks.runtime.addTag(nodeInfo, tag, config); err != nil {
		return err
	}
	if users == nil {
		return nil
	}
	if err := a.hooks.runtime.addUsers(users, nodeInfo, tag, config); err != nil {
		if cleanupErr := a.cleanupRuntimeTag(nodeInfo, tag); cleanupErr != nil {
			return errors.Join(err, fmt.Errorf("cleanup restored runtime after user restore failure: %w", cleanupErr))
		}
		return err
	}
	return nil
}

func (a nodeRuntimeStateApplyModule) rollbackNodeCertificateApply(
	candidateNodeInfo *api.NodeInfo,
	candidateTag string,
	appliedNodeInfo *api.NodeInfo,
	appliedTag string,
	appliedUsers *[]api.UserInfo,
	appliedConfig *Config,
	appliedLimiterSnapshot *limiter.InboundLimiterStateSnapshot,
	appliedRuleTag string,
	appliedRules []api.DetectRule,
	restoreRules bool,
) error {
	var rollbackErrs []error
	if err := a.cleanupRuntimeTag(candidateNodeInfo, candidateTag); err != nil {
		rollbackErrs = append(rollbackErrs, fmt.Errorf("cleanup candidate runtime: %w", err))
	}
	if candidateTag != "" {
		if err := a.hooks.limiter.deleteInbound(candidateTag); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("cleanup candidate limiter: %w", err))
		}
	}
	if err := a.restoreRuntimeAfterFailedApply(appliedNodeInfo, appliedTag, appliedUsers, appliedConfig); err != nil {
		rollbackErrs = append(rollbackErrs, fmt.Errorf("restore last-known-good runtime: %w", err))
	}
	if appliedTag != "" {
		if err := a.hooks.limiter.restoreInbound(appliedTag, appliedLimiterSnapshot); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("restore last-known-good limiter: %w", err))
		}
	}
	if restoreRules {
		if candidateTag != "" {
			if err := a.hooks.updateRule(candidateTag, nil); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("clear candidate rules: %w", err))
			}
		}
		if appliedRuleTag != "" {
			if err := a.hooks.updateRule(appliedRuleTag, appliedRules); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("restore last-known-good rules: %w", err))
			} else {
				a.controller.setAppliedRuleState(appliedRuleTag, appliedRules)
			}
		}
	}
	return errors.Join(rollbackErrs...)
}

func (a nodeRuntimeStateApplyModule) replaceCertificateRuntime(
	nodeInfo *api.NodeInfo,
	tag string,
	users *[]api.UserInfo,
	appliedConfig *Config,
	candidateConfig *Config,
	renewal preparedCertificateRenewal,
) error {
	if err := a.cleanupRuntimeTag(nodeInfo, tag); err != nil {
		rollbackErr := renewal.Rollback()
		restoreErr := a.restoreRuntimeAfterFailedApply(nodeInfo, tag, users, appliedConfig)
		joined := []error{err, rollbackErr}
		if restoreErr != nil {
			joined = append(joined, fmt.Errorf("restore last-known-good certificate runtime: %w", restoreErr))
		}
		return errors.Join(joined...)
	}

	fail := func(primary error) error {
		cleanupErr := a.cleanupRuntimeTag(nodeInfo, tag)
		rollbackErr := renewal.Rollback()
		restoreErr := a.restoreRuntimeAfterFailedApply(nodeInfo, tag, users, appliedConfig)
		var joined []error
		joined = append(joined, primary)
		if cleanupErr != nil {
			joined = append(joined, fmt.Errorf("cleanup candidate certificate runtime: %w", cleanupErr))
		}
		if rollbackErr != nil {
			joined = append(joined, fmt.Errorf("rollback candidate certificate: %w", rollbackErr))
		}
		if restoreErr != nil {
			joined = append(joined, fmt.Errorf("restore last-known-good certificate runtime: %w", restoreErr))
		}
		return errors.Join(joined...)
	}

	if err := a.hooks.runtime.addTag(nodeInfo, tag, candidateConfig); err != nil {
		return fail(err)
	}
	if users != nil {
		if err := a.hooks.runtime.addUsers(users, nodeInfo, tag, candidateConfig); err != nil {
			return fail(err)
		}
	}
	if err := renewal.Commit(); err != nil {
		return fail(err)
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
	if hooks.runtime.cleanupTag == nil {
		hooks.runtime.cleanupTag = nodeRuntimeStateApplyModule{controller: c}.cleanupRuntimeTagViaController
	}
	if hooks.runtime.addTag == nil {
		hooks.runtime.addTag = c.addNewTagWithConfig
	}
	if hooks.runtime.addUsers == nil {
		hooks.runtime.addUsers = c.addNewUserWithConfig
	}
	if hooks.runtime.removeUsers == nil {
		hooks.runtime.removeUsers = c.removeUsers
	}
	if hooks.limiter.addInbound == nil {
		hooks.limiter.addInbound = c.AddInboundLimiter
	}
	if hooks.limiter.deleteInbound == nil {
		hooks.limiter.deleteInbound = c.DeleteInboundLimiter
	}
	if hooks.limiter.replaceInbound == nil {
		hooks.limiter.replaceInbound = c.replaceInboundLimiterUsers
	}
	if hooks.limiter.snapshotInbound == nil {
		hooks.limiter.snapshotInbound = c.snapshotInboundLimiter
	}
	if hooks.limiter.restoreInbound == nil {
		hooks.limiter.restoreInbound = c.restoreInboundLimiter
	}
	if hooks.limiter.applyGlobalDevices == nil {
		hooks.limiter.applyGlobalDevices = c.applyGlobalDevices
	}
	if hooks.updateRule == nil {
		hooks.updateRule = c.UpdateRule
	}
	if hooks.retireRuleTag == nil {
		hooks.retireRuleTag = c.retireRuleTag
	}
	return hooks
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
