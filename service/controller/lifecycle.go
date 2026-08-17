package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service"
)

type controllerLifecycleState uint8

const (
	controllerStateStopped controllerLifecycleState = iota
	controllerStateStarting
	controllerStateRunning
	controllerStateStopping
	controllerStateFailed
	controllerStateFailedOwned
	controllerStateClosed
)

type controllerRuntimeOwnership struct {
	nodeSnapshot    *api.NodeSnapshot
	tag             string
	runtime         bool
	limiter         bool
	rules           bool
	periodic        bool
	websocket       bool
	syncCoordinator bool
}

func (o controllerRuntimeOwnership) hasResources() bool {
	return o.runtime || o.limiter || o.rules || o.periodic || o.websocket || o.syncCoordinator
}

// Start implement the Start() function of the service interface.
func (c *Controller) Start() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return c.StartContext(ctx)
}

func (c *Controller) StartContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultStartTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.beginLifecycleStart(); err != nil {
		return err
	}
	clientInfo := c.apiClient.Describe()
	hooks := c.resolveSyncApplyHooks(ctx)
	ownership := controllerRuntimeOwnership{}
	fail := func(primary error) error {
		cleanupCtx, cleanupCancel := service.CleanupContext(ctx)
		defer cleanupCancel()
		return c.failLifecycleStartContext(cleanupCtx, primary, ownership, hooks)
	}

	newNodeSnapshot, err := api.GetNodeSnapshotContext(ctx, c.apiClient)
	if err != nil {
		return fail(err)
	}
	if newNodeSnapshot == nil {
		return fail(errors.New("controller: panel returned nil node info"))
	}
	if newNodeSnapshot.Port == 0 || newNodeSnapshot.Port > 65535 {
		return fail(fmt.Errorf("invalid server port: %d, must be 1-65535", newNodeSnapshot.Port))
	}
	tag := c.buildNodeTagFromSnapshot(newNodeSnapshot)
	ownership.nodeSnapshot = newNodeSnapshot.Clone()
	ownership.tag = tag

	ownership.runtime = true
	if err := hooks.runtime.addTagForSnapshot(newNodeSnapshot, tag, c.config); err != nil {
		return fail(err)
	}

	userInfo, err := api.GetUserListContext(ctx, c.apiClient)
	if err != nil {
		return fail(err)
	}
	if userInfo == nil {
		return fail(errors.New("controller: panel returned nil user list"))
	}
	appliedUsers := cloneSlice(*userInfo)
	userInfo = &appliedUsers
	if err := hooks.runtime.addUsersForSnapshot(userInfo, newNodeSnapshot, tag, c.config); err != nil {
		return fail(err)
	}

	ownership.limiter = true
	if err := hooks.limiter.addInbound(tag, newNodeSnapshot.SpeedLimit, cloneUserList(userInfo), cloneGlobalDeviceLimitConfig(c.config.GlobalDeviceLimitConfig)); err != nil {
		return fail(err)
	}

	var appliedRules []api.DetectRule
	if !c.config.DisableGetRule {
		ruleList, err := api.GetNodeRuleContext(ctx, c.apiClient)
		if err != nil {
			return fail(err)
		}
		if ruleList != nil {
			appliedRules = cloneDetectRules(*ruleList)
			ownership.rules = true
			if err := hooks.updateRuleForApply(tag, appliedRules); err != nil {
				return fail(err)
			}
		}
	}

	if c.config.AutoSpeedLimitConfig == nil {
		c.config.AutoSpeedLimitConfig = &AutoSpeedLimitConfig{0, 0, 0, 0}
	}

	c.syncCoordinator = c.buildSyncCoordinator()
	if c.syncCoordinator == nil {
		return fail(errors.New("controller: sync coordinator not configured"))
	}
	ownership.syncCoordinator = true

	if c.shouldStartWSRuntime() {
		wsRuntime, err := c.buildWSRuntime(ctx, c.syncCoordinator)
		if err != nil {
			return fail(err)
		}
		c.setWSRuntime(wsRuntime)
		ownership.websocket = true
		if err := startWSRuntimeContext(ctx, wsRuntime); err != nil {
			return fail(err)
		}
	}

	ownership.periodic = true
	if err := c.startControllerPeriodicTasksSnapshotContext(ctx, newNodeSnapshot); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}

	candidateState := nodeRuntimeState{
		node:        normalizeNodeSnapshot(newNodeSnapshot),
		tag:         tag,
		userListSet: true,
		userList:    cloneSlice(appliedUsers),
	}
	if ownership.rules {
		candidateState.appliedRuleTag = tag
		candidateState.appliedRuleList = cloneDetectRules(appliedRules)
	}
	overlay := limiterUserOverlayCandidate{}
	if c.config.AutoSpeedLimitConfig.Limit > 0 {
		overlay.limitedUsers = make(map[api.UserInfo]LimitInfo)
		overlay.warnedUsers = make(map[api.UserInfo]int)
	}
	c.lifecycleMu.Lock()
	c.clientInfo = clientInfo
	c.lifecycleMu.Unlock()
	c.commitRuntimeStateWithUserOverlay(candidateState, overlay)
	c.publishLifecycleRunning(ownership)
	c.health.RecordSuccessfulSync(time.Now())
	c.refreshCertificateExpiry()
	return nil
}

// Close implement the Close() function of the service interface.
func (c *Controller) Close() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return c.CloseContext(ctx)
}

func (c *Controller) CloseContext(parent context.Context) error {
	ctx, cancel := service.WithDefaultTimeout(parent, service.DefaultCloseTimeout)
	defer cancel()
	ownership, shouldCleanup, err := c.beginLifecycleClose()
	if err != nil || !shouldCleanup {
		return err
	}
	hooks := c.resolveSyncApplyHooks(ctx)
	closeErr := c.cleanupControllerOwnershipContext(ctx, &ownership, hooks)
	c.finishLifecycleClose(ownership, closeErr)
	return closeErr
}

func (c *Controller) beginLifecycleStart() error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.lifecycleState != controllerStateStopped {
		return fmt.Errorf("controller cannot start from lifecycle state %d", c.lifecycleState)
	}
	c.lifecycleState = controllerStateStarting
	c.lifecycleErr = nil
	return nil
}

func (c *Controller) publishLifecycleRunning(ownership controllerRuntimeOwnership) {
	c.lifecycleMu.Lock()
	c.ownedRuntime = ownership
	c.lifecycleState = controllerStateRunning
	c.lifecycleErr = nil
	c.lifecycleMu.Unlock()
}

func (c *Controller) failLifecycleStart(primary error, ownership controllerRuntimeOwnership, hooks syncApplyHooks) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return c.failLifecycleStartContext(ctx, primary, ownership, hooks)
}

func (c *Controller) failLifecycleStartContext(ctx context.Context, primary error, ownership controllerRuntimeOwnership, hooks syncApplyHooks) error {
	cleanupErr := c.cleanupControllerOwnershipContext(ctx, &ownership, hooks)
	joined := errors.Join(primary, cleanupErr)
	stage := service.FailureStageStart
	if ownership.hasResources() {
		stage = service.FailureStageCleanup
	}
	c.health.RecordFailure(stage, time.Now())

	c.lifecycleMu.Lock()
	c.ownedRuntime = ownership
	if ownership.hasResources() {
		c.lifecycleState = controllerStateFailedOwned
	} else {
		c.lifecycleState = controllerStateFailed
	}
	c.lifecycleErr = joined
	c.lifecycleMu.Unlock()
	return joined
}

func (c *Controller) beginLifecycleClose() (controllerRuntimeOwnership, bool, error) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()

	switch c.lifecycleState {
	case controllerStateClosed:
		return controllerRuntimeOwnership{}, false, nil
	case controllerStateStarting:
		return controllerRuntimeOwnership{}, false, errors.New("controller cannot close while starting")
	case controllerStateStopping:
		return controllerRuntimeOwnership{}, false, errors.New("controller close already in progress")
	case controllerStateStopped, controllerStateFailed:
		c.lifecycleState = controllerStateClosed
		c.lifecycleErr = nil
		return controllerRuntimeOwnership{}, false, nil
	case controllerStateRunning, controllerStateFailedOwned:
		ownership := c.ownedRuntime
		c.lifecycleState = controllerStateStopping
		return ownership, true, nil
	default:
		return controllerRuntimeOwnership{}, false, fmt.Errorf("controller cannot close from lifecycle state %d", c.lifecycleState)
	}
}

func (c *Controller) finishLifecycleClose(ownership controllerRuntimeOwnership, closeErr error) {
	if closeErr != nil {
		stage := service.FailureStageClose
		if ownership.hasResources() {
			stage = service.FailureStageCleanup
		}
		c.health.RecordFailure(stage, time.Now())
	}
	c.lifecycleMu.Lock()
	c.ownedRuntime = ownership
	if ownership.hasResources() {
		c.lifecycleState = controllerStateFailedOwned
		c.lifecycleErr = closeErr
	} else {
		c.lifecycleState = controllerStateClosed
		c.lifecycleErr = nil
	}
	c.lifecycleMu.Unlock()

	if !ownership.hasResources() {
		c.stateMu.Lock()
		c.runtimeState = nodeRuntimeState{}
		c.limitedUsers = nil
		c.warnedUsers = nil
		c.stateMu.Unlock()
	}
}

func (c *Controller) cleanupControllerOwnership(ownership *controllerRuntimeOwnership, hooks syncApplyHooks) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return c.cleanupControllerOwnershipContext(ctx, ownership, hooks)
}

func (c *Controller) cleanupControllerOwnershipContext(ctx context.Context, ownership *controllerRuntimeOwnership, hooks syncApplyHooks) error {
	if ownership == nil {
		return nil
	}
	var cleanupErrs []error

	if ownership.websocket {
		wsRuntime := c.currentWSRuntime()
		if wsRuntime == nil {
			ownership.websocket = false
		} else if err := stopWSRuntimeContext(ctx, wsRuntime); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("close controller websocket: %w", err))
		} else {
			c.setWSRuntime(nil)
			ownership.websocket = false
		}
	}
	if ownership.periodic {
		if err := c.closePeriodicTasksContext(ctx); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("close controller periodic tasks: %w", err))
		} else {
			ownership.periodic = false
		}
	}
	if ownership.syncCoordinator {
		if c.syncCoordinator == nil {
			ownership.syncCoordinator = false
		} else if err := stopSyncCoordinatorContext(ctx, c.syncCoordinator); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("close controller sync coordinator: %w", err))
		} else {
			c.syncCoordinator = nil
			ownership.syncCoordinator = false
		}
	}
	if ownership.rules {
		if err := hooks.updateRuleForApply(ownership.tag, nil); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("delete controller rules: %w", err))
		} else {
			ownership.rules = false
		}
	}
	if ownership.limiter {
		if err := hooks.limiter.deleteInbound(ownership.tag); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("delete controller limiter: %w", err))
		} else {
			ownership.limiter = false
		}
	}
	if ownership.runtime {
		apply := nodeRuntimeStateApplyModule{controller: c, ctx: ctx, hooks: hooks}
		if err := apply.cleanupRuntimeTagSnapshot(ownership.nodeSnapshot, ownership.tag); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("delete controller runtime: %w", err))
		} else {
			ownership.runtime = false
		}
	}
	return errors.Join(cleanupErrs...)
}
