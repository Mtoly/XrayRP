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
	nodeInfo        *api.NodeInfo
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
		if err := hooks.updateRule(ownership.tag, nil); err != nil {
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
		if err := apply.cleanupRuntimeTag(ownership.nodeInfo, ownership.tag); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("delete controller runtime: %w", err))
		} else {
			ownership.runtime = false
		}
	}
	return errors.Join(cleanupErrs...)
}
