package controller

import (
	"context"
	"sync"
)

type syncActionExecutor interface {
	ExecuteSyncAction(context.Context, syncAction) error
}

type queuedSyncAction struct {
	action syncAction
	seq    uint64
}

type syncCoordinator struct {
	executor syncActionExecutor

	mu   sync.Mutex
	cond *sync.Cond

	pending map[syncActionType]queuedSyncAction
	dirty   map[syncActionType]syncAction

	inflight *syncAction
	nextSeq  uint64
}

func newSyncCoordinator(executor syncActionExecutor) *syncCoordinator {
	if executor == nil {
		panic("controller: nil sync coordinator executor")
	}

	coordinator := &syncCoordinator{
		executor: executor,
		pending:  make(map[syncActionType]queuedSyncAction),
		dirty:    make(map[syncActionType]syncAction),
	}
	coordinator.cond = sync.NewCond(&coordinator.mu)

	go coordinator.run()

	return coordinator
}

func (c *syncCoordinator) Submit(action syncAction) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch {
	case c.inflight != nil && c.inflight.Type == syncActionTypeResyncAll:
		if action.Type == syncActionTypeResyncAll {
			c.dirty[syncActionTypeResyncAll] = action
		} else {
			c.dirty[syncActionTypeResyncAll] = *c.inflight
		}
	case action.Type == syncActionTypeResyncAll:
		c.replacePendingWithResyncAllLocked(action)
	case c.inflight != nil && c.inflight.Type == action.Type:
		c.dirty[action.Type] = action
	case c.hasPendingResyncAllLocked():
		// A queued full resync already covers narrower actions.
	default:
		c.enqueueOrReplaceLocked(action)
	}

	c.cond.Signal()
}

func (c *syncCoordinator) WaitIdle() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for c.inflight != nil || len(c.pending) > 0 {
		c.cond.Wait()
	}
}

func (c *syncCoordinator) run() {
	for {
		action := c.takeNextAction()
		_ = c.executor.ExecuteSyncAction(context.Background(), action)
		c.finishAction(action)
	}
}

func (c *syncCoordinator) takeNextAction() syncAction {
	c.mu.Lock()
	defer c.mu.Unlock()

	for len(c.pending) == 0 {
		c.cond.Wait()
	}

	next := c.popNextLocked()
	c.inflight = &next
	return next
}

func (c *syncCoordinator) finishAction(finished syncAction) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.inflight = nil
	c.requeueDirtyLocked(finished)
	c.cond.Broadcast()
}

func (c *syncCoordinator) popNextLocked() syncAction {
	var (
		selectedType   syncActionType
		selectedAction queuedSyncAction
		selected       bool
	)

	for actionType, candidate := range c.pending {
		if !selected || candidate.action.Priority > selectedAction.action.Priority || (candidate.action.Priority == selectedAction.action.Priority && candidate.seq < selectedAction.seq) {
			selectedType = actionType
			selectedAction = candidate
			selected = true
		}
	}

	delete(c.pending, selectedType)
	return selectedAction.action
}

func (c *syncCoordinator) enqueueOrReplaceLocked(action syncAction) {
	if existing, ok := c.pending[action.Type]; ok {
		existing.action = action
		c.pending[action.Type] = existing
		return
	}

	c.nextSeq++
	c.pending[action.Type] = queuedSyncAction{
		action: action,
		seq:    c.nextSeq,
	}
}

func (c *syncCoordinator) replacePendingWithResyncAllLocked(action syncAction) {
	existing, ok := c.pending[syncActionTypeResyncAll]
	c.pending = make(map[syncActionType]queuedSyncAction, 1)
	if ok {
		existing.action = action
		c.pending[syncActionTypeResyncAll] = existing
		return
	}

	c.nextSeq++
	c.pending[syncActionTypeResyncAll] = queuedSyncAction{
		action: action,
		seq:    c.nextSeq,
	}
}

func (c *syncCoordinator) requeueDirtyLocked(finished syncAction) {
	dirtyAction, ok := c.dirty[finished.Type]
	delete(c.dirty, finished.Type)
	if !ok {
		return
	}

	if finished.Type != syncActionTypeResyncAll && c.hasPendingResyncAllLocked() {
		return
	}

	if finished.Type == syncActionTypeResyncAll {
		c.replacePendingWithResyncAllLocked(dirtyAction)
		return
	}

	c.enqueueOrReplaceLocked(dirtyAction)
}

func (c *syncCoordinator) hasPendingResyncAllLocked() bool {
	_, ok := c.pending[syncActionTypeResyncAll]
	return ok
}
