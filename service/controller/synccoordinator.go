package controller

import (
	"context"
	"errors"
	"sync"

	"github.com/Mtoly/XrayRP/service"
)

type syncActionExecutor interface {
	ExecuteSyncAction(context.Context, syncAction) error
}

type syncCoordinatorLifecycle interface {
	Submit(syncAction)
	Stop()
}

type contextSyncCoordinatorLifecycle interface {
	StopContext(context.Context) error
}

func stopSyncCoordinatorContext(ctx context.Context, coordinator syncCoordinatorLifecycle) error {
	if coordinator == nil {
		return nil
	}
	if contextual, ok := coordinator.(contextSyncCoordinatorLifecycle); ok {
		return contextual.StopContext(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	coordinator.Stop()
	return ctx.Err()
}

type queuedSyncAction struct {
	action syncAction
	seq    uint64
}

type syncExecutionObserver func(syncAction, error)

type syncExecutionResult struct {
	action syncAction
	err    error
}

type syncCoordinator struct {
	executor syncActionExecutor
	recorder *syncExecutionState
	observer syncExecutionObserver
	results  chan syncExecutionResult
	ctx      context.Context
	cancel   context.CancelFunc

	mu   sync.Mutex
	cond *sync.Cond

	pending map[syncActionType]queuedSyncAction
	dirty   map[syncActionType]syncAction

	inflight     *syncAction
	nextSeq      uint64
	stopped      bool
	done         chan struct{}
	observerDone chan struct{}
}

func newSyncCoordinator(executor syncActionExecutor) *syncCoordinator {
	return newSyncCoordinatorWithResultHandlingContext(context.Background(), executor, nil, nil)
}

func newSyncCoordinatorWithObserver(executor syncActionExecutor, observer syncExecutionObserver) *syncCoordinator {
	return newSyncCoordinatorWithResultHandlingContext(context.Background(), executor, nil, observer)
}

func newSyncCoordinatorWithResultHandling(executor syncActionExecutor, recorder *syncExecutionState, observer syncExecutionObserver) *syncCoordinator {
	return newSyncCoordinatorWithResultHandlingContext(context.Background(), executor, recorder, observer)
}

func newSyncCoordinatorWithResultHandlingContext(ctx context.Context, executor syncActionExecutor, recorder *syncExecutionState, observer syncExecutionObserver) *syncCoordinator {
	if executor == nil {
		panic("controller: nil sync coordinator executor")
	}

	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	coordinator := &syncCoordinator{
		executor: executor,
		ctx:      runCtx,
		cancel:   cancel,
		recorder: recorder,
		observer: observer,
		results:  make(chan syncExecutionResult, 1),
		pending:  make(map[syncActionType]queuedSyncAction),
		dirty:    make(map[syncActionType]syncAction),
		done:     make(chan struct{}),
	}
	coordinator.cond = sync.NewCond(&coordinator.mu)

	go coordinator.run()
	if observer != nil {
		coordinator.observerDone = make(chan struct{})
		go coordinator.observeResults()
	}

	return coordinator
}

func (c *syncCoordinator) Submit(action syncAction) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopped {
		return
	}

	switch {
	case c.inflight != nil && c.inflight.Type == syncActionTypeResyncAll:
		if action.Type == syncActionTypeResyncAll {
			c.dirty[syncActionTypeResyncAll] = action
		} else if syncActionCoveredByResyncAll(action.Type) {
			c.dirty[syncActionTypeResyncAll] = *c.inflight
		} else {
			c.dirty[action.Type] = action
		}
	case action.Type == syncActionTypeResyncAll:
		c.replacePendingWithResyncAllLocked(action)
	case c.inflight != nil && c.inflight.Type == action.Type:
		c.dirty[action.Type] = action
	case c.hasPendingResyncAllLocked() && syncActionCoveredByResyncAll(action.Type):
		// A queued full resync already covers narrower REST-backed actions.
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

func (c *syncCoordinator) Stop() {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	_ = c.StopContext(ctx)
}

func (c *syncCoordinator) StopContext(ctx context.Context) error {
	c.mu.Lock()
	if c.stopped {
		done := c.done
		observerDone := c.observerDone
		c.mu.Unlock()
		return errors.Join(waitCoordinatorDone(ctx, done), waitCoordinatorDone(ctx, observerDone))
	}
	c.stopped = true
	c.pending = make(map[syncActionType]queuedSyncAction)
	c.dirty = make(map[syncActionType]syncAction)
	done := c.done
	observerDone := c.observerDone
	cancel := c.cancel
	c.cond.Broadcast()
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return errors.Join(waitCoordinatorDone(ctx, done), waitCoordinatorDone(ctx, observerDone))
}

func waitCoordinatorDone(ctx context.Context, done <-chan struct{}) error {
	if done == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (c *syncCoordinator) run() {
	defer close(c.done)
	defer close(c.results)

	for {
		action, ok := c.takeNextAction()
		if !ok {
			return
		}
		err := c.executor.ExecuteSyncAction(c.ctx, action)
		if c.ctx.Err() == nil && c.recorder != nil {
			c.recorder.Record(action, err)
		}
		c.finishAction(action)
		if c.ctx.Err() == nil {
			c.notifyObserver(action, err)
		}
	}
}

func (c *syncCoordinator) notifyObserver(action syncAction, err error) {
	if c.observer == nil {
		return
	}

	select {
	case c.results <- syncExecutionResult{action: action, err: err}:
	default:
		// Observability is best-effort and must not delay coordinator progress.
	}
}

func (c *syncCoordinator) observeResults() {
	defer close(c.observerDone)
	for result := range c.results {
		if c.ctx.Err() != nil {
			continue
		}
		func() {
			defer func() {
				_ = recover()
			}()
			c.observer(result.action, result.err)
		}()
	}
}

func (c *syncCoordinator) takeNextAction() (syncAction, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for len(c.pending) == 0 {
		if c.stopped {
			return syncAction{}, false
		}
		c.cond.Wait()
	}

	next := c.popNextLocked()
	c.inflight = &next
	return next, true
}

func (c *syncCoordinator) finishAction(finished syncAction) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.inflight = nil
	if !c.stopped {
		c.requeueDirtyLocked(finished)
	}
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
	preserved := make(map[syncActionType]queuedSyncAction, len(c.pending)+1)
	for actionType, pendingAction := range c.pending {
		if !syncActionCoveredByResyncAll(actionType) {
			preserved[actionType] = pendingAction
		}
	}

	if existing, ok := c.pending[syncActionTypeResyncAll]; ok {
		existing.action = action
		preserved[syncActionTypeResyncAll] = existing
		c.pending = preserved
		return
	}

	c.nextSeq++
	preserved[syncActionTypeResyncAll] = queuedSyncAction{
		action: action,
		seq:    c.nextSeq,
	}
	c.pending = preserved
}

func (c *syncCoordinator) requeueDirtyLocked(finished syncAction) {
	if finished.Type == syncActionTypeResyncAll {
		c.requeueAllDirtyLocked()
		return
	}

	dirtyAction, ok := c.dirty[finished.Type]
	delete(c.dirty, finished.Type)
	if !ok {
		return
	}

	if c.hasPendingResyncAllLocked() && syncActionCoveredByResyncAll(dirtyAction.Type) {
		return
	}

	if dirtyAction.Type == syncActionTypeResyncAll {
		c.replacePendingWithResyncAllLocked(dirtyAction)
		return
	}

	c.enqueueOrReplaceLocked(dirtyAction)
}

func (c *syncCoordinator) requeueAllDirtyLocked() {
	if len(c.dirty) == 0 {
		return
	}

	dirtyActions := make([]syncAction, 0, len(c.dirty))
	for actionType, dirtyAction := range c.dirty {
		dirtyActions = append(dirtyActions, dirtyAction)
		delete(c.dirty, actionType)
	}

	for _, dirtyAction := range dirtyActions {
		if c.hasPendingResyncAllLocked() && syncActionCoveredByResyncAll(dirtyAction.Type) {
			continue
		}
		if dirtyAction.Type == syncActionTypeResyncAll {
			c.replacePendingWithResyncAllLocked(dirtyAction)
			continue
		}
		c.enqueueOrReplaceLocked(dirtyAction)
	}
}

func (c *syncCoordinator) hasPendingResyncAllLocked() bool {
	_, ok := c.pending[syncActionTypeResyncAll]
	return ok
}

func syncActionCoveredByResyncAll(actionType syncActionType) bool {
	switch actionType {
	case syncActionTypeSyncDevices, syncActionTypeClearGlobalDevices:
		return false
	default:
		return true
	}
}
