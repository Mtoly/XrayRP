package specialruntime

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/service"
)

const DefaultSnapshotSyncCoalesceWindow = 250 * time.Millisecond

type SnapshotSyncCoordinatorConfig struct {
	CoalesceWindow time.Duration
	Execute        func(context.Context, service.SnapshotSyncScope) error
	OnResult       func(SnapshotSyncResult)
}

type SnapshotSyncResult struct {
	Scope      service.SnapshotSyncScope
	StartedAt  time.Time
	FinishedAt time.Time
	Err        error
}

type SnapshotSyncCoordinatorSnapshot struct {
	Submitted  uint64
	Executions uint64
	Pending    service.SnapshotSyncScope
	InFlight   bool
	LastResult SnapshotSyncResult
}

type snapshotSyncTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type standardSnapshotSyncTimer struct {
	*time.Timer
}

func (timer standardSnapshotSyncTimer) C() <-chan time.Time {
	return timer.Timer.C
}

type SnapshotSyncCoordinator struct {
	config   SnapshotSyncCoordinatorConfig
	newTimer func(time.Duration) snapshotSyncTimer

	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	signal     chan struct{}
	done       chan struct{}
	started    bool
	stopping   bool
	closed     bool
	pending    service.SnapshotSyncScope
	submitted  uint64
	executions uint64
	inFlight   bool
	lastResult SnapshotSyncResult
}

func NewSnapshotSyncCoordinator(config SnapshotSyncCoordinatorConfig) *SnapshotSyncCoordinator {
	if config.CoalesceWindow <= 0 {
		config.CoalesceWindow = DefaultSnapshotSyncCoalesceWindow
	}
	return &SnapshotSyncCoordinator{
		config: config,
		newTimer: func(duration time.Duration) snapshotSyncTimer {
			return standardSnapshotSyncTimer{Timer: time.NewTimer(duration)}
		},
	}
}

func (coordinator *SnapshotSyncCoordinator) Start() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return coordinator.StartContext(ctx)
}

func (coordinator *SnapshotSyncCoordinator) StartContext(parent context.Context) error {
	if parent == nil {
		parent = context.Background()
	}
	if err := parent.Err(); err != nil {
		return err
	}
	if coordinator == nil || coordinator.config.Execute == nil {
		return errors.New("snapshot sync coordinator executor is nil")
	}

	coordinator.mu.Lock()
	if coordinator.closed {
		coordinator.mu.Unlock()
		return errors.New("snapshot sync coordinator cannot restart after close")
	}
	if coordinator.started {
		coordinator.mu.Unlock()
		return nil
	}
	runContext, cancel := context.WithCancel(context.WithoutCancel(parent))
	signal := make(chan struct{}, 1)
	done := make(chan struct{})
	coordinator.ctx = runContext
	coordinator.cancel = cancel
	coordinator.signal = signal
	coordinator.done = done
	coordinator.started = true
	coordinator.stopping = false
	coordinator.pending = 0
	coordinator.mu.Unlock()

	go coordinator.run(runContext, signal, done)
	return nil
}

func (coordinator *SnapshotSyncCoordinator) SubmitSnapshotSync(trigger service.SnapshotSyncTrigger) {
	if coordinator == nil {
		return
	}
	scope := trigger.Scope & service.SnapshotSyncAll
	if !scope.Valid() {
		return
	}

	coordinator.mu.Lock()
	if !coordinator.started || coordinator.stopping || coordinator.closed {
		coordinator.mu.Unlock()
		return
	}
	coordinator.pending |= scope
	coordinator.submitted++
	signal := coordinator.signal
	coordinator.mu.Unlock()

	select {
	case signal <- struct{}{}:
	default:
	}
}

func (coordinator *SnapshotSyncCoordinator) Stop() error {
	return coordinator.StopContext(context.Background())
}

func (coordinator *SnapshotSyncCoordinator) StopContext(ctx context.Context) error {
	if coordinator == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	callerErr := ctx.Err()

	coordinator.mu.Lock()
	if coordinator.closed || !coordinator.started {
		coordinator.closed = true
		coordinator.pending = 0
		coordinator.mu.Unlock()
		return callerErr
	}
	coordinator.stopping = true
	coordinator.pending = 0
	cancel := coordinator.cancel
	coordinator.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return callerErr
}

func (coordinator *SnapshotSyncCoordinator) Wait() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultJoinTimeout)
	defer cancel()
	return coordinator.WaitContext(ctx)
}

func (coordinator *SnapshotSyncCoordinator) WaitContext(ctx context.Context) error {
	if coordinator == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	coordinator.mu.Lock()
	done := coordinator.done
	started := coordinator.started
	coordinator.mu.Unlock()
	if started && done != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}

	coordinator.mu.Lock()
	coordinator.started = false
	coordinator.stopping = false
	coordinator.closed = true
	coordinator.pending = 0
	coordinator.ctx = nil
	coordinator.cancel = nil
	coordinator.mu.Unlock()
	return nil
}

func (coordinator *SnapshotSyncCoordinator) Close() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return coordinator.CloseContext(ctx)
}

func (coordinator *SnapshotSyncCoordinator) CloseContext(ctx context.Context) error {
	return errors.Join(coordinator.StopContext(ctx), coordinator.WaitContext(ctx))
}

func (coordinator *SnapshotSyncCoordinator) Snapshot() SnapshotSyncCoordinatorSnapshot {
	if coordinator == nil {
		return SnapshotSyncCoordinatorSnapshot{}
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return SnapshotSyncCoordinatorSnapshot{
		Submitted:  coordinator.submitted,
		Executions: coordinator.executions,
		Pending:    coordinator.pending,
		InFlight:   coordinator.inFlight,
		LastResult: coordinator.lastResult,
	}
}

func (coordinator *SnapshotSyncCoordinator) run(ctx context.Context, signal <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	for {
		select {
		case <-ctx.Done():
			return
		case <-signal:
		}

		timer := coordinator.newTimer(coordinator.config.CoalesceWindow)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C():
		}
		coordinator.drainSignal(signal)
		scope := coordinator.takePending()
		if !scope.Valid() {
			continue
		}

		startedAt := time.Now()
		coordinator.mu.Lock()
		coordinator.executions++
		coordinator.inFlight = true
		coordinator.mu.Unlock()

		operationContext, cancel := service.WithDefaultTimeout(ctx, service.DefaultSyncTimeout)
		err := coordinator.config.Execute(operationContext, scope)
		cancel()
		result := SnapshotSyncResult{
			Scope:      scope,
			StartedAt:  startedAt,
			FinishedAt: time.Now(),
			Err:        err,
		}

		coordinator.mu.Lock()
		coordinator.inFlight = false
		coordinator.lastResult = result
		coordinator.mu.Unlock()
		if coordinator.config.OnResult != nil && ctx.Err() == nil {
			coordinator.config.OnResult(result)
		}
	}
}

func (coordinator *SnapshotSyncCoordinator) takePending() service.SnapshotSyncScope {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.stopping || coordinator.closed {
		coordinator.pending = 0
		return 0
	}
	scope := coordinator.pending
	coordinator.pending = 0
	return scope
}

func (coordinator *SnapshotSyncCoordinator) drainSignal(signal <-chan struct{}) {
	for {
		select {
		case <-signal:
		default:
			return
		}
	}
}
