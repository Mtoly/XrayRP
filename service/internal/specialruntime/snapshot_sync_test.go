package specialruntime

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/service"
)

func TestSnapshotSyncCoordinatorCoalescesFiveThousandUserTriggers(t *testing.T) {
	executed := make(chan service.SnapshotSyncScope, 1)
	coordinator := NewSnapshotSyncCoordinator(SnapshotSyncCoordinatorConfig{
		CoalesceWindow: DefaultSnapshotSyncCoalesceWindow,
		Execute: func(_ context.Context, scope service.SnapshotSyncScope) error {
			executed <- scope
			return nil
		},
	})
	timers := newManualSnapshotTimerFactory()
	coordinator.newTimer = timers.New

	startSnapshotCoordinator(t, coordinator)
	for range 5000 {
		coordinator.SubmitSnapshotSync(service.SnapshotSyncTrigger{
			Scope:  service.SnapshotSyncUsers,
			Source: service.SnapshotSyncSourceWebSocket,
		})
	}

	timer := timers.Next(t)
	if timer.duration != DefaultSnapshotSyncCoalesceWindow {
		t.Fatalf("coalesce window = %s, want %s", timer.duration, DefaultSnapshotSyncCoalesceWindow)
	}
	timer.Fire()

	if scope := receiveSnapshotScope(t, executed); scope != service.SnapshotSyncUsers {
		t.Fatalf("executed scope = %v, want users", scope)
	}
	snapshot := coordinator.Snapshot()
	if snapshot.Submitted != 5000 {
		t.Fatalf("submitted = %d, want 5000", snapshot.Submitted)
	}
	if snapshot.Executions != 1 {
		t.Fatalf("executions = %d, want 1", snapshot.Executions)
	}
	if snapshot.Pending != 0 {
		t.Fatalf("pending scope = %v, want empty", snapshot.Pending)
	}
}

func TestSnapshotSyncCoordinatorMergesScopesWithinOneWindow(t *testing.T) {
	executed := make(chan service.SnapshotSyncScope, 1)
	coordinator := NewSnapshotSyncCoordinator(SnapshotSyncCoordinatorConfig{
		Execute: func(_ context.Context, scope service.SnapshotSyncScope) error {
			executed <- scope
			return nil
		},
	})
	timers := newManualSnapshotTimerFactory()
	coordinator.newTimer = timers.New
	startSnapshotCoordinator(t, coordinator)

	coordinator.SubmitSnapshotSync(service.SnapshotSyncTrigger{Scope: service.SnapshotSyncNode})
	coordinator.SubmitSnapshotSync(service.SnapshotSyncTrigger{Scope: service.SnapshotSyncUsers})
	coordinator.SubmitSnapshotSync(service.SnapshotSyncTrigger{Scope: service.SnapshotSyncRules})
	timers.Next(t).Fire()

	if scope := receiveSnapshotScope(t, executed); scope != service.SnapshotSyncAll {
		t.Fatalf("executed scope = %v, want all", scope)
	}
}

func TestSnapshotSyncCoordinatorSerializesDirtyWork(t *testing.T) {
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	executed := make(chan service.SnapshotSyncScope, 2)
	var executions atomic.Int32
	var concurrent atomic.Int32
	var maxConcurrent atomic.Int32
	coordinator := NewSnapshotSyncCoordinator(SnapshotSyncCoordinatorConfig{
		Execute: func(_ context.Context, scope service.SnapshotSyncScope) error {
			active := concurrent.Add(1)
			defer concurrent.Add(-1)
			for {
				maximum := maxConcurrent.Load()
				if active <= maximum || maxConcurrent.CompareAndSwap(maximum, active) {
					break
				}
			}
			call := executions.Add(1)
			if call == 1 {
				close(firstEntered)
				<-releaseFirst
			}
			executed <- scope
			return nil
		},
	})
	timers := newManualSnapshotTimerFactory()
	coordinator.newTimer = timers.New
	startSnapshotCoordinator(t, coordinator)

	coordinator.SubmitSnapshotSync(service.SnapshotSyncTrigger{Scope: service.SnapshotSyncNode})
	timers.Next(t).Fire()
	waitSnapshotSignal(t, firstEntered, "first execution")
	for range 1000 {
		coordinator.SubmitSnapshotSync(service.SnapshotSyncTrigger{Scope: service.SnapshotSyncUsers})
	}
	close(releaseFirst)
	if scope := receiveSnapshotScope(t, executed); scope != service.SnapshotSyncNode {
		t.Fatalf("first scope = %v, want node", scope)
	}
	timers.Next(t).Fire()
	if scope := receiveSnapshotScope(t, executed); scope != service.SnapshotSyncUsers {
		t.Fatalf("second scope = %v, want users", scope)
	}
	if got := maxConcurrent.Load(); got != 1 {
		t.Fatalf("maximum concurrent executions = %d, want 1", got)
	}
	if got := executions.Load(); got != 2 {
		t.Fatalf("executions = %d, want 2", got)
	}
}

func TestSnapshotSyncCoordinatorCloseCancelsAndJoinsExecution(t *testing.T) {
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	coordinator := NewSnapshotSyncCoordinator(SnapshotSyncCoordinatorConfig{
		Execute: func(ctx context.Context, _ service.SnapshotSyncScope) error {
			close(entered)
			<-ctx.Done()
			close(cancelled)
			return ctx.Err()
		},
	})
	timers := newManualSnapshotTimerFactory()
	coordinator.newTimer = timers.New
	startSnapshotCoordinator(t, coordinator)

	coordinator.SubmitSnapshotSync(service.SnapshotSyncTrigger{Scope: service.SnapshotSyncAll})
	timers.Next(t).Fire()
	waitSnapshotSignal(t, entered, "execution start")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := coordinator.CloseContext(ctx); err != nil {
		t.Fatalf("CloseContext() error = %v", err)
	}
	waitSnapshotSignal(t, cancelled, "execution cancellation")

	before := coordinator.Snapshot()
	coordinator.SubmitSnapshotSync(service.SnapshotSyncTrigger{Scope: service.SnapshotSyncUsers})
	after := coordinator.Snapshot()
	if after.Submitted != before.Submitted || after.Pending != 0 {
		t.Fatalf("closed coordinator accepted work: before=%+v after=%+v", before, after)
	}
}

func TestSnapshotSyncCoordinatorStopCancelsOwnerWhenCallerContextExpired(t *testing.T) {
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	coordinator := NewSnapshotSyncCoordinator(SnapshotSyncCoordinatorConfig{
		Execute: func(ctx context.Context, _ service.SnapshotSyncScope) error {
			close(entered)
			<-ctx.Done()
			close(cancelled)
			return ctx.Err()
		},
	})
	timers := newManualSnapshotTimerFactory()
	coordinator.newTimer = timers.New
	startSnapshotCoordinator(t, coordinator)

	coordinator.SubmitSnapshotSync(service.SnapshotSyncTrigger{Scope: service.SnapshotSyncAll})
	timers.Next(t).Fire()
	waitSnapshotSignal(t, entered, "execution start")

	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if err := coordinator.StopContext(expired); !errors.Is(err, context.Canceled) {
		t.Fatalf("StopContext() error = %v, want context cancellation", err)
	}
	waitSnapshotSignal(t, cancelled, "execution cancellation")
}

func BenchmarkSnapshotSyncCoordinatorFiveThousandUserTriggers(b *testing.B) {
	results := make(chan struct{}, 1)
	coordinator := NewSnapshotSyncCoordinator(SnapshotSyncCoordinatorConfig{
		Execute: func(context.Context, service.SnapshotSyncScope) error {
			return nil
		},
		OnResult: func(SnapshotSyncResult) {
			results <- struct{}{}
		},
	})
	if err := coordinator.StartContext(context.Background()); err != nil {
		b.Fatalf("StartContext() error = %v", err)
	}
	b.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := coordinator.CloseContext(ctx); err != nil {
			b.Fatalf("CloseContext() error = %v", err)
		}
	})

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for range 5000 {
			coordinator.SubmitSnapshotSync(service.SnapshotSyncTrigger{
				Scope:  service.SnapshotSyncUsers,
				Source: service.SnapshotSyncSourceWebSocket,
			})
		}
		<-results
	}
	b.StopTimer()
	snapshot := coordinator.Snapshot()
	b.ReportMetric(float64(snapshot.Executions)/float64(b.N), "fetches/op")
	b.ReportMetric(5000, "triggers/op")
}

type manualSnapshotTimerFactory struct {
	timers chan *manualSnapshotTimer
}

func newManualSnapshotTimerFactory() *manualSnapshotTimerFactory {
	return &manualSnapshotTimerFactory{timers: make(chan *manualSnapshotTimer, 8)}
}

func (f *manualSnapshotTimerFactory) New(duration time.Duration) snapshotSyncTimer {
	timer := &manualSnapshotTimer{duration: duration, ch: make(chan time.Time, 1)}
	f.timers <- timer
	return timer
}

func (f *manualSnapshotTimerFactory) Next(t *testing.T) *manualSnapshotTimer {
	t.Helper()
	select {
	case timer := <-f.timers:
		return timer
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for snapshot sync timer")
		return nil
	}
}

type manualSnapshotTimer struct {
	duration time.Duration
	ch       chan time.Time
	stopOnce sync.Once
}

func (t *manualSnapshotTimer) C() <-chan time.Time { return t.ch }
func (t *manualSnapshotTimer) Stop() bool {
	stopped := false
	t.stopOnce.Do(func() { stopped = true })
	return stopped
}
func (t *manualSnapshotTimer) Fire() { t.ch <- time.Now() }

func startSnapshotCoordinator(t *testing.T, coordinator *SnapshotSyncCoordinator) {
	t.Helper()
	if err := coordinator.StartContext(context.Background()); err != nil {
		t.Fatalf("StartContext() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := coordinator.CloseContext(ctx); err != nil {
			t.Fatalf("CloseContext() cleanup error = %v", err)
		}
	})
}

func receiveSnapshotScope(t *testing.T, scopes <-chan service.SnapshotSyncScope) service.SnapshotSyncScope {
	t.Helper()
	select {
	case scope := <-scopes:
		return scope
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for snapshot sync execution")
		return 0
	}
}

func waitSnapshotSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for %s", name)
	}
}
