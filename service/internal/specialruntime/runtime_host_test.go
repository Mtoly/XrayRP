package specialruntime

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestRuntimeHostStartsRuntimeBeforeTasks(t *testing.T) {
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&recordingTask{name: "task", events: &events})
	host := NewRuntimeHost(tasks, RuntimeHostCallbacks{
		Start: func(context.Context) error {
			events = append(events, "runtime-start")
			return nil
		},
		Stop: func(context.Context) error {
			events = append(events, "runtime-stop")
			return nil
		},
		Join: func(context.Context) error {
			events = append(events, "runtime-join")
			return nil
		},
	})

	if err := host.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"runtime-start", "start:task"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRuntimeHostCleansRuntimeStartFailure(t *testing.T) {
	startErr := errors.New("runtime not ready")
	cleanupErr := errors.New("runtime close failed")
	events := []string{}
	host := NewRuntimeHost(nil, RuntimeHostCallbacks{
		Start: func(context.Context) error {
			events = append(events, "runtime-start")
			return startErr
		},
		Stop: func(context.Context) error {
			events = append(events, "runtime-stop")
			return cleanupErr
		},
		Join: func(context.Context) error {
			events = append(events, "runtime-join")
			return nil
		},
	})

	err := host.StartContext(context.Background())
	if !errors.Is(err, startErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("StartContext() error = %v, want both start and cleanup errors", err)
	}
	if !RuntimeStartFailed(err) || !StartCleanupFailed(err) {
		t.Fatalf("StartContext() error = %v, want runtime start cleanup classification", err)
	}
	if want := []string{"runtime-start", "runtime-stop", "runtime-join"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRuntimeHostCloseStopsRuntimeWaitsTasksThenJoins(t *testing.T) {
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&recordingTask{name: "task", events: &events})
	host := NewRuntimeHost(tasks, RuntimeHostCallbacks{
		Stop: func(context.Context) error {
			events = append(events, "runtime-stop")
			return nil
		},
		Join: func(context.Context) error {
			events = append(events, "runtime-join")
			return nil
		},
	})

	if err := host.CloseStoppedContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"runtime-stop", "wait:task", "runtime-join"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRuntimeHostDelegatesCanceledExternalRuntimeToTaskRollback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&recordingTask{name: "task", events: &events})
	host := NewRuntimeHost(tasks, RuntimeHostCallbacks{
		Stop: func(context.Context) error {
			events = append(events, "runtime-stop")
			return nil
		},
		Join: func(context.Context) error {
			events = append(events, "runtime-join")
			return nil
		},
	})

	err := host.StartContext(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("StartContext() error = %v, want context.Canceled", err)
	}
	want := []string{"stop:task", "runtime-stop", "wait:task", "runtime-join"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRuntimeHostRollbackPreservesTaskAndRuntimeOrder(t *testing.T) {
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&recordingTask{name: "task", events: &events})
	host := NewRuntimeHost(tasks, RuntimeHostCallbacks{
		Stop: func(context.Context) error {
			events = append(events, "runtime-stop")
			return nil
		},
		Join: func(context.Context) error {
			events = append(events, "runtime-join")
			return nil
		},
	})

	if err := host.RollbackContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"stop:task", "runtime-stop", "wait:task", "runtime-join"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRuntimeHostAggregatesStopAndJoinErrors(t *testing.T) {
	stopErr := errors.New("runtime stop failed")
	joinErr := errors.New("runtime join failed")
	host := NewRuntimeHost(nil, RuntimeHostCallbacks{
		Stop: func(context.Context) error { return stopErr },
		Join: func(context.Context) error { return joinErr },
	})

	err := host.CloseStoppedContext(context.Background())
	if !errors.Is(err, stopErr) || !errors.Is(err, joinErr) {
		t.Fatalf("CloseStoppedContext() error = %v, want both runtime errors", err)
	}
}

func TestRuntimeHostTaskStartFailureRollsBackRuntimeAndTasks(t *testing.T) {
	startErr := errors.New("task start failed")
	stopErr := errors.New("task stop failed")
	waitErr := errors.New("task wait failed")
	runtimeStopErr := errors.New("runtime stop failed")
	runtimeJoinErr := errors.New("runtime join failed")
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&recordingTask{name: "first", events: &events, waitErr: waitErr})
	tasks.Add(&recordingTask{name: "second", events: &events, startErr: startErr, stopErr: stopErr})
	host := NewRuntimeHost(tasks, RuntimeHostCallbacks{
		Stop: func(context.Context) error {
			events = append(events, "runtime-stop")
			return runtimeStopErr
		},
		Join: func(context.Context) error {
			events = append(events, "runtime-join")
			return runtimeJoinErr
		},
	})

	err := host.StartContext(context.Background())
	for _, want := range []error{startErr, stopErr, waitErr, runtimeStopErr, runtimeJoinErr} {
		if !errors.Is(err, want) {
			t.Fatalf("StartContext() error = %v, want joined %v", err, want)
		}
	}
	if !StartCleanupFailed(err) {
		t.Fatalf("StartContext() error = %v, want cleanup failure classification", err)
	}
	wantEvents := []string{
		"start:first", "start:second",
		"stop:second", "stop:first",
		"runtime-stop", "wait:second", "wait:first", "runtime-join",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
}

func TestRuntimeHostRuntimeStartFailureUsesDetachedCleanupContext(t *testing.T) {
	startErr := errors.New("runtime not ready")
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	startCanceled := false
	stopCanceled := true
	joinCanceled := true
	host := NewRuntimeHost(nil, RuntimeHostCallbacks{
		Start: func(ctx context.Context) error {
			cancelParent()
			startCanceled = ctx.Err() != nil
			return startErr
		},
		Stop: func(ctx context.Context) error {
			stopCanceled = ctx.Err() != nil
			return nil
		},
		Join: func(ctx context.Context) error {
			joinCanceled = ctx.Err() != nil
			return nil
		},
	})

	err := host.StartContext(parent)
	if !errors.Is(err, startErr) {
		t.Fatalf("StartContext() error = %v, want %v", err, startErr)
	}
	if !startCanceled {
		t.Fatal("runtime start callback did not observe parent cancellation")
	}
	if stopCanceled || joinCanceled {
		t.Fatalf("cleanup callbacks received canceled context: stop=%v join=%v", stopCanceled, joinCanceled)
	}
}

func TestRuntimeHostStopsProducersBeforeRuntimeShutdown(t *testing.T) {
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&recordingTask{name: "first", events: &events})
	tasks.Add(&recordingTask{name: "second", events: &events})
	host := NewRuntimeHost(tasks, RuntimeHostCallbacks{
		Stop: func(context.Context) error {
			events = append(events, "runtime-stop")
			return nil
		},
		Join: func(context.Context) error {
			events = append(events, "runtime-join")
			return nil
		},
	})

	if err := host.StopProducersContext(context.Background()); err != nil {
		t.Fatalf("StopProducersContext() error = %v", err)
	}
	if want := []string{"stop:second", "stop:first"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events after StopProducersContext() = %v, want %v", events, want)
	}
	if err := host.CloseStoppedContext(context.Background()); err != nil {
		t.Fatalf("CloseStoppedContext() error = %v", err)
	}
	want := []string{
		"stop:second", "stop:first", "runtime-stop",
		"wait:second", "wait:first", "runtime-join",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events after shutdown = %v, want %v", events, want)
	}
}

type cancelingStartTask struct {
	events       *[]string
	cancelParent context.CancelFunc
	startErr     error
	stopCanceled *bool
	waitCanceled *bool
}

func (t *cancelingStartTask) Start() error {
	return errors.New("legacy Start called")
}

func (t *cancelingStartTask) Close() error {
	return errors.New("legacy Close called")
}

func (t *cancelingStartTask) StartContext(ctx context.Context) error {
	if ctx.Value(contextMarkerKey{}) != "marker" {
		return errors.New("start context marker missing")
	}
	*t.events = append(*t.events, "task-start")
	t.cancelParent()
	return t.startErr
}

func (t *cancelingStartTask) StopContext(ctx context.Context) error {
	if ctx.Value(contextMarkerKey{}) != "marker" {
		return errors.New("stop context marker missing")
	}
	*t.stopCanceled = ctx.Err() != nil
	*t.events = append(*t.events, "task-stop")
	return nil
}

func (t *cancelingStartTask) WaitContext(ctx context.Context) error {
	if ctx.Value(contextMarkerKey{}) != "marker" {
		return errors.New("wait context marker missing")
	}
	*t.waitCanceled = ctx.Err() != nil
	*t.events = append(*t.events, "task-wait")
	return nil
}

func TestRuntimeHostTaskStartFailureUsesDetachedCleanupContext(t *testing.T) {
	startErr := errors.New("task not ready")
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	events := []string{}
	stopCanceled := true
	waitCanceled := true
	tasks := NewTasks()
	tasks.Add(&cancelingStartTask{
		events:       &events,
		cancelParent: cancelParent,
		startErr:     startErr,
		stopCanceled: &stopCanceled,
		waitCanceled: &waitCanceled,
	})
	runtimeStopCanceled := true
	runtimeJoinCanceled := true
	host := NewRuntimeHost(tasks, RuntimeHostCallbacks{
		Stop: func(ctx context.Context) error {
			runtimeStopCanceled = ctx.Err() != nil
			if ctx.Value(contextMarkerKey{}) != "marker" {
				return errors.New("runtime stop context marker missing")
			}
			events = append(events, "runtime-stop")
			return nil
		},
		Join: func(ctx context.Context) error {
			runtimeJoinCanceled = ctx.Err() != nil
			if ctx.Value(contextMarkerKey{}) != "marker" {
				return errors.New("runtime join context marker missing")
			}
			events = append(events, "runtime-join")
			return nil
		},
	})

	ctx := context.WithValue(parent, contextMarkerKey{}, "marker")
	err := host.StartContext(ctx)
	if !errors.Is(err, startErr) {
		t.Fatalf("StartContext() error = %v, want %v", err, startErr)
	}
	if StartCleanupFailed(err) {
		t.Fatalf("StartContext() error = %v, cleanup unexpectedly failed", err)
	}
	if stopCanceled || waitCanceled || runtimeStopCanceled || runtimeJoinCanceled {
		t.Fatalf("cleanup callbacks received canceled context: stop=%v wait=%v runtime-stop=%v runtime-join=%v", stopCanceled, waitCanceled, runtimeStopCanceled, runtimeJoinCanceled)
	}
	want := []string{"task-start", "task-stop", "runtime-stop", "task-wait", "runtime-join"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

type rollbackContextTask struct {
	events *[]string
}

func (t *rollbackContextTask) Start() error { return nil }
func (t *rollbackContextTask) Close() error { return errors.New("legacy Close called") }

func (t *rollbackContextTask) StopContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Value(contextMarkerKey{}) != "marker" {
		return errors.New("stop context marker missing")
	}
	*t.events = append(*t.events, "task-stop")
	return nil
}

func (t *rollbackContextTask) WaitContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Value(contextMarkerKey{}) != "marker" {
		return errors.New("wait context marker missing")
	}
	*t.events = append(*t.events, "task-wait")
	return nil
}

func TestRuntimeHostRollbackUsesDetachedCleanupContext(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	ctx := context.WithValue(parent, contextMarkerKey{}, "marker")
	cancel()
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&rollbackContextTask{events: &events})
	host := NewRuntimeHost(tasks, RuntimeHostCallbacks{
		Stop: func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if ctx.Value(contextMarkerKey{}) != "marker" {
				return errors.New("runtime stop context marker missing")
			}
			events = append(events, "runtime-stop")
			return nil
		},
		Join: func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if ctx.Value(contextMarkerKey{}) != "marker" {
				return errors.New("runtime join context marker missing")
			}
			events = append(events, "runtime-join")
			return nil
		},
	})

	if err := host.RollbackContext(ctx); err != nil {
		t.Fatalf("RollbackContext() error = %v", err)
	}
	want := []string{"task-stop", "runtime-stop", "task-wait", "runtime-join"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

type cancelAfterSuccessfulStartTask struct {
	events       *[]string
	cancelParent context.CancelFunc
}

func (t *cancelAfterSuccessfulStartTask) Start() error {
	return errors.New("legacy Start called")
}

func (t *cancelAfterSuccessfulStartTask) Close() error {
	return errors.New("legacy Close called")
}

func (t *cancelAfterSuccessfulStartTask) StartContext(ctx context.Context) error {
	if ctx.Value(contextMarkerKey{}) != "marker" {
		return errors.New("start context marker missing")
	}
	*t.events = append(*t.events, "task-start")
	t.cancelParent()
	return nil
}

func (t *cancelAfterSuccessfulStartTask) StopContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Value(contextMarkerKey{}) != "marker" {
		return errors.New("stop context marker missing")
	}
	*t.events = append(*t.events, "task-stop")
	return nil
}

func (t *cancelAfterSuccessfulStartTask) WaitContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Value(contextMarkerKey{}) != "marker" {
		return errors.New("wait context marker missing")
	}
	*t.events = append(*t.events, "task-wait")
	return nil
}

func TestRuntimeHostRollsBackWhenStartupContextCancelsAfterTaskStart(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	ctx := context.WithValue(parent, contextMarkerKey{}, "marker")
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&cancelAfterSuccessfulStartTask{events: &events, cancelParent: cancelParent})
	host := NewRuntimeHost(tasks, RuntimeHostCallbacks{
		Stop: func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if ctx.Value(contextMarkerKey{}) != "marker" {
				return errors.New("runtime stop context marker missing")
			}
			events = append(events, "runtime-stop")
			return nil
		},
		Join: func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if ctx.Value(contextMarkerKey{}) != "marker" {
				return errors.New("runtime join context marker missing")
			}
			events = append(events, "runtime-join")
			return nil
		},
	})

	err := host.StartContext(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("StartContext() error = %v, want context.Canceled", err)
	}
	if StartCleanupFailed(err) {
		t.Fatalf("StartContext() error = %v, cleanup unexpectedly failed", err)
	}
	want := []string{"task-start", "task-stop", "runtime-stop", "task-wait", "runtime-join"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRuntimeHostRollsBackWhenStartupContextCancelsAfterRuntimeStart(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	ctx := context.WithValue(parent, contextMarkerKey{}, "marker")
	events := []string{}
	host := NewRuntimeHost(nil, RuntimeHostCallbacks{
		Start: func(ctx context.Context) error {
			if ctx.Value(contextMarkerKey{}) != "marker" {
				return errors.New("runtime start context marker missing")
			}
			events = append(events, "runtime-start")
			cancelParent()
			return nil
		},
		Stop: func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if ctx.Value(contextMarkerKey{}) != "marker" {
				return errors.New("runtime stop context marker missing")
			}
			events = append(events, "runtime-stop")
			return nil
		},
		Join: func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if ctx.Value(contextMarkerKey{}) != "marker" {
				return errors.New("runtime join context marker missing")
			}
			events = append(events, "runtime-join")
			return nil
		},
	})

	err := host.StartContext(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("StartContext() error = %v, want context.Canceled", err)
	}
	if !RuntimeStartFailed(err) {
		t.Fatalf("StartContext() error = %v, want runtime-start failure classification", err)
	}
	if StartCleanupFailed(err) {
		t.Fatalf("StartContext() error = %v, cleanup unexpectedly failed", err)
	}
	want := []string{"runtime-start", "runtime-stop", "runtime-join"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRuntimeHostRejectsCanceledContextBeforeTasklessStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	host := NewRuntimeHost(nil, RuntimeHostCallbacks{})
	if err := host.StartContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("StartContext() error = %v, want context.Canceled", err)
	}
}
