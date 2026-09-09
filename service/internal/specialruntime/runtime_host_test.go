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
