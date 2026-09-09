package specialruntime

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type recordingTask struct {
	name     string
	events   *[]string
	startErr error
	stopErr  error
	waitErr  error
}

func (t *recordingTask) Start() error {
	*t.events = append(*t.events, "start:"+t.name)
	return t.startErr
}

func (t *recordingTask) Close() error {
	*t.events = append(*t.events, "close:"+t.name)
	return t.stopErr
}

func (t *recordingTask) Stop() error {
	*t.events = append(*t.events, "stop:"+t.name)
	return t.stopErr
}

func (t *recordingTask) Wait() error {
	*t.events = append(*t.events, "wait:"+t.name)
	return t.waitErr
}

type closeOnlyTask struct {
	events *[]string
}

func TestPeriodicSatisfiesTaskInterface(t *testing.T) {
	var task Task = NewPeriodic(time.Hour, func() error { return nil })
	if err := task.Start(); err != nil {
		t.Fatal(err)
	}
	if err := task.Close(); err != nil {
		t.Fatal(err)
	}
}

func (t *closeOnlyTask) Start() error { return nil }
func (t *closeOnlyTask) Close() error {
	*t.events = append(*t.events, "close:fallback")
	return nil
}

func TestTasksStartFailureRollsBackInOwnershipOrder(t *testing.T) {
	startErr := errors.New("task start failed")
	stopErr := errors.New("task stop failed")
	waitErr := errors.New("task wait failed")
	runtimeStopErr := errors.New("runtime stop failed")
	runtimeJoinErr := errors.New("runtime join failed")
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&recordingTask{name: "first", events: &events, waitErr: waitErr})
	tasks.Add(&recordingTask{name: "second", events: &events, startErr: startErr, stopErr: stopErr})
	tasks.Add(&recordingTask{name: "not-started", events: &events})

	err := tasks.Start(RuntimeShutdown{
		Stop: func() error {
			events = append(events, "runtime-stop")
			return runtimeStopErr
		},
		Join: func() error {
			events = append(events, "runtime-join")
			return runtimeJoinErr
		},
	})

	for _, want := range []error{startErr, stopErr, waitErr, runtimeStopErr, runtimeJoinErr} {
		if !errors.Is(err, want) {
			t.Fatalf("Start() error = %v, want joined %v", err, want)
		}
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

func TestTasksRollbackWaitsForTaskWaitersBeforeJoiningRuntime(t *testing.T) {
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&recordingTask{name: "first", events: &events})
	tasks.Add(&recordingTask{name: "second", events: &events})

	err := tasks.Rollback(RuntimeShutdown{
		Stop: func() error { events = append(events, "runtime-stop"); return nil },
		Join: func() error { events = append(events, "runtime-join"); return nil },
	})
	if err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	want := []string{
		"stop:second", "stop:first", "runtime-stop",
		"wait:second", "wait:first", "runtime-join",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestTasksCloseWaitsForTasksBeforeJoiningRuntime(t *testing.T) {
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&recordingTask{name: "first", events: &events})
	tasks.Add(&recordingTask{name: "second", events: &events})

	err := tasks.Close(RuntimeShutdown{
		Stop: func() error { events = append(events, "runtime-stop"); return nil },
		Join: func() error { events = append(events, "runtime-join"); return nil },
	})
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	want := []string{
		"stop:second", "stop:first", "runtime-stop",
		"wait:second", "wait:first", "runtime-join",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestTasksUseCloseWhenTaskHasNoStopOrWait(t *testing.T) {
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&closeOnlyTask{events: &events})

	if err := tasks.Close(RuntimeShutdown{}); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if want := []string{"close:fallback"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

type contextMarkerKey struct{}

type contextAwareTask struct {
	events *[]string
}

func (t *contextAwareTask) Start() error {
	*t.events = append(*t.events, "legacy-start")
	return errors.New("legacy Start called")
}

func (t *contextAwareTask) Close() error {
	*t.events = append(*t.events, "legacy-close")
	return errors.New("legacy Close called")
}

func (t *contextAwareTask) StartContext(ctx context.Context) error {
	if got := ctx.Value(contextMarkerKey{}); got != "marker" {
		return errors.New("start context marker missing")
	}
	*t.events = append(*t.events, "context-start")
	return nil
}

func (t *contextAwareTask) StopContext(ctx context.Context) error {
	if got := ctx.Value(contextMarkerKey{}); got != "marker" {
		return errors.New("stop context marker missing")
	}
	*t.events = append(*t.events, "context-stop")
	return nil
}

func (t *contextAwareTask) WaitContext(ctx context.Context) error {
	if got := ctx.Value(contextMarkerKey{}); got != "marker" {
		return errors.New("wait context marker missing")
	}
	*t.events = append(*t.events, "context-wait")
	return nil
}

func TestTasksPropagateContextToLifecycleCallbacks(t *testing.T) {
	events := []string{}
	tasks := NewTasks()
	tasks.Add(&contextAwareTask{events: &events})
	ctx := context.WithValue(context.Background(), contextMarkerKey{}, "marker")
	host := NewRuntimeHost(tasks, RuntimeHostCallbacks{
		Start: func(ctx context.Context) error {
			if got := ctx.Value(contextMarkerKey{}); got != "marker" {
				return errors.New("runtime start context marker missing")
			}
			events = append(events, "runtime-context-start")
			return nil
		},
		Stop: func(ctx context.Context) error {
			if got := ctx.Value(contextMarkerKey{}); got != "marker" {
				return errors.New("runtime stop context marker missing")
			}
			events = append(events, "runtime-context-stop")
			return nil
		},
		Join: func(ctx context.Context) error {
			if got := ctx.Value(contextMarkerKey{}); got != "marker" {
				return errors.New("runtime join context marker missing")
			}
			events = append(events, "runtime-context-join")
			return nil
		},
	})

	if err := host.StartContext(ctx); err != nil {
		t.Fatalf("StartContext() error = %v", err)
	}
	if err := host.StopProducersContext(ctx); err != nil {
		t.Fatalf("StopProducersContext() error = %v", err)
	}
	if err := host.CloseStoppedContext(ctx); err != nil {
		t.Fatalf("CloseStoppedContext() error = %v", err)
	}

	want := []string{
		"runtime-context-start", "context-start", "context-stop",
		"runtime-context-stop", "context-wait", "runtime-context-join",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}
