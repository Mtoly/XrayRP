package specialruntime

import (
	"errors"
	"reflect"
	"testing"
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
		"runtime-stop", "runtime-join",
		"wait:second", "wait:first",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
}

func TestTasksRollbackJoinsRuntimeBeforeTaskWaiters(t *testing.T) {
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
		"stop:second", "stop:first", "runtime-stop", "runtime-join",
		"wait:second", "wait:first",
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
