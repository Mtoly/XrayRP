package tuic

import (
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	xcommon "github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/service/internal/specialruntime"
)

type stagedPeriodicTask struct {
	tag        string
	events     *lifecycleEvents
	startBlock <-chan struct{}
	startErr   error
	stopErr    error
	waitErr    error
}

func (t *stagedPeriodicTask) Start() error {
	if t.events != nil {
		t.events.add("task-start:" + t.tag)
	}
	if t.startBlock != nil {
		<-t.startBlock
	}
	return t.startErr
}
func (t *stagedPeriodicTask) Stop() error {
	if t.events != nil {
		t.events.add("task-stop:" + t.tag)
	}
	return t.stopErr
}
func (t *stagedPeriodicTask) Wait() error {
	if t.events != nil {
		t.events.add("task-wait:" + t.tag)
	}
	return t.waitErr
}
func (t *stagedPeriodicTask) Close() error { return errors.Join(t.Stop(), t.Wait()) }

type recordingManagedPeriodic struct {
	tag    string
	events *lifecycleEvents
	task   *xcommon.ManagedPeriodic
}

func (t *recordingManagedPeriodic) Start() error { return t.task.Start() }
func (t *recordingManagedPeriodic) Stop() error {
	t.events.add("task-stop:" + t.tag)
	return t.task.Stop()
}
func (t *recordingManagedPeriodic) Wait() error {
	t.events.add("task-wait:" + t.tag)
	return t.task.Wait()
}
func (t *recordingManagedPeriodic) Close() error { return errors.Join(t.Stop(), t.Wait()) }

func newServiceTasks(tasks ...lifecycleTask) *specialruntime.Tasks {
	group := specialruntime.NewTasks()
	for _, task := range tasks {
		group.Add(task)
	}
	return group
}

func TestCloseBeforeStartAndCloseTwiceAreNoOps(t *testing.T) {
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeInstance{events: events})

	if err := service.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if got := events.snapshot(); len(got) != 0 {
		t.Fatalf("events = %v, want no startup or cleanup work", got)
	}
}

func TestCloseAfterStartIsSequentiallyIdempotent(t *testing.T) {
	events := &lifecycleEvents{}
	service := newStartTestService(events, &fakeRuntimeInstance{events: events})
	if err := service.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	first := events.snapshot()
	if err := service.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, first) {
		t.Fatalf("second Close() events = %v, want unchanged %v", got, first)
	}
}

func TestCloseWaitsForRunningPeriodicCallback(t *testing.T) {
	events := &lifecycleEvents{}
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	var calls atomic.Int32
	var startedOnce atomic.Bool
	task := defaultTaskFactory("blocking", time.Millisecond, func() error {
		if calls.Add(1) == 1 {
			return nil
		}
		if startedOnce.CompareAndSwap(false, true) {
			close(callbackStarted)
		}
		<-releaseCallback
		events.add("task-exit")
		return nil
	})
	if err := task.Start(); err != nil {
		t.Fatalf("task Start() error = %v", err)
	}
	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("periodic callback did not start")
	}

	service := &TuicService{
		state:        stateRunning,
		box:          &fakeRuntimeInstance{events: events},
		closeRuntime: defaultCloseRuntime,
		tasks:        newServiceTasks(task),
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- service.Close() }()

	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before callback exit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"stop", "close"}) {
		t.Fatalf("events before callback release = %v, want runtime closed before wait", got)
	}
	close(releaseCallback)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestCloseJoinsTaskAndRuntimeErrors(t *testing.T) {
	stopErr := errors.New("task stop failed")
	waitErr := errors.New("task wait failed")
	runtimeErr := errors.New("runtime close failed")
	events := &lifecycleEvents{}
	service := &TuicService{
		state:        stateRunning,
		box:          &fakeRuntimeInstance{events: events, closeErr: runtimeErr},
		closeRuntime: defaultCloseRuntime,
		tasks: newServiceTasks(&stagedPeriodicTask{
			tag: "failing", events: events, stopErr: stopErr, waitErr: waitErr,
		}),
	}

	err := service.Close()
	if !errors.Is(err, stopErr) || !errors.Is(err, waitErr) || !errors.Is(err, runtimeErr) {
		t.Fatalf("Close() error = %v, want task stop, task wait, and runtime close errors", err)
	}
}

func TestStartTaskFailureStopsTasksClosesRuntimeThenWaits(t *testing.T) {
	taskStartErr := errors.New("task start failed")
	taskStopErr := errors.New("task stop failed")
	taskWaitErr := errors.New("task wait failed")
	callbackErr := errors.New("callback failed")
	runtimeCloseErr := errors.New("runtime close failed")
	events := &lifecycleEvents{}
	runtimeClosed := make(chan struct{})
	callbackStarted := make(chan struct{})
	defer func() {
		select {
		case <-runtimeClosed:
		default:
			close(runtimeClosed)
		}
	}()
	service := newStartTestService(events, &fakeRuntimeInstance{events: events})
	service.closeRuntime = func(runtimeInstance) error {
		events.add("runtime-close")
		select {
		case <-runtimeClosed:
		default:
			close(runtimeClosed)
		}
		return runtimeCloseErr
	}
	created := 0
	calls := 0
	service.taskFactory = func(tag string, _ time.Duration, _ func() error) lifecycleTask {
		created++
		if created == 1 {
			managed := &xcommon.ManagedPeriodic{
				Interval: time.Nanosecond,
				Execute: func() error {
					calls++
					if calls == 1 {
						events.add("callback-initial")
						return nil
					}
					events.add("callback-start")
					close(callbackStarted)
					<-runtimeClosed
					events.add("callback-exit")
					return callbackErr
				},
			}
			return &recordingManagedPeriodic{tag: tag, events: events, task: managed}
		}
		return &stagedPeriodicTask{
			tag: tag, events: events, startBlock: callbackStarted,
			startErr: taskStartErr, stopErr: taskStopErr, waitErr: taskWaitErr,
		}
	}

	startDone := make(chan error, 1)
	go func() { startDone <- service.Start() }()
	var err error
	select {
	case err = <-startDone:
	case <-time.After(time.Second):
		t.Fatal("Start() did not complete after task startup failure")
	}
	for _, wantErr := range []error{taskStartErr, taskStopErr, taskWaitErr, callbackErr, runtimeCloseErr} {
		if !errors.Is(err, wantErr) {
			t.Fatalf("Start() error = %v, want joined %v", err, wantErr)
		}
	}

	got := events.snapshot()
	index := func(event string) int {
		for i, gotEvent := range got {
			if gotEvent == event {
				return i
			}
		}
		return -1
	}
	ordered := []string{
		"task-stop:node monitor",
		"task-stop:Tuic_127.0.0.1_8443_8",
		"runtime-close",
		"task-wait:node monitor",
		"task-wait:Tuic_127.0.0.1_8443_8",
	}
	for i := 1; i < len(ordered); i++ {
		if index(ordered[i-1]) < 0 || index(ordered[i-1]) >= index(ordered[i]) {
			t.Fatalf("events = %v, want ordered phases %v", got, ordered)
		}
	}
	if index("runtime-close") >= index("callback-exit") {
		t.Fatalf("events = %v, want runtime close before callback exit", got)
	}
}
