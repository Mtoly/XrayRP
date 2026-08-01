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

func TestManagedPeriodicStartWaitsForFirstExecute(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	task := &managedPeriodic{
		interval: time.Hour,
		execute: func() error {
			close(started)
			<-release
			return nil
		},
	}
	startDone := make(chan error, 1)
	go func() { startDone <- task.Start() }()
	<-started
	select {
	case err := <-startDone:
		t.Fatalf("Start() returned before first Execute completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-startDone; err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := task.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestManagedPeriodicPropagatesImmediateExecuteError(t *testing.T) {
	wantErr := errors.New("execute failed")
	task := &managedPeriodic{interval: time.Hour, execute: func() error { return wantErr }}
	if err := task.Start(); !errors.Is(err, wantErr) {
		t.Fatalf("Start() error = %v, want %v", err, wantErr)
	}
	if err := task.Close(); err != nil {
		t.Fatalf("Close() after failed Start error = %v", err)
	}
}

func TestManagedPeriodicFailedStartCanBeClosedWhileExecuteReturns(t *testing.T) {
	wantErr := errors.New("execute failed")
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	task := &managedPeriodic{
		interval: time.Hour,
		execute: func() error {
			close(callbackStarted)
			<-releaseCallback
			return wantErr
		},
	}
	startDone := make(chan error, 1)
	go func() { startDone <- task.Start() }()
	<-callbackStarted
	stopDone := make(chan error, 1)
	go func() { stopDone <- task.Stop() }()
	if err := <-stopDone; err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- task.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before failed Start completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseCallback)
	if err := <-startDone; !errors.Is(err, wantErr) {
		t.Fatalf("Start() error = %v, want %v", err, wantErr)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestManagedPeriodicCloseWaitsForCallback(t *testing.T) {
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	var calls atomic.Int32
	var signaled atomic.Bool
	task := &managedPeriodic{
		interval: time.Millisecond,
		execute: func() error {
			if calls.Add(1) == 1 {
				return nil
			}
			if signaled.CompareAndSwap(false, true) {
				close(callbackStarted)
			}
			<-releaseCallback
			return nil
		},
	}
	if err := task.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	<-callbackStarted
	closeDone := make(chan error, 1)
	go func() { closeDone <- task.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before callback: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseCallback)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestManagedPeriodicCloseCancelsCallbackContextAndJoinsIt(t *testing.T) {
	timer := newManualManagedPeriodicTimer()
	callbackEntered := make(chan struct{})
	callbackCanceled := make(chan struct{})
	var calls atomic.Int32
	task := NewPeriodicContext(time.Hour, func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			return nil
		}
		close(callbackEntered)
		<-ctx.Done()
		close(callbackCanceled)
		return ctx.Err()
	})
	task.newTimer = func(time.Duration) managedPeriodicTimer { return timer }

	if err := task.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	timer.waitObserved(t)
	timer.fire()
	<-callbackEntered

	closeDone := make(chan error, 1)
	go func() { closeDone <- task.CloseContext(context.Background()) }()
	<-callbackCanceled
	if err := <-closeDone; err != nil {
		t.Fatalf("CloseContext() error = %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("callback calls = %d, want initial and one periodic callback", got)
	}
}

func TestManagedPeriodicCapsEveryCallbackWithSyncDeadline(t *testing.T) {
	timer := newManualManagedPeriodicTimer()
	deadlines := make(chan time.Duration, 2)
	task := NewPeriodicContext(time.Hour, func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("periodic callback did not receive a deadline")
		}
		deadlines <- time.Until(deadline)
		return nil
	})
	task.newTimer = func(time.Duration) managedPeriodicTimer { return timer }

	parent, cancelParent := context.WithTimeout(context.Background(), time.Hour)
	defer cancelParent()
	if err := task.StartContext(parent); err != nil {
		t.Fatalf("StartContext() error = %v", err)
	}
	assertSyncDeadline(t, <-deadlines)

	timer.waitObserved(t)
	timer.fire()
	assertSyncDeadline(t, <-deadlines)
	if err := task.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func assertSyncDeadline(t *testing.T, remaining time.Duration) {
	t.Helper()
	if remaining <= 0 || remaining > service.DefaultSyncTimeout+time.Second {
		t.Fatalf("callback deadline remaining = %s, want sync timeout cap", remaining)
	}
}

func TestManagedPeriodicCloseReturnsLaterExecuteError(t *testing.T) {
	wantErr := errors.New("later execute failed")
	secondCall := make(chan struct{})
	var calls atomic.Int32
	task := &managedPeriodic{
		interval: time.Millisecond,
		execute: func() error {
			if calls.Add(1) == 1 {
				return nil
			}
			close(secondCall)
			return wantErr
		},
	}
	if err := task.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	<-secondCall
	if err := task.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("Close() error = %v, want %v", err, wantErr)
	}
}

func TestManagedPeriodicRetriesAfterLaterExecuteError(t *testing.T) {
	wantErr := errors.New("later execute failed")
	firstTimer := newManualManagedPeriodicTimer()
	secondTimer := newManualManagedPeriodicTimer()
	thirdTimer := newManualManagedPeriodicTimer()
	thirdCall := make(chan struct{})
	var calls atomic.Int32
	var timersMu sync.Mutex
	timers := []*manualManagedPeriodicTimer{firstTimer, secondTimer, thirdTimer}
	task := &managedPeriodic{
		interval: time.Hour,
		execute: func() error {
			switch calls.Add(1) {
			case 1:
				return nil
			case 2:
				return wantErr
			case 3:
				close(thirdCall)
				return nil
			default:
				t.Fatal("unexpected extra callback")
				return nil
			}
		},
		newTimer: func(time.Duration) managedPeriodicTimer {
			timersMu.Lock()
			defer timersMu.Unlock()
			if len(timers) == 0 {
				t.Fatal("unexpected extra timer")
			}
			timer := timers[0]
			timers = timers[1:]
			return timer
		},
	}

	if err := task.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	firstTimer.waitObserved(t)
	firstTimer.fire()
	secondTimer.waitObserved(t)
	secondTimer.fire()
	select {
	case <-thirdCall:
	case <-time.After(time.Second):
		t.Fatal("callback was not retried after a later error")
	}
	thirdTimer.waitObserved(t)
	if err := task.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("Close() error = %v, want %v", err, wantErr)
	}
}

func TestManagedPeriodicSchedulesNextIntervalAfterCallbackCompletes(t *testing.T) {
	firstTimer := newManualManagedPeriodicTimer()
	secondTimer := newManualManagedPeriodicTimer()
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	var calls atomic.Int32
	var timersMu sync.Mutex
	timers := []*manualManagedPeriodicTimer{firstTimer, secondTimer}
	task := &managedPeriodic{
		interval: time.Hour,
		execute: func() error {
			if calls.Add(1) == 2 {
				close(callbackStarted)
				<-releaseCallback
			}
			return nil
		},
		newTimer: func(time.Duration) managedPeriodicTimer {
			timersMu.Lock()
			defer timersMu.Unlock()
			if len(timers) == 0 {
				t.Fatal("unexpected extra timer")
			}
			timer := timers[0]
			timers = timers[1:]
			return timer
		},
	}
	if err := task.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	firstTimer.waitObserved(t)
	firstTimer.fire()
	<-callbackStarted
	select {
	case <-secondTimer.observed:
		t.Fatal("next interval started before the previous callback completed")
	default:
	}
	close(releaseCallback)
	secondTimer.waitObserved(t)
	if err := task.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestManagedPeriodicDoesNotRestartUntilStoppedCallbackCompletes(t *testing.T) {
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	var calls atomic.Int32
	task := &managedPeriodic{
		interval: time.Millisecond,
		execute: func() error {
			if calls.Add(1) == 2 {
				close(callbackStarted)
				<-releaseCallback
			}
			return nil
		},
	}
	if err := task.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	<-callbackStarted
	if err := task.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if err := task.Start(); err != nil {
		t.Fatalf("second Start() error = %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("callback calls before prior lifecycle completed = %d, want 2", got)
	}
	close(releaseCallback)
	if err := task.Wait(); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
}

func TestManagedPeriodicStopAndWaitAreSequentiallyIdempotent(t *testing.T) {
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	var calls atomic.Int32
	task := &managedPeriodic{
		interval: time.Millisecond,
		execute: func() error {
			if calls.Add(1) == 1 {
				return nil
			}
			close(callbackStarted)
			<-releaseCallback
			return nil
		},
	}
	if err := task.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	<-callbackStarted
	if err := task.Stop(); err != nil {
		t.Fatalf("first Stop() error = %v", err)
	}
	if err := task.Stop(); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- task.Wait() }()
	select {
	case err := <-waitDone:
		t.Fatalf("Wait() returned before callback completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseCallback)
	if err := <-waitDone; err != nil {
		t.Fatalf("first Wait() error = %v", err)
	}
	if err := task.Wait(); err != nil {
		t.Fatalf("second Wait() error = %v", err)
	}
}

func TestManagedPeriodicRegistersRunningCallbackBeforeStopReturns(t *testing.T) {
	timer := newManualManagedPeriodicTimer()
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	var calls atomic.Int32
	task := &managedPeriodic{
		interval: time.Hour,
		execute: func() error {
			if calls.Add(1) == 2 {
				close(callbackStarted)
				<-releaseCallback
			}
			return nil
		},
		newTimer: func(time.Duration) managedPeriodicTimer { return timer },
	}
	if err := task.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	timer.waitObserved(t)
	timer.fire()
	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		close(releaseCallback)
		_ = task.Close()
		t.Fatal("periodic callback did not start")
	}

	task.mu.Lock()
	active := task.active
	task.mu.Unlock()
	if active != 1 {
		close(releaseCallback)
		_ = task.Close()
		t.Fatalf("active callbacks = %d, want 1 while callback runs", active)
	}
	if err := task.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	close(releaseCallback)
	if err := task.Wait(); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
}

func TestManagedPeriodicRejectsSecondStartAfterTerminal(t *testing.T) {
	task := &managedPeriodic{interval: time.Hour, execute: func() error { return nil }}
	if err := task.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	if err := task.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := task.Start(); err == nil {
		t.Fatal("second Start() error = nil, want single-use rejection")
	}
}

type manualManagedPeriodicTimer struct {
	ch       chan time.Time
	observed chan struct{}
	once     sync.Once
}

func newManualManagedPeriodicTimer() *manualManagedPeriodicTimer {
	return &manualManagedPeriodicTimer{
		ch:       make(chan time.Time, 1),
		observed: make(chan struct{}),
	}
}

func (t *manualManagedPeriodicTimer) C() <-chan time.Time {
	t.once.Do(func() { close(t.observed) })
	return t.ch
}

func (t *manualManagedPeriodicTimer) Stop() bool {
	return true
}

func (t *manualManagedPeriodicTimer) fire() {
	t.ch <- time.Now()
}

func (t *manualManagedPeriodicTimer) waitObserved(testingT *testing.T) {
	testingT.Helper()
	select {
	case <-t.observed:
	case <-time.After(time.Second):
		testingT.Fatal("timer was not observed")
	}
}
