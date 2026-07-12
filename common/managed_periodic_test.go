package common

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagedPeriodicStartWaitsForFirstExecute(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	task := &ManagedPeriodic{
		Interval: time.Hour,
		Execute: func() error {
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
	task := &ManagedPeriodic{Interval: time.Hour, Execute: func() error { return wantErr }}
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
	task := &ManagedPeriodic{
		Interval: time.Hour,
		Execute: func() error {
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
	task := &ManagedPeriodic{
		Interval: time.Millisecond,
		Execute: func() error {
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

func TestManagedPeriodicCloseReturnsLaterExecuteError(t *testing.T) {
	wantErr := errors.New("later execute failed")
	secondCall := make(chan struct{})
	var calls atomic.Int32
	task := &ManagedPeriodic{
		Interval: time.Millisecond,
		Execute: func() error {
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

func TestManagedPeriodicSchedulesNextIntervalAfterCallbackCompletes(t *testing.T) {
	firstTimer := newManualManagedPeriodicTimer()
	secondTimer := newManualManagedPeriodicTimer()
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	var calls atomic.Int32
	var timersMu sync.Mutex
	timers := []*manualManagedPeriodicTimer{firstTimer, secondTimer}
	task := &ManagedPeriodic{
		Interval: time.Hour,
		Execute: func() error {
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
	task := &ManagedPeriodic{
		Interval: time.Millisecond,
		Execute: func() error {
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
	task := &ManagedPeriodic{
		Interval: time.Millisecond,
		Execute: func() error {
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
	task := &ManagedPeriodic{
		Interval: time.Hour,
		Execute: func() error {
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
	task := &ManagedPeriodic{Interval: time.Hour, Execute: func() error { return nil }}
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
