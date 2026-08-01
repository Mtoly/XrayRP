package controller

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/sirupsen/logrus"
)

type recordingPeriodic struct {
	interval time.Duration
	execute  func() error
	started  int
	closed   int
	closeErr error
}

func (p *recordingPeriodic) Start() error {
	p.started++
	return nil
}

func (p *recordingPeriodic) Close() error {
	p.closed++
	return p.closeErr
}

type atomicCloseCountingPeriodic struct {
	closeCalls atomic.Int32
}

func (*atomicCloseCountingPeriodic) Start() error {
	return nil
}

func (p *atomicCloseCountingPeriodic) Close() error {
	p.closeCalls.Add(1)
	return nil
}

type failingPeriodic struct {
	err error
}

func (p failingPeriodic) Start() error {
	return p.err
}

func (p failingPeriodic) Close() error {
	return nil
}

type asyncFailingPeriodic struct {
	failingPeriodic
}

func (*asyncFailingPeriodic) startAsynchronously() {}

type joiningPeriodic struct {
	closeEntered chan struct{}
	releaseClose chan struct{}
}

func (*joiningPeriodic) Start() error {
	return nil
}

func (p *joiningPeriodic) Close() error {
	close(p.closeEntered)
	<-p.releaseClose
	return nil
}

type closeSignalingPeriodic struct {
	closed chan struct{}
}

func (*closeSignalingPeriodic) Start() error {
	return nil
}

func (p *closeSignalingPeriodic) Close() error {
	close(p.closed)
	return nil
}

type blockingStopPeriodic struct {
	stopEntered chan struct{}
	releaseStop chan struct{}
	waitErr     error
}

func (*blockingStopPeriodic) Start() error {
	return nil
}

func (p *blockingStopPeriodic) Stop() error {
	close(p.stopEntered)
	<-p.releaseStop
	return nil
}

func (p *blockingStopPeriodic) Wait() error {
	return p.waitErr
}

func (p *blockingStopPeriodic) Close() error {
	return errors.Join(p.Stop(), p.Wait())
}

type callbackJoiningPeriodic struct {
	stopEntered      chan struct{}
	releaseStop      chan struct{}
	waitEntered      chan struct{}
	callbackReturned <-chan struct{}
	forceWaitReturn  <-chan struct{}
	stopOnce         sync.Once
	waitOnce         sync.Once
}

func (*callbackJoiningPeriodic) Start() error {
	return nil
}

func (p *callbackJoiningPeriodic) Stop() error {
	p.stopOnce.Do(func() {
		close(p.stopEntered)
	})
	<-p.releaseStop
	return nil
}

func (p *callbackJoiningPeriodic) Wait() error {
	p.waitOnce.Do(func() {
		close(p.waitEntered)
	})
	select {
	case <-p.callbackReturned:
	case <-p.forceWaitReturn:
	}
	return nil
}

func (p *callbackJoiningPeriodic) Close() error {
	return errors.Join(p.Stop(), p.Wait())
}

type selfReplacingPeriodic struct {
	stopEntered  chan struct{}
	waitEntered  chan struct{}
	waitReturned chan struct{}
	closeEntered chan struct{}
	releaseWait  chan struct{}
	stopOnce     sync.Once
	waitOnce     sync.Once
	returnOnce   sync.Once
	closeOnce    sync.Once
}

func (*selfReplacingPeriodic) Start() error {
	return nil
}

func (p *selfReplacingPeriodic) Stop() error {
	p.stopOnce.Do(func() {
		close(p.stopEntered)
	})
	return nil
}

func (p *selfReplacingPeriodic) Wait() error {
	p.waitOnce.Do(func() {
		close(p.waitEntered)
	})
	<-p.releaseWait
	if p.waitReturned != nil {
		p.returnOnce.Do(func() {
			close(p.waitReturned)
		})
	}
	return nil
}

func (p *selfReplacingPeriodic) Close() error {
	p.closeOnce.Do(func() {
		close(p.closeEntered)
	})
	<-p.releaseWait
	return nil
}

type startNotifyingPeriodic struct {
	started chan struct{}
	closed  chan struct{}
}

func (p *startNotifyingPeriodic) Start() error {
	close(p.started)
	return nil
}

func (p *startNotifyingPeriodic) Close() error {
	close(p.closed)
	return nil
}

type causallyGatedStartPeriodic struct {
	allowed            <-chan struct{}
	started            chan struct{}
	closed             chan struct{}
	startedBeforeAllow bool
}

func (p *causallyGatedStartPeriodic) Start() error {
	select {
	case <-p.allowed:
	default:
		p.startedBeforeAllow = true
	}
	close(p.started)
	return nil
}

func (p *causallyGatedStartPeriodic) Close() error {
	close(p.closed)
	return nil
}

type closeReleasesFailingStartPeriodic struct {
	startEntered chan struct{}
	closed       chan struct{}
	startErr     error
	closeOnce    sync.Once
}

func (*closeReleasesFailingStartPeriodic) startAsynchronously() {}

func (p *closeReleasesFailingStartPeriodic) Start() error {
	close(p.startEntered)
	<-p.closed
	return p.startErr
}

func (p *closeReleasesFailingStartPeriodic) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
	})
	return nil
}

type startWindowPeriodicRunner struct {
	startEntered chan struct{}
	releaseStart chan struct{}
}

func (p *startWindowPeriodicRunner) Start() error {
	close(p.startEntered)
	<-p.releaseStart
	return nil
}

func (*startWindowPeriodicRunner) Stop() error {
	return nil
}

func (*startWindowPeriodicRunner) Wait() error {
	return nil
}

func (*startWindowPeriodicRunner) Close() error {
	return nil
}

type asynchronouslyStartedPeriodic struct {
	*startWindowPeriodicRunner
}

func (*asynchronouslyStartedPeriodic) startAsynchronously() {}

type registryReenteringJoinablePeriodic struct {
	controller *Controller
	reentered  bool
}

func (*registryReenteringJoinablePeriodic) Start() error {
	return nil
}

func (p *registryReenteringJoinablePeriodic) Stop() error {
	if !p.controller.periodicMu.TryLock() {
		return errors.New("periodic registry lock held while stopping replacement")
	}
	p.controller.periodicMu.Unlock()
	p.reentered = true
	return p.controller.startOrReplacePeriodicTask(
		periodicTaskUserMonitor,
		3*time.Hour,
		func() error { return nil },
	)
}

func (*registryReenteringJoinablePeriodic) Wait() error {
	return nil
}

func (p *registryReenteringJoinablePeriodic) Close() error {
	return errors.Join(p.Stop(), p.Wait())
}

type registryReenteringClosePeriodic struct {
	controller *Controller
	reentered  bool
}

func (*registryReenteringClosePeriodic) Start() error {
	return nil
}

func (p *registryReenteringClosePeriodic) Close() error {
	if !p.controller.periodicMu.TryLock() {
		return errors.New("periodic registry lock held while closing replacement")
	}
	p.controller.periodicMu.Unlock()
	p.reentered = true
	return p.controller.startOrReplacePeriodicTask(
		periodicTaskUserMonitor,
		3*time.Hour,
		func() error { return nil },
	)
}

type periodicRegistryReenteringLogHook struct {
	controller *Controller
	result     chan<- error
	once       sync.Once
}

func (*periodicRegistryReenteringLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *periodicRegistryReenteringLogHook) Fire(*logrus.Entry) error {
	h.once.Do(func() {
		if !h.controller.periodicMu.TryLock() {
			h.result <- errors.New("periodic registry lock held while logging task publication")
			return
		}
		h.controller.periodicMu.Unlock()
		h.result <- h.controller.startOrReplacePeriodicTask(
			periodicTaskUserMonitor,
			3*time.Hour,
			func() error { return nil },
		)
	})
	return nil
}

type periodicClosingLogHook struct {
	controller *Controller
	entered    chan<- struct{}
	levels     []logrus.Level
	result     chan<- error
	once       sync.Once
}

func (h *periodicClosingLogHook) Levels() []logrus.Level {
	if len(h.levels) > 0 {
		return h.levels
	}
	return logrus.AllLevels
}

func (h *periodicClosingLogHook) Fire(*logrus.Entry) error {
	h.once.Do(func() {
		if h.entered != nil {
			close(h.entered)
		}
		h.result <- h.controller.closePeriodicTasks()
	})
	return nil
}

func TestNewControllerPeriodicTaskOwnsRunningCallbacks(t *testing.T) {
	periodic := newControllerPeriodicTask(time.Hour, func() error { return nil })
	if _, ok := periodic.(interface {
		Stop() error
		Wait() error
		Close() error
	}); !ok {
		t.Fatalf("default controller periodic task %T cannot stop and join running callbacks", periodic)
	}
}

func TestControllerPeriodicPublicationLoggerCanReenterRegistry(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	controller := &Controller{
		tasks: []periodicTask{{
			tag:      periodicTaskUserMonitor,
			interval: 3 * time.Hour,
			Periodic: &recordingPeriodic{},
		}},
		newPeriodicTask: func(time.Duration, func() error) periodicRunner {
			return &recordingPeriodic{}
		},
	}
	hookResult := make(chan error, 1)
	logger.AddHook(&periodicRegistryReenteringLogHook{
		controller: controller,
		result:     hookResult,
	})
	controller.logger = logrus.NewEntry(logger)

	if err := controller.startOrReplacePeriodicTask(
		periodicTaskNodeMonitor,
		time.Hour,
		func() error { return nil },
	); err != nil {
		t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
	}
	if err := <-hookResult; err != nil {
		t.Fatalf("periodic publication logger reentry failed: %v", err)
	}
	if err := controller.closePeriodicTasks(); err != nil {
		t.Fatalf("closePeriodicTasks() error = %v", err)
	}
}

func TestControllerPeriodicPublicationLoggerCanCloseController(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	controller := &Controller{
		newPeriodicTask: func(time.Duration, func() error) periodicRunner {
			return &recordingPeriodic{}
		},
	}
	hookResult := make(chan error, 1)
	logger.AddHook(&periodicClosingLogHook{
		controller: controller,
		result:     hookResult,
	})
	controller.logger = logrus.NewEntry(logger)

	if err := controller.startOrReplacePeriodicTask(
		periodicTaskNodeMonitor,
		time.Hour,
		func() error { return nil },
	); err != nil {
		t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
	}
	if err := <-hookResult; err != nil {
		t.Fatalf("periodic publication logger close failed: %v", err)
	}
}

func TestControllerAsyncPeriodicPublicationLoggerCanCloseController(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	runner := &asynchronouslyStartedPeriodic{
		startWindowPeriodicRunner: &startWindowPeriodicRunner{
			startEntered: make(chan struct{}),
			releaseStart: make(chan struct{}),
		},
	}
	controller := &Controller{
		newPeriodicTask: func(time.Duration, func() error) periodicRunner {
			return runner
		},
	}
	hookResult := make(chan error, 1)
	logger.AddHook(&periodicClosingLogHook{
		controller: controller,
		levels:     []logrus.Level{logrus.InfoLevel},
		result:     hookResult,
	})
	controller.logger = logrus.NewEntry(logger)

	if err := controller.startOrReplacePeriodicTask(
		periodicTaskNodeMonitor,
		time.Hour,
		func() error { return nil },
	); err != nil {
		t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
	}
	<-runner.startEntered
	close(runner.releaseStart)
	if err := <-hookResult; err != nil {
		t.Fatalf("asynchronous periodic publication logger close failed: %v", err)
	}
}

func TestControllerPeriodicSelfReplacementLoggerCanCloseController(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		callbackReturned := make(chan struct{})
		forceWaitReturn := make(chan struct{})
		releaseStop := make(chan struct{})
		close(releaseStop)
		old := &callbackJoiningPeriodic{
			stopEntered:      make(chan struct{}),
			releaseStop:      releaseStop,
			waitEntered:      make(chan struct{}),
			callbackReturned: callbackReturned,
			forceWaitReturn:  forceWaitReturn,
		}
		controller := &Controller{
			tasks: []periodicTask{{
				tag:      periodicTaskNodeMonitor,
				interval: time.Hour,
				Periodic: old,
			}},
			newPeriodicTask: func(time.Duration, func() error) periodicRunner {
				return &recordingPeriodic{}
			},
		}

		logger := logrus.New()
		logger.SetOutput(&bytes.Buffer{})
		hookEntered := make(chan struct{})
		hookResult := make(chan error, 1)
		logger.AddHook(&periodicClosingLogHook{
			controller: controller,
			entered:    hookEntered,
			result:     hookResult,
		})
		controller.logger = logrus.NewEntry(logger)

		replacementReturned := make(chan error, 1)
		go func() {
			err := controller.startOrReplacePeriodicTask(
				periodicTaskNodeMonitor,
				2*time.Hour,
				func() error { return nil },
			)
			close(callbackReturned)
			replacementReturned <- err
		}()
		<-old.stopEntered
		<-old.waitEntered
		synctest.Wait()

		select {
		case err := <-replacementReturned:
			if err != nil {
				t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
			}
		default:
			select {
			case <-hookEntered:
			default:
				t.Fatal("periodic self-replacement stalled before publication logging")
			}
			close(forceWaitReturn)
			synctest.Wait()
			<-replacementReturned
			<-hookResult
			t.Fatal("periodic publication logger joined the callback performing the replacement")
		}

		<-hookEntered
		if err := <-hookResult; err != nil {
			t.Fatalf("periodic publication logger close failed: %v", err)
		}
	})
}

func TestControllerPeriodicStartFailureLoggerCanCloseController(t *testing.T) {
	startErr := errors.New("periodic start failed")
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	controller := &Controller{
		newPeriodicTask: func(time.Duration, func() error) periodicRunner {
			return &asyncFailingPeriodic{
				failingPeriodic: failingPeriodic{err: startErr},
			}
		},
	}
	hookResult := make(chan error, 1)
	logger.AddHook(&periodicClosingLogHook{
		controller: controller,
		levels:     []logrus.Level{logrus.WarnLevel},
		result:     hookResult,
	})
	controller.logger = logrus.NewEntry(logger)

	if err := controller.startOrReplacePeriodicTask(
		periodicTaskNodeMonitor,
		time.Hour,
		func() error { return nil },
	); err != nil {
		t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
	}
	if err := <-hookResult; !errors.Is(err, startErr) {
		t.Fatalf("periodic start failure logger close error = %v, want %v", err, startErr)
	}
}

func TestControllerPeriodicCloseFailureLoggerCanReenterClose(t *testing.T) {
	closeErr := errors.New("periodic close failed")
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	controller := &Controller{
		tasks: []periodicTask{{
			tag:      periodicTaskNodeMonitor,
			Periodic: &recordingPeriodic{closeErr: closeErr},
		}},
	}
	hookResult := make(chan error, 1)
	logger.AddHook(&periodicClosingLogHook{
		controller: controller,
		levels:     []logrus.Level{logrus.ErrorLevel},
		result:     hookResult,
	})
	controller.logger = logrus.NewEntry(logger)

	err := controller.closePeriodicTasks()
	if !errors.Is(err, closeErr) {
		t.Fatalf("closePeriodicTasks() error = %v, want %v", err, closeErr)
	}
	if reentrantErr := <-hookResult; !errors.Is(reentrantErr, closeErr) {
		t.Fatalf("reentrant closePeriodicTasks() error = %v, want %v", reentrantErr, closeErr)
	}
}

func TestControllerPeriodicReplacementStopCanReenterRegistry(t *testing.T) {
	controller := &Controller{
		newPeriodicTask: func(time.Duration, func() error) periodicRunner {
			return &recordingPeriodic{}
		},
	}
	old := &registryReenteringJoinablePeriodic{controller: controller}
	controller.tasks = []periodicTask{{
		tag:      periodicTaskNodeMonitor,
		interval: time.Hour,
		Periodic: old,
	}}

	if err := controller.startOrReplacePeriodicTask(
		periodicTaskNodeMonitor,
		2*time.Hour,
		func() error { return nil },
	); err != nil {
		t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
	}
	if !old.reentered {
		t.Fatal("periodic Stop did not reenter the registry")
	}
	if err := controller.closePeriodicTasks(); err != nil {
		t.Fatalf("closePeriodicTasks() error = %v", err)
	}
}

func TestControllerPeriodicReplacementCloseCanReenterRegistry(t *testing.T) {
	controller := &Controller{
		newPeriodicTask: func(time.Duration, func() error) periodicRunner {
			return &recordingPeriodic{}
		},
	}
	old := &registryReenteringClosePeriodic{controller: controller}
	controller.tasks = []periodicTask{{
		tag:      periodicTaskNodeMonitor,
		interval: time.Hour,
		Periodic: old,
	}}

	if err := controller.startOrReplacePeriodicTask(
		periodicTaskNodeMonitor,
		2*time.Hour,
		func() error { return nil },
	); err != nil {
		t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
	}
	if !old.reentered {
		t.Fatal("periodic Close did not reenter the registry")
	}
	if err := controller.closePeriodicTasks(); err != nil {
		t.Fatalf("closePeriodicTasks() error = %v", err)
	}
}

func TestControllerPeriodicReplacementPublishesWithoutRetainingStateLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		controller := &Controller{
			tasks: []periodicTask{{
				tag:      periodicTaskNodeMonitor,
				interval: time.Hour,
				Periodic: &recordingPeriodic{},
			}},
			newPeriodicTask: func(time.Duration, func() error) periodicRunner {
				return &recordingPeriodic{}
			},
		}

		replaceDone := make(chan error, 1)
		go func() {
			replaceDone <- controller.startOrReplacePeriodicTask(
				periodicTaskNodeMonitor,
				2*time.Hour,
				func() error { return nil },
			)
		}()
		synctest.Wait()

		if !controller.stateMu.TryLock() {
			// A mutex may be released by a different goroutine. Release the
			// retained lock so the buggy replacement can finish before failing.
			controller.stateMu.Unlock()
			err := <-replaceDone
			_ = controller.closePeriodicTasks()
			t.Fatalf("periodic replacement retained stateMu before publication: %v", err)
		}
		controller.stateMu.Unlock()
		if err := <-replaceDone; err != nil {
			t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
		}
		if err := controller.closePeriodicTasks(); err != nil {
			t.Fatalf("closePeriodicTasks() error = %v", err)
		}
	})
}

func TestControllerCloseJoinsReplacementBeforeCandidatePublication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		factoryEntered := make(chan struct{})
		releaseFactory := make(chan struct{})
		candidate := &startNotifyingPeriodic{
			started: make(chan struct{}),
			closed:  make(chan struct{}),
		}
		old := &atomicCloseCountingPeriodic{}
		controller := &Controller{
			tasks: []periodicTask{{
				tag:      periodicTaskNodeMonitor,
				interval: time.Hour,
				Periodic: old,
			}},
			newPeriodicTask: func(time.Duration, func() error) periodicRunner {
				close(factoryEntered)
				<-releaseFactory
				return candidate
			},
		}

		replaceDone := make(chan error, 1)
		go func() {
			replaceDone <- controller.startOrReplacePeriodicTask(
				periodicTaskNodeMonitor,
				2*time.Hour,
				func() error { return nil },
			)
		}()
		<-factoryEntered

		closeDone := make(chan error, 1)
		go func() {
			closeDone <- controller.closePeriodicTasks()
		}()
		synctest.Wait()
		select {
		case err := <-closeDone:
			t.Fatalf("closePeriodicTasks() returned before pending replacement cleanup: %v", err)
		default:
		}

		close(releaseFactory)
		if err := <-replaceDone; err != nil {
			t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
		}
		if err := <-closeDone; err != nil {
			t.Fatalf("closePeriodicTasks() error = %v", err)
		}
		select {
		case <-candidate.closed:
		default:
			t.Fatal("controller close did not clean the unpublished candidate")
		}
		select {
		case <-candidate.started:
			t.Fatal("unpublished candidate started after controller close")
		default:
		}
		if got := old.closeCalls.Load(); got != 1 {
			t.Fatalf("old periodic Close calls = %d, want one lifecycle owner", got)
		}
	})
}

func TestControllerCloseReportsPendingPeriodicReplacementCleanupErrors(t *testing.T) {
	oldWaitErr := errors.New("old periodic wait failed")
	candidateCloseErr := errors.New("candidate periodic close failed")
	old := &blockingStopPeriodic{
		stopEntered: make(chan struct{}),
		releaseStop: make(chan struct{}),
		waitErr:     oldWaitErr,
	}
	closeSignal := &closeSignalingPeriodic{closed: make(chan struct{})}
	candidate := &recordingPeriodic{closeErr: candidateCloseErr}
	controller := &Controller{
		tasks: []periodicTask{
			{
				tag:      periodicTaskNodeMonitor,
				interval: time.Hour,
				Periodic: old,
			},
			{
				tag:      periodicTaskUserMonitor,
				interval: time.Hour,
				Periodic: closeSignal,
			},
		},
		newPeriodicTask: func(time.Duration, func() error) periodicRunner {
			return candidate
		},
	}

	replaceDone := make(chan error, 1)
	go func() {
		replaceDone <- controller.startOrReplacePeriodicTask(
			periodicTaskNodeMonitor,
			2*time.Hour,
			func() error { return nil },
		)
	}()
	<-old.stopEntered

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- controller.closePeriodicTasks()
	}()
	<-closeSignal.closed
	close(old.releaseStop)

	replaceErr := <-replaceDone
	if !errors.Is(replaceErr, candidateCloseErr) {
		t.Fatalf("replacement error = %v, want candidate close %v", replaceErr, candidateCloseErr)
	}
	if errors.Is(replaceErr, oldWaitErr) {
		t.Fatalf("replacement synchronously joined the old callback: %v", replaceErr)
	}
	closeErr := <-closeDone
	if !errors.Is(closeErr, oldWaitErr) || !errors.Is(closeErr, candidateCloseErr) {
		t.Fatalf("close error = %v, want wait %v and candidate close %v", closeErr, oldWaitErr, candidateCloseErr)
	}
}

func TestControllerCloseDoesNotMakePeriodicCallbackJoinItself(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		callbackReturned := make(chan struct{})
		forceWaitReturn := make(chan struct{})
		old := &callbackJoiningPeriodic{
			stopEntered:      make(chan struct{}),
			releaseStop:      make(chan struct{}),
			waitEntered:      make(chan struct{}),
			callbackReturned: callbackReturned,
			forceWaitReturn:  forceWaitReturn,
		}
		closeSignal := &closeSignalingPeriodic{closed: make(chan struct{})}
		controller := &Controller{
			tasks: []periodicTask{
				{
					tag:      periodicTaskNodeMonitor,
					interval: time.Hour,
					Periodic: old,
				},
				{
					tag:      periodicTaskUserMonitor,
					interval: time.Hour,
					Periodic: closeSignal,
				},
			},
			newPeriodicTask: func(time.Duration, func() error) periodicRunner {
				return &recordingPeriodic{}
			},
		}

		allowCallbackReturn := make(chan struct{})
		replacementReturned := make(chan error, 1)
		go func() {
			replacementReturned <- controller.startOrReplacePeriodicTask(
				periodicTaskNodeMonitor,
				2*time.Hour,
				func() error { return nil },
			)
			<-allowCallbackReturn
			close(callbackReturned)
		}()
		<-old.stopEntered

		closeDone := make(chan error, 1)
		go func() {
			closeDone <- controller.closePeriodicTasks()
		}()
		<-closeSignal.closed
		close(old.releaseStop)
		<-old.waitEntered
		synctest.Wait()

		var replacementErr error
		select {
		case replacementErr = <-replacementReturned:
		default:
			close(forceWaitReturn)
			synctest.Wait()
			replacementErr = <-replacementReturned
			close(allowCallbackReturn)
			<-closeDone
			t.Fatalf("periodic replacement joined its own callback before returning: %v", replacementErr)
		}
		if replacementErr != nil {
			close(allowCallbackReturn)
			<-closeDone
			t.Fatalf("startOrReplacePeriodicTask() error = %v", replacementErr)
		}
		select {
		case err := <-closeDone:
			close(allowCallbackReturn)
			t.Fatalf("closePeriodicTasks() returned before the callback ended: %v", err)
		default:
		}

		close(allowCallbackReturn)
		if err := <-closeDone; err != nil {
			t.Fatalf("closePeriodicTasks() error = %v", err)
		}
	})
}

func TestControllerPeriodicCloseBeforeStartPreventsLateStart(t *testing.T) {
	executed := false
	periodic := newControllerPeriodicTask(time.Hour, func() error {
		executed = true
		return nil
	})

	if err := periodic.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := periodic.Start(); err != nil {
		t.Fatalf("Start() after Close() error = %v", err)
	}
	if executed {
		t.Fatal("periodic callback executed after task was closed")
	}
}

func TestControllerPeriodicCallbackCanReplaceItsOwnInterval(t *testing.T) {
	old := &selfReplacingPeriodic{
		stopEntered:  make(chan struct{}),
		waitEntered:  make(chan struct{}),
		closeEntered: make(chan struct{}),
		releaseWait:  make(chan struct{}),
	}
	candidate := &startNotifyingPeriodic{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	controller := &Controller{
		tasks: []periodicTask{{
			tag:      periodicTaskNodeMonitor,
			interval: time.Hour,
			Periodic: old,
		}},
		newPeriodicTask: func(time.Duration, func() error) periodicRunner {
			return candidate
		},
	}

	replaceDone := make(chan error, 1)
	go func() {
		replaceDone <- controller.startOrReplacePeriodicTask(
			periodicTaskNodeMonitor,
			2*time.Hour,
			func() error { return nil },
		)
	}()

	select {
	case <-old.closeEntered:
		close(old.releaseWait)
		<-replaceDone
		t.Fatal("periodic replacement synchronously closed and joined its own running callback")
	case <-old.stopEntered:
	}
	if err := <-replaceDone; err != nil {
		close(old.releaseWait)
		t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
	}
	<-old.waitEntered
	close(old.releaseWait)
	<-candidate.started

	if err := controller.closePeriodicTasks(); err != nil {
		t.Fatalf("closePeriodicTasks() error = %v", err)
	}
	<-candidate.closed
}

func TestControllerCloseJoinsAndReportsAsynchronousPeriodicStart(t *testing.T) {
	startErr := errors.New("periodic start failed during close")
	periodic := &closeReleasesFailingStartPeriodic{
		startEntered: make(chan struct{}),
		closed:       make(chan struct{}),
		startErr:     startErr,
	}
	controller := &Controller{
		newPeriodicTask: func(time.Duration, func() error) periodicRunner {
			return periodic
		},
	}

	if err := controller.startOrReplacePeriodicTask(
		periodicTaskCertMonitor,
		time.Hour,
		func() error { return nil },
	); err != nil {
		t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
	}
	<-periodic.startEntered

	err := controller.closePeriodicTasks()

	if !errors.Is(err, startErr) {
		t.Fatalf("closePeriodicTasks() error = %v, want asynchronous Start error %v", err, startErr)
	}
}

func TestControllerPeriodicReplacementWaitsForManagedStartToFinish(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runner := &startWindowPeriodicRunner{
			startEntered: make(chan struct{}),
			releaseStart: make(chan struct{}),
		}
		old := &controllerManagedPeriodic{runner: runner}
		candidate := &recordingPeriodic{}
		controller := &Controller{
			tasks: []periodicTask{{
				tag:      periodicTaskNodeMonitor,
				interval: time.Hour,
				Periodic: old,
			}},
			newPeriodicTask: func(time.Duration, func() error) periodicRunner {
				return candidate
			},
		}

		oldStartDone := make(chan error, 1)
		go func() {
			oldStartDone <- old.Start()
		}()
		<-runner.startEntered

		if err := controller.startOrReplacePeriodicTask(
			periodicTaskNodeMonitor,
			2*time.Hour,
			func() error { return nil },
		); err != nil {
			t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
		}
		synctest.Wait()
		startedBeforeOld := candidate.started != 0

		close(runner.releaseStart)
		synctest.Wait()
		if err := <-oldStartDone; err != nil {
			t.Fatalf("old Start() error = %v", err)
		}
		if err := controller.closePeriodicTasks(); err != nil {
			t.Fatalf("closePeriodicTasks() error = %v", err)
		}

		if startedBeforeOld {
			t.Fatal("replacement periodic started before the old managed Start completed")
		}
		if candidate.started != 1 {
			t.Fatalf("replacement periodic starts = %d, want 1", candidate.started)
		}
	})
}

func TestControllerCloseJoinsPendingPeriodicReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := &selfReplacingPeriodic{
			stopEntered:  make(chan struct{}),
			waitEntered:  make(chan struct{}),
			closeEntered: make(chan struct{}),
			releaseWait:  make(chan struct{}),
		}
		candidate := &startNotifyingPeriodic{
			started: make(chan struct{}),
			closed:  make(chan struct{}),
		}
		controller := &Controller{
			tasks: []periodicTask{{
				tag:      periodicTaskNodeMonitor,
				interval: time.Hour,
				Periodic: old,
			}},
			newPeriodicTask: func(time.Duration, func() error) periodicRunner {
				return candidate
			},
		}

		replaceDone := make(chan error, 1)
		go func() {
			replaceDone <- controller.startOrReplacePeriodicTask(
				periodicTaskNodeMonitor,
				2*time.Hour,
				func() error { return nil },
			)
		}()
		<-old.stopEntered
		if err := <-replaceDone; err != nil {
			close(old.releaseWait)
			t.Fatalf("startOrReplacePeriodicTask() error = %v", err)
		}
		<-old.waitEntered

		closeDone := make(chan error, 1)
		go func() {
			closeDone <- controller.closePeriodicTasks()
		}()
		<-candidate.closed
		synctest.Wait()
		select {
		case err := <-closeDone:
			close(old.releaseWait)
			t.Fatalf("closePeriodicTasks() returned before joining the replaced callback: %v", err)
		default:
		}

		close(old.releaseWait)
		if err := <-closeDone; err != nil {
			t.Fatalf("closePeriodicTasks() error = %v", err)
		}
		synctest.Wait()
		select {
		case <-candidate.started:
			t.Fatal("pending replacement started after controller close")
		default:
		}
	})
}

func TestControllerManagedPeriodicCallbackCanReplaceItself(t *testing.T) {
	controller := &Controller{}
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	callbackDone := make(chan error, 1)
	replacementExecuted := make(chan struct{})

	if err := controller.startOrReplacePeriodicTask(
		periodicTaskNodeMonitor,
		time.Hour,
		func() error {
			close(callbackEntered)
			<-releaseCallback
			callbackDone <- controller.startOrReplacePeriodicTask(
				periodicTaskNodeMonitor,
				2*time.Hour,
				func() error {
					close(replacementExecuted)
					return nil
				},
			)
			return nil
		},
	); err != nil {
		t.Fatalf("initial startOrReplacePeriodicTask() error = %v", err)
	}
	<-callbackEntered

	controller.stateMu.RLock()
	managed, ok := controller.tasks[0].Periodic.(*controllerManagedPeriodic)
	controller.stateMu.RUnlock()
	if !ok {
		close(releaseCallback)
		t.Fatalf("periodic task type = %T, want *controllerManagedPeriodic", controller.tasks[0].Periodic)
	}
	if !managed.mu.TryLock() {
		close(releaseCallback)
		t.Fatal("managed periodic held its state lock across the synchronous callback")
	}
	managed.mu.Unlock()
	close(releaseCallback)

	if err := <-callbackDone; err != nil {
		t.Fatalf("callback replacement error = %v", err)
	}
	<-replacementExecuted
	if err := controller.closePeriodicTasks(); err != nil {
		t.Fatalf("closePeriodicTasks() error = %v", err)
	}
}

func TestControllerPeriodicReplacementInheritsPendingPredecessor(t *testing.T) {
	old := &selfReplacingPeriodic{
		stopEntered:  make(chan struct{}),
		waitEntered:  make(chan struct{}),
		waitReturned: make(chan struct{}),
		closeEntered: make(chan struct{}),
		releaseWait:  make(chan struct{}),
	}
	intermediate := &selfReplacingPeriodic{
		stopEntered:  make(chan struct{}),
		waitEntered:  make(chan struct{}),
		waitReturned: make(chan struct{}),
		closeEntered: make(chan struct{}),
		releaseWait:  make(chan struct{}),
	}
	allowLatestStart := make(chan struct{})
	latest := &causallyGatedStartPeriodic{
		allowed: allowLatestStart,
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	candidates := []periodicRunner{intermediate, latest}
	controller := &Controller{
		tasks: []periodicTask{{
			tag:      periodicTaskNodeMonitor,
			interval: time.Hour,
			Periodic: old,
		}},
		newPeriodicTask: func(time.Duration, func() error) periodicRunner {
			candidate := candidates[0]
			candidates = candidates[1:]
			return candidate
		},
	}

	if err := controller.startOrReplacePeriodicTask(
		periodicTaskNodeMonitor,
		2*time.Hour,
		func() error { return nil },
	); err != nil {
		t.Fatalf("first startOrReplacePeriodicTask() error = %v", err)
	}
	<-old.waitEntered

	close(intermediate.releaseWait)
	if err := controller.startOrReplacePeriodicTask(
		periodicTaskNodeMonitor,
		3*time.Hour,
		func() error { return nil },
	); err != nil {
		close(old.releaseWait)
		t.Fatalf("second startOrReplacePeriodicTask() error = %v", err)
	}
	<-intermediate.waitEntered
	<-intermediate.waitReturned

	controller.stateMu.RLock()
	predecessorsDone := controller.tasks[0].predecessorsDone
	controller.stateMu.RUnlock()
	if predecessorsDone == nil {
		close(old.releaseWait)
		t.Fatal("latest replacement did not inherit the pending predecessor join")
	}

	close(allowLatestStart)
	close(old.releaseWait)
	<-old.waitReturned
	<-predecessorsDone
	<-latest.started
	if latest.startedBeforeAllow {
		t.Fatal("latest periodic replacement started while the original callback was still running")
	}
	if err := controller.closePeriodicTasks(); err != nil {
		t.Fatalf("closePeriodicTasks() error = %v", err)
	}
}

func TestControllerStartPeriodicTaskOmitsErrorDetailsByDefault(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := logrus.New()
	logger.SetOutput(buffer)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	err := errors.New("token=secret")
	controller := &Controller{logger: logrus.NewEntry(logger)}

	controller.startPeriodicTask("node monitor", failingPeriodic{err: err})

	logOutput := buffer.String()
	if strings.Contains(logOutput, err.Error()) {
		t.Fatalf("expected sensitive error to be omitted, got %q", logOutput)
	}
	if !strings.Contains(logOutput, "details omitted") {
		t.Fatalf("expected redacted log message, got %q", logOutput)
	}
}

func TestControllerStartPeriodicTaskCanShowErrorDetails(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := logrus.New()
	logger.SetOutput(buffer)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	err := errors.New("token=secret")
	controller := &Controller{
		config: &Config{ShowErrorDetails: true},
		logger: logrus.NewEntry(logger),
	}

	controller.startPeriodicTask("node monitor", failingPeriodic{err: err})

	logOutput := buffer.String()
	if !strings.Contains(logOutput, err.Error()) {
		t.Fatalf("expected detailed error to be logged, got %q", logOutput)
	}
}

func TestNormalizeBaseConfigInterval(t *testing.T) {
	tests := []struct {
		name    string
		seconds int
		min     int
		want    int
	}{
		{name: "zero", seconds: 0, min: 30, want: 0},
		{name: "negative", seconds: -1, min: 30, want: 0},
		{name: "clamped", seconds: 5, min: 30, want: 30},
		{name: "unchanged", seconds: 60, min: 30, want: 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeBaseConfigInterval(tt.seconds, tt.min); got != tt.want {
				t.Fatalf("normalizeBaseConfigInterval(%d, %d) = %d, want %d", tt.seconds, tt.min, got, tt.want)
			}
		})
	}
}

func TestMaterializeControllerRuntimeSchedule(t *testing.T) {
	tests := []struct {
		name     string
		local    int
		base     *api.BaseConfig
		wantPull time.Duration
		wantPush time.Duration
	}{
		{name: "no base config uses local defaults", local: 60, wantPull: 60 * time.Second, wantPush: 60 * time.Second},
		{name: "missing base config intervals use local defaults", local: 60, base: apiBaseConfig(0, 0), wantPull: 60 * time.Second, wantPush: 60 * time.Second},
		{name: "negative base config intervals use local defaults", local: 60, base: apiBaseConfig(-1, -1), wantPull: 60 * time.Second, wantPush: 60 * time.Second},
		{name: "base config intervals override local defaults", local: 60, base: apiBaseConfig(15, 45), wantPull: 45 * time.Second, wantPush: 15 * time.Second},
		{name: "base config intervals keep existing clamps", local: 60, base: apiBaseConfig(3, 4), wantPull: minBaseConfigPullInterval * time.Second, wantPush: minBaseConfigPushInterval * time.Second},
		{name: "partial pull override preserves local push", local: 60, base: apiBaseConfig(0, 45), wantPull: 45 * time.Second, wantPush: 60 * time.Second},
		{name: "partial push override preserves local pull", local: 60, base: apiBaseConfig(15, 0), wantPull: 60 * time.Second, wantPush: 15 * time.Second},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schedule := materializeControllerRuntimeSchedule(test.local, test.base)
			if schedule.pullInterval != test.wantPull || schedule.pushInterval != test.wantPush {
				t.Fatalf("expected pull=%s push=%s, got pull=%s push=%s", test.wantPull, test.wantPush, schedule.pullInterval, schedule.pushInterval)
			}
		})
	}
}

func TestControllerApplyBaseConfigStartsAndReplacesIntervals(t *testing.T) {
	created := make([]*recordingPeriodic, 0)
	controller := &Controller{
		config: &Config{UpdatePeriodic: 60},
	}
	controller.newPeriodicTask = func(interval time.Duration, execute func() error) periodicRunner {
		periodic := &recordingPeriodic{interval: interval, execute: execute}
		created = append(created, periodic)
		return periodic
	}

	if err := controller.applyBaseConfig(apiBaseConfig(15, 45)); err != nil {
		t.Fatalf("applyBaseConfig returned error: %v", err)
	}
	if len(created) != 2 {
		t.Fatalf("expected two periodic tasks, got %d", len(created))
	}
	if created[0].interval != 45*time.Second || created[1].interval != 15*time.Second {
		t.Fatalf("unexpected intervals: pull=%s push=%s", created[0].interval, created[1].interval)
	}
	if created[0].started != 1 || created[1].started != 1 {
		t.Fatalf("expected both tasks to start once, got %d/%d", created[0].started, created[1].started)
	}

	if err := controller.applyBaseConfig(apiBaseConfig(3, 4)); err != nil {
		t.Fatalf("second applyBaseConfig returned error: %v", err)
	}
	if len(created) != 4 {
		t.Fatalf("expected replacement tasks, got %d", len(created))
	}
	if created[0].closed != 1 || created[1].closed != 1 {
		t.Fatalf("expected old tasks to close once, got %d/%d", created[0].closed, created[1].closed)
	}
	if created[2].interval != minBaseConfigPullInterval*time.Second || created[3].interval != minBaseConfigPushInterval*time.Second {
		t.Fatalf("unexpected clamped intervals: pull=%s push=%s", created[2].interval, created[3].interval)
	}
}

func TestControllerApplyBaseConfigIgnoresMissingIntervals(t *testing.T) {
	created := 0
	controller := &Controller{}
	controller.newPeriodicTask = func(interval time.Duration, execute func() error) periodicRunner {
		created++
		return &recordingPeriodic{interval: interval, execute: execute}
	}

	if err := controller.applyBaseConfig(nil); err != nil {
		t.Fatalf("nil applyBaseConfig returned error: %v", err)
	}
	if err := controller.applyBaseConfig(apiBaseConfig(0, 0)); err != nil {
		t.Fatalf("zero applyBaseConfig returned error: %v", err)
	}
	if created != 0 {
		t.Fatalf("expected no periodic tasks, got %d", created)
	}
}

func TestControllerApplyBaseConfigReturnsCloseError(t *testing.T) {
	closeErr := errors.New("close failed")
	created := make([]*recordingPeriodic, 0)
	controller := &Controller{}
	controller.newPeriodicTask = func(interval time.Duration, execute func() error) periodicRunner {
		periodic := &recordingPeriodic{interval: interval, execute: execute}
		created = append(created, periodic)
		return periodic
	}

	if err := controller.applyBaseConfig(apiBaseConfig(15, 45)); err != nil {
		t.Fatalf("initial applyBaseConfig returned error: %v", err)
	}
	created[0].closeErr = closeErr

	err := controller.applyBaseConfig(apiBaseConfig(20, 50))
	if !errors.Is(err, closeErr) {
		t.Fatalf("expected close error, got %v", err)
	}
	if len(controller.tasks) != 2 || controller.tasks[0].Periodic != created[0] {
		t.Fatalf("close failure published an unstarted replacement task: %#v", controller.tasks)
	}
	if len(created) != 3 || created[2].started != 0 || created[2].closed != 1 {
		t.Fatalf("replacement candidate ownership = created:%d started:%d closed:%d, want 3/0/1", len(created), created[2].started, created[2].closed)
	}
}

func TestControllerCloseContinuesAfterPeriodicFailure(t *testing.T) {
	closeErr := errors.New("periodic close failed")
	periodic := &recordingPeriodic{closeErr: closeErr}
	ws := &fakeLifecycleWSRuntime{}
	coordinator := &fakeLifecycleCoordinator{}
	controller := &Controller{
		tasks: []periodicTask{{
			tag:      periodicTaskCertMonitor,
			Periodic: periodic,
		}},
		wsRuntime:       ws,
		syncCoordinator: coordinator,
		lifecycleState:  controllerStateRunning,
		ownedRuntime: controllerRuntimeOwnership{
			periodic:        true,
			websocket:       true,
			syncCoordinator: true,
		},
	}

	err := controller.Close()

	if !errors.Is(err, closeErr) {
		t.Fatalf("Close() error = %v, want %v", err, closeErr)
	}
	if !ws.stopped || !coordinator.stopped {
		t.Fatalf("Close() skipped owned runtimes after periodic failure: ws=%v coordinator=%v", ws.stopped, coordinator.stopped)
	}
	if controller.wsRuntime != nil || controller.syncCoordinator != nil {
		t.Fatal("Close() retained stopped runtime ownership")
	}
}

func TestControllerClosePeriodicTasksDoesNotHoldRegistryLockWhileJoining(t *testing.T) {
	periodic := &joiningPeriodic{
		closeEntered: make(chan struct{}),
		releaseClose: make(chan struct{}),
	}
	controller := &Controller{
		tasks: []periodicTask{{
			tag:      periodicTaskCertMonitor,
			Periodic: periodic,
		}},
	}
	done := make(chan error, 1)
	go func() {
		done <- controller.closePeriodicTasks()
	}()
	<-periodic.closeEntered

	if !controller.periodicMu.TryLock() {
		close(periodic.releaseClose)
		<-done
		t.Fatal("closePeriodicTasks held the registry lock while joining a running callback")
	}
	controller.periodicMu.Unlock()
	close(periodic.releaseClose)
	if err := <-done; err != nil {
		t.Fatalf("closePeriodicTasks() error = %v", err)
	}
}

func TestControllerPeriodicTasksCannotRestartAfterClose(t *testing.T) {
	created := 0
	controller := &Controller{
		newPeriodicTask: func(time.Duration, func() error) periodicRunner {
			created++
			return &recordingPeriodic{}
		},
	}
	if err := controller.closePeriodicTasks(); err != nil {
		t.Fatalf("closePeriodicTasks() error = %v", err)
	}

	if err := controller.startOrReplacePeriodicTask(periodicTaskCertMonitor, time.Hour, func() error { return nil }); err != nil {
		t.Fatalf("startOrReplacePeriodicTask() after close error = %v", err)
	}
	if created != 0 || len(controller.tasks) != 0 {
		t.Fatalf("closed controller restarted periodic ownership: created=%d tasks=%d", created, len(controller.tasks))
	}
}

func TestControllerStartPeriodicTasksUsesBaseConfigBeforeFallback(t *testing.T) {
	created := make([]*recordingPeriodic, 0)
	controller := &Controller{config: &Config{UpdatePeriodic: 60}}
	controller.newPeriodicTask = func(interval time.Duration, execute func() error) periodicRunner {
		periodic := &recordingPeriodic{interval: interval, execute: execute}
		created = append(created, periodic)
		return periodic
	}
	controller.apiClient = baseConfigAPI{BaseConfig: api.BaseConfig{PushInterval: 15, PullInterval: 45}}

	if err := controller.startControllerPeriodicTasks(&api.NodeInfo{}); err != nil {
		t.Fatalf("startControllerPeriodicTasks returned error: %v", err)
	}
	if len(created) != 2 {
		t.Fatalf("expected two periodic tasks, got %d", len(created))
	}
	if created[0].interval != 45*time.Second || created[1].interval != 15*time.Second {
		t.Fatalf("unexpected intervals: pull=%s push=%s", created[0].interval, created[1].interval)
	}
}

func TestControllerStartPeriodicTasksFallsBackToLocalUpdatePeriodic(t *testing.T) {
	created := make([]*recordingPeriodic, 0)
	controller := &Controller{config: &Config{UpdatePeriodic: 60}}
	controller.newPeriodicTask = func(interval time.Duration, execute func() error) periodicRunner {
		periodic := &recordingPeriodic{interval: interval, execute: execute}
		created = append(created, periodic)
		return periodic
	}

	if err := controller.startControllerPeriodicTasks(&api.NodeInfo{}); err != nil {
		t.Fatalf("startControllerPeriodicTasks returned error: %v", err)
	}
	if len(created) != 2 {
		t.Fatalf("expected two periodic tasks, got %d", len(created))
	}
	if created[0].interval != 60*time.Second || created[1].interval != 60*time.Second {
		t.Fatalf("unexpected fallback intervals: pull=%s push=%s", created[0].interval, created[1].interval)
	}
}

type baseConfigAPI struct {
	PanelClient
	api.BaseConfig
}

func (a baseConfigAPI) GetBaseConfig() *api.BaseConfig {
	baseConfig := a.BaseConfig
	return &baseConfig
}

func apiBaseConfig(push, pull int) *api.BaseConfig {
	return &api.BaseConfig{PushInterval: push, PullInterval: pull}
}
