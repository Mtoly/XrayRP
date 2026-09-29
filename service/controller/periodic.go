package controller

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/internal/specialruntime"
)

const (
	periodicTaskNodeMonitor = "node monitor"
	periodicTaskUserMonitor = "user monitor"
	periodicTaskCertMonitor = "cert monitor"

	minBaseConfigPushInterval = 5
	minBaseConfigPullInterval = 30
)

type periodicRunner interface {
	Start() error
	Close() error
}

type controllerPeriodicTask struct {
	tag                     string
	interval                time.Duration
	generation              uint64
	predecessorsDone        <-chan struct{}
	replacementOwnsPeriodic bool
	Periodic                periodicRunner
}

type periodicTaskFactory func(interval time.Duration, execute func() error) periodicRunner

type joinablePeriodicRunner interface {
	periodicRunner
	Stop() error
	Wait() error
}

type contextStartPeriodicRunner interface {
	StartContext(context.Context) error
}

type contextStopPeriodicRunner interface {
	StopContext(context.Context) error
}

type contextWaitPeriodicRunner interface {
	WaitContext(context.Context) error
}

type contextClosePeriodicRunner interface {
	CloseContext(context.Context) error
}

type controllerManagedPeriodic struct {
	mu              sync.Mutex
	runner          joinablePeriodicRunner
	closed          bool
	started         bool
	startInProgress bool
	startDone       chan struct{}
}

func (c *Controller) nodeInfoMonitor() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return c.nodeInfoMonitorContext(ctx)
}

func (c *Controller) nodeInfoMonitorContext(ctx context.Context) error {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}

	action := syncActionFromPollingTick(time.Now())
	if err := c.submitSyncActionContext(ctx, action); err != nil {
		c.logger.Print(err)
		return nil
	}
	return nil
}

func newControllerPeriodicTask(interval time.Duration, execute func() error) periodicRunner {
	return newControllerPeriodicTaskContext(interval, func(context.Context) error {
		return execute()
	})
}

func newControllerPeriodicTaskContext(interval time.Duration, execute func(context.Context) error) periodicRunner {
	periodic := &controllerManagedPeriodic{}
	periodic.runner = specialruntime.NewPeriodicContext(interval, func(ctx context.Context) error {
		periodic.mu.Lock()
		closed := periodic.closed
		periodic.mu.Unlock()
		if closed {
			return nil
		}
		return execute(ctx)
	})
	return periodic
}

func (p *controllerManagedPeriodic) finishStart(done chan struct{}) {
	p.mu.Lock()
	p.startInProgress = false
	p.started = true
	close(done)
	p.mu.Unlock()
}

func (p *controllerManagedPeriodic) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

func (p *controllerManagedPeriodic) beginStart() (chan struct{}, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.started || p.startInProgress {
		return nil, false
	}
	p.startInProgress = true
	p.startDone = make(chan struct{})
	return p.startDone, true
}

func (p *controllerManagedPeriodic) Start() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return p.StartContext(ctx)
}

func (p *controllerManagedPeriodic) StartContext(ctx context.Context) error {
	done, ok := p.beginStart()
	if !ok {
		return nil
	}
	err := startPeriodicRunnerContext(ctx, p.runner)
	if p.isClosed() {
		err = errors.Join(err, stopPeriodicRunnerContext(ctx, p.runner))
	}
	p.finishStart(done)
	return err
}

func (p *controllerManagedPeriodic) Stop() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return p.StopContext(ctx)
}

func (p *controllerManagedPeriodic) StopContext(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return stopPeriodicRunnerContext(ctx, p.runner)
}

func (p *controllerManagedPeriodic) Wait() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultJoinTimeout)
	defer cancel()
	return p.WaitContext(ctx)
}

func (p *controllerManagedPeriodic) WaitContext(ctx context.Context) error {
	p.mu.Lock()
	startDone := p.startDone
	startInProgress := p.startInProgress
	p.mu.Unlock()
	if startInProgress {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-startDone:
		}
	}
	return waitPeriodicRunnerContext(ctx, p.runner)
}

func (p *controllerManagedPeriodic) Close() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return p.CloseContext(ctx)
}

func (p *controllerManagedPeriodic) CloseContext(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	startDone := p.startDone
	startInProgress := p.startInProgress
	p.mu.Unlock()

	stopErr := stopPeriodicRunnerContext(ctx, p.runner)
	if startInProgress {
		select {
		case <-ctx.Done():
			return errors.Join(stopErr, ctx.Err())
		case <-startDone:
		}
	}
	return errors.Join(stopErr, waitPeriodicRunnerContext(ctx, p.runner))
}

func startPeriodicRunnerContext(ctx context.Context, runner periodicRunner) error {
	if contextual, ok := runner.(contextStartPeriodicRunner); ok {
		return contextual.StartContext(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return runner.Start()
}

func stopPeriodicRunnerContext(ctx context.Context, runner periodicRunner) error {
	if contextual, ok := runner.(contextStopPeriodicRunner); ok {
		return contextual.StopContext(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if joinable, ok := runner.(joinablePeriodicRunner); ok {
		return joinable.Stop()
	}
	return nil
}

func waitPeriodicRunnerContext(ctx context.Context, runner periodicRunner) error {
	if contextual, ok := runner.(contextWaitPeriodicRunner); ok {
		return contextual.WaitContext(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if joinable, ok := runner.(joinablePeriodicRunner); ok {
		return joinable.Wait()
	}
	return nil
}

func closePeriodicRunnerContext(ctx context.Context, runner periodicRunner) error {
	if contextual, ok := runner.(contextClosePeriodicRunner); ok {
		return contextual.CloseContext(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return runner.Close()
}
func (*controllerManagedPeriodic) startAsynchronously() {}

func (c *Controller) periodicTaskFactoryContext(interval time.Duration, execute func(context.Context) error) periodicRunner {
	if c == nil || c.newPeriodicTask == nil {
		return newControllerPeriodicTaskContext(interval, execute)
	}
	return c.newPeriodicTask(interval, func() error {
		ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
		defer cancel()
		return execute(ctx)
	})
}

func (c *Controller) periodicTaskFactory() periodicTaskFactory {
	if c == nil || c.newPeriodicTask == nil {
		return newControllerPeriodicTask
	}
	return c.newPeriodicTask
}

func (c *Controller) startPeriodicTask(tag string, periodic periodicRunner) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	err := startPeriodicRunnerContext(ctx, periodic)
	c.logPeriodicTaskError(tag, err)
	return err
}

func (c *Controller) logPeriodicTaskError(tag string, err error) {
	if err == nil || c.logger == nil {
		return
	}
	if c.showErrorDetails() {
		c.logger.WithField("task", tag).Warn(err)
	} else {
		c.logger.WithField("task", tag).Warn("periodic task failed; error details omitted because they may contain credentials")
	}
}

func (c *Controller) showErrorDetails() bool {
	return common.ShowErrorDetails() || c != nil && c.config != nil && c.config.ShowErrorDetails
}

func (c *Controller) launchPeriodicTask(tag string, periodic periodicRunner) (error, bool) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return c.launchPeriodicTaskContext(ctx, tag, periodic)
}

func (c *Controller) launchPeriodicTaskContext(ctx context.Context, tag string, periodic periodicRunner) (error, bool) {
	if err := ctx.Err(); err != nil {
		return err, false
	}
	if _, ok := periodic.(interface{ startAsynchronously() }); ok {
		startCtx, cancel := service.WithDefaultTimeout(context.WithoutCancel(ctx), service.DefaultStartTimeout)
		// Register the asynchronous launch while holding the periodic registry
		// lock, so a shutdown request that already owns the producer cannot race
		// this increment past the close wait.
		c.periodicMu.Lock()
		if c.periodicShutdownRequested {
			c.periodicMu.Unlock()
			cancel()
			return nil, true
		}
		c.periodicJoinWG.Add(1)
		c.periodicMu.Unlock()
		go func() {
			defer cancel()
			launchDone := false
			defer func() {
				if !launchDone {
					c.periodicJoinWG.Done()
				}
			}()
			err := startPeriodicRunnerContext(startCtx, periodic)
			if err != nil {
				c.periodicMu.Lock()
				c.periodicAsyncErrs = append(c.periodicAsyncErrs, err)
				c.periodicMu.Unlock()
			}
			c.periodicJoinWG.Done()
			launchDone = true
			c.logPeriodicTaskError(tag, err)
			c.periodicMu.Lock()
			shouldLogStart := !c.periodicShutdownRequested
			c.periodicMu.Unlock()
			if shouldLogStart && c.logger != nil {
				c.logger.Printf("Start %s periodic task", tag)
			}
		}()
		return nil, true
	}
	return startPeriodicRunnerContext(ctx, periodic), false
}
func (c *Controller) recordPeriodicReplacementError(err error) error {
	if err == nil {
		return nil
	}
	c.periodicMu.Lock()
	if c.periodicShutdownRequested {
		c.periodicAsyncErrs = append(c.periodicAsyncErrs, err)
	}
	c.periodicMu.Unlock()
	return err
}

func (c *Controller) launchPeriodicCleanup(cleanup func() error) {
	if cleanup == nil {
		return
	}
	// Register under periodicMu so the increment can never race the shutdown
	// flag check that decides whether closePeriodicTasks will wait on it.
	c.periodicMu.Lock()
	c.periodicJoinWG.Add(1)
	c.periodicMu.Unlock()
	go func() {
		defer c.periodicJoinWG.Done()
		if err := cleanup(); err != nil {
			c.periodicMu.Lock()
			c.periodicAsyncErrs = append(c.periodicAsyncErrs, err)
			c.periodicMu.Unlock()
		}
	}()
}

func (c *Controller) startOrReplacePeriodicTask(tag string, interval time.Duration, execute func() error) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return c.startOrReplacePeriodicTaskContext(ctx, tag, interval, func(context.Context) error { return execute() }, false)
}

func (c *Controller) startInitialPeriodicTask(tag string, interval time.Duration, execute func() error) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return c.startOrReplacePeriodicTaskContext(ctx, tag, interval, func(context.Context) error { return execute() }, true)
}

func (c *Controller) startOrReplacePeriodicTaskWithMode(tag string, interval time.Duration, execute func() error, synchronous bool) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return c.startOrReplacePeriodicTaskContext(ctx, tag, interval, func(context.Context) error { return execute() }, synchronous)
}

func (c *Controller) startOrReplacePeriodicTaskContext(ctx context.Context, tag string, interval time.Duration, execute func(context.Context) error, synchronous bool) error {
	if interval <= 0 || execute == nil {
		return nil
	}

	c.periodicMu.Lock()
	if c.periodicShutdownRequested {
		c.periodicMu.Unlock()
		return nil
	}

	var old periodicRunner
	var inheritedPredecessorsDone <-chan struct{}
	var observedGeneration uint64
	var observedInterval time.Duration
	c.stateMu.Lock()
	for i := range c.tasks {
		if c.tasks[i].tag != tag {
			continue
		}
		if c.tasks[i].interval == interval {
			c.stateMu.Unlock()
			c.periodicMu.Unlock()
			return nil
		}
		old = c.tasks[i].Periodic
		inheritedPredecessorsDone = c.tasks[i].predecessorsDone
		observedGeneration = c.tasks[i].generation
		observedInterval = c.tasks[i].interval
		break
	}
	c.stateMu.Unlock()
	c.periodicJoinWG.Add(1)
	c.periodicMu.Unlock()
	replacementTransactionDone := false
	defer func() {
		if !replacementTransactionDone {
			c.periodicJoinWG.Done()
		}
	}()

	if err := ctx.Err(); err != nil {
		return err
	}
	periodic := c.periodicTaskFactoryContext(interval, execute)
	if periodic == nil {
		return nil
	}

	c.periodicMu.Lock()
	if c.periodicShutdownRequested {
		c.periodicMu.Unlock()
		return c.recordPeriodicReplacementError(closePeriodicRunnerContext(ctx, periodic))
	}

	replacementIndex := -1
	stateUnchanged := old == nil
	c.stateMu.Lock()
	for i := range c.tasks {
		if c.tasks[i].tag != tag {
			continue
		}
		replacementIndex = i
		stateUnchanged = old != nil &&
			c.tasks[i].generation == observedGeneration &&
			c.tasks[i].interval == observedInterval &&
			!c.tasks[i].replacementOwnsPeriodic
		if stateUnchanged {
			c.tasks[i].replacementOwnsPeriodic = true
		}
		break
	}
	c.stateMu.Unlock()
	c.periodicMu.Unlock()
	if !stateUnchanged {
		return c.recordPeriodicReplacementError(closePeriodicRunnerContext(ctx, periodic))
	}

	releaseReplacementOwnership := func() bool {
		c.periodicMu.Lock()
		closed := c.periodicShutdownRequested
		if !closed && old != nil {
			c.stateMu.Lock()
			for i := range c.tasks {
				if c.tasks[i].tag == tag &&
					c.tasks[i].generation == observedGeneration &&
					c.tasks[i].interval == observedInterval {
					c.tasks[i].replacementOwnsPeriodic = false
					break
				}
			}
			c.stateMu.Unlock()
		}
		c.periodicMu.Unlock()
		return closed
	}

	var stoppedOld joinablePeriodicRunner
	if old != nil {
		if joinable, ok := old.(joinablePeriodicRunner); ok {
			if err := stopPeriodicRunnerContext(ctx, joinable); err != nil {
				if releaseReplacementOwnership() {
					c.launchPeriodicCleanup(old.Close)
				}
				return c.recordPeriodicReplacementError(errors.Join(err, closePeriodicRunnerContext(ctx, periodic)))
			}
			stoppedOld = joinable
		} else if err := closePeriodicRunnerContext(ctx, old); err != nil {
			releaseReplacementOwnership()
			return c.recordPeriodicReplacementError(errors.Join(err, closePeriodicRunnerContext(ctx, periodic)))
		}
	}

	c.periodicMu.Lock()
	if c.periodicShutdownRequested {
		c.periodicMu.Unlock()
		if stoppedOld != nil {
			c.launchPeriodicCleanup(stoppedOld.Wait)
		}
		return c.recordPeriodicReplacementError(closePeriodicRunnerContext(ctx, periodic))
	}

	replacementIndex = -1
	stateUnchanged = old == nil
	c.stateMu.Lock()
	for i := range c.tasks {
		if c.tasks[i].tag != tag {
			continue
		}
		replacementIndex = i
		stateUnchanged = old != nil &&
			c.tasks[i].generation == observedGeneration &&
			c.tasks[i].interval == observedInterval &&
			c.tasks[i].replacementOwnsPeriodic
		break
	}
	if !stateUnchanged {
		c.stateMu.Unlock()
		c.periodicMu.Unlock()
		if stoppedOld != nil {
			c.launchPeriodicCleanup(stoppedOld.Wait)
		}
		return c.recordPeriodicReplacementError(closePeriodicRunnerContext(ctx, periodic))
	}

	c.periodicGeneration++
	generation := c.periodicGeneration
	var predecessorsDone chan struct{}
	if stoppedOld != nil || inheritedPredecessorsDone != nil {
		predecessorsDone = make(chan struct{})
	}
	if replacementIndex >= 0 {
		c.tasks[replacementIndex].interval = interval
		c.tasks[replacementIndex].Periodic = periodic
		c.tasks[replacementIndex].generation = generation
		c.tasks[replacementIndex].predecessorsDone = predecessorsDone
		c.tasks[replacementIndex].replacementOwnsPeriodic = false
	} else {
		c.tasks = append(c.tasks, periodicTask{
			tag:              tag,
			interval:         interval,
			generation:       generation,
			predecessorsDone: predecessorsDone,
			Periodic:         periodic,
		})
	}
	c.stateMu.Unlock()

	if predecessorsDone != nil {
		c.periodicJoinWG.Add(1)
		go c.joinAndLaunchPeriodicReplacement(
			tag,
			generation,
			inheritedPredecessorsDone,
			stoppedOld,
			predecessorsDone,
			periodic,
		)
	}
	c.periodicMu.Unlock()

	var startErr error
	startedAsynchronously := false
	if predecessorsDone == nil {
		if synchronous {
			startErr = startPeriodicRunnerContext(ctx, periodic)
		} else {
			startErr, startedAsynchronously = c.launchPeriodicTaskContext(ctx, tag, periodic)
		}
	}
	c.periodicJoinWG.Done()
	replacementTransactionDone = true

	if !startedAsynchronously {
		c.logPeriodicTaskError(tag, startErr)
		if predecessorsDone == nil && c.logger != nil {
			c.logger.Printf("Start %s periodic task", tag)
		}
	}
	if synchronous {
		return startErr
	}
	return nil
}

func (c *Controller) joinAndLaunchPeriodicReplacement(
	tag string,
	generation uint64,
	inheritedPredecessorsDone <-chan struct{},
	old joinablePeriodicRunner,
	predecessorsDone chan<- struct{},
	replacement periodicRunner,
) {
	replacementJoinDone := false
	defer func() {
		if !replacementJoinDone {
			c.periodicJoinWG.Done()
		}
	}()
	var waitErr error
	if old != nil {
		waitErr = old.Wait()
	}
	if inheritedPredecessorsDone != nil {
		<-inheritedPredecessorsDone
	}
	close(predecessorsDone)

	c.periodicMu.Lock()
	if waitErr != nil {
		c.periodicAsyncErrs = append(c.periodicAsyncErrs, waitErr)
	}
	shouldStart := !c.periodicShutdownRequested
	if shouldStart {
		c.stateMu.RLock()
		shouldStart = false
		for i := range c.tasks {
			if c.tasks[i].tag == tag && c.tasks[i].generation == generation {
				shouldStart = true
				break
			}
		}
		c.stateMu.RUnlock()
	}
	c.periodicMu.Unlock()

	var startErr error
	startedAsynchronously := false
	if shouldStart {
		startCtx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
		startErr, startedAsynchronously = c.launchPeriodicTaskContext(startCtx, tag, replacement)
		cancel()
	}
	c.periodicJoinWG.Done()
	replacementJoinDone = true
	if !startedAsynchronously {
		c.logPeriodicTaskError(tag, startErr)
		if shouldStart && c.logger != nil {
			c.logger.Printf("Start %s periodic task", tag)
		}
	}
}

func (c *Controller) closePeriodicTasks() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return c.closePeriodicTasksContext(ctx)
}

// periodicShutdownTarget tracks one producer across shutdown attempts. Stop is
// signalled at most once, and joins stay registered so a Close that returns on
// its deadline can be retried against the real runner later.
type periodicShutdownTarget struct {
	tag    string
	runner periodicRunner

	stopStarted bool
	stopDone    chan struct{}
	stopErr     error

	joinStarted bool
	joinDone    chan struct{}
	joinErr     error
}

// periodicShutdownError reports a periodic shutdown attempt that could not join
// every producer before its deadline. PendingTags names the periodic tasks that
// were still running when the attempt gave up.
type periodicShutdownError struct {
	pending []string
	err     error
}

func (e *periodicShutdownError) Error() string {
	if e == nil {
		return ""
	}
	tags := "periodic tasks"
	if len(e.pending) > 0 {
		tags = "periodic tasks " + strings.Join(e.pending, ", ")
	}
	if e.err == nil {
		return "periodic shutdown incomplete: " + tags
	}
	return "periodic shutdown incomplete: " + tags + ": " + e.err.Error()
}

func (e *periodicShutdownError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// PendingTags returns the periodic task tags that had not exited when the
// shutdown attempt hit its deadline.
func (e *periodicShutdownError) PendingTags() []string {
	if e == nil {
		return nil
	}
	return append([]string(nil), e.pending...)
}

type periodicCloseFailure struct {
	tag string
	err error
}

// periodicShutdownCompleted reports whether every periodic producer has exited
// and all outstanding asynchronous periodic work has been joined.
func (c *Controller) periodicShutdownCompleted() bool {
	c.periodicMu.Lock()
	defer c.periodicMu.Unlock()
	return c.periodicShutdownDone
}

func (c *Controller) closePeriodicTasksContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// One shutdown attempt at a time: concurrent Close calls must not stop or
	// join the same producer twice. The lock is released before failures are
	// logged so a logging hook can safely reenter Close.
	c.periodicShutdownMu.Lock()
	attemptErr, failures := c.runPeriodicShutdownAttempt(ctx)
	c.periodicShutdownMu.Unlock()

	if c.logger != nil {
		for _, failure := range failures {
			c.logger.Errorf("%s periodic task close failed: %s", failure.tag, failure.err)
		}
	}
	return attemptErr
}

func (c *Controller) runPeriodicShutdownAttempt(ctx context.Context) (error, []periodicCloseFailure) {
	c.periodicMu.Lock()
	if c.periodicShutdownDone {
		err := c.periodicShutdownErr
		c.periodicMu.Unlock()
		return err, nil
	}
	if !c.periodicShutdownRequested {
		// First request: atomically block new periodic tasks and replacements,
		// then capture the producers that must be stopped.
		c.periodicShutdownRequested = true
		targets := make([]*periodicShutdownTarget, 0, len(c.tasks))
		c.stateMu.Lock()
		for i := range c.tasks {
			if c.tasks[i].replacementOwnsPeriodic || c.tasks[i].Periodic == nil {
				continue
			}
			targets = append(targets, &periodicShutdownTarget{
				tag:    c.tasks[i].tag,
				runner: c.tasks[i].Periodic,
			})
		}
		c.tasks = nil
		c.stateMu.Unlock()
		c.periodicShutdownTargets = targets
	}
	targets := append([]*periodicShutdownTarget(nil), c.periodicShutdownTargets...)
	c.periodicMu.Unlock()

	// Deliver every stop signal before joining any producer, so one slow
	// producer cannot delay stopping or joining the others.
	c.issuePeriodicShutdownStops(targets)
	if err := c.joinPeriodicShutdownTargets(ctx, targets); err != nil {
		return c.periodicShutdownAttemptFailure(err, targets), nil
	}
	if err := c.waitPeriodicJoinGroup(ctx); err != nil {
		return c.periodicShutdownAttemptFailure(err, targets), nil
	}

	failures := c.periodicShutdownFailures(targets)
	errs := make([]error, 0, len(failures)+1)
	for _, failure := range failures {
		errs = append(errs, failure.err)
	}
	c.periodicMu.Lock()
	errs = append(errs, c.periodicAsyncErrs...)
	c.periodicAsyncErrs = nil
	terminalErr := errors.Join(errs...)
	c.periodicShutdownErr = terminalErr
	c.periodicShutdownDone = true
	c.periodicMu.Unlock()
	return terminalErr, failures
}

// issuePeriodicShutdownStops starts at most one stop per producer. Stops are
// detached from the attempt context so a retry never re-signals a producer that
// is still shutting down.
func (c *Controller) issuePeriodicShutdownStops(targets []*periodicShutdownTarget) {
	var toStart []*periodicShutdownTarget
	c.periodicMu.Lock()
	for _, target := range targets {
		if target.stopStarted {
			continue
		}
		target.stopStarted = true
		target.stopDone = make(chan struct{})
		toStart = append(toStart, target)
	}
	c.periodicMu.Unlock()

	for _, target := range toStart {
		go func(target *periodicShutdownTarget) {
			// The stop signal is deliberately detached from the attempt
			// context: a shutdown attempt may give up on its deadline, but the
			// signal it already delivered must stay delivered exactly once.
			err := stopOrClosePeriodicRunner(context.Background(), target.runner)
			c.periodicMu.Lock()
			target.stopErr = err
			close(target.stopDone)
			c.periodicMu.Unlock()
		}(target)
	}
}

// stopOrClosePeriodicRunner signals one producer. Runners with a separate
// Stop/Wait lifecycle are only stopped here; runners that expose nothing but
// Close have no separate join, so Close is their single ownership hand-off.
func stopOrClosePeriodicRunner(ctx context.Context, runner periodicRunner) error {
	switch runner.(type) {
	case contextStopPeriodicRunner, joinablePeriodicRunner:
		return stopPeriodicRunnerContext(ctx, runner)
	default:
		return closePeriodicRunnerContext(ctx, runner)
	}
}

// joinPeriodicShutdownTargets joins every producer. Each join first waits for
// that producer's stop signal to be acknowledged, then waits for the producer
// itself. The underlying join is not bounded by the attempt context, so a retry
// observes the real exit instead of a cached deadline error.
func (c *Controller) joinPeriodicShutdownTargets(ctx context.Context, targets []*periodicShutdownTarget) error {
	if err := c.waitPeriodicShutdownStops(ctx, targets); err != nil {
		return err
	}
	c.issuePeriodicShutdownJoins(targets)
	return c.waitPeriodicShutdownJoins(ctx, targets)
}

func (c *Controller) waitPeriodicShutdownStops(ctx context.Context, targets []*periodicShutdownTarget) error {
	for _, target := range targets {
		c.periodicMu.Lock()
		done := target.stopDone
		c.periodicMu.Unlock()
		if done == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
	return nil
}

func (c *Controller) issuePeriodicShutdownJoins(targets []*periodicShutdownTarget) {
	var toStart []*periodicShutdownTarget
	c.periodicMu.Lock()
	for _, target := range targets {
		if target.joinStarted {
			continue
		}
		target.joinStarted = true
		target.joinDone = make(chan struct{})
		toStart = append(toStart, target)
	}
	c.periodicMu.Unlock()

	for _, target := range toStart {
		go func(target *periodicShutdownTarget) {
			err := waitPeriodicRunnerContext(context.Background(), target.runner)
			c.periodicMu.Lock()
			target.joinErr = err
			close(target.joinDone)
			c.periodicMu.Unlock()
		}(target)
	}
}

func (c *Controller) waitPeriodicShutdownJoins(ctx context.Context, targets []*periodicShutdownTarget) error {
	for _, target := range targets {
		c.periodicMu.Lock()
		done := target.joinDone
		c.periodicMu.Unlock()
		if done == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
	return nil
}

// waitPeriodicJoinGroup waits for every outstanding asynchronous periodic
// operation (launches and replacement cleanups) with a deadline.
func (c *Controller) waitPeriodicJoinGroup(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		c.periodicJoinWG.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

// periodicShutdownFailures reports producer-level stop and join errors. An
// error that only reflects the attempt's own deadline is reported by the
// attempt instead.
func (c *Controller) periodicShutdownFailures(targets []*periodicShutdownTarget) []periodicCloseFailure {
	c.periodicMu.Lock()
	defer c.periodicMu.Unlock()
	var failures []periodicCloseFailure
	for _, target := range targets {
		if target.joinErr != nil && !errors.Is(target.joinErr, context.Canceled) {
			failures = append(failures, periodicCloseFailure{tag: target.tag, err: target.joinErr})
			continue
		}
		if target.stopErr != nil {
			failures = append(failures, periodicCloseFailure{tag: target.tag, err: target.stopErr})
		}
	}
	return failures
}

// periodicShutdownAttemptFailure builds the typed error for a shutdown attempt
// that did not finish, naming the producers that had not exited.
func (c *Controller) periodicShutdownAttemptFailure(err error, targets []*periodicShutdownTarget) error {
	c.periodicMu.Lock()
	pending := make([]string, 0, len(targets))
	for _, target := range targets {
		if target.joinDone == nil || !channelClosed(target.joinDone) {
			pending = append(pending, target.tag)
		}
	}
	c.periodicMu.Unlock()
	if len(pending) == 0 {
		return err
	}
	return &periodicShutdownError{pending: pending, err: err}
}

func channelClosed(ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
func (c *Controller) startControllerPeriodicTasks(nodeInfo *api.NodeInfo) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return c.startControllerPeriodicTasksContext(ctx, nodeInfo)
}

func (c *Controller) startControllerPeriodicTasksContext(ctx context.Context, nodeInfo *api.NodeInfo) error {
	return c.startControllerPeriodicTasksSnapshotContext(ctx, api.NormalizeNodeInfo(nodeInfo))
}

func (c *Controller) startControllerPeriodicTasksSnapshotContext(ctx context.Context, snapshot *api.NodeSnapshot) error {
	schedule := materializeControllerRuntimeSchedule(c.config.UpdatePeriodic, c.currentBaseConfig())

	if err := c.startOrReplacePeriodicTaskContext(ctx, periodicTaskNodeMonitor, schedule.pullInterval, c.nodeInfoMonitorContext, true); err != nil {
		return err
	}
	if err := c.startOrReplacePeriodicTaskContext(ctx, periodicTaskUserMonitor, schedule.pushInterval, c.userInfoMonitorContext, true); err != nil {
		return err
	}
	if snapshot != nil && snapshot.EnableTLS && c.config.EnableREALITY == false {
		if err := c.startOrReplacePeriodicTaskContext(ctx, periodicTaskCertMonitor, time.Duration(c.config.UpdatePeriodic)*time.Second*60, c.certMonitorPeriodicContext, true); err != nil {
			return err
		}
	}
	return nil
}

type controllerRuntimeSchedule struct {
	pullInterval time.Duration
	pushInterval time.Duration
}

func materializeControllerRuntimeSchedule(localUpdatePeriodic int, baseConfig *api.BaseConfig) controllerRuntimeSchedule {
	localInterval := time.Duration(localUpdatePeriodic) * time.Second
	schedule := controllerRuntimeSchedule{
		pullInterval: localInterval,
		pushInterval: localInterval,
	}
	if baseConfig == nil {
		return schedule
	}

	if normalizedPull := normalizeBaseConfigInterval(baseConfig.PullInterval, minBaseConfigPullInterval); normalizedPull > 0 {
		schedule.pullInterval = time.Duration(normalizedPull) * time.Second
	}
	if normalizedPush := normalizeBaseConfigInterval(baseConfig.PushInterval, minBaseConfigPushInterval); normalizedPush > 0 {
		schedule.pushInterval = time.Duration(normalizedPush) * time.Second
	}
	return schedule
}

func (c *Controller) currentBaseConfig() *api.BaseConfig {
	provider, ok := c.apiClient.(api.BaseConfigProvider)
	if !ok {
		return nil
	}
	return cloneBaseConfig(provider.GetBaseConfig())
}

func normalizeBaseConfigInterval(seconds, min int) int {
	if seconds <= 0 {
		return 0
	}
	if seconds < min {
		return min
	}
	return seconds
}

func (c *Controller) applyBaseConfig(baseConfig *api.BaseConfig) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return c.applyBaseConfigContext(ctx, baseConfig)
}

func (c *Controller) applyBaseConfigContext(ctx context.Context, baseConfig *api.BaseConfig) error {
	if baseConfig == nil {
		return nil
	}

	if pullInterval := normalizeBaseConfigInterval(baseConfig.PullInterval, minBaseConfigPullInterval); pullInterval > 0 {
		if err := c.startOrReplacePeriodicTaskContext(ctx, periodicTaskNodeMonitor, time.Duration(pullInterval)*time.Second, c.nodeInfoMonitorContext, false); err != nil {
			return err
		}
	}
	if pushInterval := normalizeBaseConfigInterval(baseConfig.PushInterval, minBaseConfigPushInterval); pushInterval > 0 {
		if err := c.startOrReplacePeriodicTaskContext(ctx, periodicTaskUserMonitor, time.Duration(pushInterval)*time.Second, c.userInfoMonitorContext, false); err != nil {
			return err
		}
	}
	return nil
}
