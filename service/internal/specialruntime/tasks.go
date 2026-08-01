package specialruntime

import (
	"context"
	"errors"

	"github.com/Mtoly/XrayRP/service"
)

type taskStartFailure struct {
	startErr   error
	cleanupErr error
}

func (e *taskStartFailure) Error() string {
	return errors.Join(e.startErr, e.cleanupErr).Error()
}

func (e *taskStartFailure) Unwrap() []error {
	result := make([]error, 0, 2)
	if e.startErr != nil {
		result = append(result, e.startErr)
	}
	if e.cleanupErr != nil {
		result = append(result, e.cleanupErr)
	}
	return result
}

// StartCleanupFailed reports whether Tasks.Start failed to release all
// resources it attempted to roll back.
func StartCleanupFailed(err error) bool {
	var failure *taskStartFailure
	return errors.As(err, &failure) && failure.cleanupErr != nil
}

// Task is the lifecycle surface shared by controller periodic tasks.
type Task interface {
	Start() error
	Close() error
}

type contextStartTask interface {
	StartContext(context.Context) error
}

type stoppableTask interface {
	Stop() error
}

type contextStoppableTask interface {
	StopContext(context.Context) error
}

type waitableTask interface {
	Wait() error
}

type contextWaitableTask interface {
	WaitContext(context.Context) error
}

type contextCloseTask interface {
	CloseContext(context.Context) error
}

// RuntimeShutdown keeps adapter-specific runtime mechanics behind callbacks
// while Tasks owns their ordering relative to periodic work.
type RuntimeShutdown struct {
	Stop        func() error
	Join        func() error
	StopContext func(context.Context) error
	JoinContext func(context.Context) error
}

// Tasks owns ordered startup and reverse-order shutdown for periodic work.
type Tasks struct {
	tasks []Task
}

func NewTasks() *Tasks {
	return &Tasks{}
}

func (t *Tasks) Add(task Task) {
	if task != nil {
		t.tasks = append(t.tasks, task)
	}
}

func (t *Tasks) Start(runtime RuntimeShutdown) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return t.StartContext(ctx, runtime)
}

// StartContext starts tasks in registration order. A failure rolls back every
// task whose Start was attempted and shuts down the runtime in rollback order.
func (t *Tasks) StartContext(ctx context.Context, runtime RuntimeShutdown) error {
	for i := range t.tasks {
		if err := startTaskContext(ctx, t.tasks[i]); err != nil {
			cleanupCtx, cancel := service.CleanupContext(ctx)
			cleanupErr := t.rollbackThroughContext(cleanupCtx, i, runtime)
			cancel()
			return &taskStartFailure{startErr: err, cleanupErr: cleanupErr}
		}
	}
	return nil
}

func (t *Tasks) Rollback(runtime RuntimeShutdown) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return t.RollbackContext(ctx, runtime)
}

func (t *Tasks) RollbackContext(ctx context.Context, runtime RuntimeShutdown) error {
	return t.rollbackThroughContext(ctx, len(t.tasks)-1, runtime)
}

func (t *Tasks) StopContext(ctx context.Context) error {
	return errors.Join(t.stopThroughContext(ctx, len(t.tasks)-1)...)
}

func (t *Tasks) Close(runtime RuntimeShutdown) error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return t.CloseContext(ctx, runtime)
}

// CloseContext stops task producers, stops the runtime, waits for task
// callbacks, then joins runtime-owned background work.
func (t *Tasks) CloseContext(ctx context.Context, runtime RuntimeShutdown) error {
	return errors.Join(t.StopContext(ctx), t.CloseStoppedContext(ctx, runtime))
}

// CloseStoppedContext completes shutdown after producers have already been
// stopped, preserving stop errors without invoking legacy task Close twice.
func (t *Tasks) CloseStoppedContext(ctx context.Context, runtime RuntimeShutdown) error {
	var errs []error
	errs = append(errs, callRuntimeStopContext(ctx, runtime))
	errs = append(errs, t.waitThroughContext(ctx, len(t.tasks)-1)...)
	errs = append(errs, callRuntimeJoinContext(ctx, runtime))
	return errors.Join(errs...)
}

func (t *Tasks) rollbackThroughContext(ctx context.Context, last int, runtime RuntimeShutdown) error {
	var errs []error
	errs = append(errs, t.stopThroughContext(ctx, last)...)
	errs = append(errs, callRuntimeStopContext(ctx, runtime), callRuntimeJoinContext(ctx, runtime))
	errs = append(errs, t.waitThroughContext(ctx, last)...)
	return errors.Join(errs...)
}

func (t *Tasks) stopThroughContext(ctx context.Context, last int) []error {
	var errs []error
	for i := last; i >= 0; i-- {
		switch task := t.tasks[i].(type) {
		case contextStoppableTask:
			errs = append(errs, task.StopContext(ctx))
		case stoppableTask:
			errs = append(errs, task.Stop())
		case contextCloseTask:
			errs = append(errs, task.CloseContext(ctx))
		default:
			errs = append(errs, t.tasks[i].Close())
		}
	}
	return errs
}

func (t *Tasks) waitThroughContext(ctx context.Context, last int) []error {
	var errs []error
	for i := last; i >= 0; i-- {
		switch task := t.tasks[i].(type) {
		case contextWaitableTask:
			errs = append(errs, task.WaitContext(ctx))
		case waitableTask:
			errs = append(errs, task.Wait())
		}
	}
	return errs
}

func startTaskContext(ctx context.Context, task Task) error {
	if contextual, ok := task.(contextStartTask); ok {
		return contextual.StartContext(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return task.Start()
}

func callRuntimeStopContext(ctx context.Context, runtime RuntimeShutdown) error {
	if runtime.StopContext != nil {
		return runtime.StopContext(ctx)
	}
	return call(runtime.Stop)
}

func callRuntimeJoinContext(ctx context.Context, runtime RuntimeShutdown) error {
	if runtime.JoinContext != nil {
		return runtime.JoinContext(ctx)
	}
	return call(runtime.Join)
}

func call(operation func() error) error {
	if operation == nil {
		return nil
	}
	return operation()
}
