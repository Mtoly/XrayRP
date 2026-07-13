package specialruntime

import "errors"

// Task is the lifecycle surface shared by controller periodic tasks.
type Task interface {
	Start() error
	Close() error
}

type stoppableTask interface {
	Stop() error
}

type waitableTask interface {
	Wait() error
}

// RuntimeShutdown keeps adapter-specific runtime mechanics behind callbacks
// while Tasks owns their ordering relative to periodic work.
type RuntimeShutdown struct {
	Stop func() error
	Join func() error
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

// Start starts tasks in registration order. A failure rolls back every task
// whose Start was attempted and shuts down the runtime in rollback order.
func (t *Tasks) Start(runtime RuntimeShutdown) error {
	for i := range t.tasks {
		if err := t.tasks[i].Start(); err != nil {
			return errors.Join(err, t.rollbackThrough(i, runtime))
		}
	}
	return nil
}

// Rollback stops and joins the runtime before waiting for task callbacks.
func (t *Tasks) Rollback(runtime RuntimeShutdown) error {
	return t.rollbackThrough(len(t.tasks)-1, runtime)
}

// Close stops task producers, stops the runtime, waits for task callbacks,
// then joins runtime-owned background work.
func (t *Tasks) Close(runtime RuntimeShutdown) error {
	var errs []error
	errs = append(errs, t.stopThrough(len(t.tasks)-1)...)
	errs = append(errs, call(runtime.Stop))
	errs = append(errs, t.waitThrough(len(t.tasks)-1)...)
	errs = append(errs, call(runtime.Join))
	return errors.Join(errs...)
}

func (t *Tasks) rollbackThrough(last int, runtime RuntimeShutdown) error {
	var errs []error
	errs = append(errs, t.stopThrough(last)...)
	errs = append(errs, call(runtime.Stop), call(runtime.Join))
	errs = append(errs, t.waitThrough(last)...)
	return errors.Join(errs...)
}

func (t *Tasks) stopThrough(last int) []error {
	var errs []error
	for i := last; i >= 0; i-- {
		if task, ok := t.tasks[i].(stoppableTask); ok {
			errs = append(errs, task.Stop())
		} else {
			errs = append(errs, t.tasks[i].Close())
		}
	}
	return errs
}

func (t *Tasks) waitThrough(last int) []error {
	var errs []error
	for i := last; i >= 0; i-- {
		if task, ok := t.tasks[i].(waitableTask); ok {
			errs = append(errs, task.Wait())
		}
	}
	return errs
}

func call(operation func() error) error {
	if operation == nil {
		return nil
	}
	return operation()
}
