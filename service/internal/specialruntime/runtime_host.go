package specialruntime

import (
	"context"
	"errors"

	"github.com/Mtoly/XrayRP/service"
)

// RuntimeHostCallbacks adapts protocol-specific runtime mechanics to the
// lifecycle ordering owned by RuntimeHost.
type RuntimeHostCallbacks struct {
	Start func(context.Context) error
	Stop  func(context.Context) error
	Join  func(context.Context) error
}

// RuntimeHost composes one runtime with its periodic tasks. It deliberately
// does not own replacement policy, configuration publication, or protocol
// resources outside the runtime/task lifecycle.
type RuntimeHost struct {
	tasks     *Tasks
	callbacks RuntimeHostCallbacks
}

func NewRuntimeHost(tasks *Tasks, callbacks RuntimeHostCallbacks) *RuntimeHost {
	return &RuntimeHost{tasks: tasks, callbacks: callbacks}
}

// StartContext starts the runtime to readiness when a Start callback is
// provided, then starts periodic tasks. Without a Start callback the caller is
// asserting that the runtime already reached readiness. A runtime-start
// failure is cleaned up with a detached close context so a canceled start does
// not strand an owned runtime.
func (h *RuntimeHost) StartContext(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if h.callbacks.Start != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := h.callbacks.Start(ctx); err != nil {
			cleanupCtx, cancel := service.CleanupContext(ctx)
			cleanupErr := h.closeRuntimeContext(cleanupCtx)
			cancel()
			return &runtimeStartFailure{startErr: err, cleanupErr: cleanupErr}
		}
	}
	if h.tasks == nil {
		return nil
	}
	return h.tasks.StartContext(ctx, h.runtimeShutdown())
}

// StopProducersContext stops periodic task producers without touching the
// runtime. Callers use this before waiting for synchronization and acquiring
// their replacement gate.
func (h *RuntimeHost) StopProducersContext(ctx context.Context) error {
	if h == nil || h.tasks == nil {
		return nil
	}
	return h.tasks.StopContext(ctx)
}

// CloseStoppedContext finishes shutdown after producers have already stopped.
// Tasks owns the shared stop/wait/join ordering when tasks are present; a
// taskless host still closes and joins the runtime in the same order.
func (h *RuntimeHost) CloseStoppedContext(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if h.tasks != nil {
		return h.tasks.CloseStoppedContext(ctx, h.runtimeShutdown())
	}
	return h.closeRuntimeContext(ctx)
}

// RollbackContext reverses task and runtime startup when a later activation
// step fails.
func (h *RuntimeHost) RollbackContext(ctx context.Context) error {
	if h == nil {
		return nil
	}
	cleanupCtx, cancel := service.CleanupContext(ctx)
	defer cancel()
	if h.tasks != nil {
		return h.tasks.RollbackContext(cleanupCtx, h.runtimeShutdown())
	}
	return h.closeRuntimeContext(cleanupCtx)
}

func (h *RuntimeHost) runtimeShutdown() RuntimeShutdown {
	return RuntimeShutdown{
		StopContext: h.callbacks.Stop,
		JoinContext: h.callbacks.Join,
	}
}

func (h *RuntimeHost) closeRuntimeContext(ctx context.Context) error {
	return errors.Join(callContext(h.callbacks.Stop, ctx), callContext(h.callbacks.Join, ctx))
}

func callContext(operation func(context.Context) error, ctx context.Context) error {
	if operation == nil {
		return nil
	}
	return operation(ctx)
}
