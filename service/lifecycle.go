package service

import (
	"context"
	"time"
)

const (
	DefaultStartTimeout = 2 * time.Minute
	DefaultCloseTimeout = 30 * time.Second
	DefaultJoinTimeout  = 30 * time.Second
	DefaultSyncTimeout  = 30 * time.Second
)

type ContextStarter interface {
	StartContext(context.Context) error
}

type ContextCloser interface {
	CloseContext(context.Context) error
}

type ContextJoiner interface {
	JoinContext(context.Context) error
}

func WithDefaultTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func CleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), DefaultCloseTimeout)
}

func StartContext(ctx context.Context, runtime Service) error {
	if runtime == nil {
		return nil
	}
	ctx, cancel := WithDefaultTimeout(ctx, DefaultStartTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if contextual, ok := runtime.(ContextStarter); ok {
		return contextual.StartContext(ctx)
	}
	return runtime.Start()
}

func CloseContext(ctx context.Context, runtime Service) error {
	if runtime == nil {
		return nil
	}
	ctx, cancel := WithDefaultTimeout(ctx, DefaultCloseTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if contextual, ok := runtime.(ContextCloser); ok {
		return contextual.CloseContext(ctx)
	}
	return runtime.Close()
}

func JoinContext(ctx context.Context, owner any) error {
	if owner == nil {
		return nil
	}
	ctx, cancel := WithDefaultTimeout(ctx, DefaultJoinTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if contextual, ok := owner.(ContextJoiner); ok {
		return contextual.JoinContext(ctx)
	}
	return nil
}
