package specialruntime

import (
	"context"
	"errors"
)

// CleanupOwnedContext releases owned resources in acquisition order and keeps
// every resource whose cleanup was skipped or failed for a later retry.
func CleanupOwnedContext[T any](ctx context.Context, owned []T, cleanup func(context.Context, T) error) ([]T, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cleanup == nil {
		return append([]T(nil), owned...), errors.New("specialruntime: cleanup callback is nil")
	}

	remaining := make([]T, 0, len(owned))
	var cleanupErr error
	for _, item := range owned {
		if err := ctx.Err(); err != nil {
			remaining = append(remaining, item)
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		if err := cleanup(ctx, item); err != nil {
			remaining = append(remaining, item)
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	return remaining, cleanupErr
}
