package limiter

import (
	"context"
	"fmt"

	"golang.org/x/time/rate"
)

type byteLimiter interface {
	Burst() int
	WaitN(context.Context, int) error
}

// WaitN admits count bytes without asking the limiter for more than its burst
// in one operation. The first wait failure stops admission.
func WaitN(ctx context.Context, limiter *rate.Limiter, count uint64) error {
	if limiter == nil || count == 0 {
		return nil
	}
	return waitN(ctx, limiter, count)
}

func waitN(ctx context.Context, limiter byteLimiter, count uint64) error {
	if limiter == nil || count == 0 {
		return nil
	}

	burst := limiter.Burst()
	if burst <= 0 {
		return fmt.Errorf("rate limiter burst must be positive: %d", burst)
	}

	for remaining := count; remaining > 0; {
		chunk := uint64(burst)
		if remaining < chunk {
			chunk = remaining
		}
		if err := limiter.WaitN(ctx, int(chunk)); err != nil {
			return err
		}
		remaining -= chunk
	}
	return nil
}
