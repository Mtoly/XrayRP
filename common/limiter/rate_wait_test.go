package limiter

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"golang.org/x/time/rate"
)

type recordingByteLimiter struct {
	burst     int
	calls     []int
	failAfter int
	err       error
}

func (l *recordingByteLimiter) Burst() int {
	return l.burst
}

func (l *recordingByteLimiter) WaitN(ctx context.Context, n int) error {
	l.calls = append(l.calls, n)
	if err := ctx.Err(); err != nil {
		return err
	}
	if l.failAfter > 0 && len(l.calls) >= l.failAfter {
		return l.err
	}
	return nil
}

func TestWaitNChunksRequestsAtBurst(t *testing.T) {
	limiter := &recordingByteLimiter{burst: 3}

	if err := waitN(context.Background(), limiter, 8); err != nil {
		t.Fatalf("WaitN() error = %v", err)
	}
	if want := []int{3, 3, 2}; !reflect.DeepEqual(limiter.calls, want) {
		t.Fatalf("WaitN() chunks = %v, want %v", limiter.calls, want)
	}
}

func TestWaitNStopsAtFirstFailure(t *testing.T) {
	waitErr := errors.New("wait failed")
	limiter := &recordingByteLimiter{
		burst:     3,
		failAfter: 2,
		err:       waitErr,
	}

	err := waitN(context.Background(), limiter, 8)
	if !errors.Is(err, waitErr) {
		t.Fatalf("WaitN() error = %v, want %v", err, waitErr)
	}
	if want := []int{3, 3}; !reflect.DeepEqual(limiter.calls, want) {
		t.Fatalf("WaitN() calls = %v, want %v", limiter.calls, want)
	}
}

func TestWaitNHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	limiter := &recordingByteLimiter{burst: 3}

	err := waitN(ctx, limiter, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitN() error = %v, want context.Canceled", err)
	}
}

func TestWaitNRejectsInvalidBurstWithoutCallingLimiter(t *testing.T) {
	limiter := &recordingByteLimiter{burst: 0}

	if err := waitN(context.Background(), limiter, 1); err == nil {
		t.Fatal("WaitN() error = nil, want invalid burst error")
	}
	if len(limiter.calls) != 0 {
		t.Fatalf("WaitN() called limiter with invalid burst: %v", limiter.calls)
	}
}

func TestWaitNAllowsNilRateLimiter(t *testing.T) {
	var limiter *rate.Limiter
	if err := WaitN(context.Background(), limiter, 1); err != nil {
		t.Fatalf("WaitN(nil) error = %v", err)
	}
}
