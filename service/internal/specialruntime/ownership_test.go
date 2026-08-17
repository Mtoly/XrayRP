package specialruntime

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestCleanupOwnedContextRetainsFailuresAndContinues(t *testing.T) {
	firstErr := errors.New("first cleanup failed")
	thirdErr := errors.New("third cleanup failed")
	var seen []int
	remaining, err := CleanupOwnedContext(context.Background(), []int{1, 2, 3}, func(_ context.Context, item int) error {
		seen = append(seen, item)
		switch item {
		case 1:
			return firstErr
		case 3:
			return thirdErr
		default:
			return nil
		}
	})

	if !errors.Is(err, firstErr) || !errors.Is(err, thirdErr) {
		t.Fatalf("CleanupOwnedContext() error = %v, want both cleanup errors", err)
	}
	if want := []int{1, 3}; !reflect.DeepEqual(remaining, want) {
		t.Fatalf("remaining = %v, want %v", remaining, want)
	}
	if want := []int{1, 2, 3}; !reflect.DeepEqual(seen, want) {
		t.Fatalf("seen = %v, want %v", seen, want)
	}
}

func TestCleanupOwnedContextRetainsAllResourcesWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var called bool
	remaining, err := CleanupOwnedContext(ctx, []string{"a", "b"}, func(_ context.Context, _ string) error {
		called = true
		return nil
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CleanupOwnedContext() error = %v, want context.Canceled", err)
	}
	if called {
		t.Fatal("cleanup callback ran after context cancellation")
	}
	if want := []string{"a", "b"}; !reflect.DeepEqual(remaining, want) {
		t.Fatalf("remaining = %v, want %v", remaining, want)
	}
}
