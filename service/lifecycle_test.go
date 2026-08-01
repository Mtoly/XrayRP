package service

import (
	"context"
	"testing"
	"time"
)

func TestWithDefaultTimeoutCapsLongerParentDeadline(t *testing.T) {
	parent, parentCancel := context.WithTimeout(context.Background(), time.Hour)
	defer parentCancel()

	started := time.Now()
	ctx, cancel := WithDefaultTimeout(parent, 30*time.Second)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("WithDefaultTimeout() did not install a deadline")
	}
	if remaining := deadline.Sub(started); remaining <= 0 || remaining > 31*time.Second {
		t.Fatalf("deadline remaining = %s, want default timeout cap", remaining)
	}
}

func TestWithDefaultTimeoutPreservesEarlierParentDeadline(t *testing.T) {
	parent, parentCancel := context.WithTimeout(context.Background(), time.Second)
	defer parentCancel()

	started := time.Now()
	ctx, cancel := WithDefaultTimeout(parent, 30*time.Second)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("WithDefaultTimeout() lost the parent deadline")
	}
	if remaining := deadline.Sub(started); remaining <= 0 || remaining > 2*time.Second {
		t.Fatalf("deadline remaining = %s, want earlier parent deadline", remaining)
	}
}
