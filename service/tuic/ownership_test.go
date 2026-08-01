package tuic

import (
	"errors"
	"testing"
)

func TestCloseFailureRetainsRuntimeOwnershipAndRetries(t *testing.T) {
	closeErr := errors.New("runtime close failed")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeInstance{events: events, closeErr: closeErr}
	service := &TuicService{
		state:        stateRunning,
		box:          runtime,
		closeRuntime: defaultCloseRuntime,
	}

	if err := service.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("first Close() error = %v, want %v", err, closeErr)
	}
	if service.state != stateFailed || service.closed || service.box != runtime {
		t.Fatalf("failed Close lost ownership: state=%v closed=%v box=%v", service.state, service.closed, service.box)
	}

	runtime.closeErr = nil
	if err := service.Close(); err != nil {
		t.Fatalf("retry Close() error = %v", err)
	}
	if service.state != stateStopped || !service.closed || service.box != nil {
		t.Fatalf("successful retry state: state=%v closed=%v box=%v", service.state, service.closed, service.box)
	}
	before := len(events.snapshot())
	if err := service.Close(); err != nil {
		t.Fatalf("idempotent Close() error = %v", err)
	}
	if got := len(events.snapshot()); got != before {
		t.Fatalf("idempotent Close repeated runtime cleanup: before=%d after=%d", before, got)
	}
}

func TestStartCleanupFailureRetainsCandidateForCloseRetry(t *testing.T) {
	startErr := errors.New("runtime start failed")
	closeErr := errors.New("runtime cleanup failed")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeInstance{events: events, startErr: startErr, closeErr: closeErr}
	service := newStartTestService(events, runtime)

	err := service.Start()
	if !errors.Is(err, startErr) || !errors.Is(err, closeErr) {
		t.Fatalf("Start() error = %v, want start and cleanup errors", err)
	}
	if service.state != stateFailed || service.box != runtime || service.closed {
		t.Fatalf("failed Start lost candidate ownership: state=%v box=%v closed=%v", service.state, service.box, service.closed)
	}

	runtime.closeErr = nil
	if err := service.Close(); err != nil {
		t.Fatalf("Close() retry error = %v", err)
	}
	if service.state != stateStopped || service.box != nil || !service.closed {
		t.Fatalf("retry state: state=%v box=%v closed=%v", service.state, service.box, service.closed)
	}
}
