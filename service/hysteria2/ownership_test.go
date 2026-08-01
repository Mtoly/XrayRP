package hysteria2

import (
	"errors"
	"testing"
)

func TestCloseFailureRetainsRuntimeOwnershipAndRetries(t *testing.T) {
	closeErr := errors.New("runtime close failed")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events, closeErr: closeErr}
	service := &Hysteria2Service{
		state:        stateRunning,
		server:       runtime,
		closeRuntime: defaultCloseRuntime,
	}

	if err := service.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("first Close() error = %v, want %v", err, closeErr)
	}
	if service.state != stateFailed || service.closed || service.server != runtime {
		t.Fatalf("failed Close lost ownership: state=%v closed=%v server=%v", service.state, service.closed, service.server)
	}

	runtime.closeErr = nil
	if err := service.Close(); err != nil {
		t.Fatalf("retry Close() error = %v", err)
	}
	if service.state != stateStopped || !service.closed || service.server != nil {
		t.Fatalf("successful retry state: state=%v closed=%v server=%v", service.state, service.closed, service.server)
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
	serveErr := errors.New("runtime serve failed")
	closeErr := errors.New("runtime cleanup failed")
	events := &lifecycleEvents{}
	runtime := &fakeRuntimeServer{events: events, serveErr: serveErr, closeErr: closeErr}
	service := newStartTestService(events, runtime)
	service.serveHandshake = func(start func(), _ <-chan struct{}, result <-chan error) error {
		start()
		return <-result
	}

	err := service.Start()
	if !errors.Is(err, serveErr) || !errors.Is(err, closeErr) {
		t.Fatalf("Start() error = %v, want serve and cleanup errors", err)
	}
	if service.state != stateFailed || service.server != runtime || service.closed {
		t.Fatalf("failed Start lost candidate ownership: state=%v server=%v closed=%v", service.state, service.server, service.closed)
	}

	runtime.closeErr = nil
	if err := service.Close(); err != nil {
		t.Fatalf("Close() retry error = %v", err)
	}
	if service.state != stateStopped || service.server != nil || !service.closed {
		t.Fatalf("retry state: state=%v server=%v closed=%v", service.state, service.server, service.closed)
	}
}
