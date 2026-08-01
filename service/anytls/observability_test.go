package anytls

import (
	"errors"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/service"
)

func TestObservabilitySnapshotReportsFailedOwnedCleanup(t *testing.T) {
	runtime := &fakeRuntimeInstance{closeErr: errors.New("close failed")}
	s := &AnyTLSService{
		state:           stateFailed,
		box:             runtime,
		cleanupRuntimes: []runtimeInstance{runtime},
	}
	s.health.RecordFailure(service.FailureStageCleanup, time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC))
	snapshot := s.ObservabilitySnapshot()
	if snapshot.Lifecycle != service.RuntimeLifecycleFailedOwned || !snapshot.CleanupPending || snapshot.LastFailureStage != service.FailureStageCleanup {
		t.Fatalf("AnyTLS snapshot = %#v", snapshot)
	}
}
