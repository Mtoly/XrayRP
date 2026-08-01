package hysteria2

import (
	"errors"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/service"
)

func TestObservabilitySnapshotReportsFailedOwnedCleanup(t *testing.T) {
	runtime := &fakeRuntimeServer{closeErr: errors.New("close failed")}
	h := &Hysteria2Service{
		state:  stateFailed,
		server: runtime,
		cleanupRuntimes: []reloadRuntime{{
			runtime: runtime,
		}},
	}
	h.health.RecordFailure(service.FailureStageCleanup, time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC))
	snapshot := h.ObservabilitySnapshot()
	if snapshot.Lifecycle != service.RuntimeLifecycleFailedOwned || !snapshot.CleanupPending || snapshot.LastFailureStage != service.FailureStageCleanup {
		t.Fatalf("Hysteria2 snapshot = %#v", snapshot)
	}
}
