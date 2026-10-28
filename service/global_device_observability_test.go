package service

import (
	"testing"
	"time"
)

func TestReadinessReportsGlobalDeviceDegradation(t *testing.T) {
	now := time.Now()
	snapshot := RuntimeSnapshot{
		Kind: RuntimeKindController, Lifecycle: RuntimeLifecycleRunning,
		LastSuccessfulSync: now, GlobalDeviceDegraded: true,
	}
	state := EvaluateReadiness(snapshot, now, time.Minute)
	if !state.Ready || !state.Degraded || len(state.Reasons) != 1 || state.Reasons[0] != ReadinessReasonGlobalDevice {
		t.Fatalf("Redis degradation readiness = %#v", state)
	}
	snapshot.GlobalDeviceDegraded = false
	state = EvaluateReadiness(snapshot, now, time.Minute)
	if !state.Ready || state.Degraded || len(state.Reasons) != 0 {
		t.Fatalf("recovered readiness = %#v", state)
	}
}
