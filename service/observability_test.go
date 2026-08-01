package service

import (
	"reflect"
	"testing"
	"time"
)

func TestEvaluateReadinessMatrix(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Minute)
	stale := now.Add(-10 * time.Minute)

	tests := []struct {
		name         string
		snapshot     RuntimeSnapshot
		wantReady    bool
		wantDegraded bool
		wantReasons  []ReadinessReason
	}{
		{
			name: "normal",
			snapshot: RuntimeSnapshot{
				Kind:      RuntimeKindPanel,
				Lifecycle: RuntimeLifecycleRunning,
				Children: []RuntimeSnapshot{{
					Kind:               RuntimeKindController,
					Lifecycle:          RuntimeLifecycleRunning,
					LastSuccessfulSync: fresh,
					WebSocket:          WebSocketConnected,
				}},
			},
			wantReady: true,
		},
		{
			name: "websocket degraded remains ready while sync is fresh",
			snapshot: RuntimeSnapshot{
				Kind:      RuntimeKindPanel,
				Lifecycle: RuntimeLifecycleRunning,
				Children: []RuntimeSnapshot{{
					Kind:               RuntimeKindController,
					Lifecycle:          RuntimeLifecycleRunning,
					LastSuccessfulSync: fresh,
					WebSocket:          WebSocketDegraded,
				}},
			},
			wantReady:    true,
			wantDegraded: true,
		},
		{
			name: "failed owned",
			snapshot: RuntimeSnapshot{
				Kind:           RuntimeKindPanel,
				Lifecycle:      RuntimeLifecycleFailedOwned,
				CleanupPending: true,
			},
			wantReasons: []ReadinessReason{
				ReadinessReasonCleanupPending,
				ReadinessReasonLifecycle,
			},
		},
		{
			name: "stale sync",
			snapshot: RuntimeSnapshot{
				Kind:               RuntimeKindController,
				Lifecycle:          RuntimeLifecycleRunning,
				LastSuccessfulSync: stale,
			},
			wantReasons: []ReadinessReason{ReadinessReasonSyncStale},
		},
		{
			name: "shutdown",
			snapshot: RuntimeSnapshot{
				Kind:      RuntimeKindPanel,
				Lifecycle: RuntimeLifecycleClosed,
			},
			wantReasons: []ReadinessReason{ReadinessReasonShutdown},
		},
		{
			name: "expired certificate",
			snapshot: RuntimeSnapshot{
				Kind:                 RuntimeKindController,
				Lifecycle:            RuntimeLifecycleRunning,
				LastSuccessfulSync:   fresh,
				CertificateExpiresAt: now.Add(-time.Second),
			},
			wantReasons: []ReadinessReason{ReadinessReasonCertificateExpired},
		},
		{
			name: "traffic backlog is degraded but ready",
			snapshot: RuntimeSnapshot{
				Kind:                 RuntimeKindController,
				Lifecycle:            RuntimeLifecycleRunning,
				LastSuccessfulSync:   fresh,
				TrafficReportBacklog: 3,
			},
			wantReady:    true,
			wantDegraded: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := EvaluateReadiness(test.snapshot, now, 3*time.Minute)
			if got.Ready != test.wantReady || got.Degraded != test.wantDegraded {
				t.Fatalf("readiness = ready:%t degraded:%t, want ready:%t degraded:%t", got.Ready, got.Degraded, test.wantReady, test.wantDegraded)
			}
			if !reflect.DeepEqual(got.Reasons, test.wantReasons) {
				t.Fatalf("reasons = %v, want %v", got.Reasons, test.wantReasons)
			}
		})
	}
}

func TestRuntimeHealthStateRetainsLatestFailureAndSuccessfulSync(t *testing.T) {
	var state RuntimeHealthState
	first := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	second := first.Add(time.Minute)
	state.RecordFailure(FailureStageWebSocket, first)
	state.RecordFailure(FailureStageSync, second)
	state.RecordFailure(FailureStageStart, first)
	state.RecordSuccessfulSync(first)
	state.RecordSuccessfulSync(second)

	got := state.Snapshot()
	if got.LastFailureStage != FailureStageSync || !got.LastFailureAt.Equal(second) {
		t.Fatalf("failure snapshot = %#v", got)
	}
	if !got.LastSuccessfulSync.Equal(second) {
		t.Fatalf("last successful sync = %v, want %v", got.LastSuccessfulSync, second)
	}
}
