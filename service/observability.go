package service

import (
	"sort"
	"sync"
	"time"
)

const DefaultReadinessStaleAfter = 3 * time.Minute

type RuntimeKind string

const (
	RuntimeKindPanel      RuntimeKind = "panel"
	RuntimeKindMachine    RuntimeKind = "machine"
	RuntimeKindController RuntimeKind = "controller"
	RuntimeKindAnyTLS     RuntimeKind = "anytls"
	RuntimeKindTUIC       RuntimeKind = "tuic"
	RuntimeKindHysteria2  RuntimeKind = "hysteria2"
)

type RuntimeMode string

const (
	RuntimeModeStatic  RuntimeMode = "static"
	RuntimeModeMachine RuntimeMode = "machine"
)

type RuntimeLifecycle string

const (
	RuntimeLifecycleStopped     RuntimeLifecycle = "stopped"
	RuntimeLifecycleStarting    RuntimeLifecycle = "starting"
	RuntimeLifecycleRunning     RuntimeLifecycle = "running"
	RuntimeLifecycleReloading   RuntimeLifecycle = "reloading"
	RuntimeLifecycleStopping    RuntimeLifecycle = "stopping"
	RuntimeLifecycleFailed      RuntimeLifecycle = "failed"
	RuntimeLifecycleFailedOwned RuntimeLifecycle = "failed-owned"
	RuntimeLifecycleRetiring    RuntimeLifecycle = "retiring"
	RuntimeLifecycleClosed      RuntimeLifecycle = "closed"
)

type WebSocketState string

const (
	WebSocketDisabled     WebSocketState = "disabled"
	WebSocketDisconnected WebSocketState = "disconnected"
	WebSocketConnected    WebSocketState = "connected"
	WebSocketDegraded     WebSocketState = "degraded"
)

type WebSocketSnapshot struct {
	State         WebSocketState
	LastFailureAt time.Time
}

type WebSocketSnapshotProvider interface {
	WebSocketObservabilitySnapshot() WebSocketSnapshot
}

type FailureStage string

const (
	FailureStageNone        FailureStage = "none"
	FailureStageStart       FailureStage = "start"
	FailureStageSync        FailureStage = "sync"
	FailureStageWebSocket   FailureStage = "websocket"
	FailureStageReconcile   FailureStage = "reconcile"
	FailureStageReport      FailureStage = "report"
	FailureStageCertificate FailureStage = "certificate"
	FailureStageRuntime     FailureStage = "runtime"
	FailureStageClose       FailureStage = "close"
	FailureStageCleanup     FailureStage = "cleanup"
)

type RuntimeSnapshot struct {
	Kind                 RuntimeKind
	Mode                 RuntimeMode
	NodeID               int
	Lifecycle            RuntimeLifecycle
	TopologyGeneration   uint64
	LastSuccessfulSync   time.Time
	WebSocket            WebSocketState
	LastFailureStage     FailureStage
	LastFailureAt        time.Time
	CleanupPending       bool
	TrafficReportBacklog int
	CertificateExpiresAt time.Time
	Children             []RuntimeSnapshot
}

type RuntimeSnapshotProvider interface {
	ObservabilitySnapshot() RuntimeSnapshot
}

func (s RuntimeSnapshot) Clone() RuntimeSnapshot {
	cloned := s
	cloned.Children = make([]RuntimeSnapshot, len(s.Children))
	for i := range s.Children {
		cloned.Children[i] = s.Children[i].Clone()
	}
	return cloned
}

func SortRuntimeSnapshots(snapshots []RuntimeSnapshot) {
	sort.SliceStable(snapshots, func(i, j int) bool {
		if snapshots[i].NodeID != snapshots[j].NodeID {
			return snapshots[i].NodeID < snapshots[j].NodeID
		}
		if snapshots[i].Kind != snapshots[j].Kind {
			return snapshots[i].Kind < snapshots[j].Kind
		}
		return snapshots[i].Lifecycle < snapshots[j].Lifecycle
	})
}

type RuntimeHealthSnapshot struct {
	LastSuccessfulSync time.Time
	LastFailureStage   FailureStage
	LastFailureAt      time.Time
	TrafficBacklog     int
	CertificateExpiry  time.Time
}

type RuntimeHealthState struct {
	mu       sync.RWMutex
	snapshot RuntimeHealthSnapshot
}

func (s *RuntimeHealthState) RecordSuccessfulSync(at time.Time) {
	if s == nil {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	s.mu.Lock()
	if at.After(s.snapshot.LastSuccessfulSync) {
		s.snapshot.LastSuccessfulSync = at
	}
	s.mu.Unlock()
}

func (s *RuntimeHealthState) RecordFailure(stage FailureStage, at time.Time) {
	if s == nil || stage == FailureStageNone {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	s.mu.Lock()
	if !at.Before(s.snapshot.LastFailureAt) {
		s.snapshot.LastFailureStage = stage
		s.snapshot.LastFailureAt = at
	}
	s.mu.Unlock()
}

func (s *RuntimeHealthState) Snapshot() RuntimeHealthSnapshot {
	if s == nil {
		return RuntimeHealthSnapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot
}

func (s *RuntimeHealthState) SetTrafficBacklog(backlog int) {
	if s == nil {
		return
	}
	if backlog < 0 {
		backlog = 0
	}
	s.mu.Lock()
	s.snapshot.TrafficBacklog = backlog
	s.mu.Unlock()
}

func (s *RuntimeHealthState) SetCertificateExpiry(expiry time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.snapshot.CertificateExpiry = expiry
	s.mu.Unlock()
}

type ReadinessReason string

const (
	ReadinessReasonShutdown           ReadinessReason = "shutdown"
	ReadinessReasonLifecycle          ReadinessReason = "lifecycle"
	ReadinessReasonCleanupPending     ReadinessReason = "cleanup_pending"
	ReadinessReasonSyncUnavailable    ReadinessReason = "sync_unavailable"
	ReadinessReasonSyncStale          ReadinessReason = "sync_stale"
	ReadinessReasonCertificateExpired ReadinessReason = "certificate_expired"
)

type Readiness struct {
	Ready    bool
	Degraded bool
	Reasons  []ReadinessReason
}

func EvaluateReadiness(snapshot RuntimeSnapshot, now time.Time, staleAfter time.Duration) Readiness {
	if now.IsZero() {
		now = time.Now()
	}
	if staleAfter <= 0 {
		staleAfter = DefaultReadinessStaleAfter
	}

	result := Readiness{Ready: true}
	reasons := make(map[ReadinessReason]struct{})
	var visit func(RuntimeSnapshot, bool)
	visit = func(current RuntimeSnapshot, root bool) {
		switch current.Lifecycle {
		case RuntimeLifecycleRunning:
		case RuntimeLifecycleReloading:
			result.Degraded = true
		case RuntimeLifecycleClosed, RuntimeLifecycleStopping:
			result.Ready = false
			if root {
				reasons[ReadinessReasonShutdown] = struct{}{}
			} else {
				reasons[ReadinessReasonLifecycle] = struct{}{}
			}
		default:
			result.Ready = false
			reasons[ReadinessReasonLifecycle] = struct{}{}
		}

		if current.CleanupPending || current.Lifecycle == RuntimeLifecycleFailedOwned || current.Lifecycle == RuntimeLifecycleRetiring {
			result.Ready = false
			reasons[ReadinessReasonCleanupPending] = struct{}{}
		}
		if current.WebSocket == WebSocketDegraded || current.TrafficReportBacklog > 0 {
			result.Degraded = true
		}
		if requiresFreshSync(current.Kind) && current.Lifecycle == RuntimeLifecycleRunning {
			switch {
			case current.LastSuccessfulSync.IsZero():
				result.Ready = false
				reasons[ReadinessReasonSyncUnavailable] = struct{}{}
			case now.Sub(current.LastSuccessfulSync) > staleAfter:
				result.Ready = false
				reasons[ReadinessReasonSyncStale] = struct{}{}
			}
		}
		if !current.CertificateExpiresAt.IsZero() && !current.CertificateExpiresAt.After(now) {
			result.Ready = false
			reasons[ReadinessReasonCertificateExpired] = struct{}{}
		}
		for _, child := range current.Children {
			visit(child, false)
		}
	}
	visit(snapshot, true)

	for reason := range reasons {
		result.Reasons = append(result.Reasons, reason)
	}
	sort.Slice(result.Reasons, func(i, j int) bool {
		return result.Reasons[i] < result.Reasons[j]
	})
	return result
}

func requiresFreshSync(kind RuntimeKind) bool {
	switch kind {
	case RuntimeKindMachine, RuntimeKindController, RuntimeKindAnyTLS, RuntimeKindTUIC, RuntimeKindHysteria2:
		return true
	default:
		return false
	}
}
