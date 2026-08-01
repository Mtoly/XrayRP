package service

import "time"

// SnapshotSyncScope identifies authoritative panel snapshots that need refresh.
// Values are flags so burst triggers can be merged without an unbounded queue.
type SnapshotSyncScope uint8

const (
	SnapshotSyncNode SnapshotSyncScope = 1 << iota
	SnapshotSyncUsers
	SnapshotSyncRules
	SnapshotSyncAll = SnapshotSyncNode | SnapshotSyncUsers | SnapshotSyncRules
)

func (scope SnapshotSyncScope) Includes(required SnapshotSyncScope) bool {
	return scope&required == required
}

func (scope SnapshotSyncScope) Valid() bool {
	return scope != 0 && scope&^SnapshotSyncAll == 0
}

type SnapshotSyncSource string

const (
	SnapshotSyncSourceWebSocket  SnapshotSyncSource = "websocket"
	SnapshotSyncSourceReconnect  SnapshotSyncSource = "reconnect"
	SnapshotSyncSourceParseError SnapshotSyncSource = "parse_error"
	SnapshotSyncSourcePolling    SnapshotSyncSource = "polling"
)

type SnapshotSyncTrigger struct {
	Scope      SnapshotSyncScope
	Source     SnapshotSyncSource
	OccurredAt time.Time
}

// SnapshotSyncSubmitter accepts non-blocking authoritative snapshot triggers.
// Implementations must bound and coalesce pending work.
type SnapshotSyncSubmitter interface {
	SubmitSnapshotSync(SnapshotSyncTrigger)
}

// SnapshotSyncAppliedRecorder commits fetched candidates only after the
// runtime has successfully applied the corresponding authoritative snapshot.
type SnapshotSyncAppliedRecorder interface {
	RecordSnapshotSyncApplied(SnapshotSyncScope)
}

func RecordSnapshotSyncApplied(target any, scope SnapshotSyncScope) {
	if recorder, ok := target.(SnapshotSyncAppliedRecorder); ok {
		recorder.RecordSnapshotSyncApplied(scope)
	}
}
