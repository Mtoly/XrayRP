package controller

import (
	"sync"
	"time"
)

type syncActionSnapshot struct {
	Type       syncActionType
	Source     syncActionSource
	Trigger    string
	OccurredAt time.Time
}

type syncExecutionSnapshot struct {
	Action        syncActionSnapshot
	LastAttemptAt time.Time
	LastSuccessAt time.Time
	// LastError retains the original error for internal diagnostics. It must not
	// be exposed directly because it may contain credentials or other secrets.
	LastError error
	// ConsecutiveFailures counts failures across all synchronization action
	// types globally. A success of any synchronization action resets it.
	ConsecutiveFailures uint64
}

type syncExecutionState struct {
	mu       sync.RWMutex
	snapshot syncExecutionSnapshot
}

func newSyncExecutionState() *syncExecutionState {
	return &syncExecutionState{}
}

func (s *syncExecutionState) Record(action syncAction, err error) {
	if s == nil {
		return
	}

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshot.Action = syncActionSnapshot{
		Type:       action.Type,
		Source:     action.Source,
		Trigger:    action.Metadata.Trigger,
		OccurredAt: action.Metadata.OccurredAt,
	}
	s.snapshot.LastAttemptAt = now
	if err != nil {
		s.snapshot.LastError = err
		s.snapshot.ConsecutiveFailures++
		return
	}

	s.snapshot.LastSuccessAt = now
	s.snapshot.LastError = nil
	s.snapshot.ConsecutiveFailures = 0
}

func (s *syncExecutionState) Snapshot() syncExecutionSnapshot {
	if s == nil {
		return syncExecutionSnapshot{}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot
}
