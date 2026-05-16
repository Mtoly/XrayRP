package controller

import (
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api/newV2board"
)

func TestSyncActionFromWSEventMapsCanonicalControlEvents(t *testing.T) {
	t.Parallel()

	occurredAt := time.Date(2026, time.May, 16, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		name       string
		event      string
		wantType   syncActionType
		wantReason string
	}{
		{name: "resync_all", event: newV2board.WSEventResyncAll, wantType: syncActionTypeResyncAll, wantReason: "websocket requested full resync"},
		{name: "node_changed", event: newV2board.WSEventNodeChanged, wantType: syncActionTypeSyncNodeConfig, wantReason: "websocket node config changed"},
		{name: "users_changed", event: newV2board.WSEventUsersChanged, wantType: syncActionTypeSyncUsers, wantReason: "websocket users changed"},
		{name: "cert_changed", event: newV2board.WSEventCertChanged, wantType: syncActionTypeSyncCertConfig, wantReason: "websocket certificate config changed"},
		{name: "routes_changed", event: newV2board.WSEventRoutesChanged, wantType: syncActionTypeSyncRoutesAndOutbounds, wantReason: "websocket routes or outbounds changed"},
		{name: "outbounds_changed", event: newV2board.WSEventOutboundsChanged, wantType: syncActionTypeSyncRoutesAndOutbounds, wantReason: "websocket routes or outbounds changed"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := syncActionFromWSEvent(tt.event, occurredAt)
			if !ok {
				t.Fatalf("syncActionFromWSEvent(%q) reported unsupported event", tt.event)
			}
			if got.Type != tt.wantType {
				t.Fatalf("unexpected action type: got %q want %q", got.Type, tt.wantType)
			}
			if got.Source != syncActionSourceWS {
				t.Fatalf("unexpected action source: got %q want %q", got.Source, syncActionSourceWS)
			}
			if got.Metadata.Trigger != tt.event {
				t.Fatalf("unexpected metadata trigger: got %q want %q", got.Metadata.Trigger, tt.event)
			}
			if got.Metadata.Reason != tt.wantReason {
				t.Fatalf("unexpected metadata reason: got %q want %q", got.Metadata.Reason, tt.wantReason)
			}
			if got.Metadata.OccurredAt != occurredAt {
				t.Fatalf("unexpected metadata timestamp: got %v want %v", got.Metadata.OccurredAt, occurredAt)
			}
		})
	}
}

func TestSyncActionFromPollingTickMapsToResyncAll(t *testing.T) {
	t.Parallel()

	occurredAt := time.Date(2026, time.May, 16, 11, 0, 0, 0, time.UTC)

	got := syncActionFromPollingTick(occurredAt)
	if got.Type != syncActionTypeResyncAll {
		t.Fatalf("unexpected action type: got %q want %q", got.Type, syncActionTypeResyncAll)
	}
	if got.Source != syncActionSourcePolling {
		t.Fatalf("unexpected action source: got %q want %q", got.Source, syncActionSourcePolling)
	}
	if got.Metadata.Trigger != syncActionTriggerPollingTick {
		t.Fatalf("unexpected metadata trigger: got %q want %q", got.Metadata.Trigger, syncActionTriggerPollingTick)
	}
	if got.Metadata.Reason != "periodic polling correction" {
		t.Fatalf("unexpected metadata reason: got %q want %q", got.Metadata.Reason, "periodic polling correction")
	}
	if got.Metadata.OccurredAt != occurredAt {
		t.Fatalf("unexpected metadata timestamp: got %v want %v", got.Metadata.OccurredAt, occurredAt)
	}
}

func TestSyncActionResyncAllHasHighestPriority(t *testing.T) {
	t.Parallel()

	resyncAll := newSyncAction(syncActionTypeResyncAll, syncActionSourceManual, syncActionMetadata{})
	others := []syncActionType{
		syncActionTypeSyncNodeConfig,
		syncActionTypeSyncUsers,
		syncActionTypeSyncCertConfig,
		syncActionTypeSyncRoutesAndOutbounds,
		syncActionTypeSyncAliveState,
	}

	for _, actionType := range others {
		action := newSyncAction(actionType, syncActionSourceManual, syncActionMetadata{})
		if resyncAll.Priority <= action.Priority {
			t.Fatalf("expected ResyncAll priority %d to be greater than %q priority %d", resyncAll.Priority, actionType, action.Priority)
		}
	}
}

func TestSyncActionConstructorPreservesSourceAndMetadata(t *testing.T) {
	t.Parallel()

	metadata := syncActionMetadata{
		Trigger:    "manual_resync",
		Reason:     "operator requested manual resync",
		OccurredAt: time.Date(2026, time.May, 16, 12, 0, 0, 0, time.UTC),
	}

	got := newSyncAction(syncActionTypeSyncAliveState, syncActionSourceReconnect, metadata)
	if got.Source != syncActionSourceReconnect {
		t.Fatalf("unexpected action source: got %q want %q", got.Source, syncActionSourceReconnect)
	}
	if got.Metadata != metadata {
		t.Fatalf("unexpected metadata: got %#v want %#v", got.Metadata, metadata)
	}
}
