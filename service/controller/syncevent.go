package controller

import (
	"time"

	"github.com/Mtoly/XrayRP/api/newV2board"
)

type syncActionType string

type syncActionSource string

type syncActionPriority int

const (
	syncActionTypeSyncNodeConfig         syncActionType = "SyncNodeConfig"
	syncActionTypeSyncUsers              syncActionType = "SyncUsers"
	syncActionTypeSyncCertConfig         syncActionType = "SyncCertConfig"
	syncActionTypeSyncRoutesAndOutbounds syncActionType = "SyncRoutesAndOutbounds"
	syncActionTypeSyncAliveState         syncActionType = "SyncAliveState"
	syncActionTypeResyncAll              syncActionType = "ResyncAll"
)

const (
	syncActionSourceWS        syncActionSource = "ws"
	syncActionSourcePolling   syncActionSource = "polling"
	syncActionSourceManual    syncActionSource = "manual"
	syncActionSourceReconnect syncActionSource = "reconnect"
)

const (
	syncActionPrioritySyncAliveState         syncActionPriority = 10
	syncActionPrioritySyncUsers              syncActionPriority = 20
	syncActionPrioritySyncNodeConfig         syncActionPriority = 30
	syncActionPrioritySyncCertConfig         syncActionPriority = 30
	syncActionPrioritySyncRoutesAndOutbounds syncActionPriority = 40
	syncActionPriorityResyncAll              syncActionPriority = 100
)

const syncActionTriggerPollingTick = "polling_tick"

type syncActionMetadata struct {
	Trigger    string
	OccurredAt time.Time
	Reason     string
}

type syncAction struct {
	Type     syncActionType
	Source   syncActionSource
	Priority syncActionPriority
	Metadata syncActionMetadata
}

type wsActionDescriptor struct {
	actionType syncActionType
	reason     string
}

var wsControlActionMap = map[string]wsActionDescriptor{
	newV2board.WSEventResyncAll: {
		actionType: syncActionTypeResyncAll,
		reason:     "websocket requested full resync",
	},
	newV2board.WSEventNodeChanged: {
		actionType: syncActionTypeSyncNodeConfig,
		reason:     "websocket node config changed",
	},
	newV2board.WSEventUsersChanged: {
		actionType: syncActionTypeSyncUsers,
		reason:     "websocket users changed",
	},
	newV2board.WSEventCertChanged: {
		actionType: syncActionTypeSyncCertConfig,
		reason:     "websocket certificate config changed",
	},
	newV2board.WSEventRoutesChanged: {
		actionType: syncActionTypeSyncRoutesAndOutbounds,
		reason:     "websocket routes or outbounds changed",
	},
	newV2board.WSEventOutboundsChanged: {
		actionType: syncActionTypeSyncRoutesAndOutbounds,
		reason:     "websocket routes or outbounds changed",
	},
	newV2board.WSEventXboardSyncConfig: {
		actionType: syncActionTypeSyncNodeConfig,
		reason:     "websocket node config changed",
	},
	newV2board.WSEventXboardSyncUsers: {
		actionType: syncActionTypeSyncUsers,
		reason:     "websocket users changed",
	},
	newV2board.WSEventXboardSyncUserDelta: {
		actionType: syncActionTypeSyncUsers,
		reason:     "websocket user delta changed",
	},
}

func newSyncAction(actionType syncActionType, source syncActionSource, metadata syncActionMetadata) syncAction {
	return syncAction{
		Type:     actionType,
		Source:   source,
		Priority: syncActionPriorityFor(actionType),
		Metadata: metadata,
	}
}

func syncActionPriorityFor(actionType syncActionType) syncActionPriority {
	switch actionType {
	case syncActionTypeSyncAliveState:
		return syncActionPrioritySyncAliveState
	case syncActionTypeSyncUsers:
		return syncActionPrioritySyncUsers
	case syncActionTypeSyncNodeConfig:
		return syncActionPrioritySyncNodeConfig
	case syncActionTypeSyncCertConfig:
		return syncActionPrioritySyncCertConfig
	case syncActionTypeSyncRoutesAndOutbounds:
		return syncActionPrioritySyncRoutesAndOutbounds
	case syncActionTypeResyncAll:
		return syncActionPriorityResyncAll
	default:
		return 0
	}
}

func syncActionFromWSEvent(event string, occurredAt time.Time) (syncAction, bool) {
	descriptor, ok := wsControlActionMap[event]
	if !ok {
		return syncAction{}, false
	}

	return newSyncAction(descriptor.actionType, syncActionSourceWS, syncActionMetadata{
		Trigger:    event,
		OccurredAt: occurredAt,
		Reason:     descriptor.reason,
	}), true
}

func syncActionFromPollingTick(occurredAt time.Time) syncAction {
	return newSyncAction(syncActionTypeResyncAll, syncActionSourcePolling, syncActionMetadata{
		Trigger:    syncActionTriggerPollingTick,
		OccurredAt: occurredAt,
		Reason:     "periodic polling correction",
	})
}
