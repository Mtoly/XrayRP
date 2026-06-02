package controller

import (
	"strconv"
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
	syncActionTypeSyncDevices            syncActionType = "SyncDevices"
	syncActionTypeClearGlobalDevices     syncActionType = "ClearGlobalDevices"
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
	syncActionPriorityDeviceState            syncActionPriority = 15
	syncActionPrioritySyncUsers              syncActionPriority = 20
	syncActionPrioritySyncNodeConfig         syncActionPriority = 30
	syncActionPrioritySyncCertConfig         syncActionPriority = 30
	syncActionPrioritySyncRoutesAndOutbounds syncActionPriority = 40
	syncActionPriorityResyncAll              syncActionPriority = 100
)

const syncActionTriggerPollingTick = "polling_tick"
const syncActionTriggerWSDisconnect = "ws_disconnect"
const syncActionTriggerWSParseError = "ws_parse_error"

type syncActionMetadata struct {
	Trigger    string
	OccurredAt time.Time
	Reason     string
}

type syncActionPayload struct {
	Devices map[int][]string
}

type syncAction struct {
	Type     syncActionType
	Source   syncActionSource
	Priority syncActionPriority
	Metadata syncActionMetadata
	Payload  syncActionPayload
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
	newV2board.WSEventXboardSyncNodes: {
		actionType: syncActionTypeResyncAll,
		reason:     "websocket machine nodes changed; single-node controller will resync",
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
	case syncActionTypeSyncDevices, syncActionTypeClearGlobalDevices:
		return syncActionPriorityDeviceState
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

func syncActionFromWSEventPayload(event *newV2board.WSEvent, occurredAt time.Time) (syncAction, bool) {
	if event == nil {
		return syncAction{}, false
	}

	if event.Event == newV2board.WSEventXboardSyncDevices {
		devices, ok := parseSyncDevicesPayload(event.Payload)
		if !ok {
			return newSyncAction(syncActionTypeResyncAll, syncActionSourceWS, syncActionMetadata{
				Trigger:    event.Event,
				OccurredAt: occurredAt,
				Reason:     "malformed websocket device sync payload",
			}), true
		}

		action := newSyncAction(syncActionTypeSyncDevices, syncActionSourceWS, syncActionMetadata{
			Trigger:    event.Event,
			OccurredAt: occurredAt,
			Reason:     "websocket devices changed",
		})
		action.Payload.Devices = devices
		return action, true
	}

	return syncActionFromWSEvent(event.Event, occurredAt)
}

func parseSyncDevicesPayload(payload map[string]any) (map[int][]string, bool) {
	if payload == nil {
		return nil, false
	}

	users, ok := payload["users"]
	if !ok {
		return nil, false
	}

	switch typedUsers := users.(type) {
	case map[string]any:
		return parseSyncDevicesStringAnyMap(typedUsers)
	case map[string][]string:
		return parseSyncDevicesStringSliceMap(typedUsers)
	case map[int][]string:
		return parseSyncDevicesIntSliceMap(typedUsers), true
	default:
		return nil, false
	}
}

func parseSyncDevicesStringAnyMap(users map[string]any) (map[int][]string, bool) {
	devices := make(map[int][]string, len(users))
	for uidKey, rawIPs := range users {
		uid, ok := parseSyncDeviceUIDKey(uidKey)
		if !ok {
			continue
		}

		ips, ok := parseSyncDeviceIPs(rawIPs)
		if !ok {
			return nil, false
		}
		devices[uid] = ips
	}
	return devices, true
}

func parseSyncDevicesStringSliceMap(users map[string][]string) (map[int][]string, bool) {
	devices := make(map[int][]string, len(users))
	for uidKey, rawIPs := range users {
		uid, ok := parseSyncDeviceUIDKey(uidKey)
		if !ok {
			continue
		}
		devices[uid] = copySyncDeviceIPs(rawIPs)
	}
	return devices, true
}

func parseSyncDevicesIntSliceMap(users map[int][]string) map[int][]string {
	devices := make(map[int][]string, len(users))
	for uid, rawIPs := range users {
		if uid <= 0 {
			continue
		}
		devices[uid] = copySyncDeviceIPs(rawIPs)
	}
	return devices
}

func parseSyncDeviceUIDKey(uidKey string) (int, bool) {
	uid, err := strconv.Atoi(uidKey)
	if err != nil || uid <= 0 {
		return 0, false
	}
	return uid, true
}

func parseSyncDeviceIPs(rawIPs any) ([]string, bool) {
	switch ips := rawIPs.(type) {
	case []any:
		if len(ips) == 0 {
			return []string{}, true
		}
		parsed := make([]string, 0, len(ips))
		for _, rawIP := range ips {
			ip, ok := rawIP.(string)
			if !ok {
				return nil, false
			}
			parsed = append(parsed, ip)
		}
		return parsed, true
	case []string:
		return copySyncDeviceIPs(ips), true
	default:
		return nil, false
	}
}

func copySyncDeviceIPs(ips []string) []string {
	if len(ips) == 0 {
		return []string{}
	}
	return append([]string(nil), ips...)
}

func syncActionFromWSDisconnect(occurredAt time.Time) syncAction {
	return newSyncAction(syncActionTypeClearGlobalDevices, syncActionSourceReconnect, syncActionMetadata{
		Trigger:    syncActionTriggerWSDisconnect,
		OccurredAt: occurredAt,
		Reason:     "websocket disconnected; clearing global device state",
	})
}

func syncActionFromWSParseError(occurredAt time.Time) syncAction {
	return newSyncAction(syncActionTypeResyncAll, syncActionSourceWS, syncActionMetadata{
		Trigger:    syncActionTriggerWSParseError,
		OccurredAt: occurredAt,
		Reason:     "websocket parse error",
	})
}

func syncActionFromPollingTick(occurredAt time.Time) syncAction {
	return newSyncAction(syncActionTypeResyncAll, syncActionSourcePolling, syncActionMetadata{
		Trigger:    syncActionTriggerPollingTick,
		OccurredAt: occurredAt,
		Reason:     "periodic polling correction",
	})
}
