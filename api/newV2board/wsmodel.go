package newV2board

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrInvalidWSJSON       = errors.New("invalid websocket JSON")
	ErrWSEventMissingField = errors.New("websocket event missing required field")
	ErrUnsupportedWSEvent  = errors.New("unsupported websocket event")
)

type WSEventCategory string

const (
	WSEventCategoryControl WSEventCategory = "control"
	WSEventCategoryStatus  WSEventCategory = "status"
	WSEventCategoryConfig  WSEventCategory = "config"
)

const (
	WSEventResyncAll        = "resync_all"
	WSEventNodeChanged      = "node_changed"
	WSEventUsersChanged     = "users_changed"
	WSEventCertChanged      = "cert_changed"
	WSEventRoutesChanged    = "routes_changed"
	WSEventOutboundsChanged = "outbounds_changed"
	WSEventPing             = "ping"
	WSEventPong             = "pong"
	WSEventNodeConfig       = "node_config"
	WSEventUsersPayload     = "users_payload"
	WSEventRoutesPayload    = "routes_payload"
	WSEventOutboundsPayload = "outbounds_payload"
	WSEventCertPayload      = "cert_payload"
	WSEventMachineMode      = "machine_mode"
)

const (
	WSEventXboardAuthSuccess   = "auth.success"
	WSEventXboardError         = "error"
	WSEventXboardSyncConfig    = "sync.config"
	WSEventXboardSyncUsers     = "sync.users"
	WSEventXboardSyncUserDelta = "sync.user.delta"
	WSEventXboardSyncNodes     = "sync.nodes"
	WSEventXboardSyncDevices   = "sync.devices"
	WSEventXboardReportDevices = "report.devices"
)

// WSMessageEnvelope is the minimal raw upstream websocket envelope.
type WSMessageEnvelope struct {
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
	Data    json.RawMessage `json:"data"`
}

// WSEvent is the normalized internal websocket event representation.
type WSEvent struct {
	Event    string
	Category WSEventCategory
	Payload  map[string]any
}

func ParseWSEvent(data []byte) (*WSEvent, error) {
	var raw WSMessageEnvelope
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidWSJSON, err)
	}

	if raw.Event == "" {
		return nil, fmt.Errorf("%w: event", ErrWSEventMissingField)
	}

	category, ok := classifyWSEvent(raw.Event)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedWSEvent, raw.Event)
	}

	payload, err := normalizeWSPayload(raw, raw.Event)
	if err != nil {
		return nil, err
	}

	return &WSEvent{
		Event:    raw.Event,
		Category: category,
		Payload:  payload,
	}, nil
}

func normalizeWSPayload(raw WSMessageEnvelope, event string) (map[string]any, error) {
	if payload, ok, err := decodeWSPayloadObject(raw.Payload); err != nil {
		return nil, fmt.Errorf("%w: payload", ErrWSEventMissingField)
	} else if ok {
		return payload, nil
	}

	if payload, ok, err := decodeWSPayloadObject(raw.Data); err != nil {
		return nil, fmt.Errorf("%w: data", ErrWSEventMissingField)
	} else if ok {
		return payload, nil
	}

	if allowsEmptyWSPayload(event) {
		return map[string]any{}, nil
	}

	return nil, fmt.Errorf("%w: payload", ErrWSEventMissingField)
}

func decodeWSPayloadObject(raw json.RawMessage) (map[string]any, bool, error) {
	payloadBytes := bytes.TrimSpace(raw)
	if len(payloadBytes) == 0 || string(payloadBytes) == "null" {
		return nil, false, nil
	}
	if payloadBytes[0] != '{' {
		return nil, false, ErrWSEventMissingField
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil || payload == nil {
		return nil, false, ErrWSEventMissingField
	}
	return payload, true, nil
}

func allowsEmptyWSPayload(event string) bool {
	switch event {
	case WSEventPing, WSEventPong, WSEventXboardAuthSuccess, WSEventXboardError:
		return true
	default:
		return false
	}
}

func classifyWSEvent(event string) (WSEventCategory, bool) {
	switch event {
	case WSEventResyncAll,
		WSEventNodeChanged,
		WSEventUsersChanged,
		WSEventCertChanged,
		WSEventRoutesChanged,
		WSEventOutboundsChanged,
		WSEventXboardSyncConfig,
		WSEventXboardSyncUsers,
		WSEventXboardSyncUserDelta:
		return WSEventCategoryControl, true
	case WSEventPing, WSEventPong, WSEventXboardAuthSuccess, WSEventXboardError:
		return WSEventCategoryStatus, true
	case WSEventNodeConfig,
		WSEventUsersPayload,
		WSEventRoutesPayload,
		WSEventOutboundsPayload,
		WSEventCertPayload,
		WSEventMachineMode,
		WSEventXboardSyncNodes,
		WSEventXboardSyncDevices:
		return WSEventCategoryConfig, true
	default:
		return "", false
	}
}
