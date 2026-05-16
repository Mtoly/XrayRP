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

// WSMessageEnvelope is the minimal raw upstream websocket envelope.
type WSMessageEnvelope struct {
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
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

	payloadBytes := bytes.TrimSpace(raw.Payload)
	if len(payloadBytes) == 0 || payloadBytes[0] != '{' {
		return nil, fmt.Errorf("%w: payload", ErrWSEventMissingField)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil || payload == nil {
		return nil, fmt.Errorf("%w: payload", ErrWSEventMissingField)
	}

	return &WSEvent{
		Event:    raw.Event,
		Category: category,
		Payload:  payload,
	}, nil
}

func classifyWSEvent(event string) (WSEventCategory, bool) {
	switch event {
	case WSEventResyncAll,
		WSEventNodeChanged,
		WSEventUsersChanged,
		WSEventCertChanged,
		WSEventRoutesChanged,
		WSEventOutboundsChanged:
		return WSEventCategoryControl, true
	case WSEventPing, WSEventPong:
		return WSEventCategoryStatus, true
	case WSEventNodeConfig,
		WSEventUsersPayload,
		WSEventRoutesPayload,
		WSEventOutboundsPayload,
		WSEventCertPayload,
		WSEventMachineMode:
		return WSEventCategoryConfig, true
	default:
		return "", false
	}
}
