package newV2board

import (
	"errors"
	"testing"
)

func TestParseWSEventRecognizesCanonicalEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		raw          string
		wantEvent    string
		wantCategory WSEventCategory
	}{
		{name: "control_resync_all", raw: `{"event":"resync_all","payload":{}}`, wantEvent: "resync_all", wantCategory: WSEventCategoryControl},
		{name: "control_node_changed", raw: `{"event":"node_changed","payload":{"node_id":1}}`, wantEvent: "node_changed", wantCategory: WSEventCategoryControl},
		{name: "control_users_changed", raw: `{"event":"users_changed","payload":{"count":2}}`, wantEvent: "users_changed", wantCategory: WSEventCategoryControl},
		{name: "control_cert_changed", raw: `{"event":"cert_changed","payload":{"provider":"alidns"}}`, wantEvent: "cert_changed", wantCategory: WSEventCategoryControl},
		{name: "control_routes_changed", raw: `{"event":"routes_changed","payload":{"revision":3}}`, wantEvent: "routes_changed", wantCategory: WSEventCategoryControl},
		{name: "control_outbounds_changed", raw: `{"event":"outbounds_changed","payload":{"revision":4}}`, wantEvent: "outbounds_changed", wantCategory: WSEventCategoryControl},
		{name: "status_ping", raw: `{"event":"ping","payload":{}}`, wantEvent: "ping", wantCategory: WSEventCategoryStatus},
		{name: "status_pong", raw: `{"event":"pong","payload":{}}`, wantEvent: "pong", wantCategory: WSEventCategoryStatus},
		{name: "config_node_config", raw: `{"event":"node_config","payload":{"transport":"ws"}}`, wantEvent: "node_config", wantCategory: WSEventCategoryConfig},
		{name: "config_users_payload", raw: `{"event":"users_payload","payload":{"users":[]}}`, wantEvent: "users_payload", wantCategory: WSEventCategoryConfig},
		{name: "config_routes_payload", raw: `{"event":"routes_payload","payload":{"routes":[]}}`, wantEvent: "routes_payload", wantCategory: WSEventCategoryConfig},
		{name: "config_outbounds_payload", raw: `{"event":"outbounds_payload","payload":{"outbounds":[]}}`, wantEvent: "outbounds_payload", wantCategory: WSEventCategoryConfig},
		{name: "config_cert_payload", raw: `{"event":"cert_payload","payload":{"email":"ops@example.com"}}`, wantEvent: "cert_payload", wantCategory: WSEventCategoryConfig},
		{name: "config_machine_mode", raw: `{"event":"machine_mode","payload":{"enabled":true}}`, wantEvent: "machine_mode", wantCategory: WSEventCategoryConfig},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			event, err := ParseWSEvent([]byte(tt.raw))
			if err != nil {
				t.Fatalf("ParseWSEvent returned error: %v", err)
			}
			if event.Event != tt.wantEvent {
				t.Fatalf("unexpected event name: got %q want %q", event.Event, tt.wantEvent)
			}
			if event.Category != tt.wantCategory {
				t.Fatalf("unexpected category: got %q want %q", event.Category, tt.wantCategory)
			}
			if event.Payload == nil {
				t.Fatal("expected payload object, got nil")
			}
		})
	}
}

func TestParseWSEventIgnoresUnknownTopLevelFields(t *testing.T) {
	t.Parallel()

	event, err := ParseWSEvent([]byte(`{"event":"node_changed","payload":{"node_id":7},"trace_id":"abc123"}`))
	if err != nil {
		t.Fatalf("ParseWSEvent returned error: %v", err)
	}
	if event.Category != WSEventCategoryControl {
		t.Fatalf("unexpected category: got %q want %q", event.Category, WSEventCategoryControl)
	}
	if got := event.Payload["node_id"]; got != float64(7) {
		t.Fatalf("unexpected payload value: got %#v want 7", got)
	}
}

func TestParseWSEventRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := ParseWSEvent([]byte(`{"event":"ping"`))
	if !errors.Is(err, ErrInvalidWSJSON) {
		t.Fatalf("expected ErrInvalidWSJSON, got %v", err)
	}
}

func TestParseWSEventRejectsMissingRequiredFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{name: "missing_event", raw: `{"payload":{}}`},
		{name: "missing_payload", raw: `{"event":"ping"}`},
		{name: "payload_null", raw: `{"event":"ping","payload":null}`},
		{name: "payload_array", raw: `{"event":"ping","payload":[]}`},
		{name: "payload_string", raw: `{"event":"ping","payload":"nope"}`},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseWSEvent([]byte(tt.raw))
			if !errors.Is(err, ErrWSEventMissingField) {
				t.Fatalf("expected ErrWSEventMissingField, got %v", err)
			}
		})
	}
}

func TestParseWSEventRejectsUnsupportedEvent(t *testing.T) {
	t.Parallel()

	_, err := ParseWSEvent([]byte(`{"event":"totally_new_event","payload":{}}`))
	if !errors.Is(err, ErrUnsupportedWSEvent) {
		t.Fatalf("expected ErrUnsupportedWSEvent, got %v", err)
	}
}
