package controller

import (
	"errors"
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

type stubWSEndpointDiscoverer struct {
	endpoint string
	err      error
	calls    int
}

func (d *stubWSEndpointDiscoverer) DiscoverWSEndpoint() (string, error) {
	d.calls++
	return d.endpoint, d.err
}

func TestResolveWSEndpointRejectsMissingConfigBeforeDiscoveryValidation(t *testing.T) {
	t.Parallel()

	discoverer := &stubWSEndpointDiscoverer{endpoint: "wss://panel.example/ws"}
	endpoint, err := resolveWSEndpoint(discoverer, nil, &WebSocketConfig{})
	if err == nil {
		t.Fatalf("expected missing websocket config to fail, got endpoint %q", endpoint)
	}
	if endpoint != "" {
		t.Fatalf("expected no endpoint with missing websocket config, got %q", endpoint)
	}
}

func TestResolveWSEndpointExplicitEndpointWins(t *testing.T) {
	t.Parallel()

	discoverer := &stubWSEndpointDiscoverer{endpoint: "wss://discovered.example/ws"}
	endpoint, err := resolveWSEndpoint(discoverer, &api.WSConfig{
		APIHost:  "https://panel.example",
		NodeID:   7,
		NodeType: "vless",
		Key:      "secret",
	}, &WebSocketConfig{Endpoint: "https://override.example/custom"})
	if err != nil {
		t.Fatalf("resolveWSEndpoint returned error: %v", err)
	}
	if discoverer.calls != 0 {
		t.Fatalf("expected discovery not to be called, got %d calls", discoverer.calls)
	}
	want := "wss://override.example/custom?node_id=7&node_type=vless&token=secret"
	if endpoint != want {
		t.Fatalf("unexpected endpoint: got %q want %q", endpoint, want)
	}
}

func TestResolveWSEndpointUsesDiscoveryWhenNoExplicitEndpoint(t *testing.T) {
	t.Parallel()

	discoverer := &stubWSEndpointDiscoverer{endpoint: "https://panel.example/ws"}
	endpoint, err := resolveWSEndpoint(discoverer, &api.WSConfig{
		APIHost:  "https://panel.example",
		NodeID:   7,
		NodeType: "vless",
		Key:      "secret",
	}, &WebSocketConfig{})
	if err != nil {
		t.Fatalf("resolveWSEndpoint returned error: %v", err)
	}
	if discoverer.calls != 1 {
		t.Fatalf("expected discovery to be called once, got %d", discoverer.calls)
	}
	want := "wss://panel.example/ws?node_id=7&node_type=vless&token=secret"
	if endpoint != want {
		t.Fatalf("unexpected endpoint: got %q want %q", endpoint, want)
	}
}

func TestResolveWSEndpointRejectsCrossOriginDiscoveredEndpoint(t *testing.T) {
	t.Parallel()

	discoverer := &stubWSEndpointDiscoverer{endpoint: "wss://attacker.example/ws"}
	endpoint, err := resolveWSEndpoint(discoverer, &api.WSConfig{
		APIHost:  "https://panel.example",
		NodeID:   7,
		NodeType: "vless",
		Key:      "secret-token",
	}, &WebSocketConfig{})
	if err == nil {
		t.Fatalf("expected cross-origin discovery to fail, got endpoint %q", endpoint)
	}
	if endpoint != "" {
		t.Fatalf("expected no endpoint on validation failure, got %q", endpoint)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("validation error leaked token: %v", err)
	}
}

func TestResolveWSEndpointRejectsHTTPSDowngradeFromDiscovery(t *testing.T) {
	t.Parallel()

	discoverer := &stubWSEndpointDiscoverer{endpoint: "ws://panel.example/ws"}
	endpoint, err := resolveWSEndpoint(discoverer, &api.WSConfig{
		APIHost:  "https://panel.example",
		NodeID:   7,
		NodeType: "vless",
		Key:      "secret-token",
	}, &WebSocketConfig{})
	if err == nil {
		t.Fatalf("expected HTTPS downgrade discovery to fail, got endpoint %q", endpoint)
	}
	if endpoint != "" {
		t.Fatalf("expected no endpoint on validation failure, got %q", endpoint)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("validation error leaked token: %v", err)
	}
}

func TestResolveWSEndpointAllowsSameOriginWSSDiscovery(t *testing.T) {
	t.Parallel()

	discoverer := &stubWSEndpointDiscoverer{endpoint: "wss://PANEL.EXAMPLE:443/ws"}
	endpoint, err := resolveWSEndpoint(discoverer, &api.WSConfig{
		APIHost:  "https://panel.example",
		NodeID:   7,
		NodeType: "vless",
		Key:      "secret",
	}, &WebSocketConfig{})
	if err != nil {
		t.Fatalf("resolveWSEndpoint returned error: %v", err)
	}
	want := "wss://PANEL.EXAMPLE:443/ws?node_id=7&node_type=vless&token=secret"
	if endpoint != want {
		t.Fatalf("unexpected endpoint: got %q want %q", endpoint, want)
	}
}

func TestResolveWSEndpointAllowsRelativeDiscovery(t *testing.T) {
	t.Parallel()

	discoverer := &stubWSEndpointDiscoverer{endpoint: "/custom/ws"}
	endpoint, err := resolveWSEndpoint(discoverer, &api.WSConfig{
		APIHost:  "https://panel.example/base/",
		NodeID:   7,
		NodeType: "vless",
		Key:      "secret",
	}, &WebSocketConfig{})
	if err != nil {
		t.Fatalf("resolveWSEndpoint returned error: %v", err)
	}
	want := "wss://panel.example/custom/ws?node_id=7&node_type=vless&token=secret"
	if endpoint != want {
		t.Fatalf("unexpected endpoint: got %q want %q", endpoint, want)
	}
}

func TestResolveWSEndpointFallsBackToLegacyWhenDiscoveryEmptyOrErrors(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		discoverer *stubWSEndpointDiscoverer
	}{
		{name: "empty", discoverer: &stubWSEndpointDiscoverer{}},
		{name: "error", discoverer: &stubWSEndpointDiscoverer{err: errors.New("handshake failed")}},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			endpoint, err := resolveWSEndpoint(tt.discoverer, &api.WSConfig{
				APIHost:  "https://panel.example/base",
				NodeID:   7,
				NodeType: "vless",
				Key:      "secret",
			}, &WebSocketConfig{})
			if err != nil {
				t.Fatalf("resolveWSEndpoint returned error: %v", err)
			}
			want := "wss://panel.example/base/api/v1/server/UniProxy/ws?node_id=7&node_type=vless&token=secret"
			if endpoint != want {
				t.Fatalf("unexpected endpoint: got %q want %q", endpoint, want)
			}
		})
	}
}

func TestBuildWSEndpointUsesMachineIdentityWhenConfigured(t *testing.T) {
	t.Parallel()

	endpoint, err := BuildWSEndpoint(&api.WSConfig{
		APIHost:   "https://panel.example",
		NodeID:    7,
		MachineID: 42,
		NodeType:  "vless",
		Key:       "machine-token",
	}, &WebSocketConfig{Endpoint: "wss://panel.example/ws?node_id=7&node_type=vless"})
	if err != nil {
		t.Fatalf("BuildWSEndpoint returned error: %v", err)
	}

	want := "wss://panel.example/ws?machine_id=42&token=machine-token"
	if endpoint != want {
		t.Fatalf("unexpected endpoint: got %q want %q", endpoint, want)
	}
}
