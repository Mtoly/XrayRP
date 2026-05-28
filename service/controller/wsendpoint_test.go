package controller

import (
	"errors"
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
