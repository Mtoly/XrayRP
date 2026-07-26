// Package api contains shared panel API data types and optional capabilities.

package api

import "errors"

var ErrUnsupportedPanelFeature = errors.New("panel feature unsupported by adapter")

// WSConfig carries the minimum panel adapter state needed to opt into
// websocket-driven control-plane features without changing the base API contract.
type WSConfig struct {
	APIHost   string
	NodeID    int
	MachineID int
	Key       string
	NodeType  string
}

// WSCapable is an optional capability implemented only by adapters that expose
// websocket-specific configuration.
type WSCapable interface {
	GetWSConfig() *WSConfig
}

// WSEndpointDiscoverer is an optional capability for adapters that can discover
// the panel-provided websocket endpoint dynamically.
type WSEndpointDiscoverer interface {
	DiscoverWSEndpoint() (string, error)
}

// CertConfigProvider is an optional capability for adapters that can expose
// panel-managed certificate configuration. A nil config with no error means
// the capability is supported but no certificate config is currently present.
type CertConfigProvider interface {
	GetXrayRCertConfig() (*XrayRCertConfig, error)
}

// AliveListProvider is an optional capability for adapters that can expose an
// authoritative panel snapshot of currently alive client IPs. A nil map with
// no error means no snapshot is available; every non-nil map, including an
// empty map, is an authoritative replacement snapshot.
type AliveListProvider interface {
	GetAliveList() (map[int][]string, error)
}
