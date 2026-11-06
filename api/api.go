// Package api contains shared panel API data types and optional capabilities.

package api

import (
	"errors"
	"maps"
	"slices"
)

var ErrUnsupportedPanelFeature = errors.New("panel feature unsupported by adapter")

// PanelClient is the base contract every panel adapter implements.
// Optional capabilities stay separate.
type PanelClient interface {
	Describe() ClientInfo
	GetNodeInfo() (*NodeInfo, error)
	GetUserList() (*[]UserInfo, error)
	GetNodeRule() (*[]DetectRule, error)
	ReportNodeStatus(*NodeStatus) error
	ReportNodeOnlineUsers(*[]OnlineUser) error
	ReportUserTraffic(*[]UserTraffic) error
	ReportIllegal(*[]DetectResult) error
}

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

// NodeSnapshotProvider is an optional capability for adapters that can expose
// a normalized panel snapshot directly. GetNodeInfo remains the compatibility
// contract for existing callers.
type NodeSnapshotProvider interface {
	GetNodeSnapshot() (*NodeSnapshot, error)
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

// AliveSnapshot is a complete panel device snapshot. Each UID appears in
// either IPs or Counts, never both. Counts are non-negative device counts;
// they do not identify IPs. A non-nil empty snapshot clears previous panel
// state, while a nil snapshot means no update is available.
type AliveSnapshot struct {
	IPs    map[int][]string
	Counts map[int]int
}

// AliveSnapshotProvider is an optional capability for adapters that expose
// device counts as well as IP lists without changing AliveListProvider.
type AliveSnapshotProvider interface {
	GetAliveSnapshot() (*AliveSnapshot, error)
}

// Clone returns a detached snapshot, preserving nil maps and IP lists.
func (s *AliveSnapshot) Clone() *AliveSnapshot {
	if s == nil {
		return nil
	}
	cloned := &AliveSnapshot{Counts: maps.Clone(s.Counts)}
	if s.IPs != nil {
		cloned.IPs = make(map[int][]string, len(s.IPs))
		for uid, ips := range s.IPs {
			cloned.IPs[uid] = slices.Clone(ips)
		}
	}
	return cloned
}
