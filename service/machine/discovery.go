package machine

import (
	"context"
	"fmt"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
	"github.com/Mtoly/XrayRP/service"
)

// NewV2boardDiscoverer is retained as a compatibility wrapper. New
// composition code should obtain the machine capability from the panel
// registry. The wrapper remains for callers that used the legacy constructor.
type NewV2boardDiscoverer struct {
	Config newV2board.MachineDiscoveryConfig
}

func (d *NewV2boardDiscoverer) DiscoverMachineNodes() (*api.MachineNodesResponse, error) {
	return newV2board.DiscoverMachineNodes(d.Config)
}

func (d *NewV2boardDiscoverer) DiscoverMachineNodesContext(ctx context.Context) (*api.MachineNodesResponse, error) {
	return newV2board.DiscoverMachineNodesContext(ctx, d.Config)
}

func (s *Supervisor) discoverSnapshot() (discoverySnapshot, error) {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return s.discoverSnapshotContext(ctx)
}

func (s *Supervisor) discoverSnapshotContext(ctx context.Context) (discoverySnapshot, error) {
	var response *api.MachineNodesResponse
	var err error
	if contextual, ok := s.discoverer.(ContextNodeDiscoverer); ok {
		response, err = contextual.DiscoverMachineNodesContext(ctx)
	} else {
		if err := ctx.Err(); err != nil {
			return discoverySnapshot{}, err
		}
		response, err = s.discoverer.DiscoverMachineNodes()
	}
	if err != nil {
		return discoverySnapshot{}, fmt.Errorf("discover machine nodes: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return discoverySnapshot{}, err
	}
	return materializeDiscoverySnapshot(response)
}

func materializeDiscoverySnapshot(response *api.MachineNodesResponse) (discoverySnapshot, error) {
	if response == nil {
		return discoverySnapshot{}, fmt.Errorf("discover machine nodes: empty response")
	}

	bindings, err := NormalizeNodeBindings(response.Nodes)
	if err != nil {
		return discoverySnapshot{}, fmt.Errorf("normalize machine node bindings: %w", err)
	}
	return discoverySnapshot{bindings: bindings, baseConfig: response.BaseConfig}, nil
}
