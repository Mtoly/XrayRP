package gov2panel

import (
	"context"

	"github.com/Mtoly/XrayRP/api"
)

func (c *APIClient) GetNodeSnapshot() (*api.NodeSnapshot, error) {
	return c.GetNodeSnapshotContext(context.Background())
}

func (c *APIClient) GetNodeSnapshotContext(ctx context.Context) (*api.NodeSnapshot, error) {
	return c.getNodeSnapshotContext(ctx)
}
