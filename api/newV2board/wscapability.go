package newV2board

import "github.com/Mtoly/XrayRP/api"

var _ api.WSCapable = (*APIClient)(nil)

// GetWSConfig exposes websocket-related adapter context as an opt-in capability.
func (c *APIClient) GetWSConfig() *api.WSConfig {
	return c.wsConfig()
}
