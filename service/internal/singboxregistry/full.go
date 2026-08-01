package singboxregistry

import (
	"context"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
)

// WithFullRegistry installs sing-box's complete build-tag-selected registry
// set. Narrowing this boundary changes accepted runtime configuration and
// requires a separately approved compatibility batch.
func WithFullRegistry(ctx context.Context) context.Context {
	return box.Context(
		ctx,
		include.InboundRegistry(),
		include.OutboundRegistry(),
		include.EndpointRegistry(),
		include.DNSTransportRegistry(),
		include.ServiceRegistry(),
	)
}
