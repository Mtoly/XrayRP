package singboxregistry

import (
	"context"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
)

// WithFullRegistry installs sing-box's complete build-tag-selected registry
// set. Narrowing this boundary changes accepted runtime configuration and
// requires a separately approved compatibility batch. The AnyTLS and TUIC
// inbounds are replaced by equivalents that accept runtime user updates.
func WithFullRegistry(ctx context.Context) context.Context {
	inboundRegistry := include.InboundRegistry()
	registerAnyTLSInbound(inboundRegistry)
	registerQUICUserInbounds(inboundRegistry)
	return box.Context(
		ctx,
		inboundRegistry,
		include.OutboundRegistry(),
		include.EndpointRegistry(),
		include.DNSTransportRegistry(),
		include.ServiceRegistry(),
		include.CertificateProviderRegistry(),
	)
}
