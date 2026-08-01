//go:build !with_quic

package singboxregistry

import (
	"context"
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	singservice "github.com/sagernet/sing/service"
)

func TestWithFullRegistryRetainsQUICStubsWithoutBuildTag(t *testing.T) {
	ctx := WithFullRegistry(context.Background())
	inboundOptions := singservice.FromContext[option.InboundOptionsRegistry](ctx)
	outboundOptions := singservice.FromContext[option.OutboundOptionsRegistry](ctx)
	inboundRegistry := singservice.FromContext[adapter.InboundRegistry](ctx)
	outboundRegistry := singservice.FromContext[adapter.OutboundRegistry](ctx)

	for _, name := range []string{"hysteria", "tuic", "hysteria2"} {
		inboundValue, ok := inboundOptions.CreateOptions(name)
		if !ok || inboundValue == nil {
			t.Fatalf("inbound stub %q is not registered", name)
		}
		if _, err := inboundRegistry.Create(ctx, nil, nil, "test", name, inboundValue); !errors.Is(err, C.ErrQUICNotIncluded) {
			t.Fatalf("inbound stub %q error = %v, want %v", name, err, C.ErrQUICNotIncluded)
		}

		outboundValue, ok := outboundOptions.CreateOptions(name)
		if !ok || outboundValue == nil {
			t.Fatalf("outbound stub %q is not registered", name)
		}
		if _, err := outboundRegistry.CreateOutbound(ctx, nil, nil, "test", name, outboundValue); !errors.Is(err, C.ErrQUICNotIncluded) {
			t.Fatalf("outbound stub %q error = %v, want %v", name, err, C.ErrQUICNotIncluded)
		}
	}
}
