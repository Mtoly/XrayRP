//go:build with_quic

package singboxregistry

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	singservice "github.com/sagernet/sing/service"
)

func TestWithFullRegistryIncludesQUICWithBuildTag(t *testing.T) {
	ctx := WithFullRegistry(context.Background())
	inboundOptions := singservice.FromContext[option.InboundOptionsRegistry](ctx)
	outboundOptions := singservice.FromContext[option.OutboundOptionsRegistry](ctx)

	assertRegisteredOptions(t, "inbound", inboundOptions, []string{"hysteria", "tuic", "hysteria2"})
	assertRegisteredOptions(t, "outbound", outboundOptions, []string{"hysteria", "tuic", "hysteria2"})
}
