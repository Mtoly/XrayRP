package singboxregistry

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	singservice "github.com/sagernet/sing/service"
)

func TestWithFullRegistryInstallsBaseRegistries(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	ctx := WithFullRegistry(parent)
	cancel()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("registry context detached from parent cancellation")
	}

	inboundOptions := singservice.FromContext[option.InboundOptionsRegistry](ctx)
	outboundOptions := singservice.FromContext[option.OutboundOptionsRegistry](ctx)
	if inboundOptions == nil || outboundOptions == nil {
		t.Fatal("registry context is missing inbound or outbound option registry")
	}
	if singservice.FromContext[adapter.InboundRegistry](ctx) == nil ||
		singservice.FromContext[adapter.OutboundRegistry](ctx) == nil ||
		singservice.FromContext[adapter.EndpointRegistry](ctx) == nil ||
		singservice.FromContext[adapter.DNSTransportRegistry](ctx) == nil ||
		singservice.FromContext[adapter.ServiceRegistry](ctx) == nil {
		t.Fatal("registry context is missing a runtime registry")
	}

	assertRegisteredOptions(t, "inbound", inboundOptions, []string{
		"tun", "redirect", "tproxy", "direct", "socks", "http", "mixed",
		"shadowsocks", "vmess", "trojan", "naive", "shadowtls", "vless",
		"anytls", "shadowsocksr",
	})
	assertRegisteredOptions(t, "outbound", outboundOptions, []string{
		"direct", "block", "selector", "urltest", "socks", "http",
		"shadowsocks", "vmess", "trojan", "tor", "ssh", "shadowtls",
		"vless", "anytls", "shadowsocksr", "wireguard",
	})

	for _, name := range []string{"AnyTLS", " anytls", "anytls "} {
		if value, ok := inboundOptions.CreateOptions(name); ok || value != nil {
			t.Fatalf("inbound %q unexpectedly normalized to %#v", name, value)
		}
	}
	if value, ok := outboundOptions.CreateOptions("missing-outbound"); ok || value != nil {
		t.Fatalf("unknown outbound unexpectedly registered as %#v", value)
	}
}

type optionRegistry interface {
	CreateOptions(string) (any, bool)
}

func assertRegisteredOptions(t *testing.T, kind string, registry optionRegistry, names []string) {
	t.Helper()
	for _, name := range names {
		t.Run(kind+"/"+name, func(t *testing.T) {
			value, ok := registry.CreateOptions(name)
			if !ok || value == nil {
				t.Fatalf("%s %q is not registered", kind, name)
			}
		})
	}
}
