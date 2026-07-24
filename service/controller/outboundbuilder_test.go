package controller

import (
	"testing"

	"github.com/xtls/xray-core/proxy/freedom"
)

func TestFocusedOutboundBuilderPreservesDokodemoRedirect(t *testing.T) {
	outbound, err := buildOutbound(&Config{SendIP: "0.0.0.0"}, outboundNodeView{
		nodeType: "dokodemo-door",
		port:     8444,
	}, "dokodemo-test")
	if err != nil {
		t.Fatal(err)
	}

	settings, err := outbound.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	freedomConfig := settings.(*freedom.Config)
	if freedomConfig.DestinationOverride == nil || freedomConfig.DestinationOverride.Server == nil {
		t.Fatalf("expected dokodemo redirect, got %#v", freedomConfig.DestinationOverride)
	}
	if got := freedomConfig.DestinationOverride.Server.Port; got != 8443 {
		t.Fatalf("redirect port = %d, want 8443", got)
	}
}
