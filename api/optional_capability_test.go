package api_test

import (
	"errors"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/bunpanel"
	"github.com/Mtoly/XrayRP/api/gov2panel"
	"github.com/Mtoly/XrayRP/api/pmpanel"
	"github.com/Mtoly/XrayRP/api/proxypanel"
	"github.com/Mtoly/XrayRP/api/sspanel"
	"github.com/Mtoly/XrayRP/api/v2raysocks"
)

func TestUnsupportedCertificateCapabilitiesReturnSentinel(t *testing.T) {
	clients := map[string]api.CertConfigProvider{
		"BunPanel":   bunpanel.New(&api.Config{}),
		"GoV2Panel":  gov2panel.New(&api.Config{}),
		"PMPanel":    pmpanel.New(&api.Config{}),
		"ProxyPanel": proxypanel.New(&api.Config{}),
		"V2RaySocks": v2raysocks.New(&api.Config{}),
	}

	for name, client := range clients {
		t.Run(name, func(t *testing.T) {
			config, err := client.GetXrayRCertConfig()
			if config != nil {
				t.Fatalf("certificate config = %#v, want nil", config)
			}
			if !errors.Is(err, api.ErrUnsupportedPanelFeature) {
				t.Fatalf("error = %v, want ErrUnsupportedPanelFeature", err)
			}
		})
	}
}

func TestUnsupportedAliveListCapabilitiesReturnSentinel(t *testing.T) {
	clients := map[string]api.AliveListProvider{
		"BunPanel":   bunpanel.New(&api.Config{}),
		"GoV2Panel":  gov2panel.New(&api.Config{}),
		"PMPanel":    pmpanel.New(&api.Config{}),
		"ProxyPanel": proxypanel.New(&api.Config{}),
		"SSPanel":    sspanel.New(&api.Config{}),
		"V2RaySocks": v2raysocks.New(&api.Config{}),
	}

	for name, client := range clients {
		t.Run(name, func(t *testing.T) {
			alive, err := client.GetAliveList()
			if alive != nil {
				t.Fatalf("alive list = %#v, want nil", alive)
			}
			if !errors.Is(err, api.ErrUnsupportedPanelFeature) {
				t.Fatalf("error = %v, want ErrUnsupportedPanelFeature", err)
			}
		})
	}
}
