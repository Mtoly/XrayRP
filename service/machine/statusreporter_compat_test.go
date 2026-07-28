package machine

import (
	"fmt"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

var (
	_ func(PanelClient, int, any) PanelClient                = WrapAPIWithReporter
	_ func(PanelClient, int, NodeStatusReporter) PanelClient = WrapAPIWithStatusReporter
)

func TestLegacyReporterWrapperPreservesPartialCapabilities(t *testing.T) {
	wsConfig := &api.WSConfig{NodeID: 9}
	client := &statusReporterWSCapableStub{
		statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		wsConfig:                      wsConfig,
	}

	wrapped := WrapAPIWithReporter(client, 9, &statusReporterStub{})

	wsProvider, ok := wrapped.(api.WSCapable)
	if !ok || wsProvider.GetWSConfig() != wsConfig {
		t.Fatal("legacy reporter wrapper did not preserve websocket config capability")
	}
	if _, ok := wrapped.(api.WSEndpointDiscoverer); ok {
		t.Fatal("legacy reporter wrapper fabricated websocket endpoint capability")
	}

}
func TestLegacyReportingAPIExhaustivelyPreservesCapabilityMethodSets(t *testing.T) {
	source := &statusReporterAllCapableStub{
		statusReporterCertAliveCapableStub: &statusReporterCertAliveCapableStub{
			statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		},
	}
	allCapabilities := panelCapabilities{
		wsConfig:   source,
		wsEndpoint: source,
		baseConfig: source,
		certConfig: source,
		aliveList:  source,
	}

	for mask := 0; mask < 1<<5; mask++ {
		t.Run(fmt.Sprintf("mask_%02d", mask), func(t *testing.T) {
			capabilities := allCapabilities
			capabilities.mask = mask
			wrapped := wrapReportingAPIWithCapabilities(
				&reportingAPI{PanelClient: &statusReporterPanelClientStub{}},
				capabilities,
			)

			assertCapability := func(name string, capabilityMask int, present bool) {
				t.Helper()
				want := mask&capabilityMask != 0
				if present != want {
					t.Fatalf("%s presence = %t, want %t for mask %05b", name, present, want, mask)
				}
			}
			_, hasWSConfig := wrapped.(api.WSCapable)
			assertCapability("websocket config", hasWSConfigCapability, hasWSConfig)
			_, hasWSEndpoint := wrapped.(api.WSEndpointDiscoverer)
			assertCapability("websocket endpoint", hasWSEndpointCapability, hasWSEndpoint)
			_, hasBaseConfig := wrapped.(api.BaseConfigProvider)
			assertCapability("base config", hasBaseConfigCapability, hasBaseConfig)
			_, hasCertConfig := wrapped.(api.CertConfigProvider)
			assertCapability("certificate config", hasCertConfigCapability, hasCertConfig)
			_, hasAliveList := wrapped.(api.AliveListProvider)
			assertCapability("alive list", hasAliveListCapability, hasAliveList)
		})
	}
}
