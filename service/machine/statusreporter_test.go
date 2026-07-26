package machine

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

type statusReporterPanelClientStub struct {
	reportStatusCalls int
	reportStatusErr   error
}

type statusReporterAllCapableStub struct {
	*statusReporterCertAliveCapableStub
	wsConfig   *api.WSConfig
	wsEndpoint string
	baseConfig *api.BaseConfig
}

type statusReporterWSCapableStub struct {
	*statusReporterPanelClientStub
	wsConfig *api.WSConfig
}

func (c *statusReporterWSCapableStub) GetWSConfig() *api.WSConfig {
	return c.wsConfig
}

type statusReporterWSEndpointStub struct {
	*statusReporterPanelClientStub
	wsEndpoint string
}

func (c *statusReporterWSEndpointStub) DiscoverWSEndpoint() (string, error) {
	return c.wsEndpoint, nil
}

type statusReporterBaseConfigStub struct {
	*statusReporterPanelClientStub
	baseConfig *api.BaseConfig
}

func (c *statusReporterBaseConfigStub) GetBaseConfig() *api.BaseConfig {
	return c.baseConfig
}

func (c *statusReporterAllCapableStub) GetWSConfig() *api.WSConfig {
	return c.wsConfig
}

func (c *statusReporterAllCapableStub) DiscoverWSEndpoint() (string, error) {
	return c.wsEndpoint, nil
}

func (c *statusReporterAllCapableStub) GetBaseConfig() *api.BaseConfig {
	return c.baseConfig
}

type statusReporterCertCapableStub struct {
	*statusReporterPanelClientStub
	certConfig *api.XrayRCertConfig
	certErr    error
}

func (c *statusReporterCertCapableStub) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	return c.certConfig, c.certErr
}

type statusReporterAliveCapableStub struct {
	*statusReporterPanelClientStub
	aliveList map[int][]string
	aliveErr  error
}

func (c *statusReporterAliveCapableStub) GetAliveList() (map[int][]string, error) {
	return c.aliveList, c.aliveErr
}

type statusReporterCertAliveCapableStub struct {
	*statusReporterPanelClientStub
	certConfig *api.XrayRCertConfig
	certErr    error
	aliveList  map[int][]string
	aliveErr   error
}

func (c *statusReporterCertAliveCapableStub) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	return c.certConfig, c.certErr
}

func (c *statusReporterCertAliveCapableStub) GetAliveList() (map[int][]string, error) {
	return c.aliveList, c.aliveErr
}

func (*statusReporterPanelClientStub) Describe() api.ClientInfo              { return api.ClientInfo{} }
func (*statusReporterPanelClientStub) GetNodeInfo() (*api.NodeInfo, error)   { return nil, nil }
func (*statusReporterPanelClientStub) GetUserList() (*[]api.UserInfo, error) { return nil, nil }
func (*statusReporterPanelClientStub) GetNodeRule() (*[]api.DetectRule, error) {
	return nil, nil
}
func (c *statusReporterPanelClientStub) ReportNodeStatus(*api.NodeStatus) error {
	c.reportStatusCalls++
	return c.reportStatusErr
}
func (*statusReporterPanelClientStub) ReportNodeOnlineUsers(*[]api.OnlineUser) error {
	return nil
}
func (*statusReporterPanelClientStub) ReportUserTraffic(*[]api.UserTraffic) error { return nil }
func (*statusReporterPanelClientStub) ReportIllegal(*[]api.DetectResult) error    { return nil }

type statusReporterStub struct {
	nodeID      int
	status      *api.NodeStatus
	devices     map[int][]string
	ready       bool
	statusCalls int
}

func (r *statusReporterStub) ReportNodeStatus(nodeID int, status *api.NodeStatus) error {
	r.nodeID = nodeID
	r.status = status
	r.statusCalls++
	return errors.New("reporter failure")
}

func (r *statusReporterStub) ReportNodeDevices(nodeID int, devices map[int][]string) error {
	r.nodeID = nodeID
	r.devices = devices
	return nil
}

func (r *statusReporterStub) DeviceReporterReady() bool { return r.ready }

func TestReportingAPIReportsStatusToReporterAndRESTClient(t *testing.T) {
	restErr := errors.New("REST failure")
	client := &statusReporterPanelClientStub{reportStatusErr: restErr}
	reporter := &statusReporterStub{}
	wrapped := WrapAPIWithReporter(client, 7, reporter)
	status := &api.NodeStatus{CPU: 12}

	err := wrapped.ReportNodeStatus(status)

	if !errors.Is(err, restErr) {
		t.Fatalf("expected REST error, got %v", err)
	}
	if client.reportStatusCalls != 1 || reporter.statusCalls != 1 {
		t.Fatalf("expected one REST and reporter call, got REST=%d reporter=%d", client.reportStatusCalls, reporter.statusCalls)
	}
	if reporter.nodeID != 7 || reporter.status != status {
		t.Fatalf("unexpected reporter arguments: nodeID=%d status=%p", reporter.nodeID, reporter.status)
	}
}

func TestReportingAPIDeviceReportingAndReadiness(t *testing.T) {
	reporter := &statusReporterStub{ready: true}
	wrapped := WrapAPIWithReporter(&statusReporterPanelClientStub{}, 8, reporter)
	capable, ok := wrapped.(interface {
		ReportNodeDevices(map[int][]string) error
		DeviceReporterReady() bool
	})
	if !ok {
		t.Fatal("expected wrapped client to expose device reporting capabilities")
	}
	devices := map[int][]string{3: {"phone"}}

	if err := capable.ReportNodeDevices(devices); err != nil {
		t.Fatalf("ReportNodeDevices returned error: %v", err)
	}
	if !capable.DeviceReporterReady() {
		t.Fatal("expected reporter readiness to be forwarded")
	}
	if reporter.nodeID != 8 || reporter.devices[3][0] != "phone" {
		t.Fatalf("unexpected device report: nodeID=%d devices=%v", reporter.nodeID, reporter.devices)
	}
}

func TestReportingAPIForwardsWSCapabilities(t *testing.T) {
	wsConfig := &api.WSConfig{NodeID: 9}
	baseConfig := &api.BaseConfig{PushInterval: 15, PullInterval: 45}
	wrapped := WrapAPIWithReporter(&statusReporterAllCapableStub{
		statusReporterCertAliveCapableStub: &statusReporterCertAliveCapableStub{
			statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		},
		wsConfig:   wsConfig,
		wsEndpoint: "wss://panel.example.com/ws",
		baseConfig: baseConfig,
	}, 9, &statusReporterStub{})

	capable, ok := wrapped.(api.WSCapable)
	if !ok || capable.GetWSConfig() != wsConfig {
		t.Fatal("expected websocket config capability to be forwarded")
	}
	discoverer, ok := wrapped.(api.WSEndpointDiscoverer)
	if !ok {
		t.Fatal("expected websocket endpoint capability to be forwarded")
	}
	endpoint, err := discoverer.DiscoverWSEndpoint()
	if err != nil || endpoint != "wss://panel.example.com/ws" {
		t.Fatalf("unexpected websocket endpoint: endpoint=%q err=%v", endpoint, err)
	}
	baseProvider, ok := wrapped.(api.BaseConfigProvider)
	if !ok || baseProvider.GetBaseConfig() != baseConfig {
		t.Fatal("expected base-config capability to be forwarded")
	}
}

func TestReportingAPIPreservesIndependentPanelCapabilities(t *testing.T) {
	wsConfig := &api.WSConfig{NodeID: 9}
	wsOnly := WrapAPIWithReporter(&statusReporterWSCapableStub{
		statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		wsConfig:                      wsConfig,
	}, 9, &statusReporterStub{})
	wsProvider, ok := wsOnly.(api.WSCapable)
	if !ok || wsProvider.GetWSConfig() != wsConfig {
		t.Fatal("expected standalone websocket config capability to be preserved")
	}
	if _, ok := wsOnly.(api.WSEndpointDiscoverer); ok {
		t.Fatal("did not expect websocket endpoint capability")
	}
	if _, ok := wsOnly.(api.BaseConfigProvider); ok {
		t.Fatal("did not expect base-config capability")
	}

	endpoint := "wss://panel.example.com/ws"
	endpointOnly := WrapAPIWithReporter(&statusReporterWSEndpointStub{
		statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		wsEndpoint:                    endpoint,
	}, 9, &statusReporterStub{})
	endpointProvider, ok := endpointOnly.(api.WSEndpointDiscoverer)
	if !ok {
		t.Fatal("expected standalone websocket endpoint capability to be preserved")
	}
	gotEndpoint, err := endpointProvider.DiscoverWSEndpoint()
	if err != nil || gotEndpoint != endpoint {
		t.Fatalf("unexpected websocket endpoint: endpoint=%q err=%v", gotEndpoint, err)
	}
	if _, ok := endpointOnly.(api.WSCapable); ok {
		t.Fatal("did not expect websocket config capability")
	}
	if _, ok := endpointOnly.(api.BaseConfigProvider); ok {
		t.Fatal("did not expect base-config capability")
	}

	baseConfig := &api.BaseConfig{PushInterval: 15, PullInterval: 45}
	baseOnly := WrapAPIWithReporter(&statusReporterBaseConfigStub{
		statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		baseConfig:                    baseConfig,
	}, 9, &statusReporterStub{})
	baseProvider, ok := baseOnly.(api.BaseConfigProvider)
	if !ok || baseProvider.GetBaseConfig() != baseConfig {
		t.Fatal("expected standalone base-config capability to be preserved")
	}
	if _, ok := baseOnly.(api.WSCapable); ok {
		t.Fatal("did not expect websocket config capability")
	}
	if _, ok := baseOnly.(api.WSEndpointDiscoverer); ok {
		t.Fatal("did not expect websocket endpoint capability")
	}
}

func TestReportingAPIPreservesCertAndAliveCapabilities(t *testing.T) {
	cert := &api.XrayRCertConfig{CertMode: "file"}
	alive := map[int][]string{4: {"phone"}}
	wrapped := WrapAPIWithReporter(&statusReporterCertAliveCapableStub{
		statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		certConfig:                    cert,
		aliveList:                     alive,
	}, 9, &statusReporterStub{})

	certProvider, ok := wrapped.(api.CertConfigProvider)
	if !ok {
		t.Fatal("expected certificate capability to be preserved")
	}
	gotCert, err := certProvider.GetXrayRCertConfig()
	if err != nil || gotCert != cert {
		t.Fatalf("unexpected certificate forwarding: cert=%p err=%v", gotCert, err)
	}

	aliveProvider, ok := wrapped.(api.AliveListProvider)
	if !ok {
		t.Fatal("expected alive-list capability to be preserved")
	}
	gotAlive, err := aliveProvider.GetAliveList()
	if err != nil || gotAlive[4][0] != "phone" {
		t.Fatalf("unexpected alive-list forwarding: alive=%v err=%v", gotAlive, err)
	}
}

func TestReportingAPIPreservesOnlyCapabilitiesProvidedByClient(t *testing.T) {
	certOnly := WrapAPIWithReporter(&statusReporterCertCapableStub{
		statusReporterPanelClientStub: &statusReporterPanelClientStub{},
	}, 9, &statusReporterStub{})
	if _, ok := certOnly.(api.CertConfigProvider); !ok {
		t.Fatal("expected certificate capability to be preserved")
	}
	if _, ok := certOnly.(api.AliveListProvider); ok {
		t.Fatal("did not expect alive-list capability to be exposed")
	}

	aliveOnly := WrapAPIWithReporter(&statusReporterAliveCapableStub{
		statusReporterPanelClientStub: &statusReporterPanelClientStub{},
	}, 9, &statusReporterStub{})
	if _, ok := aliveOnly.(api.CertConfigProvider); ok {
		t.Fatal("did not expect certificate capability to be exposed")
	}
	if _, ok := aliveOnly.(api.AliveListProvider); !ok {
		t.Fatal("expected alive-list capability to be preserved")
	}

	baseOnly := WrapAPIWithReporter(&statusReporterPanelClientStub{}, 9, &statusReporterStub{})
	if _, ok := baseOnly.(api.CertConfigProvider); ok {
		t.Fatal("did not expect certificate capability to be exposed")
	}
	if _, ok := baseOnly.(api.AliveListProvider); ok {
		t.Fatal("did not expect alive-list capability to be exposed")
	}
	if _, ok := baseOnly.(api.WSCapable); ok {
		t.Fatal("did not expect websocket capability to be exposed")
	}
	if _, ok := baseOnly.(api.WSEndpointDiscoverer); ok {
		t.Fatal("did not expect websocket discovery capability to be exposed")
	}
	if _, ok := baseOnly.(api.BaseConfigProvider); ok {
		t.Fatal("did not expect base-config capability to be exposed")
	}
}

func TestReportingAPIExhaustivelyPreservesCapabilityMethodSets(t *testing.T) {
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
