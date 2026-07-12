package machine

import (
	"errors"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

type statusReporterPanelClientStub struct {
	reportStatusCalls int
	reportStatusErr   error
	wsConfig          *api.WSConfig
	wsEndpoint        string
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
func (c *statusReporterPanelClientStub) GetWSConfig() *api.WSConfig               { return c.wsConfig }
func (c *statusReporterPanelClientStub) DiscoverWSEndpoint() (string, error) {
	return c.wsEndpoint, nil
}

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
	wrapped := WrapAPIWithReporter(&statusReporterPanelClientStub{
		wsConfig:   wsConfig,
		wsEndpoint: "wss://panel.example.com/ws",
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
}

func TestReportingAPIPreservesCertAndAliveCapabilities(t *testing.T) {
	cert := &api.XrayRCertConfig{CertMode: "file"}
	alive := map[int][]string{4: {"phone"}}
	wrapped := WrapAPIWithReporter(&statusReporterCertAliveCapableStub{
		statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		certConfig:                    cert,
		aliveList:                     alive,
	}, 9, &statusReporterStub{})

	certProvider, ok := wrapped.(certConfigProvider)
	if !ok {
		t.Fatal("expected certificate capability to be preserved")
	}
	gotCert, err := certProvider.GetXrayRCertConfig()
	if err != nil || gotCert != cert {
		t.Fatalf("unexpected certificate forwarding: cert=%p err=%v", gotCert, err)
	}

	aliveProvider, ok := wrapped.(aliveListProvider)
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
	if _, ok := certOnly.(certConfigProvider); !ok {
		t.Fatal("expected certificate capability to be preserved")
	}
	if _, ok := certOnly.(aliveListProvider); ok {
		t.Fatal("did not expect alive-list capability to be exposed")
	}

	aliveOnly := WrapAPIWithReporter(&statusReporterAliveCapableStub{
		statusReporterPanelClientStub: &statusReporterPanelClientStub{},
	}, 9, &statusReporterStub{})
	if _, ok := aliveOnly.(certConfigProvider); ok {
		t.Fatal("did not expect certificate capability to be exposed")
	}
	if _, ok := aliveOnly.(aliveListProvider); !ok {
		t.Fatal("expected alive-list capability to be preserved")
	}

	baseOnly := WrapAPIWithReporter(&statusReporterPanelClientStub{}, 9, &statusReporterStub{})
	if _, ok := baseOnly.(certConfigProvider); ok {
		t.Fatal("did not expect certificate capability to be exposed")
	}
	if _, ok := baseOnly.(aliveListProvider); ok {
		t.Fatal("did not expect alive-list capability to be exposed")
	}
}
