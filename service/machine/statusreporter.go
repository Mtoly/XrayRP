package machine

import "github.com/Mtoly/XrayRP/api"

type NodeStatusReporter interface {
	ReportNodeStatus(nodeID int, nodeStatus *api.NodeStatus) error
}

type MachineStatusReporter interface {
	ReportMachineStatus(status api.MachineStatus) error
}

type MachineStatusCollector func() (api.MachineStatus, error)

type NodeDeviceReporter interface {
	ReportNodeDevices(nodeID int, devices map[int][]string) error
}

type DeviceReporterReadiness interface {
	DeviceReporterReady() bool
}

type PanelClient interface {
	Describe() api.ClientInfo
	GetNodeInfo() (*api.NodeInfo, error)
	GetUserList() (*[]api.UserInfo, error)
	GetNodeRule() (*[]api.DetectRule, error)
	ReportNodeStatus(*api.NodeStatus) error
	ReportNodeOnlineUsers(*[]api.OnlineUser) error
	ReportUserTraffic(*[]api.UserTraffic) error
	ReportIllegal(*[]api.DetectResult) error
}

type certConfigProvider interface {
	GetXrayRCertConfig() (*api.XrayRCertConfig, error)
}

type aliveListProvider interface {
	GetAliveList() (map[int][]string, error)
}

func WrapAPIWithReporter(apiClient PanelClient, nodeID int, reporter any) PanelClient {
	if apiClient == nil || reporter == nil || nodeID <= 0 {
		return apiClient
	}
	wrapped := &reportingAPI{
		PanelClient: apiClient,
		nodeID:      nodeID,
		reporter:    reporter,
	}
	certProvider, hasCert := apiClient.(certConfigProvider)
	aliveProvider, hasAlive := apiClient.(aliveListProvider)
	switch {
	case hasCert && hasAlive:
		return &reportingAPIWithCertAndAlive{
			reportingAPI:       wrapped,
			certConfigProvider: certProvider,
			aliveListProvider:  aliveProvider,
		}
	case hasCert:
		return &reportingAPIWithCert{
			reportingAPI:       wrapped,
			certConfigProvider: certProvider,
		}
	case hasAlive:
		return &reportingAPIWithAlive{
			reportingAPI:      wrapped,
			aliveListProvider: aliveProvider,
		}
	default:
		return wrapped
	}
}

func WrapAPIWithStatusReporter(apiClient PanelClient, nodeID int, reporter NodeStatusReporter) PanelClient {
	return WrapAPIWithReporter(apiClient, nodeID, reporter)
}

type reportingAPI struct {
	PanelClient
	nodeID   int
	reporter any
}

type reportingAPIWithCert struct {
	*reportingAPI
	certConfigProvider
}

type reportingAPIWithAlive struct {
	*reportingAPI
	aliveListProvider
}

type reportingAPIWithCertAndAlive struct {
	*reportingAPI
	certConfigProvider
	aliveListProvider
}

func (a *reportingAPI) ReportNodeStatus(nodeStatus *api.NodeStatus) error {
	if reporter, ok := a.reporter.(NodeStatusReporter); ok {
		_ = reporter.ReportNodeStatus(a.nodeID, nodeStatus)
	}
	return a.PanelClient.ReportNodeStatus(nodeStatus)
}

func (a *reportingAPI) ReportNodeDevices(devices map[int][]string) error {
	if reporter, ok := a.reporter.(NodeDeviceReporter); ok {
		return reporter.ReportNodeDevices(a.nodeID, devices)
	}
	return nil
}

func (a *reportingAPI) DeviceReporterReady() bool {
	readiness, ok := a.reporter.(DeviceReporterReadiness)
	return !ok || readiness.DeviceReporterReady()
}

func (a *reportingAPI) GetWSConfig() *api.WSConfig {
	capable, ok := a.PanelClient.(api.WSCapable)
	if !ok {
		return nil
	}
	return capable.GetWSConfig()
}

func (a *reportingAPI) DiscoverWSEndpoint() (string, error) {
	discoverer, ok := a.PanelClient.(api.WSEndpointDiscoverer)
	if !ok {
		return "", nil
	}
	return discoverer.DiscoverWSEndpoint()
}
