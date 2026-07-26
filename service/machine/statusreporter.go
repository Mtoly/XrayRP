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

func WrapAPIWithReporter(apiClient PanelClient, nodeID int, reporter any) PanelClient {
	if apiClient == nil || reporter == nil || nodeID <= 0 {
		return apiClient
	}
	wrapped := &reportingAPI{
		PanelClient: apiClient,
		nodeID:      nodeID,
		reporter:    reporter,
	}
	return preservePanelCapabilities(wrapped, apiClient)
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
	api.CertConfigProvider
}

type reportingAPIWithAlive struct {
	*reportingAPI
	api.AliveListProvider
}

type reportingAPIWithCertAndAlive struct {
	*reportingAPI
	api.CertConfigProvider
	api.AliveListProvider
}

const (
	hasWSConfigCapability = 1 << iota
	hasWSEndpointCapability
	hasBaseConfigCapability
	hasCertConfigCapability
	hasAliveListCapability
)

type panelCapabilities struct {
	wsConfig   api.WSCapable
	wsEndpoint api.WSEndpointDiscoverer
	baseConfig api.BaseConfigProvider
	certConfig api.CertConfigProvider
	aliveList  api.AliveListProvider
	mask       int
}

func preservePanelCapabilities(wrapped *reportingAPI, client PanelClient) PanelClient {
	capabilities := panelCapabilities{}
	if provider, ok := client.(api.WSCapable); ok {
		capabilities.wsConfig = provider
		capabilities.mask |= hasWSConfigCapability
	}
	if provider, ok := client.(api.WSEndpointDiscoverer); ok {
		capabilities.wsEndpoint = provider
		capabilities.mask |= hasWSEndpointCapability
	}
	if provider, ok := client.(api.BaseConfigProvider); ok {
		capabilities.baseConfig = provider
		capabilities.mask |= hasBaseConfigCapability
	}
	if provider, ok := client.(api.CertConfigProvider); ok {
		capabilities.certConfig = provider
		capabilities.mask |= hasCertConfigCapability
	}
	if provider, ok := client.(api.AliveListProvider); ok {
		capabilities.aliveList = provider
		capabilities.mask |= hasAliveListCapability
	}
	return wrapReportingAPIWithCapabilities(wrapped, capabilities)
}

func wrapReportingAPIWithCapabilities(wrapped *reportingAPI, capabilities panelCapabilities) PanelClient {
	// Each concrete result has exactly the original client's method set.
	// Keeping this explicit prevents both fabricated and accidentally hidden
	// optional capabilities.
	switch capabilities.mask {
	case 0:
		return wrapped
	case hasWSConfigCapability:
		return struct {
			*reportingAPI
			api.WSCapable
		}{wrapped, capabilities.wsConfig}
	case hasWSEndpointCapability:
		return struct {
			*reportingAPI
			api.WSEndpointDiscoverer
		}{wrapped, capabilities.wsEndpoint}
	case hasWSConfigCapability | hasWSEndpointCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.WSEndpointDiscoverer
		}{wrapped, capabilities.wsConfig, capabilities.wsEndpoint}
	case hasBaseConfigCapability:
		return struct {
			*reportingAPI
			api.BaseConfigProvider
		}{wrapped, capabilities.baseConfig}
	case hasWSConfigCapability | hasBaseConfigCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.BaseConfigProvider
		}{wrapped, capabilities.wsConfig, capabilities.baseConfig}
	case hasWSEndpointCapability | hasBaseConfigCapability:
		return struct {
			*reportingAPI
			api.WSEndpointDiscoverer
			api.BaseConfigProvider
		}{wrapped, capabilities.wsEndpoint, capabilities.baseConfig}
	case hasWSConfigCapability | hasWSEndpointCapability | hasBaseConfigCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.WSEndpointDiscoverer
			api.BaseConfigProvider
		}{wrapped, capabilities.wsConfig, capabilities.wsEndpoint, capabilities.baseConfig}
	case hasCertConfigCapability:
		return &reportingAPIWithCert{wrapped, capabilities.certConfig}
	case hasWSConfigCapability | hasCertConfigCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.CertConfigProvider
		}{wrapped, capabilities.wsConfig, capabilities.certConfig}
	case hasWSEndpointCapability | hasCertConfigCapability:
		return struct {
			*reportingAPI
			api.WSEndpointDiscoverer
			api.CertConfigProvider
		}{wrapped, capabilities.wsEndpoint, capabilities.certConfig}
	case hasWSConfigCapability | hasWSEndpointCapability | hasCertConfigCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.WSEndpointDiscoverer
			api.CertConfigProvider
		}{wrapped, capabilities.wsConfig, capabilities.wsEndpoint, capabilities.certConfig}
	case hasBaseConfigCapability | hasCertConfigCapability:
		return struct {
			*reportingAPI
			api.BaseConfigProvider
			api.CertConfigProvider
		}{wrapped, capabilities.baseConfig, capabilities.certConfig}
	case hasWSConfigCapability | hasBaseConfigCapability | hasCertConfigCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.BaseConfigProvider
			api.CertConfigProvider
		}{wrapped, capabilities.wsConfig, capabilities.baseConfig, capabilities.certConfig}
	case hasWSEndpointCapability | hasBaseConfigCapability | hasCertConfigCapability:
		return struct {
			*reportingAPI
			api.WSEndpointDiscoverer
			api.BaseConfigProvider
			api.CertConfigProvider
		}{wrapped, capabilities.wsEndpoint, capabilities.baseConfig, capabilities.certConfig}
	case hasWSConfigCapability | hasWSEndpointCapability | hasBaseConfigCapability | hasCertConfigCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.WSEndpointDiscoverer
			api.BaseConfigProvider
			api.CertConfigProvider
		}{wrapped, capabilities.wsConfig, capabilities.wsEndpoint, capabilities.baseConfig, capabilities.certConfig}
	case hasAliveListCapability:
		return &reportingAPIWithAlive{wrapped, capabilities.aliveList}
	case hasWSConfigCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.AliveListProvider
		}{wrapped, capabilities.wsConfig, capabilities.aliveList}
	case hasWSEndpointCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.WSEndpointDiscoverer
			api.AliveListProvider
		}{wrapped, capabilities.wsEndpoint, capabilities.aliveList}
	case hasWSConfigCapability | hasWSEndpointCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.WSEndpointDiscoverer
			api.AliveListProvider
		}{wrapped, capabilities.wsConfig, capabilities.wsEndpoint, capabilities.aliveList}
	case hasBaseConfigCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.BaseConfigProvider
			api.AliveListProvider
		}{wrapped, capabilities.baseConfig, capabilities.aliveList}
	case hasWSConfigCapability | hasBaseConfigCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.BaseConfigProvider
			api.AliveListProvider
		}{wrapped, capabilities.wsConfig, capabilities.baseConfig, capabilities.aliveList}
	case hasWSEndpointCapability | hasBaseConfigCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.WSEndpointDiscoverer
			api.BaseConfigProvider
			api.AliveListProvider
		}{wrapped, capabilities.wsEndpoint, capabilities.baseConfig, capabilities.aliveList}
	case hasWSConfigCapability | hasWSEndpointCapability | hasBaseConfigCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.WSEndpointDiscoverer
			api.BaseConfigProvider
			api.AliveListProvider
		}{wrapped, capabilities.wsConfig, capabilities.wsEndpoint, capabilities.baseConfig, capabilities.aliveList}
	case hasCertConfigCapability | hasAliveListCapability:
		return &reportingAPIWithCertAndAlive{wrapped, capabilities.certConfig, capabilities.aliveList}
	case hasWSConfigCapability | hasCertConfigCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.CertConfigProvider
			api.AliveListProvider
		}{wrapped, capabilities.wsConfig, capabilities.certConfig, capabilities.aliveList}
	case hasWSEndpointCapability | hasCertConfigCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.WSEndpointDiscoverer
			api.CertConfigProvider
			api.AliveListProvider
		}{wrapped, capabilities.wsEndpoint, capabilities.certConfig, capabilities.aliveList}
	case hasWSConfigCapability | hasWSEndpointCapability | hasCertConfigCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.WSEndpointDiscoverer
			api.CertConfigProvider
			api.AliveListProvider
		}{wrapped, capabilities.wsConfig, capabilities.wsEndpoint, capabilities.certConfig, capabilities.aliveList}
	case hasBaseConfigCapability | hasCertConfigCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.BaseConfigProvider
			api.CertConfigProvider
			api.AliveListProvider
		}{wrapped, capabilities.baseConfig, capabilities.certConfig, capabilities.aliveList}
	case hasWSConfigCapability | hasBaseConfigCapability | hasCertConfigCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.BaseConfigProvider
			api.CertConfigProvider
			api.AliveListProvider
		}{wrapped, capabilities.wsConfig, capabilities.baseConfig, capabilities.certConfig, capabilities.aliveList}
	case hasWSEndpointCapability | hasBaseConfigCapability | hasCertConfigCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.WSEndpointDiscoverer
			api.BaseConfigProvider
			api.CertConfigProvider
			api.AliveListProvider
		}{wrapped, capabilities.wsEndpoint, capabilities.baseConfig, capabilities.certConfig, capabilities.aliveList}
	case hasWSConfigCapability | hasWSEndpointCapability | hasBaseConfigCapability | hasCertConfigCapability | hasAliveListCapability:
		return struct {
			*reportingAPI
			api.WSCapable
			api.WSEndpointDiscoverer
			api.BaseConfigProvider
			api.CertConfigProvider
			api.AliveListProvider
		}{wrapped, capabilities.wsConfig, capabilities.wsEndpoint, capabilities.baseConfig, capabilities.certConfig, capabilities.aliveList}
	default:
		return wrapped
	}
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
