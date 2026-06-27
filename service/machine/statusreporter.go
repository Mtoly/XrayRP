package machine

import "github.com/Mtoly/XrayRP/api"

type NodeStatusReporter interface {
	ReportNodeStatus(nodeID int, nodeStatus *api.NodeStatus) error
}

type NodeDeviceReporter interface {
	ReportNodeDevices(nodeID int, devices map[int][]string) error
}

type DeviceReporterReadiness interface {
	DeviceReporterReady() bool
}

func WrapAPIWithReporter(apiClient api.API, nodeID int, reporter any) api.API {
	if apiClient == nil || reporter == nil || nodeID <= 0 {
		return apiClient
	}
	return &reportingAPI{
		API:      apiClient,
		nodeID:   nodeID,
		reporter: reporter,
	}
}

func WrapAPIWithStatusReporter(apiClient api.API, nodeID int, reporter NodeStatusReporter) api.API {
	return WrapAPIWithReporter(apiClient, nodeID, reporter)
}

type reportingAPI struct {
	api.API
	nodeID   int
	reporter any
}

func (a *reportingAPI) ReportNodeStatus(nodeStatus *api.NodeStatus) error {
	if reporter, ok := a.reporter.(NodeStatusReporter); ok {
		_ = reporter.ReportNodeStatus(a.nodeID, nodeStatus)
	}
	return a.API.ReportNodeStatus(nodeStatus)
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
	capable, ok := a.API.(api.WSCapable)
	if !ok {
		return nil
	}
	return capable.GetWSConfig()
}

func (a *reportingAPI) DiscoverWSEndpoint() (string, error) {
	discoverer, ok := a.API.(api.WSEndpointDiscoverer)
	if !ok {
		return "", nil
	}
	return discoverer.DiscoverWSEndpoint()
}
