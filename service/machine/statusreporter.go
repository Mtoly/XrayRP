package machine

import "github.com/Mtoly/XrayRP/api"

type NodeStatusReporter interface {
	ReportNodeStatus(nodeID int, nodeStatus *api.NodeStatus) error
}

func WrapAPIWithStatusReporter(apiClient api.API, nodeID int, reporter NodeStatusReporter) api.API {
	if apiClient == nil || reporter == nil || nodeID <= 0 {
		return apiClient
	}
	return &statusReportingAPI{
		API:      apiClient,
		nodeID:   nodeID,
		reporter: reporter,
	}
}

type statusReportingAPI struct {
	api.API
	nodeID   int
	reporter NodeStatusReporter
}

func (a *statusReportingAPI) ReportNodeStatus(nodeStatus *api.NodeStatus) error {
	if a.reporter != nil {
		_ = a.reporter.ReportNodeStatus(a.nodeID, nodeStatus)
	}
	return a.API.ReportNodeStatus(nodeStatus)
}

func (a *statusReportingAPI) GetWSConfig() *api.WSConfig {
	capable, ok := a.API.(api.WSCapable)
	if !ok {
		return nil
	}
	return capable.GetWSConfig()
}

func (a *statusReportingAPI) DiscoverWSEndpoint() (string, error) {
	discoverer, ok := a.API.(api.WSEndpointDiscoverer)
	if !ok {
		return "", nil
	}
	return discoverer.DiscoverWSEndpoint()
}
