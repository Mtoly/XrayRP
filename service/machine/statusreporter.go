package machine

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
)

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

type machinePanelClient interface {
	PanelClient
	api.WSCapable
	api.WSEndpointDiscoverer
	api.BaseConfigProvider
	api.CertConfigProvider
	api.AliveListProvider
}

var _ machinePanelClient = (*newV2board.APIClient)(nil)

func requireMachinePanelClient(client PanelClient) (machinePanelClient, error) {
	if client == nil || isNilPanelClient(client) {
		return nil, fmt.Errorf("machine panel client must not be nil")
	}
	var missing []string
	if _, ok := client.(api.WSCapable); !ok {
		missing = append(missing, "websocket config")
	}
	if _, ok := client.(api.WSEndpointDiscoverer); !ok {
		missing = append(missing, "websocket endpoint discovery")
	}
	if _, ok := client.(api.BaseConfigProvider); !ok {
		missing = append(missing, "base config")
	}
	if _, ok := client.(api.CertConfigProvider); !ok {
		missing = append(missing, "certificate config")
	}
	if _, ok := client.(api.AliveListProvider); !ok {
		missing = append(missing, "alive list")
	}
	if len(missing) != 0 {
		return nil, fmt.Errorf(
			"machine panel client is missing required capabilities: %s",
			strings.Join(missing, ", "),
		)
	}
	return client.(machinePanelClient), nil
}

func isNilPanelClient(client PanelClient) bool {
	value := reflect.ValueOf(client)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func WrapAPIWithReporter(apiClient PanelClient, nodeID int, reporter any) (PanelClient, error) {
	if reporter == nil || nodeID <= 0 {
		return apiClient, nil
	}
	client, err := requireMachinePanelClient(apiClient)
	if err != nil {
		return nil, err
	}
	return &reportingAPI{
		machinePanelClient: client,
		nodeID:             nodeID,
		reporter:           reporter,
	}, nil
}

func WrapAPIWithStatusReporter(apiClient PanelClient, nodeID int, reporter NodeStatusReporter) (PanelClient, error) {
	return WrapAPIWithReporter(apiClient, nodeID, reporter)
}

type reportingAPI struct {
	machinePanelClient
	nodeID   int
	reporter any
}

func (a *reportingAPI) ReportNodeStatus(nodeStatus *api.NodeStatus) error {
	if reporter, ok := a.reporter.(NodeStatusReporter); ok {
		_ = reporter.ReportNodeStatus(a.nodeID, nodeStatus)
	}
	return a.machinePanelClient.ReportNodeStatus(nodeStatus)
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
