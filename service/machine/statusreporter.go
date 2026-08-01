package machine

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
)

type NodeStatusReporter interface {
	ReportNodeStatus(nodeID int, nodeStatus *api.NodeStatus) error
}

type ContextNodeStatusReporter interface {
	ReportNodeStatusContext(context.Context, int, *api.NodeStatus) error
}

type MachineStatusReporter interface {
	ReportMachineStatus(status api.MachineStatus) error
}

type ContextMachineStatusReporter interface {
	ReportMachineStatusContext(context.Context, api.MachineStatus) error
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

func WrapMachineAPIWithReporter(apiClient PanelClient, nodeID int, reporter any) (PanelClient, error) {
	if reporter == nil || nodeID <= 0 {
		return apiClient, nil
	}
	client, err := requireMachinePanelClient(apiClient)
	if err != nil {
		return nil, err
	}
	return &machineReportingAPI{
		machinePanelClient: client,
		nodeID:             nodeID,
		reporter:           reporter,
	}, nil
}

func WrapMachineAPIWithStatusReporter(apiClient PanelClient, nodeID int, reporter NodeStatusReporter) (PanelClient, error) {
	return WrapMachineAPIWithReporter(apiClient, nodeID, reporter)
}

type machineReportingAPI struct {
	machinePanelClient
	nodeID   int
	reporter any
}

func (a *machineReportingAPI) GetNodeInfoContext(ctx context.Context) (*api.NodeInfo, error) {
	return api.GetNodeInfoContext(ctx, a.machinePanelClient)
}

func (a *machineReportingAPI) GetUserListContext(ctx context.Context) (*[]api.UserInfo, error) {
	return api.GetUserListContext(ctx, a.machinePanelClient)
}

func (a *machineReportingAPI) GetNodeRuleContext(ctx context.Context) (*[]api.DetectRule, error) {
	return api.GetNodeRuleContext(ctx, a.machinePanelClient)
}

func (a *machineReportingAPI) ReportNodeStatus(nodeStatus *api.NodeStatus) error {
	return a.ReportNodeStatusContext(context.Background(), nodeStatus)
}

func (a *machineReportingAPI) ReportNodeStatusContext(ctx context.Context, nodeStatus *api.NodeStatus) error {
	if reporter, ok := a.reporter.(ContextNodeStatusReporter); ok {
		_ = reporter.ReportNodeStatusContext(ctx, a.nodeID, nodeStatus)
	} else if reporter, ok := a.reporter.(NodeStatusReporter); ok && ctx.Err() == nil {
		_ = reporter.ReportNodeStatus(a.nodeID, nodeStatus)
	}
	return api.ReportNodeStatusContext(ctx, a.machinePanelClient, nodeStatus)
}

func (a *machineReportingAPI) ReportNodeOnlineUsersContext(ctx context.Context, users *[]api.OnlineUser) error {
	return api.ReportNodeOnlineUsersContext(ctx, a.machinePanelClient, users)
}

func (a *machineReportingAPI) ReportUserTrafficContext(ctx context.Context, traffic *[]api.UserTraffic) error {
	return api.ReportUserTrafficContext(ctx, a.machinePanelClient, traffic)
}

func (a *machineReportingAPI) ReportIllegalContext(ctx context.Context, results *[]api.DetectResult) error {
	return api.ReportIllegalContext(ctx, a.machinePanelClient, results)
}

func (a *machineReportingAPI) GetXrayRCertConfigContext(ctx context.Context) (*api.XrayRCertConfig, error) {
	return api.GetXrayRCertConfigContext(ctx, a.machinePanelClient)
}

func (a *machineReportingAPI) GetAliveListContext(ctx context.Context) (map[int][]string, error) {
	return api.GetAliveListContext(ctx, a.machinePanelClient)
}

func (a *machineReportingAPI) DiscoverWSEndpointContext(ctx context.Context) (string, error) {
	return api.DiscoverWSEndpointContext(ctx, a.machinePanelClient)
}

func (a *machineReportingAPI) ReportNodeDevices(devices map[int][]string) error {
	if reporter, ok := a.reporter.(NodeDeviceReporter); ok {
		return reporter.ReportNodeDevices(a.nodeID, devices)
	}
	return nil
}

func (a *machineReportingAPI) DeviceReporterReady() bool {
	readiness, ok := a.reporter.(DeviceReporterReadiness)
	return !ok || readiness.DeviceReporterReady()
}
