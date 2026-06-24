package machine

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/newV2board"
)

type recordingWSEventSubmitter struct {
	events      chan string
	parseErrors chan struct{}
	disconnects chan struct{}
	reconnects  chan struct{}
}

func newRecordingWSEventSubmitter() *recordingWSEventSubmitter {
	return &recordingWSEventSubmitter{
		events:      make(chan string, 4),
		parseErrors: make(chan struct{}, 4),
		disconnects: make(chan struct{}, 4),
		reconnects:  make(chan struct{}, 4),
	}
}

func (s *recordingWSEventSubmitter) SubmitWSEvent(event *newV2board.WSEvent) {
	if event == nil {
		return
	}
	s.events <- event.Event
}

func (s *recordingWSEventSubmitter) SubmitWSParseError() {
	s.parseErrors <- struct{}{}
}

func (s *recordingWSEventSubmitter) SubmitWSDisconnect() {
	s.disconnects <- struct{}{}
}

func (s *recordingWSEventSubmitter) SubmitWSReconnect() {
	s.reconnects <- struct{}{}
}

func TestSharedWSRuntimeCloseCancelsInFlightConnect(t *testing.T) {
	runtime := NewSharedWSRuntime(SharedWSRuntimeConfig{})
	ctxReceived := make(chan context.Context, 1)
	factoryDone := make(chan struct{})
	runtime.factory = func(ctx context.Context) (sharedWSClient, error) {
		ctxReceived <- ctx
		<-ctx.Done()
		close(factoryDone)
		return nil, ctx.Err()
	}

	if err := runtime.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	select {
	case <-ctxReceived:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for factory context")
	}

	closed := make(chan struct{})
	go func() {
		_ = runtime.Close()
		close(closed)
	}()

	select {
	case <-factoryDone:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for factory cancellation")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for runtime close")
	}
}

func TestSharedWSRuntimeRoutesNodeEventsToMatchingMailboxOnly(t *testing.T) {
	runtime := NewSharedWSRuntime(SharedWSRuntimeConfig{})
	first := newRecordingWSEventSubmitter()
	second := newRecordingWSEventSubmitter()

	firstRuntime, err := runtime.NewNodeRuntimeFactory(1)(first)
	if err != nil {
		t.Fatalf("build first mailbox: %v", err)
	}
	secondRuntime, err := runtime.NewNodeRuntimeFactory(2)(second)
	if err != nil {
		t.Fatalf("build second mailbox: %v", err)
	}
	firstRuntime.Start()
	secondRuntime.Start()
	defer firstRuntime.Stop()
	defer secondRuntime.Stop()

	runtime.handleEvent(nil, &newV2board.WSEvent{
		Event:   newV2board.WSEventXboardSyncUsers,
		Payload: map[string]any{"node_id": float64(1)},
	})

	if got := receiveString(t, first.events); got != newV2board.WSEventXboardSyncUsers {
		t.Fatalf("unexpected first event: got %q", got)
	}
	assertNoString(t, second.events)

	runtime.handleEvent(nil, &newV2board.WSEvent{
		Event:   newV2board.WSEventXboardSyncUsers,
		Payload: map[string]any{},
	})
	assertNoString(t, first.events)
	assertNoString(t, second.events)
}

func TestSharedWSRuntimeSyncNodesTriggersRediscover(t *testing.T) {
	runtime := NewSharedWSRuntime(SharedWSRuntimeConfig{})
	called := make(chan struct{}, 1)
	runtime.SetRediscover(func() error {
		called <- struct{}{}
		return nil
	})

	runtime.handleEvent(nil, &newV2board.WSEvent{
		Event:   newV2board.WSEventXboardSyncNodes,
		Payload: map[string]any{},
	})

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for rediscover trigger")
	}
}

func TestSharedWSRuntimeReportsNodeStatusThroughCurrentClient(t *testing.T) {
	runtime := NewSharedWSRuntime(SharedWSRuntimeConfig{})
	client := newRecordingSharedWSClient()
	runtime.setClient(client)

	status := &api.NodeStatus{CPU: 1, Mem: 2, Disk: 3, Uptime: 4}
	if err := runtime.ReportNodeStatus(7, status); err != nil {
		t.Fatalf("ReportNodeStatus returned error: %v", err)
	}

	call := receiveStatusCall(t, client.statusCalls)
	if call.nodeID != 7 {
		t.Fatalf("unexpected node ID: got %d want 7", call.nodeID)
	}
	if call.status != status {
		t.Fatalf("expected same status pointer")
	}
}

func TestSupervisorReconcileNowDiscoversImmediately(t *testing.T) {
	first := &fakeService{}
	second := &fakeService{}
	discoverer := &fakeDiscoverer{responses: []*newV2board.MachineNodesResponse{
		machineNodesResponse(newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"}),
		machineNodesResponse(
			newV2board.MachineNode{ID: 1, Type: "vless", Name: "first"},
			newV2board.MachineNode{ID: 2, Type: "trojan", Name: "second"},
		),
	}}
	factory := newFakeFactory()
	factory.services[1] = first
	factory.services[2] = second
	supervisor := newTestSupervisor(t, discoverer, factory)
	if err := supervisor.startInitial(); err != nil {
		t.Fatalf("startInitial returned error: %v", err)
	}

	if err := supervisor.ReconcileNow(); err != nil {
		t.Fatalf("ReconcileNow returned error: %v", err)
	}

	if discoverer.calls != 2 {
		t.Fatalf("expected two discovery calls, got %d", discoverer.calls)
	}
	if second.starts != 1 {
		t.Fatalf("expected second service to start once, got %d", second.starts)
	}
}

func TestSharedWSRuntimeReportsNodeDevicesThroughCurrentClient(t *testing.T) {
	runtime := NewSharedWSRuntime(SharedWSRuntimeConfig{})
	client := newRecordingSharedWSClient()
	runtime.setClient(client)

	if !runtime.DeviceReporterReady() {
		t.Fatal("expected device reporter to be ready with current client")
	}

	devices := map[int][]string{1: []string{"192.0.2.1"}}
	if err := runtime.ReportNodeDevices(7, devices); err != nil {
		t.Fatalf("ReportNodeDevices returned error: %v", err)
	}
	devices[1][0] = "198.51.100.1"

	call := receiveDeviceCall(t, client.deviceCalls)
	if call.nodeID != 7 {
		t.Fatalf("unexpected node ID: got %d want 7", call.nodeID)
	}
	want := map[int][]string{1: []string{"192.0.2.1"}}
	if !reflect.DeepEqual(call.devices, want) {
		t.Fatalf("unexpected devices: got %#v want %#v", call.devices, want)
	}
}

func TestStatusReportingAPIReportsWSBestEffortThenREST(t *testing.T) {
	restErr := errors.New("rest failed")
	apiClient := &recordingStatusAPI{err: restErr}
	reporter := &recordingNodeStatusReporter{}
	wrapped := WrapAPIWithStatusReporter(apiClient, 9, reporter)
	status := &api.NodeStatus{CPU: 1}

	err := wrapped.ReportNodeStatus(status)
	if !errors.Is(err, restErr) {
		t.Fatalf("expected REST error, got %v", err)
	}
	if reporter.nodeID != 9 || reporter.status != status {
		t.Fatalf("unexpected reporter call: nodeID=%d status=%#v", reporter.nodeID, reporter.status)
	}
	if apiClient.status != status {
		t.Fatalf("expected REST ReportNodeStatus to receive status")
	}
}

func TestReportingAPIReportsNodeDevicesOverWS(t *testing.T) {
	apiClient := &recordingStatusAPI{}
	reporter := &recordingNodeDeviceReporter{ready: true}
	wrapped := WrapAPIWithReporter(apiClient, 9, reporter)
	deviceReporter, ok := wrapped.(interface {
		ReportNodeDevices(map[int][]string) error
	})
	if !ok {
		t.Fatal("expected wrapped API to expose node device reporter")
	}
	readiness, ok := wrapped.(interface{ DeviceReporterReady() bool })
	if !ok || !readiness.DeviceReporterReady() {
		t.Fatal("expected wrapped API to expose ready device reporter")
	}

	devices := map[int][]string{1: []string{"192.0.2.1"}}
	if err := deviceReporter.ReportNodeDevices(devices); err != nil {
		t.Fatalf("ReportNodeDevices returned error: %v", err)
	}
	devices[1][0] = "198.51.100.1"

	if reporter.nodeID != 9 {
		t.Fatalf("unexpected reporter node ID: got %d want 9", reporter.nodeID)
	}
	want := map[int][]string{1: []string{"192.0.2.1"}}
	if !reflect.DeepEqual(reporter.devices, want) {
		t.Fatalf("unexpected reported devices: got %#v want %#v", reporter.devices, want)
	}
}

type statusCall struct {
	nodeID int
	status *api.NodeStatus
}

type deviceCall struct {
	nodeID  int
	devices map[int][]string
}

type recordingSharedWSClient struct {
	events      chan *newV2board.WSEvent
	errs        chan error
	done        chan struct{}
	statusCalls chan statusCall
	deviceCalls chan deviceCall
}

func newRecordingSharedWSClient() *recordingSharedWSClient {
	return &recordingSharedWSClient{
		events:      make(chan *newV2board.WSEvent),
		errs:        make(chan error),
		done:        make(chan struct{}),
		statusCalls: make(chan statusCall, 4),
		deviceCalls: make(chan deviceCall, 4),
	}
}

func (c *recordingSharedWSClient) Events() <-chan *newV2board.WSEvent { return c.events }
func (c *recordingSharedWSClient) Errors() <-chan error               { return c.errs }
func (c *recordingSharedWSClient) Done() <-chan struct{}              { return c.done }
func (c *recordingSharedWSClient) KeepAlive() error                   { return nil }
func (c *recordingSharedWSClient) Pong() error                        { return nil }
func (c *recordingSharedWSClient) Close() error                       { close(c.done); return nil }
func (c *recordingSharedWSClient) SendDeviceReport(devices map[int][]string) error {
	c.deviceCalls <- deviceCall{devices: cloneDeviceReport(devices)}
	return nil
}
func (c *recordingSharedWSClient) SendNodeDeviceReport(nodeID int, devices map[int][]string) error {
	c.deviceCalls <- deviceCall{nodeID: nodeID, devices: cloneDeviceReport(devices)}
	return nil
}
func (c *recordingSharedWSClient) SendNodeStatusReport(nodeID int, status *api.NodeStatus) error {
	c.statusCalls <- statusCall{nodeID: nodeID, status: status}
	return nil
}

type recordingNodeStatusReporter struct {
	nodeID int
	status *api.NodeStatus
}

func (r *recordingNodeStatusReporter) ReportNodeStatus(nodeID int, nodeStatus *api.NodeStatus) error {
	r.nodeID = nodeID
	r.status = nodeStatus
	return nil
}

type recordingNodeDeviceReporter struct {
	nodeID  int
	devices map[int][]string
	ready   bool
}

func (r *recordingNodeDeviceReporter) ReportNodeDevices(nodeID int, devices map[int][]string) error {
	r.nodeID = nodeID
	r.devices = cloneDeviceReport(devices)
	return nil
}

func (r *recordingNodeDeviceReporter) DeviceReporterReady() bool {
	return r.ready
}

type recordingStatusAPI struct {
	status *api.NodeStatus
	err    error
}

func (a *recordingStatusAPI) GetNodeInfo() (*api.NodeInfo, error) { return nil, nil }
func (a *recordingStatusAPI) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	return nil, nil
}
func (a *recordingStatusAPI) GetUserList() (*[]api.UserInfo, error)         { return nil, nil }
func (a *recordingStatusAPI) GetAliveList() (map[int][]string, error)       { return nil, nil }
func (a *recordingStatusAPI) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (a *recordingStatusAPI) ReportUserTraffic(*[]api.UserTraffic) error    { return nil }
func (a *recordingStatusAPI) Describe() api.ClientInfo                      { return api.ClientInfo{} }
func (a *recordingStatusAPI) GetNodeRule() (*[]api.DetectRule, error)       { return nil, nil }
func (a *recordingStatusAPI) ReportIllegal(*[]api.DetectResult) error       { return nil }
func (a *recordingStatusAPI) Debug()                                        {}
func (a *recordingStatusAPI) ReportNodeStatus(status *api.NodeStatus) error {
	a.status = status
	return a.err
}

func receiveString(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for string")
		return ""
	}
}

func assertNoString(t *testing.T, ch <-chan string) {
	t.Helper()
	select {
	case got := <-ch:
		t.Fatalf("unexpected string: %q", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func receiveStatusCall(t *testing.T, ch <-chan statusCall) statusCall {
	t.Helper()
	select {
	case call := <-ch:
		return call
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for status call")
		return statusCall{}
	}
}

func receiveDeviceCall(t *testing.T, ch <-chan deviceCall) deviceCall {
	t.Helper()
	select {
	case call := <-ch:
		return call
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for device call")
		return deviceCall{}
	}
}

func cloneDeviceReport(devices map[int][]string) map[int][]string {
	if devices == nil {
		return nil
	}
	cloned := make(map[int][]string, len(devices))
	for uid, ips := range devices {
		cloned[uid] = append([]string(nil), ips...)
	}
	return cloned
}
