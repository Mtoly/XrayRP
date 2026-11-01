package machine

import (
	"context"
	"errors"
	"reflect"
	"strings"
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

type statusReporterMissingWSConfigStub struct {
	*statusReporterAllCapableStub
	api.WSCapable
}

type statusReporterMissingWSEndpointStub struct {
	*statusReporterAllCapableStub
	api.WSEndpointDiscoverer
}

type statusReporterMissingBaseConfigStub struct {
	*statusReporterAllCapableStub
	api.BaseConfigProvider
}

type statusReporterMissingCertConfigStub struct {
	*statusReporterAliveCapableStub
	wsConfig   *api.WSConfig
	wsEndpoint string
	baseConfig *api.BaseConfig
}

type statusReporterMissingAliveListStub struct {
	*statusReporterCertCapableStub
	wsConfig   *api.WSConfig
	wsEndpoint string
	baseConfig *api.BaseConfig
}

func (c *statusReporterMissingCertConfigStub) GetWSConfig() *api.WSConfig {
	return c.wsConfig
}

func (c *statusReporterMissingCertConfigStub) DiscoverWSEndpoint() (string, error) {
	return c.wsEndpoint, nil
}

func (c *statusReporterMissingCertConfigStub) GetBaseConfig() *api.BaseConfig {
	return c.baseConfig
}

func (c *statusReporterMissingAliveListStub) GetWSConfig() *api.WSConfig {
	return c.wsConfig
}

func (c *statusReporterMissingAliveListStub) DiscoverWSEndpoint() (string, error) {
	return c.wsEndpoint, nil
}

func (c *statusReporterMissingAliveListStub) GetBaseConfig() *api.BaseConfig {
	return c.baseConfig
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

type statusReporterAliveSnapshotStub struct {
	*statusReporterAllCapableStub
	snapshot      *api.AliveSnapshot
	snapshotErr   error
	snapshotCalls int
	contextValue  any
	aliveCalls    int
	call          func(context.Context) error
}

func (c *statusReporterAliveSnapshotStub) GetAliveSnapshotContext(ctx context.Context) (*api.AliveSnapshot, error) {
	c.snapshotCalls++
	c.contextValue = ctx.Value(statusReporterAliveContextKey{})
	if c.call != nil {
		if err := c.call(ctx); err != nil {
			return c.snapshot, err
		}
	}
	return c.snapshot, c.snapshotErr
}

func (c *statusReporterAliveSnapshotStub) GetAliveList() (map[int][]string, error) {
	c.aliveCalls++
	return map[int][]string{99: {"198.51.100.99"}}, nil
}

type statusReporterAliveContextKey struct{}

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

func mustWrapMachineAPIWithReporter(t *testing.T, client PanelClient, nodeID int, reporter any) PanelClient {
	t.Helper()
	wrapped, err := WrapMachineAPIWithReporter(client, nodeID, reporter)
	if err != nil {
		t.Fatalf("WrapMachineAPIWithReporter returned error: %v", err)
	}
	return wrapped
}

func TestReportingAPIReportsStatusToReporterAndRESTClient(t *testing.T) {
	restErr := errors.New("REST failure")
	client := newStatusReporterAllCapableStub()
	client.reportStatusErr = restErr
	reporter := &statusReporterStub{}
	wrapped := mustWrapMachineAPIWithReporter(t, client, 7, reporter)
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

func TestReportingAPIForwardsTypedAliveSnapshot(t *testing.T) {
	sourceSnapshot := &api.AliveSnapshot{
		IPs:    map[int][]string{2: {"192.0.2.2"}},
		Counts: map[int]int{1: 3},
	}
	source := &statusReporterAliveSnapshotStub{
		statusReporterAllCapableStub: newStatusReporterAllCapableStub(),
		snapshot:                     sourceSnapshot,
	}
	wrapped := mustWrapMachineAPIWithReporter(t, source, 9, &statusReporterStub{})
	snapshotProvider, ok := wrapped.(api.AliveSnapshotProvider)
	if !ok {
		t.Fatal("machine reporting wrapper did not expose typed alive snapshots")
	}

	snapshot, err := snapshotProvider.GetAliveSnapshot()
	if err != nil {
		t.Fatalf("GetAliveSnapshot() error = %v", err)
	}
	if !reflect.DeepEqual(snapshot, sourceSnapshot) || snapshot == sourceSnapshot {
		t.Fatalf("GetAliveSnapshot() = %#v, want detached %#v", snapshot, sourceSnapshot)
	}
	if source.snapshotCalls != 1 || source.aliveCalls != 0 || source.contextValue != nil {
		t.Fatalf("typed dispatch = snapshots:%d legacy:%d value:%v", source.snapshotCalls, source.aliveCalls, source.contextValue)
	}
	snapshot.IPs[2][0] = "192.0.2.3"
	snapshot.Counts[1] = 4
	if sourceSnapshot.IPs[2][0] != "192.0.2.2" || sourceSnapshot.Counts[1] != 3 {
		t.Fatal("machine reporting wrapper leaked snapshot mutation to source")
	}

	ctx := context.WithValue(context.Background(), statusReporterAliveContextKey{}, "request")
	contextualProvider, ok := wrapped.(api.ContextAliveSnapshotProvider)
	if !ok {
		t.Fatal("machine reporting wrapper did not expose contextual typed alive snapshots")
	}
	snapshot, err = contextualProvider.GetAliveSnapshotContext(ctx)
	if err != nil {
		t.Fatalf("GetAliveSnapshotContext() error = %v", err)
	}
	if source.snapshotCalls != 2 || source.aliveCalls != 0 || source.contextValue != "request" {
		t.Fatalf("context forwarding = snapshots:%d legacy:%d value:%v", source.snapshotCalls, source.aliveCalls, source.contextValue)
	}
	if !reflect.DeepEqual(snapshot, sourceSnapshot) || snapshot == sourceSnapshot {
		t.Fatalf("GetAliveSnapshotContext() = %#v, want detached %#v", snapshot, sourceSnapshot)
	}
}

func TestReportingAPIAliveSnapshotOutcomes(t *testing.T) {
	providerErr := errors.New("alive snapshot unavailable")
	t.Run("typed nil", func(t *testing.T) {
		source := &statusReporterAliveSnapshotStub{
			statusReporterAllCapableStub: newStatusReporterAllCapableStub(),
		}
		wrapped := mustWrapMachineAPIWithReporter(t, source, 9, &statusReporterStub{})
		snapshot, err := wrapped.(api.AliveSnapshotProvider).GetAliveSnapshot()
		if snapshot != nil || err != nil {
			t.Fatalf("GetAliveSnapshot() = %#v, %v; want nil, nil", snapshot, err)
		}
	})
	t.Run("typed empty", func(t *testing.T) {
		source := &statusReporterAliveSnapshotStub{
			statusReporterAllCapableStub: newStatusReporterAllCapableStub(),
			snapshot:                     &api.AliveSnapshot{},
		}
		wrapped := mustWrapMachineAPIWithReporter(t, source, 9, &statusReporterStub{})
		snapshot, err := wrapped.(api.AliveSnapshotProvider).GetAliveSnapshot()
		if err != nil || !reflect.DeepEqual(snapshot, &api.AliveSnapshot{}) {
			t.Fatalf("GetAliveSnapshot() = %#v, %v; want empty snapshot, nil", snapshot, err)
		}
	})
	t.Run("typed error does not fall back", func(t *testing.T) {
		source := &statusReporterAliveSnapshotStub{
			statusReporterAllCapableStub: newStatusReporterAllCapableStub(),
			snapshot:                     &api.AliveSnapshot{Counts: map[int]int{1: 2}},
			snapshotErr:                  providerErr,
		}
		wrapped := mustWrapMachineAPIWithReporter(t, source, 9, &statusReporterStub{})
		snapshot, err := wrapped.(api.AliveSnapshotProvider).GetAliveSnapshot()
		if snapshot != nil || !errors.Is(err, providerErr) || source.snapshotCalls != 1 || source.aliveCalls != 0 {
			t.Fatalf("GetAliveSnapshot() = %#v, %v; calls: typed=%d legacy=%d", snapshot, err, source.snapshotCalls, source.aliveCalls)
		}
	})
	t.Run("canceled before provider", func(t *testing.T) {
		source := &statusReporterAliveSnapshotStub{
			statusReporterAllCapableStub: newStatusReporterAllCapableStub(),
			snapshot:                     &api.AliveSnapshot{Counts: map[int]int{1: 2}},
		}
		wrapped := mustWrapMachineAPIWithReporter(t, source, 9, &statusReporterStub{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		snapshot, err := wrapped.(api.ContextAliveSnapshotProvider).GetAliveSnapshotContext(ctx)
		if snapshot != nil || !errors.Is(err, context.Canceled) || source.snapshotCalls != 0 {
			t.Fatalf("GetAliveSnapshotContext() = %#v, %v; calls:%d", snapshot, err, source.snapshotCalls)
		}
	})
	t.Run("canceled after provider returns", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		source := &statusReporterAliveSnapshotStub{
			statusReporterAllCapableStub: newStatusReporterAllCapableStub(),
			snapshot:                     &api.AliveSnapshot{Counts: map[int]int{1: 2}},
			call: func(context.Context) error {
				cancel()
				return nil
			},
		}
		wrapped := mustWrapMachineAPIWithReporter(t, source, 9, &statusReporterStub{})
		snapshot, err := wrapped.(api.ContextAliveSnapshotProvider).GetAliveSnapshotContext(ctx)
		if snapshot != nil || !errors.Is(err, context.Canceled) || source.snapshotCalls != 1 {
			t.Fatalf("GetAliveSnapshotContext() = %#v, %v; calls:%d", snapshot, err, source.snapshotCalls)
		}
	})
	t.Run("legacy list fallback", func(t *testing.T) {
		source := newStatusReporterAllCapableStub()
		source.aliveList = map[int][]string{
			1: {"192.0.2.1", "2001:db8::1"},
			2: {},
		}
		wrapped := mustWrapMachineAPIWithReporter(t, source, 9, &statusReporterStub{})
		snapshot, err := wrapped.(api.AliveSnapshotProvider).GetAliveSnapshot()
		want := &api.AliveSnapshot{IPs: source.aliveList}
		if err != nil || !reflect.DeepEqual(snapshot, want) {
			t.Fatalf("GetAliveSnapshot() = %#v, %v; want %#v, nil", snapshot, err, want)
		}
		snapshot.IPs[1][0] = "192.0.2.2"
		if source.aliveList[1][0] != "192.0.2.1" {
			t.Fatal("legacy list fallback leaked snapshot mutation to source")
		}
	})
}

func TestReportingAPIDeviceReportingAndReadiness(t *testing.T) {
	reporter := &statusReporterStub{ready: true}
	wrapped := mustWrapMachineAPIWithReporter(t, newStatusReporterAllCapableStub(), 8, reporter)
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
	cert := &api.XrayRCertConfig{CertMode: "file"}
	alive := map[int][]string{4: {"phone"}}
	wrapped := mustWrapMachineAPIWithReporter(t, &statusReporterAllCapableStub{
		statusReporterCertAliveCapableStub: &statusReporterCertAliveCapableStub{
			statusReporterPanelClientStub: &statusReporterPanelClientStub{},
			certConfig:                    cert,
			aliveList:                     alive,
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

func TestReportingAPISupportsExplicitMachineCapabilitySets(t *testing.T) {
	tests := []struct {
		name   string
		client PanelClient
	}{
		{
			name:   "full machine capability set",
			client: newStatusReporterAllCapableStub(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapped, err := WrapMachineAPIWithReporter(test.client, 9, &statusReporterStub{})
			if err != nil {
				t.Fatalf("WrapMachineAPIWithReporter returned error: %v", err)
			}
			if _, ok := wrapped.(machinePanelClient); !ok {
				t.Fatalf("supported capability set was not preserved: %T", wrapped)
			}
		})
	}
}

func TestReportingAPIRejectsIncompleteMachineCapabilitySets(t *testing.T) {
	source := newStatusReporterAllCapableStub()
	tests := []struct {
		name      string
		client    PanelClient
		wantError string
	}{
		{
			name:      "websocket config",
			client:    &statusReporterMissingWSConfigStub{statusReporterAllCapableStub: source},
			wantError: "machine panel client is missing required capabilities: websocket config",
		},
		{
			name:      "websocket endpoint discovery",
			client:    &statusReporterMissingWSEndpointStub{statusReporterAllCapableStub: source},
			wantError: "machine panel client is missing required capabilities: websocket endpoint discovery",
		},
		{
			name:      "base config",
			client:    &statusReporterMissingBaseConfigStub{statusReporterAllCapableStub: source},
			wantError: "machine panel client is missing required capabilities: base config",
		},
		{
			name: "certificate config",
			client: &statusReporterMissingCertConfigStub{
				statusReporterAliveCapableStub: &statusReporterAliveCapableStub{
					statusReporterPanelClientStub: &statusReporterPanelClientStub{},
				},
			},
			wantError: "machine panel client is missing required capabilities: certificate config",
		},
		{
			name: "alive list",
			client: &statusReporterMissingAliveListStub{
				statusReporterCertCapableStub: &statusReporterCertCapableStub{
					statusReporterPanelClientStub: &statusReporterPanelClientStub{},
				},
			},
			wantError: "machine panel client is missing required capabilities: alive list",
		},
		{
			name:      "base panel client",
			client:    &statusReporterPanelClientStub{},
			wantError: "machine panel client is missing required capabilities: websocket config, websocket endpoint discovery, base config, certificate config, alive list",
		},
		{
			name: "certificate and alive only",
			client: &statusReporterCertAliveCapableStub{
				statusReporterPanelClientStub: &statusReporterPanelClientStub{},
			},
			wantError: "machine panel client is missing required capabilities: websocket config, websocket endpoint discovery, base config",
		},
		{
			name: "websocket config only",
			client: &statusReporterWSCapableStub{
				statusReporterPanelClientStub: &statusReporterPanelClientStub{},
			},
			wantError: "machine panel client is missing required capabilities: websocket endpoint discovery, base config, certificate config, alive list",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapped, err := WrapMachineAPIWithReporter(test.client, 9, &statusReporterStub{})
			if err == nil {
				t.Fatalf("expected capability error, got wrapped client %T", wrapped)
			}
			if wrapped != nil {
				t.Fatalf("expected no wrapped client, got %T", wrapped)
			}
			if err.Error() != test.wantError {
				t.Fatalf("capability error = %q, want %q", err, test.wantError)
			}
		})
	}
}

func TestReportingAPIRejectsNilMachineClientWhenReporterIsEnabled(t *testing.T) {
	wrapped, err := WrapMachineAPIWithReporter(nil, 9, &statusReporterStub{})
	if err == nil {
		t.Fatalf("expected nil machine client error, got wrapped client %T", wrapped)
	}
	if wrapped != nil {
		t.Fatalf("expected no wrapped client, got %T", wrapped)
	}
	if !strings.Contains(err.Error(), "must not be nil") {
		t.Fatalf("expected nil client error, got %v", err)
	}
}

func TestReportingAPIRejectsTypedNilMachineClientWhenReporterIsEnabled(t *testing.T) {
	var client *statusReporterAllCapableStub
	wrapped, err := WrapMachineAPIWithReporter(client, 9, &statusReporterStub{})
	if err == nil {
		t.Fatalf("expected typed-nil machine client error, got wrapped client %T", wrapped)
	}
	if wrapped != nil {
		t.Fatalf("expected no wrapped client, got %T", wrapped)
	}
	if !strings.Contains(err.Error(), "must not be nil") {
		t.Fatalf("expected nil client error, got %v", err)
	}
}

func TestReportingAPIKeepsDisabledReporterInputsAsNoOps(t *testing.T) {
	client := &statusReporterPanelClientStub{}
	tests := []struct {
		name     string
		nodeID   int
		reporter any
	}{
		{name: "nil reporter", nodeID: 9},
		{name: "zero node ID", reporter: &statusReporterStub{}},
		{name: "negative node ID", nodeID: -1, reporter: &statusReporterStub{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapped, err := WrapMachineAPIWithReporter(client, test.nodeID, test.reporter)
			if err != nil {
				t.Fatalf("WrapMachineAPIWithReporter returned error: %v", err)
			}
			if wrapped != client {
				t.Fatalf("disabled reporter changed client: got %T, want original", wrapped)
			}
		})
	}
}

func newStatusReporterAllCapableStub() *statusReporterAllCapableStub {
	return &statusReporterAllCapableStub{
		statusReporterCertAliveCapableStub: &statusReporterCertAliveCapableStub{
			statusReporterPanelClientStub: &statusReporterPanelClientStub{},
		},
	}
}
