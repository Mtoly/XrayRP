package controller_test

import (
	"net"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/app/mydispatcher"
	_ "github.com/Mtoly/XrayRP/cmd/distro/all"
	"github.com/Mtoly/XrayRP/service/controller"
)

type realCorePanelClient struct {
	node  api.NodeInfo
	users []api.UserInfo
}

func (c *realCorePanelClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: "http://127.0.0.1", NodeID: c.node.NodeID, NodeType: c.node.NodeType}
}
func (c *realCorePanelClient) GetNodeInfo() (*api.NodeInfo, error) {
	node := c.node
	return &node, nil
}
func (c *realCorePanelClient) GetUserList() (*[]api.UserInfo, error) {
	users := append([]api.UserInfo(nil), c.users...)
	return &users, nil
}
func (*realCorePanelClient) GetNodeRule() (*[]api.DetectRule, error) {
	rules := []api.DetectRule{}
	return &rules, nil
}
func (*realCorePanelClient) ReportNodeStatus(*api.NodeStatus) error        { return nil }
func (*realCorePanelClient) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (*realCorePanelClient) ReportUserTraffic(*[]api.UserTraffic) error    { return nil }
func (*realCorePanelClient) ReportIllegal(*[]api.DetectResult) error       { return nil }

func TestControllerRealCoreCanAddRemoveAndReAddSameNode(t *testing.T) {
	server := newRealControllerCore(t)
	port := reserveLoopbackPort(t)
	client := &realCorePanelClient{
		node: api.NodeInfo{
			NodeType:          "Socks",
			NodeID:            901,
			Port:              uint32(port),
			TransportProtocol: "tcp",
		},
		users: []api.UserInfo{{UID: 1, Email: "real-core@example.test", UUID: "real-core-user"}},
	}
	config := &controller.Config{
		ListenIP:       "127.0.0.1",
		SendIP:         "0.0.0.0",
		UpdatePeriodic: 3600,
		DisableGetRule: true,
	}

	first := controller.New(server, client, config, "test")
	if err := first.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}

	second := controller.New(server, client, config, "test")
	if err := second.Start(); err != nil {
		t.Fatalf("re-add Start() error = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func newRealControllerCore(t *testing.T) *core.Instance {
	t.Helper()
	policyConfig, err := (&conf.PolicyConfig{Levels: map[uint32]*conf.Policy{0: {
		StatsUserUplink:   true,
		StatsUserDownlink: true,
	}}}).Build()
	if err != nil {
		t.Fatal(err)
	}
	dnsConfig, err := (&conf.DNSConfig{}).Build()
	if err != nil {
		t.Fatal(err)
	}
	routeConfig, err := (&conf.RouterConfig{}).Build()
	if err != nil {
		t.Fatal(err)
	}
	server, err := core.New(&core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage((&conf.LogConfig{LogLevel: "none"}).Build()),
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&mydispatcher.Config{}),
		serial.ToTypedMessage(&stats.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(policyConfig),
		serial.ToTypedMessage(dnsConfig),
		serial.ToTypedMessage(routeConfig),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("core Close() error = %v", err)
		}
	})
	return server
}

func reserveLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
