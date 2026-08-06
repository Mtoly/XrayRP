package panel

import (
	"context"
	"errors"
	"net"
	"reflect"
	"regexp"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/service"
	"github.com/Mtoly/XrayRP/service/controller"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

type machineAppliedTestClient struct {
	node      *api.NodeInfo
	users     *[]api.UserInfo
	rules     *[]api.DetectRule
	fetchErr  error
	nodeCalls int
	userCalls int
	ruleCalls int
}

type orderedMachineRuntimeService struct {
	client runtimePanelClient
	order  *[]string
}

func (s *orderedMachineRuntimeService) Start() error {
	*s.order = append(*s.order, "runtime-start")
	if _, err := s.client.GetNodeInfo(); err != nil {
		return err
	}
	if _, err := s.client.GetUserList(); err != nil {
		return err
	}
	return nil
}

func (s *orderedMachineRuntimeService) Close() error {
	*s.order = append(*s.order, "runtime-close")
	return nil
}

type orderedMachineSnapshotRuntime struct {
	order    *[]string
	startErr error
}

func (runtime *orderedMachineSnapshotRuntime) StartContext(context.Context) error {
	*runtime.order = append(*runtime.order, "mailbox-start")
	return runtime.startErr
}

func (runtime *orderedMachineSnapshotRuntime) StopContext(context.Context) error {
	*runtime.order = append(*runtime.order, "mailbox-stop")
	return nil
}

func TestMachineRuntimeNodeServiceOwnsSnapshotMailboxOrdering(t *testing.T) {
	users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
	source := &machineAppliedTestClient{
		node:  &api.NodeInfo{NodeID: 7, NodeType: "AnyTLS", Port: 443},
		users: &users,
	}
	client := newMachineAppliedPanelClient(source, nil)
	order := make([]string, 0, 4)
	runtime := newMachineRuntimeNodeService(
		&orderedMachineRuntimeService{client: client, order: &order},
		client,
		&controller.Config{},
		nil,
		nil,
	)
	runtime.snapshotRuntime = &orderedMachineSnapshotRuntime{order: &order}

	if err := runtime.StartContext(context.Background()); err != nil {
		t.Fatalf("StartContext() error = %v", err)
	}
	if err := runtime.CloseContext(context.Background()); err != nil {
		t.Fatalf("CloseContext() error = %v", err)
	}
	want := []string{"runtime-start", "mailbox-start", "mailbox-stop", "runtime-close"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("lifecycle order = %v, want %v", order, want)
	}
}

func TestMachineRuntimeNodeServiceRollsBackWhenSnapshotMailboxStartFails(t *testing.T) {
	users := []api.UserInfo{{UID: 1, Email: "user@example.test"}}
	source := &machineAppliedTestClient{
		node:  &api.NodeInfo{NodeID: 7, NodeType: "AnyTLS", Port: 443},
		users: &users,
	}
	client := newMachineAppliedPanelClient(source, nil)
	order := make([]string, 0, 3)
	mailboxErr := errors.New("mailbox start failed")
	runtime := newMachineRuntimeNodeService(
		&orderedMachineRuntimeService{client: client, order: &order},
		client,
		&controller.Config{},
		nil,
		nil,
	)
	runtime.snapshotRuntime = &orderedMachineSnapshotRuntime{order: &order, startErr: mailboxErr}

	err := runtime.StartContext(context.Background())
	if !errors.Is(err, mailboxErr) {
		t.Fatalf("StartContext() error = %v, want mailbox error", err)
	}
	want := []string{"runtime-start", "mailbox-start", "mailbox-stop", "runtime-close"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("rollback order = %v, want %v", order, want)
	}
	if runtime.appliedValue != nil {
		t.Fatal("failed mailbox start published applied value")
	}
}

func (c *machineAppliedTestClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: "https://panel.example.test", NodeID: 7, NodeType: "Vless"}
}

func (c *machineAppliedTestClient) GetNodeInfo() (*api.NodeInfo, error) {
	c.nodeCalls++
	if c.fetchErr != nil {
		return nil, c.fetchErr
	}
	return c.node, nil
}

func (c *machineAppliedTestClient) GetUserList() (*[]api.UserInfo, error) {
	c.userCalls++
	if c.fetchErr != nil {
		return nil, c.fetchErr
	}
	return c.users, nil
}

func (c *machineAppliedTestClient) GetNodeRule() (*[]api.DetectRule, error) {
	c.ruleCalls++
	if c.fetchErr != nil {
		return nil, c.fetchErr
	}
	return c.rules, nil
}

func (*machineAppliedTestClient) ReportNodeStatus(*api.NodeStatus) error        { return nil }
func (*machineAppliedTestClient) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (*machineAppliedTestClient) ReportUserTraffic(*[]api.UserTraffic) error    { return nil }
func (*machineAppliedTestClient) ReportIllegal(*[]api.DetectResult) error       { return nil }

type machineAppliedProbeService struct {
	client runtimePanelClient
	node   *api.NodeInfo
	users  *[]api.UserInfo
	rules  *[]api.DetectRule
	starts int
	closes int
}

func (s *machineAppliedProbeService) Start() error {
	s.starts++
	var err error
	if s.node, err = s.client.GetNodeInfo(); err != nil {
		return err
	}
	if s.users, err = s.client.GetUserList(); err != nil {
		return err
	}
	if s.rules, err = s.client.GetNodeRule(); err != nil {
		return err
	}
	return nil
}

func (s *machineAppliedProbeService) Close() error {
	s.closes++
	return nil
}

func TestMachineAppliedPanelClientDoesNotPublishUnconfirmedCandidate(t *testing.T) {
	initialUsers := []api.UserInfo{{UID: 1, UUID: "initial-user"}}
	initialRules := []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile(`initial`)}}
	source := &machineAppliedTestClient{
		node:  &api.NodeInfo{NodeID: 7, NodeType: "AnyTLS", Port: 443},
		users: &initialUsers,
		rules: &initialRules,
	}
	client := newMachineAppliedPanelClient(source, nil)
	if _, err := client.GetNodeInfo(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetUserList(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetNodeRule(); err != nil {
		t.Fatal(err)
	}
	initial, err := client.appliedNodeValue()
	if err != nil {
		t.Fatal(err)
	}

	candidateUsers := []api.UserInfo{{UID: 2, UUID: "candidate-user"}}
	candidateRules := []api.DetectRule{{ID: 2, Pattern: regexp.MustCompile(`candidate`)}}
	source.node = &api.NodeInfo{NodeID: 7, NodeType: "AnyTLS", Port: 8443}
	source.users = &candidateUsers
	source.rules = &candidateRules
	if _, err := client.GetNodeInfo(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetUserList(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetNodeRule(); err != nil {
		t.Fatal(err)
	}

	stillApplied, err := client.appliedNodeValue()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stillApplied, initial) {
		t.Fatalf("unconfirmed candidate replaced applied value: got %#v want %#v", stillApplied, initial)
	}

	client.RecordSnapshotSyncApplied(service.SnapshotSyncAll)
	confirmed, err := client.appliedNodeValue()
	if err != nil {
		t.Fatal(err)
	}
	if confirmed.nodeInfo == nil || confirmed.nodeInfo.Port != 8443 {
		t.Fatalf("confirmed node = %#v, want candidate port", confirmed.nodeInfo)
	}
	if confirmed.userList == nil || len(*confirmed.userList) != 1 || (*confirmed.userList)[0].UUID != "candidate-user" {
		t.Fatalf("confirmed users = %#v", confirmed.userList)
	}
	if confirmed.ruleList == nil || len(*confirmed.ruleList) != 1 || (*confirmed.ruleList)[0].Pattern.String() != `candidate` {
		t.Fatalf("confirmed rules = %#v", confirmed.ruleList)
	}
}

func TestMachineRuntimeRollbackUsesLocalAppliedNodeValueWhenPanelIsUnavailable(t *testing.T) {
	users := []api.UserInfo{{UID: 3, UUID: "local-user", Email: "local@example.test"}}
	rules := []api.DetectRule{{ID: 9, Pattern: regexp.MustCompile(`example\\.test`)}}
	source := &machineAppliedTestClient{
		node: &api.NodeInfo{
			NodeID:            7,
			NodeType:          "Vless",
			Port:              443,
			TransportProtocol: "ws",
			Headers:           map[string]string{"X-Applied": "yes"},
			ServerNames:       []string{"applied.example.test"},
		},
		users: &users,
		rules: &rules,
	}
	config := &controller.Config{UpdatePeriodic: 60}

	var buildRestored func(machineAppliedNodeValue, *controller.Config) (service.Service, error)
	buildRestored = func(value machineAppliedNodeValue, appliedConfig *controller.Config) (service.Service, error) {
		client := newMachineAppliedPanelClient(source, &value)
		probe := &machineAppliedProbeService{client: client}
		return newMachineRuntimeNodeService(probe, client, appliedConfig, &value, buildRestored), nil
	}
	client := newMachineAppliedPanelClient(source, nil)
	probe := &machineAppliedProbeService{client: client}
	runtime := newMachineRuntimeNodeService(probe, client, config, nil, buildRestored)
	if err := runtime.Start(); err != nil {
		t.Fatalf("initial Start() error = %v", err)
	}

	source.node.Headers["X-Applied"] = "mutated"
	source.node.ServerNames[0] = "mutated.example.test"
	(*source.users)[0].UUID = "mutated-user"
	(*source.rules)[0].Pattern = regexp.MustCompile(`mutated`)
	panelErr := errors.New("panel unavailable")
	source.fetchErr = panelErr
	if err := runtime.Close(); err != nil {
		t.Fatalf("initial Close() error = %v", err)
	}

	restoredService, err := runtime.RestoreMachineRuntime()
	if err != nil {
		t.Fatalf("RestoreMachineRuntime() error = %v", err)
	}
	if err := restoredService.Start(); err != nil {
		t.Fatalf("restored Start() accessed unavailable panel: %v", err)
	}
	restored := restoredService.(*machineRuntimeNodeService).inner.(*machineAppliedProbeService)
	if restored.node == nil || restored.node.Headers["X-Applied"] != "yes" || restored.node.ServerNames[0] != "applied.example.test" {
		t.Fatalf("restored node value = %#v", restored.node)
	}
	wantUsers := []api.UserInfo{{UID: 3, UUID: "local-user", Email: "local@example.test"}}
	if restored.users == nil || !reflect.DeepEqual(*restored.users, wantUsers) {
		t.Fatalf("restored users = %#v, want %#v", restored.users, wantUsers)
	}
	if restored.rules == nil || len(*restored.rules) != 1 || (*restored.rules)[0].Pattern.String() != `example\\.test` {
		t.Fatalf("restored rules = %#v", restored.rules)
	}
	if source.nodeCalls != 1 || source.userCalls != 1 || source.ruleCalls != 1 {
		t.Fatalf("rollback panel calls = node:%d users:%d rules:%d, want initial calls only", source.nodeCalls, source.userCalls, source.ruleCalls)
	}
	if err := restoredService.Close(); err != nil {
		t.Fatalf("restored Close() error = %v", err)
	}
}

func TestCloneMachineAddressPreservesFamilyValueAndTypedNil(t *testing.T) {
	tests := []struct {
		name    string
		address xraynet.Address
		family  xraynet.AddressFamily
	}{
		{name: "numeric domain", address: xraynet.DomainAddress("1.1.1.1"), family: xraynet.AddressFamilyDomain},
		{name: "IPv4", address: xraynet.IPAddress(net.IPv4(192, 0, 2, 1).To4()), family: xraynet.AddressFamilyIPv4},
		{name: "IPv6", address: xraynet.IPAddress(net.ParseIP("2001:db8::1")), family: xraynet.AddressFamilyIPv6},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clonedNode := cloneMachineNodeInfo(&api.NodeInfo{NameServerConfig: []*conf.NameServerConfig{{
				Address: &conf.Address{Address: test.address},
			}}})
			cloned := clonedNode.NameServerConfig[0].Address
			if cloned == nil || cloned.Address == nil {
				t.Fatalf("expected cloned address, got %#v", cloned)
			}
			if cloned.Address.Family() != test.family || cloned.Address.String() != test.address.String() {
				t.Fatalf("cloned address = family:%d value:%q", cloned.Address.Family(), cloned.Address.String())
			}
		})
	}

	var typedNil xraynet.Address = xraynet.IPAddress(nil)
	clonedNode := cloneMachineNodeInfo(&api.NodeInfo{NameServerConfig: []*conf.NameServerConfig{{
		Address: &conf.Address{Address: typedNil},
	}}})
	cloned := clonedNode.NameServerConfig[0].Address
	if cloned == nil || !reflect.DeepEqual(cloned.Address, typedNil) {
		t.Fatalf("typed-nil address clone = %#v", cloned)
	}
}
