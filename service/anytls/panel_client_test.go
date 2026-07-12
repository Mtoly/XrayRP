package anytls

import "github.com/Mtoly/XrayRP/api"

type anyTLSPanelClientContractStub struct{}

func (anyTLSPanelClientContractStub) Describe() api.ClientInfo                      { return api.ClientInfo{} }
func (anyTLSPanelClientContractStub) GetNodeInfo() (*api.NodeInfo, error)           { return nil, nil }
func (anyTLSPanelClientContractStub) GetUserList() (*[]api.UserInfo, error)         { return nil, nil }
func (anyTLSPanelClientContractStub) GetNodeRule() (*[]api.DetectRule, error)       { return nil, nil }
func (anyTLSPanelClientContractStub) ReportNodeStatus(*api.NodeStatus) error        { return nil }
func (anyTLSPanelClientContractStub) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (anyTLSPanelClientContractStub) ReportUserTraffic(*[]api.UserTraffic) error    { return nil }
func (anyTLSPanelClientContractStub) ReportIllegal(*[]api.DetectResult) error       { return nil }

var _ PanelClient = anyTLSPanelClientContractStub{}
