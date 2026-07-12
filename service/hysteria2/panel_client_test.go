package hysteria2

import "github.com/Mtoly/XrayRP/api"

type hysteria2PanelClientContractStub struct{}

func (hysteria2PanelClientContractStub) Describe() api.ClientInfo                      { return api.ClientInfo{} }
func (hysteria2PanelClientContractStub) GetNodeInfo() (*api.NodeInfo, error)           { return nil, nil }
func (hysteria2PanelClientContractStub) GetUserList() (*[]api.UserInfo, error)         { return nil, nil }
func (hysteria2PanelClientContractStub) GetNodeRule() (*[]api.DetectRule, error)       { return nil, nil }
func (hysteria2PanelClientContractStub) ReportNodeStatus(*api.NodeStatus) error        { return nil }
func (hysteria2PanelClientContractStub) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (hysteria2PanelClientContractStub) ReportUserTraffic(*[]api.UserTraffic) error    { return nil }
func (hysteria2PanelClientContractStub) ReportIllegal(*[]api.DetectResult) error       { return nil }

var _ PanelClient = hysteria2PanelClientContractStub{}
