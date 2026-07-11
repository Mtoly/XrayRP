package tuic

import "github.com/Mtoly/XrayRP/api"

type tuicPanelClientContractStub struct{}

func (tuicPanelClientContractStub) Describe() api.ClientInfo                      { return api.ClientInfo{} }
func (tuicPanelClientContractStub) GetNodeInfo() (*api.NodeInfo, error)           { return nil, nil }
func (tuicPanelClientContractStub) GetUserList() (*[]api.UserInfo, error)         { return nil, nil }
func (tuicPanelClientContractStub) GetNodeRule() (*[]api.DetectRule, error)       { return nil, nil }
func (tuicPanelClientContractStub) ReportNodeStatus(*api.NodeStatus) error        { return nil }
func (tuicPanelClientContractStub) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (tuicPanelClientContractStub) ReportUserTraffic(*[]api.UserTraffic) error    { return nil }
func (tuicPanelClientContractStub) ReportIllegal(*[]api.DetectResult) error       { return nil }

var _ PanelClient = tuicPanelClientContractStub{}
