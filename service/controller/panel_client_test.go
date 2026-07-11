package controller

import "github.com/Mtoly/XrayRP/api"

type panelClientWithoutDebug struct{}

func (panelClientWithoutDebug) Describe() api.ClientInfo                      { return api.ClientInfo{} }
func (panelClientWithoutDebug) GetNodeInfo() (*api.NodeInfo, error)           { return nil, nil }
func (panelClientWithoutDebug) GetUserList() (*[]api.UserInfo, error)         { return nil, nil }
func (panelClientWithoutDebug) GetNodeRule() (*[]api.DetectRule, error)       { return nil, nil }
func (panelClientWithoutDebug) ReportNodeStatus(*api.NodeStatus) error        { return nil }
func (panelClientWithoutDebug) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (panelClientWithoutDebug) ReportUserTraffic(*[]api.UserTraffic) error    { return nil }
func (panelClientWithoutDebug) ReportIllegal(*[]api.DetectResult) error       { return nil }

var _ PanelClient = panelClientWithoutDebug{}
