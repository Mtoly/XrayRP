// Package api contains all the api used by XrayR
// To implement an api , one needs to implement the interface below.

package api

import "errors"

var ErrUnsupportedPanelFeature = errors.New("panel feature unsupported by adapter")

// API is the interface for different panel's api.
type API interface {
	GetNodeInfo() (nodeInfo *NodeInfo, err error)
	// GetXrayRCertConfig returns optional global certificate settings from panel
	GetXrayRCertConfig() (certConfig *XrayRCertConfig, err error)
	GetUserList() (userList *[]UserInfo, err error)
	GetAliveList() (aliveList map[int][]string, err error)
	ReportNodeStatus(nodeStatus *NodeStatus) (err error)
	ReportNodeOnlineUsers(onlineUser *[]OnlineUser) (err error)
	ReportUserTraffic(userTraffic *[]UserTraffic) (err error)
	Describe() ClientInfo
	GetNodeRule() (ruleList *[]DetectRule, err error)
	ReportIllegal(detectResultList *[]DetectResult) (err error)
	Debug()
}

// WSConfig carries the minimum panel adapter state needed to opt into
// websocket-driven control-plane features without changing the base API contract.
type WSConfig struct {
	APIHost  string
	NodeID   int
	Key      string
	NodeType string
}

// WSCapable is an optional capability implemented only by adapters that expose
// websocket-specific configuration.
type WSCapable interface {
	GetWSConfig() *WSConfig
}
