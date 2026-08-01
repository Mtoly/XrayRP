package gov2panel

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/internal/panelrules"
	"github.com/Mtoly/XrayRP/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

// APIClient API config
type APIClient struct {
	APIHost             string
	NodeID              int
	Key                 string
	NodeType            string
	EnableVless         bool
	VlessFlow           string
	Timeout             int
	SpeedLimit          float64
	DeviceLimit         int
	RuleListPath        string
	DisableCustomConfig bool

	LocalRuleList []api.DetectRule
}

// New create an api instance
func New(apiConfig *api.Config) *APIClient {

	//https://goframe.org/pages/viewpage.action?pageId=1114381
	localRuleList, diagnostics := panelrules.Load(apiConfig.RuleListPath)
	for _, diagnostic := range diagnostics {
		log.Print(diagnostic)
	}

	apiClient := &APIClient{
		APIHost:             apiConfig.APIHost,
		NodeID:              apiConfig.NodeID,
		Key:                 apiConfig.Key,
		NodeType:            apiConfig.NodeType,
		EnableVless:         apiConfig.EnableVless,
		VlessFlow:           apiConfig.VlessFlow,
		Timeout:             apiConfig.Timeout,
		DeviceLimit:         apiConfig.DeviceLimit,
		RuleListPath:        apiConfig.RuleListPath,
		DisableCustomConfig: apiConfig.DisableCustomConfig,

		LocalRuleList: localRuleList, //加载本地路由规则
	}
	return apiClient
}

func (c *APIClient) GetNodeInfo() (*api.NodeInfo, error) {
	return c.GetNodeInfoContext(context.Background())
}

func (c *APIClient) GetNodeInfoContext(ctx context.Context) (nodeInfo *api.NodeInfo, err error) {

	apiPath := "/api/server/config"
	response, err := c.sendRequestContext(ctx,
		nil,
		"POST",
		apiPath,
		map[string]any{})
	if err != nil {
		return nil, err
	}

	if response.stringAt("data") == "" {
		return nil, errors.New("gov2panel node config data is null")
	}

	if response.intAt("data.port") == 0 {
		return nil, errors.New("server port must > 0")
	}

	nodeInfo = new(api.NodeInfo)
	err = response.scanAt("data", nodeInfo)
	if err != nil {
		return nil, fmt.Errorf("parse node info failed: \nError: %v", err)
	}

	routes := make([]route, 0)
	err = response.scanAt("data.routes", &routes)
	if err != nil {
		return nil, fmt.Errorf("parse node routes failed: \nError: %v", err)
	}

	nodeInfo.NodeType = c.NodeType
	nodeInfo.NodeID = c.NodeID
	nodeInfo.EnableVless = c.EnableVless
	nodeInfo.VlessFlow = c.VlessFlow

	nodeInfo.AlterID = 0

	nodeInfo.NameServerConfig = parseDNSConfig(routes)

	return nodeInfo, nil

}

func parseDNSConfig(routes []route) (nameServerList []*conf.NameServerConfig) {

	nameServerList = make([]*conf.NameServerConfig, 0)
	for i := range routes {
		if routes[i].Action == "dns" {
			nameServerList = append(nameServerList, &conf.NameServerConfig{
				Address: &conf.Address{Address: net.ParseAddress(routes[i].ActionValue)},
				Domains: routes[i].Match,
			})
		}
	}

	return
}

// GetUserList will pull user form panel
func (c *APIClient) GetUserList() (*[]api.UserInfo, error) {
	return c.GetUserListContext(context.Background())
}

func (c *APIClient) GetUserListContext(ctx context.Context) (UserList *[]api.UserInfo, err error) {

	apiPath := "/api/server/user"

	switch c.NodeType {
	case "V2ray", "Trojan", "Shadowsocks", "Vmess", "Vless":
		break
	default:
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	response, err := c.sendRequestContext(ctx,
		nil,
		"GET",
		apiPath,
		map[string]any{})
	if err != nil {
		return nil, err
	}

	var users []*user
	response.scanAt("data.users", &users)

	userList := make([]api.UserInfo, len(users))
	for i := 0; i < len(users); i++ {
		u := api.UserInfo{
			UID:  users[i].Id,
			UUID: users[i].Uuid,
		}

		// Support 1.7.1 speed limit
		if c.SpeedLimit > 0 {
			u.SpeedLimit = uint64(c.SpeedLimit * 1000000 / 8)
		} else {
			u.SpeedLimit = uint64(users[i].SpeedLimit * 1000000 / 8)
		}

		u.DeviceLimit = c.DeviceLimit // todo waiting v2board send configuration
		u.Email = u.UUID + "@gov2panel.user"
		if c.NodeType == "Shadowsocks" {
			u.Passwd = u.UUID
		}
		userList[i] = u
	}

	return &userList, nil
}

func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) error {
	return c.ReportNodeStatusContext(context.Background(), nodeStatus)
}

func (*APIClient) ReportNodeStatusContext(ctx context.Context, _ *api.NodeStatus) error {
	return ctx.Err()
}

// GetAliveList is not supported by GoV2Panel.
func (c *APIClient) GetAliveList() (map[int][]string, error) {
	return c.GetAliveListContext(context.Background())
}

func (*APIClient) GetAliveListContext(ctx context.Context) (map[int][]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, api.ErrUnsupportedPanelFeature
}

func (c *APIClient) ReportNodeOnlineUsers(onlineUser *[]api.OnlineUser) error {
	return c.ReportNodeOnlineUsersContext(context.Background(), onlineUser)
}

func (*APIClient) ReportNodeOnlineUsersContext(ctx context.Context, _ *[]api.OnlineUser) error {
	return ctx.Err()
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	return c.ReportUserTrafficContext(context.Background(), userTraffic)
}

func (c *APIClient) ReportUserTrafficContext(ctx context.Context, userTraffic *[]api.UserTraffic) (err error) {
	apiPath := "/api/server/push"
	response, err := c.sendRequestContext(ctx,
		nil,
		"POST",
		apiPath,
		map[string]any{
			"data": userTraffic,
		})
	if err != nil {
		return err
	}

	if response.intAt("code") != 0 {
		return errors.New(response.stringAt("message"))
	}

	return
}

func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: "", NodeType: c.NodeType}
}

// GetXrayRCertConfig is not provided by GoV2Panel.
func (c *APIClient) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	return c.GetXrayRCertConfigContext(context.Background())
}

func (*APIClient) GetXrayRCertConfigContext(ctx context.Context) (*api.XrayRCertConfig, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, api.ErrUnsupportedPanelFeature
}

// GetNodeRule implements the API interface
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	return c.GetNodeRuleContext(context.Background())
}

func (c *APIClient) GetNodeRuleContext(ctx context.Context) (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList

	apiPath := "/api/server/config"
	response, err := c.sendRequestContext(ctx,
		nil,
		"POST",
		apiPath,
		map[string]any{})
	if err != nil {
		return nil, err
	}

	routes := make([]route, 0)
	err = response.scanAt("data.routes", &routes)
	if err != nil {
		return nil, fmt.Errorf("parse node routes failed: \nError: %v", err)
	}

	for i := range routes {
		if routes[i].Action == "block" {
			for _, v := range routes[i].Match {
				pattern, err := common.SafeCompileRegex(v)
				if err != nil {
					log.Printf("Invalid route rule regex (index=%d): %s, skipping", i, err)
					continue
				}
				ruleList = append(ruleList, api.DetectRule{
					ID:      i,
					Pattern: pattern,
				})
			}

		}
	}

	return &ruleList, nil

}

func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	return c.ReportIllegalContext(context.Background(), detectResultList)
}

func (*APIClient) ReportIllegalContext(ctx context.Context, _ *[]api.DetectResult) error {
	return ctx.Err()
}

func (c *APIClient) Debug() {

}
