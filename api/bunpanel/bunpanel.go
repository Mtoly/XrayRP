package bunpanel

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/internal/panelhttp"
	"github.com/Mtoly/XrayRP/api/internal/panelrules"
)

type APIClient struct {
	client           *resty.Client
	httpPolicy       panelhttp.Policy
	APIHost          string
	NodeID           int
	Key              string
	NodeType         string
	EnableVless      bool
	VlessFlow        string
	SpeedLimit       float64
	DeviceLimit      int
	LocalRuleList    []api.DetectRule
	LastReportOnline map[int]int
	access           sync.Mutex
	eTags            panelhttp.ETagState
}

// ReportIllegal accepts illegal-access reports for this adapter.
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	return c.ReportIllegalContext(context.Background(), detectResultList)
}

func (*APIClient) ReportIllegalContext(ctx context.Context, _ *[]api.DetectResult) error {
	return ctx.Err()
}

// ReportNodeStatus accepts node status reports for this adapter.
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) error {
	return c.ReportNodeStatusContext(context.Background(), nodeStatus)
}

func (*APIClient) ReportNodeStatusContext(ctx context.Context, _ *api.NodeStatus) error {
	return ctx.Err()
}

// GetXrayRCertConfig is not supported by BunPanel.
func (c *APIClient) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	return c.GetXrayRCertConfigContext(context.Background())
}

func (*APIClient) GetXrayRCertConfigContext(ctx context.Context) (*api.XrayRCertConfig, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, api.ErrUnsupportedPanelFeature
}

// GetNodeRule returns the configured local detection rules.
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	return c.GetNodeRuleContext(context.Background())
}

func (c *APIClient) GetNodeRuleContext(ctx context.Context) (*[]api.DetectRule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ruleList := c.LocalRuleList
	return &ruleList, nil
}

func New(apiConfig *api.Config) *APIClient {
	client, httpPolicy := panelhttp.NewClient(panelhttp.ClientConfig{
		BaseURL:        apiConfig.APIHost,
		TimeoutSeconds: apiConfig.Timeout,
		Credentials:    []string{apiConfig.Key},
	})
	// Create Key for each requests
	client.SetQueryParams(map[string]string{
		"serverId": strconv.Itoa(apiConfig.NodeID),
		"nodeType": strings.ToLower(apiConfig.NodeType),
		"token":    apiConfig.Key,
	})
	// Read local rule list
	localRuleList, diagnostics := panelrules.Load(apiConfig.RuleListPath)
	for _, diagnostic := range diagnostics {
		log.Print(diagnostic)
	}
	apiClient := &APIClient{
		client:        client,
		httpPolicy:    httpPolicy,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		NodeType:      apiConfig.NodeType,
		EnableVless:   apiConfig.EnableVless,
		VlessFlow:     apiConfig.VlessFlow,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
	}
	return apiClient
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: "", NodeType: c.NodeType}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*Response, error) {
	response, err := panelhttp.TypedResult[Response](c.httpPolicy, res, path, err)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("request %s returned unexpected status code: %d", c.assembleURL(path), response.StatusCode)
	}
	return response, nil
}

func (c *APIClient) GetNodeInfo() (*api.NodeInfo, error) {
	return c.GetNodeInfoContext(context.Background())
}

func (c *APIClient) GetNodeInfoContext(ctx context.Context) (nodeInfo *api.NodeInfo, err error) {
	path := fmt.Sprintf("/v2/server/%d/get", c.NodeID)
	res, err := c.client.R().
		SetContext(ctx).
		SetResult(&Response{}).
		SetHeader("If-None-Match", c.eTags.Get("node")).
		ForceContentType("application/json").
		Get(path)
	if err := c.httpPolicy.CheckResponse(res, path, err); err != nil {
		return nil, err
	}
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, api.ErrNodeNotModified
	}
	candidateETag := res.Header().Get("ETag")

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	nodeInfoResponse := new(Server)

	if err := json.Unmarshal(response.Datas, nodeInfoResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(nodeInfoResponse), err)
	}

	nodeInfo, err = c.ParseNodeInfo(nodeInfoResponse)
	if err != nil {
		return nil, panelhttp.NodeInfoParseError(err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.eTags.Publish("node", candidateETag)
	return nodeInfo, nil
}

func (c *APIClient) GetUserList() (*[]api.UserInfo, error) {
	return c.GetUserListContext(context.Background())
}

func (c *APIClient) GetUserListContext(ctx context.Context) (UserList *[]api.UserInfo, err error) {
	path := "/v2/user/get"
	res, err := c.client.R().
		SetContext(ctx).
		SetQueryParam("serverId", strconv.Itoa(c.NodeID)).
		SetHeader("If-None-Match", c.eTags.Get("users")).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)
	if err := c.httpPolicy.CheckResponse(res, path, err); err != nil {
		return nil, err
	}
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, api.ErrUserNotModified
	}
	candidateETag := res.Header().Get("ETag")

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	userListResponse := new([]User)

	if err := json.Unmarshal(response.Datas, userListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(userListResponse), err)
	}
	userList, err := c.ParseUserListResponse(userListResponse)
	if err != nil {
		return nil, panelhttp.UserListParseError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.eTags.Publish("users", candidateETag)
	return userList, nil
}

func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	return c.ReportNodeOnlineUsersContext(context.Background(), onlineUserList)
}

func (c *APIClient) ReportNodeOnlineUsersContext(ctx context.Context, onlineUserList *[]api.OnlineUser) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	reportOnline := make(map[int]int)
	data := make([]OnlineUser, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = OnlineUser{UID: user.UID, IP: user.IP}
		reportOnline[user.UID]++
	}
	postData := &PostData{Data: data}
	path := "/v2/user/online/create"
	res, err := c.client.R().
		SetContext(ctx).
		SetQueryParam("serverId", strconv.Itoa(c.NodeID)).
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.access.Lock()
	c.LastReportOnline = reportOnline
	c.access.Unlock()
	return nil
}

// GetAliveList is not supported by BunPanel.
func (c *APIClient) GetAliveList() (map[int][]string, error) {
	return c.GetAliveListContext(context.Background())
}

func (*APIClient) GetAliveListContext(ctx context.Context) (map[int][]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, api.ErrUnsupportedPanelFeature
}

func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	return c.ReportUserTrafficContext(context.Background(), userTraffic)
}

func (c *APIClient) ReportUserTrafficContext(ctx context.Context, userTraffic *[]api.UserTraffic) error {

	data := make([]UserTraffic, len(*userTraffic))
	for i, traffic := range *userTraffic {
		data[i] = UserTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download}
	}
	postData := &PostData{Data: data}
	path := "/v2/user/data-usage/create"
	res, err := c.client.R().
		SetContext(ctx).
		SetQueryParam("serverId", strconv.Itoa(c.NodeID)).
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

func (c *APIClient) ParseUserListResponse(userInfoResponse *[]User) (*[]api.UserInfo, error) {
	c.access.Lock()
	// Clear Last report log
	defer func() {
		c.LastReportOnline = make(map[int]int)
		c.access.Unlock()
	}()

	var deviceLimit, localDeviceLimit = 0, 0
	var speedLimit uint64 = 0
	var userList []api.UserInfo
	for _, user := range *userInfoResponse {
		if c.DeviceLimit > 0 {
			deviceLimit = c.DeviceLimit
		} else {
			deviceLimit = user.DeviceLimit
		}

		// If there is still device available, add the user
		if deviceLimit > 0 && user.AliveIP > 0 {
			lastOnline := 0
			if v, ok := c.LastReportOnline[user.ID]; ok {
				lastOnline = v
			}
			// If there are any available device.
			if localDeviceLimit = deviceLimit - user.AliveIP + lastOnline; localDeviceLimit > 0 {
				deviceLimit = localDeviceLimit
				// If this backend server has reported any user in the last reporting period.
			} else if lastOnline > 0 {
				deviceLimit = lastOnline
				// Remove this user.
			} else {
				continue
			}
		}

		if c.SpeedLimit > 0 {
			speedLimit = uint64((c.SpeedLimit * 1000000) / 8)
		} else {
			speedLimit = uint64((user.SpeedLimit * 1000000) / 8)
		}
		userList = append(userList, api.UserInfo{
			UID:         user.ID,
			UUID:        user.UUID,
			SpeedLimit:  speedLimit,
			DeviceLimit: deviceLimit,
			Passwd:      user.UUID,
			Email:       user.UUID + "@bunpanel.user",
		})
	}

	return &userList, nil
}

func (c *APIClient) ParseNodeInfo(nodeInfoResponse *Server) (*api.NodeInfo, error) {
	var (
		speedLimit                            uint64 = 0
		enableTLS, enableVless, enableREALITY bool
		alterID                               uint16 = 0
		tlsType, transportProtocol            string
	)

	nodeConfig := nodeInfoResponse
	port := uint32(nodeConfig.Port)

	switch c.NodeType {
	case "Shadowsocks":
		transportProtocol = "tcp"
	case "V2ray":
		transportProtocol = nodeConfig.Network
		tlsType = nodeConfig.Security

		if tlsType == "tls" || tlsType == "xtls" {
			enableTLS = true
		}
		if tlsType == "reality" {
			enableREALITY = true
			enableVless = true
		}
	case "Trojan":
		enableTLS = true
		tlsType = "tls"
		transportProtocol = "tcp"
	}

	// parse reality config
	realityConfig := new(api.REALITYConfig)
	if nodeConfig.RealitySettings != nil {
		r := new(RealitySettings)
		if err := json.Unmarshal(nodeConfig.RealitySettings, r); err != nil {
			return nil, fmt.Errorf("unmarshal RealitySettings failed: %w", err)
		}
		realityConfig = &api.REALITYConfig{
			Dest:             r.Dest,
			ProxyProtocolVer: r.ProxyProtocolVer,
			ServerNames:      r.ServerNames,
			PrivateKey:       r.PrivateKey,
			MinClientVer:     r.MinClientVer,
			MaxClientVer:     r.MaxClientVer,
			MaxTimeDiff:      r.MaxTimeDiff,
			ShortIds:         r.ShortIds,
		}
	}
	wsConfig := new(WsSettings)
	if nodeConfig.WsSettings != nil {
		if err := json.Unmarshal(nodeConfig.WsSettings, wsConfig); err != nil {
			return nil, fmt.Errorf("unmarshal WsSettings failed: %w", err)
		}
	}

	grpcConfig := new(GrpcSettigns)
	if nodeConfig.GrpcSettings != nil {
		if err := json.Unmarshal(nodeConfig.GrpcSettings, grpcConfig); err != nil {
			return nil, fmt.Errorf("unmarshal GrpcSettings failed: %w", err)
		}
	}

	tcpConfig := new(TcpSettings)
	if nodeConfig.TcpSettings != nil {
		if err := json.Unmarshal(nodeConfig.TcpSettings, tcpConfig); err != nil {
			return nil, fmt.Errorf("unmarshal TcpSettings failed: %w", err)
		}
	}

	// Parse SplitHTTP/XHTTP settings
	splithttpConfig := new(SplitHTTPSettings)
	if nodeConfig.XHTTPSettings != nil {
		if err := validateOptionalXPaddingBytes(nodeConfig.XHTTPSettings); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(nodeConfig.XHTTPSettings, splithttpConfig); err != nil {
			return nil, fmt.Errorf("unmarshal XHTTPSettings failed: %w", err)
		}
	} else if nodeConfig.SplitHTTPSettings != nil {
		if err := validateOptionalXPaddingBytes(nodeConfig.SplitHTTPSettings); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(nodeConfig.SplitHTTPSettings, splithttpConfig); err != nil {
			return nil, fmt.Errorf("unmarshal SplitHTTPSettings failed: %w", err)
		}
	}
	if splithttpConfig.UplinkChunkSize > math.MaxInt32 {
		return nil, fmt.Errorf("decode uplinkChunkSize: value %d exceeds runtime maximum %d", splithttpConfig.UplinkChunkSize, math.MaxInt32)
	}

	// Parse HttpUpgrade settings
	httpupgradeConfig := new(HttpUpgradeSettings)
	if nodeConfig.HttpUpgradeSettings != nil {
		if err := json.Unmarshal(nodeConfig.HttpUpgradeSettings, httpupgradeConfig); err != nil {
			return nil, fmt.Errorf("unmarshal HttpUpgradeSettings failed: %w", err)
		}
	}

	var host, path, serviceName string
	var header json.RawMessage
	var headers map[string]string
	switch transportProtocol {
	case "ws":
		host = wsConfig.Headers.Host
		path = wsConfig.Path
	case "grpc":
		serviceName = grpcConfig.ServiceName
	case "tcp":
		header = tcpConfig.Header
	case "splithttp", "xhttp":
		host = splithttpConfig.Host
		path = splithttpConfig.Path
		headers = splithttpConfig.Headers
	case "httpupgrade":
		host = httpupgradeConfig.Host
		path = httpupgradeConfig.Path
		headers = httpupgradeConfig.Headers
	default:
		host = wsConfig.Headers.Host
		path = wsConfig.Path
	}

	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:            c.NodeType,
		NodeID:              c.NodeID,
		Port:                port,
		SpeedLimit:          speedLimit,
		AlterID:             alterID,
		TransportProtocol:   transportProtocol,
		Host:                host,
		Path:                path,
		EnableTLS:           enableTLS,
		EnableVless:         enableVless,
		VlessFlow:           nodeConfig.Flow,
		CypherMethod:        nodeConfig.Method,
		ServiceName:         serviceName,
		Header:              header,
		Headers:             headers,
		EnableREALITY:       enableREALITY,
		REALITYConfig:       realityConfig,
		XHTTPMode:           splithttpConfig.Mode,
		XHTTPExtra:          splithttpConfig.Extra,
		XPaddingBytes:       splithttpConfig.XPaddingBytes,
		XPaddingObfsMode:    splithttpConfig.XPaddingObfsMode,
		XPaddingKey:         splithttpConfig.XPaddingKey,
		XPaddingHeader:      splithttpConfig.XPaddingHeader,
		XPaddingPlacement:   splithttpConfig.XPaddingPlacement,
		XPaddingMethod:      splithttpConfig.XPaddingMethod,
		UplinkHTTPMethod:    splithttpConfig.UplinkHTTPMethod,
		SessionPlacement:    splithttpConfig.SessionPlacement,
		SessionKey:          splithttpConfig.SessionKey,
		SeqPlacement:        splithttpConfig.SeqPlacement,
		SeqKey:              splithttpConfig.SeqKey,
		UplinkDataPlacement: splithttpConfig.UplinkDataPlacement,
		UplinkDataKey:       splithttpConfig.UplinkDataKey,
		UplinkChunkSize:     splithttpConfig.UplinkChunkSize,
		NoGRPCHeader:        splithttpConfig.NoGRPCHeader,
		NoSSEHeader:         splithttpConfig.NoSSEHeader,
	}

	return nodeInfo, nil
}

func validateOptionalXPaddingBytes(settings json.RawMessage) error {
	var raw struct {
		XPaddingBytes json.RawMessage `json:"xPaddingBytes"`
	}
	if err := json.Unmarshal(settings, &raw); err != nil {
		return fmt.Errorf("decode xPaddingBytes settings: %w", err)
	}
	if len(raw.XPaddingBytes) == 0 {
		return nil
	}

	var values []int32
	if err := json.Unmarshal(raw.XPaddingBytes, &values); err != nil {
		return fmt.Errorf("decode xPaddingBytes: %w", err)
	}
	if values == nil {
		return nil
	}
	if len(values) != 2 {
		return fmt.Errorf("decode xPaddingBytes: expected 2 values, got %d", len(values))
	}
	return nil
}
