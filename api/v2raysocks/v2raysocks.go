package v2raysocks

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/internal/panelhttp"
	"github.com/Mtoly/XrayRP/api/internal/panelrules"
	"github.com/Mtoly/XrayRP/common"
	"github.com/Mtoly/XrayRP/internal/buildinfo"
)

// APIClient create an api client to the panel.
type APIClient struct {
	client        *resty.Client
	httpPolicy    panelhttp.Policy
	APIHost       string
	NodeID        int
	Key           string
	NodeType      string
	EnableVless   bool
	VlessFlow     string
	SpeedLimit    float64
	DeviceLimit   int
	LocalRuleList []api.DetectRule
	ConfigResp    *simplejson.Json
	access        sync.Mutex
	eTags         panelhttp.ETagState
}

// New create an api instance
func New(apiConfig *api.Config) *APIClient {
	client, httpPolicy := panelhttp.NewClient(panelhttp.ClientConfig{
		BaseURL:        apiConfig.APIHost,
		TimeoutSeconds: apiConfig.Timeout,
		Credentials:    []string{apiConfig.Key},
	})
	client.SetHeader("User-Agent", buildinfo.UserAgent())

	// Create Key for each requests
	client.SetQueryParams(map[string]string{
		"node_id": strconv.Itoa(apiConfig.NodeID),
		"token":   apiConfig.Key,
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

// GetXrayRCertConfig is not provided by V2RaySocks panel.
func (c *APIClient) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	return c.GetXrayRCertConfigContext(context.Background())
}

func (*APIClient) GetXrayRCertConfigContext(ctx context.Context) (*api.XrayRCertConfig, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, api.ErrUnsupportedPanelFeature
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*simplejson.Json, error) {
	if err := c.httpPolicy.CheckResponse(res, path, err); err != nil {
		return nil, err
	}
	rtn, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("request %s returned invalid JSON", c.assembleURL(path))
	}
	return rtn, nil
}

// GetNodeInfo will pull NodeInfo Config from panel
func (c *APIClient) GetNodeInfo() (*api.NodeInfo, error) {
	return c.GetNodeInfoContext(context.Background())
}

func (c *APIClient) GetNodeInfoContext(ctx context.Context) (nodeInfo *api.NodeInfo, err error) {
	var nodeType string
	switch strings.ToLower(c.NodeType) {
	case "v2ray", "vmess", "vless":
		nodeType = "v2ray"
	case "trojan", "shadowsocks":
		nodeType = strings.ToLower(c.NodeType)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	configETag := c.eTags.Get("config")
	res, err := c.client.R().
		SetContext(ctx).
		SetHeader("If-None-Match", configETag).
		SetQueryParams(map[string]string{
			"act":       "config",
			"node_type": nodeType,
		}).
		ForceContentType("application/json").
		Get(c.APIHost)
	if err := c.httpPolicy.CheckResponse(res, "", err); err != nil {
		return nil, err
	}

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, api.ErrNodeNotModified
	}
	candidateETag := res.Header().Get("Etag")

	response, err := c.parseResponse(res, "", err)
	if err != nil {
		return nil, err
	}

	switch c.NodeType {
	case "V2ray", "Vmess", "Vless":
		nodeInfo, err = c.ParseV2rayNodeResponse(response)
	case "Trojan":
		nodeInfo, err = c.ParseTrojanNodeResponse(response)
	case "Shadowsocks":
		nodeInfo, err = c.ParseSSNodeResponse(response)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}

	if err != nil {
		return nil, fmt.Errorf("parse node info failed: %v", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.access.Lock()
	c.ConfigResp = response
	c.eTags.Publish("config", candidateETag)
	c.access.Unlock()
	return nodeInfo, nil
}

// GetUserList will pull user form panel
func (c *APIClient) GetUserList() (*[]api.UserInfo, error) {
	return c.GetUserListContext(context.Background())
}

func (c *APIClient) GetUserListContext(ctx context.Context) (UserList *[]api.UserInfo, err error) {
	var nodeType string
	switch c.NodeType {
	case "V2ray", "Vmess", "Vless", "Trojan", "Shadowsocks":
		nodeType = strings.ToLower(c.NodeType)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	userETag := c.eTags.Get("user")
	res, err := c.client.R().
		SetContext(ctx).
		SetHeader("If-None-Match", userETag).
		SetQueryParams(map[string]string{
			"act":       "user",
			"node_type": nodeType,
		}).
		ForceContentType("application/json").
		Get(c.APIHost)
	if err := c.httpPolicy.CheckResponse(res, "", err); err != nil {
		return nil, err
	}

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, api.ErrUserNotModified
	}
	candidateETag := res.Header().Get("Etag")

	response, err := c.parseResponse(res, "", err)
	if err != nil {
		return nil, err
	}
	users, err := response.Get("data").Array()
	if err != nil {
		return nil, fmt.Errorf("parse user list failed: invalid data")
	}
	for i, item := range users {
		if _, ok := item.(map[string]interface{}); !ok {
			return nil, fmt.Errorf("parse user list failed: invalid user at index %d", i)
		}
	}
	numOfUsers := len(users)
	userList := make([]api.UserInfo, numOfUsers)
	for i := 0; i < numOfUsers; i++ {
		user := api.UserInfo{}
		user.UID = response.Get("data").GetIndex(i).Get("id").MustInt()
		switch c.NodeType {
		case "Shadowsocks":
			user.Email = response.Get("data").GetIndex(i).Get("secret").MustString()
			user.Passwd = response.Get("data").GetIndex(i).Get("secret").MustString()
			user.Method = response.Get("data").GetIndex(i).Get("cipher").MustString()
			user.SpeedLimit = response.Get("data").GetIndex(i).Get("st").MustUint64() * 1000000 / 8
			user.DeviceLimit = response.Get("data").GetIndex(i).Get("dt").MustInt()
		case "Trojan":
			user.UUID = response.Get("data").GetIndex(i).Get("password").MustString()
			user.Email = response.Get("data").GetIndex(i).Get("password").MustString()
			user.SpeedLimit = response.Get("data").GetIndex(i).Get("st").MustUint64() * 1000000 / 8
			user.DeviceLimit = response.Get("data").GetIndex(i).Get("dt").MustInt()
		case "V2ray", "Vmess", "Vless":
			user.UUID = response.Get("data").GetIndex(i).Get("uuid").MustString()
			user.Email = user.UUID + "@x.com"
			user.SpeedLimit = response.Get("data").GetIndex(i).Get("st").MustUint64() * 1000000 / 8
			user.DeviceLimit = response.Get("data").GetIndex(i).Get("dt").MustInt()
		}
		if c.SpeedLimit > 0 {
			user.SpeedLimit = uint64((c.SpeedLimit * 1000000) / 8)
		}

		if c.DeviceLimit > 0 {
			user.DeviceLimit = c.DeviceLimit
		}

		userList[i] = user
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.eTags.Publish("user", candidateETag)
	return &userList, nil
}

// GetAliveList is not supported by V2RaySocks.
func (c *APIClient) GetAliveList() (map[int][]string, error) {
	return c.GetAliveListContext(context.Background())
}

func (*APIClient) GetAliveListContext(ctx context.Context) (map[int][]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, api.ErrUnsupportedPanelFeature
}

// ReportUserTraffic reports the user traffic
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

	res, err := c.client.R().
		SetContext(ctx).
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetQueryParams(map[string]string{
			"act":       "submit",
			"node_type": strings.ToLower(c.NodeType),
		}).
		SetBody(data).
		ForceContentType("application/json").
		Post(c.APIHost)
	_, err = c.parseResponse(res, "", err)
	if err != nil {
		return err
	}
	return nil
}

// GetNodeRule implements the API interface
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	return c.GetNodeRuleContext(context.Background())
}

func (c *APIClient) GetNodeRuleContext(ctx context.Context) (*[]api.DetectRule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ruleList := c.LocalRuleList

	// fix: reuse config response
	c.access.Lock()
	defer c.access.Unlock()
	ruleListResponse := c.ConfigResp.Get("routing").Get("rules").GetIndex(1).Get("domain").MustStringArray()
	for i, rule := range ruleListResponse {
		rule = strings.TrimPrefix(rule, "regexp:")
		pattern, err := common.SafeCompileRegex(rule)
		if err != nil {
			log.Printf("Invalid rule regex (index=%d): %s, skipping", i, err)
			continue
		}
		ruleListItem := api.DetectRule{
			ID:      i,
			Pattern: pattern,
		}
		ruleList = append(ruleList, ruleListItem)
	}
	return &ruleList, nil
}

// ReportNodeStatus implements the API interface
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) error {
	return c.ReportNodeStatusContext(context.Background(), nodeStatus)
}

func (c *APIClient) ReportNodeStatusContext(ctx context.Context, nodeStatus *api.NodeStatus) (err error) {
	systemload := NodeStatus{
		Uptime: int(nodeStatus.Uptime),
		CPU:    fmt.Sprintf("%d%%", int(nodeStatus.CPU)),
		Mem:    fmt.Sprintf("%d%%", int(nodeStatus.Mem)),
		Disk:   fmt.Sprintf("%d%%", int(nodeStatus.Disk)),
	}

	res, err := c.client.R().
		SetContext(ctx).
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetQueryParams(map[string]string{
			"act":       "nodestatus",
			"node_type": strings.ToLower(c.NodeType),
		}).
		SetBody(systemload).
		ForceContentType("application/json").
		Post(c.APIHost)
	_, err = c.parseResponse(res, "", err)
	if err != nil {
		return err
	}
	return nil
}

// ReportNodeOnlineUsers implements the API interface
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	return c.ReportNodeOnlineUsersContext(context.Background(), onlineUserList)
}

func (c *APIClient) ReportNodeOnlineUsersContext(ctx context.Context, onlineUserList *[]api.OnlineUser) error {
	data := make([]NodeOnline, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = NodeOnline{UID: user.UID, IP: user.IP}
	}

	res, err := c.client.R().
		SetContext(ctx).
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetQueryParams(map[string]string{
			"act":       "onlineusers",
			"node_type": strings.ToLower(c.NodeType),
		}).
		SetBody(data).
		ForceContentType("application/json").
		Post(c.APIHost)
	_, err = c.parseResponse(res, "", err)
	if err != nil {
		return err
	}
	return nil
}

// ReportIllegal implements the API interface
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	return c.ReportIllegalContext(context.Background(), detectResultList)
}

func (c *APIClient) ReportIllegalContext(ctx context.Context, detectResultList *[]api.DetectResult) error {
	data := make([]IllegalItem, len(*detectResultList))
	for i, r := range *detectResultList {
		data[i] = IllegalItem{
			UID: r.UID,
		}
	}

	res, err := c.client.R().
		SetContext(ctx).
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetQueryParams(map[string]string{
			"act":       "illegal",
			"node_type": strings.ToLower(c.NodeType),
		}).
		SetBody(data).
		ForceContentType("application/json").
		Post(c.APIHost)
	_, err = c.parseResponse(res, "", err)
	if err != nil {
		return err
	}
	return nil
}

// ParseTrojanNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) ParseTrojanNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {
	tmpInboundInfo := nodeInfoResponse.Get("inbounds").MustArray()
	if len(tmpInboundInfo) == 0 {
		return nil, fmt.Errorf("no inbound info in response")
	}
	inboundMap, ok := tmpInboundInfo[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid inbound info format")
	}
	marshalByte, err := json.Marshal(inboundMap)
	if err != nil {
		return nil, fmt.Errorf("marshal inbound info: %w", err)
	}
	inboundInfo, err := simplejson.NewJson(marshalByte)
	if err != nil {
		return nil, fmt.Errorf("parse inbound info: %w", err)
	}

	port := uint32(inboundInfo.Get("port").MustUint64())
	host := inboundInfo.Get("streamSettings").Get("tlsSettings").Get("serverName").MustString()

	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		TransportProtocol: "tcp",
		EnableTLS:         true,
		Host:              host,
	}
	return nodeInfo, nil
}

// ParseSSNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) ParseSSNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {
	var method, serverPsk string
	tmpInboundInfo := nodeInfoResponse.Get("inbounds").MustArray()
	if len(tmpInboundInfo) == 0 {
		return nil, fmt.Errorf("no inbound info in response")
	}
	inboundMap, ok := tmpInboundInfo[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid inbound info format")
	}
	marshalByte, err := json.Marshal(inboundMap)
	if err != nil {
		return nil, fmt.Errorf("marshal inbound info: %w", err)
	}
	inboundInfo, err := simplejson.NewJson(marshalByte)
	if err != nil {
		return nil, fmt.Errorf("parse inbound info: %w", err)
	}

	port := uint32(inboundInfo.Get("port").MustUint64())
	method = inboundInfo.Get("settings").Get("method").MustString()
	// Shadowsocks 2022
	if C.Contains(shadowaead_2022.List, method) {
		serverPsk = inboundInfo.Get("settings").Get("password").MustString()
	}

	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		TransportProtocol: "tcp",
		CypherMethod:      method,
		ServerKey:         serverPsk,
	}

	return nodeInfo, nil
}

func decodeOptionalTransportHeaders(settings *simplejson.Json) (map[string]string, error) {
	if settings == nil {
		return nil, nil
	}
	value, ok := settings.CheckGet("headers")
	if !ok || value.Interface() == nil {
		return nil, nil
	}
	raw, err := value.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal transport headers: %w", err)
	}
	var headers map[string]string
	if err := json.Unmarshal(raw, &headers); err != nil {
		return nil, fmt.Errorf("decode transport headers: %w", err)
	}
	return headers, nil
}

func decodeOptionalXPaddingBytes(settings *simplejson.Json) (*[2]int32, error) {
	if settings == nil {
		return nil, nil
	}
	value, ok := settings.CheckGet("xPaddingBytes")
	if !ok || value.Interface() == nil {
		return nil, nil
	}
	raw, err := value.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal xPaddingBytes: %w", err)
	}
	var values []int32
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("decode xPaddingBytes: %w", err)
	}
	if len(values) != 2 {
		return nil, fmt.Errorf("decode xPaddingBytes: expected 2 values, got %d", len(values))
	}
	return &[2]int32{values[0], values[1]}, nil
}

func decodeOptionalUplinkChunkSize(settings *simplejson.Json) (uint32, error) {
	if settings == nil {
		return 0, nil
	}
	value, ok := settings.CheckGet("uplinkChunkSize")
	if !ok || value.Interface() == nil {
		return 0, nil
	}
	raw, err := value.MarshalJSON()
	if err != nil {
		return 0, fmt.Errorf("marshal uplinkChunkSize: %w", err)
	}
	var chunkSize uint32
	if err := json.Unmarshal(raw, &chunkSize); err != nil {
		return 0, fmt.Errorf("decode uplinkChunkSize: %w", err)
	}
	if chunkSize > math.MaxInt32 {
		return 0, fmt.Errorf("decode uplinkChunkSize: value %d exceeds runtime maximum %d", chunkSize, math.MaxInt32)
	}
	return chunkSize, nil
}

func enrichNodeInfoWithXHTTPSettings(nodeInfo *api.NodeInfo, inboundInfo *simplejson.Json, transportProtocol string) error {
	if nodeInfo == nil || inboundInfo == nil {
		return nil
	}
	if transportProtocol != "splithttp" && transportProtocol != "xhttp" {
		return nil
	}

	settingsKey := "splithttpSettings"
	if transportProtocol == "xhttp" {
		if _, ok := inboundInfo.Get("streamSettings").CheckGet("xhttpSettings"); ok {
			settingsKey = "xhttpSettings"
		}
	}
	ss := inboundInfo.Get("streamSettings").Get(settingsKey)
	paddingBytes, err := decodeOptionalXPaddingBytes(ss)
	if err != nil {
		return err
	}
	uplinkChunkSize, err := decodeOptionalUplinkChunkSize(ss)
	if err != nil {
		return err
	}
	nodeInfo.XHTTPMode = ss.Get("mode").MustString()
	nodeInfo.XPaddingBytes = paddingBytes
	nodeInfo.XPaddingObfsMode = ss.Get("xPaddingObfsMode").MustBool()
	nodeInfo.XPaddingKey = ss.Get("xPaddingKey").MustString()
	nodeInfo.XPaddingHeader = ss.Get("xPaddingHeader").MustString()
	nodeInfo.XPaddingPlacement = ss.Get("xPaddingPlacement").MustString()
	nodeInfo.XPaddingMethod = ss.Get("xPaddingMethod").MustString()
	nodeInfo.UplinkHTTPMethod = ss.Get("uplinkHTTPMethod").MustString()
	nodeInfo.SessionPlacement = ss.Get("sessionPlacement").MustString()
	nodeInfo.SessionKey = ss.Get("sessionKey").MustString()
	nodeInfo.SeqPlacement = ss.Get("seqPlacement").MustString()
	nodeInfo.SeqKey = ss.Get("seqKey").MustString()
	nodeInfo.UplinkDataPlacement = ss.Get("uplinkDataPlacement").MustString()
	nodeInfo.UplinkDataKey = ss.Get("uplinkDataKey").MustString()
	nodeInfo.UplinkChunkSize = uplinkChunkSize
	nodeInfo.NoGRPCHeader = ss.Get("noGRPCHeader").MustBool()
	nodeInfo.NoSSEHeader = ss.Get("noSSEHeader").MustBool()
	if extra := ss.Get("extra"); extra.Interface() != nil {
		if extraBytes, err := extra.MarshalJSON(); err == nil {
			nodeInfo.XHTTPExtra = extraBytes
		}
	}
	return nil
}

func enrichNodeInfoWithEndpoint(nodeInfo *api.NodeInfo, inboundInfo *simplejson.Json, transportProtocol string) error {
	if nodeInfo == nil || inboundInfo == nil {
		return nil
	}

	switch transportProtocol {
	case "ws":
		nodeInfo.Path = inboundInfo.Get("streamSettings").Get("wsSettings").Get("path").MustString()
		nodeInfo.Host = inboundInfo.Get("streamSettings").Get("wsSettings").Get("headers").Get("Host").MustString()
	case "httpupgrade":
		settings := inboundInfo.Get("streamSettings").Get("httpupgradeSettings")
		nodeInfo.Host = settings.Get("Host").MustString()
		nodeInfo.Path = settings.Get("path").MustString()
		headers, err := decodeOptionalTransportHeaders(settings)
		if err != nil {
			return err
		}
		nodeInfo.Headers = headers
	case "splithttp":
		settings := inboundInfo.Get("streamSettings").Get("splithttpSettings")
		nodeInfo.Host = settings.Get("Host").MustString()
		nodeInfo.Path = settings.Get("path").MustString()
		headers, err := decodeOptionalTransportHeaders(settings)
		if err != nil {
			return err
		}
		nodeInfo.Headers = headers
	case "xhttp":
		xhttpSettings := inboundInfo.Get("streamSettings").Get("xhttpSettings")
		splitHTTPSettings := inboundInfo.Get("streamSettings").Get("splithttpSettings")
		nodeInfo.Host = xhttpSettings.Get("Host").MustString()
		if nodeInfo.Host == "" {
			nodeInfo.Host = splitHTTPSettings.Get("Host").MustString()
		}
		nodeInfo.Path = xhttpSettings.Get("path").MustString()
		if nodeInfo.Path == "" {
			nodeInfo.Path = splitHTTPSettings.Get("path").MustString()
		}
		headers, err := decodeOptionalTransportHeaders(xhttpSettings)
		if err != nil {
			return err
		}
		if headers == nil {
			headers, err = decodeOptionalTransportHeaders(splitHTTPSettings)
			if err != nil {
				return err
			}
		}
		nodeInfo.Headers = headers
	case "grpc":
		if data, ok := inboundInfo.Get("streamSettings").Get("grpcSettings").CheckGet("serviceName"); ok {
			nodeInfo.ServiceName = data.MustString()
		}
	case "tcp":
		if data, ok := inboundInfo.Get("streamSettings").Get("tcpSettings").CheckGet("header"); ok {
			header, err := data.MarshalJSON()
			if err != nil {
				return err
			}
			nodeInfo.Header = header
		}
	}
	return nil
}

func enrichNodeInfoWithSecurity(nodeInfo *api.NodeInfo, inboundInfo *simplejson.Json, fallbackVlessFlow string) {
	if nodeInfo == nil || inboundInfo == nil {
		return
	}

	security := inboundInfo.Get("streamSettings").Get("security").MustString()
	nodeInfo.EnableTLS = security == "tls"
	nodeInfo.EnableVless = inboundInfo.Get("protocol").MustString() == "vless"
	nodeInfo.EnableREALITY = security == "reality"

	nodeInfo.REALITYConfig = new(api.REALITYConfig)
	if nodeInfo.EnableVless {
		// parse reality config
		nodeInfo.REALITYConfig = &api.REALITYConfig{
			Dest:             inboundInfo.Get("streamSettings").Get("realitySettings").Get("dest").MustString(),
			ProxyProtocolVer: inboundInfo.Get("streamSettings").Get("realitySettings").Get("xver").MustUint64(),
			ServerNames:      inboundInfo.Get("streamSettings").Get("realitySettings").Get("serverNames").MustStringArray(),
			PrivateKey:       inboundInfo.Get("streamSettings").Get("realitySettings").Get("privateKey").MustString(),
			MinClientVer:     inboundInfo.Get("streamSettings").Get("realitySettings").Get("minClientVer").MustString(),
			MaxClientVer:     inboundInfo.Get("streamSettings").Get("realitySettings").Get("maxClientVer").MustString(),
			MaxTimeDiff:      inboundInfo.Get("streamSettings").Get("realitySettings").Get("maxTimeDiff").MustUint64(),
			ShortIds:         inboundInfo.Get("streamSettings").Get("realitySettings").Get("shortIds").MustStringArray(),
		}
	}

	// XTLS only supports TLS and REALITY directly for now
	if (nodeInfo.TransportProtocol == "grpc" || nodeInfo.TransportProtocol == "h2") && nodeInfo.EnableREALITY {
		nodeInfo.VlessFlow = ""
	} else if nodeInfo.TransportProtocol == "tcp" && nodeInfo.EnableREALITY {
		nodeInfo.VlessFlow = "xtls-rprx-vision"
	} else {
		nodeInfo.VlessFlow = fallbackVlessFlow
	}
}

func enrichNodeInfoWithTransport(nodeInfo *api.NodeInfo, inboundInfo *simplejson.Json, fallbackVlessFlow string) error {
	if nodeInfo == nil || inboundInfo == nil {
		return nil
	}

	transportProtocol := inboundInfo.Get("streamSettings").Get("network").MustString()
	nodeInfo.TransportProtocol = transportProtocol
	enrichNodeInfoWithSecurity(nodeInfo, inboundInfo, fallbackVlessFlow)
	if err := enrichNodeInfoWithEndpoint(nodeInfo, inboundInfo, transportProtocol); err != nil {
		return err
	}
	return enrichNodeInfoWithXHTTPSettings(nodeInfo, inboundInfo, transportProtocol)
}

// ParseV2rayNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) ParseV2rayNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {
	tmpInboundInfo := nodeInfoResponse.Get("inbounds").MustArray()
	if len(tmpInboundInfo) == 0 {
		return nil, fmt.Errorf("no inbound info in response")
	}
	inboundMap, ok := tmpInboundInfo[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid inbound info format")
	}
	marshalByte, err := json.Marshal(inboundMap)
	if err != nil {
		return nil, fmt.Errorf("marshal inbound info: %w", err)
	}
	inboundInfo, err := simplejson.NewJson(marshalByte)
	if err != nil {
		return nil, fmt.Errorf("parse inbound info: %w", err)
	}

	port := uint32(inboundInfo.Get("port").MustUint64())

	// Create GeneralNodeInfo
	// AlterID will be updated after next sync
	nodeInfo := &api.NodeInfo{
		NodeType: c.NodeType,
		NodeID:   c.NodeID,
		Port:     port,
		AlterID:  0,
	}
	if err := enrichNodeInfoWithTransport(nodeInfo, inboundInfo, c.VlessFlow); err != nil {
		return nil, err
	}
	return nodeInfo, nil
}
