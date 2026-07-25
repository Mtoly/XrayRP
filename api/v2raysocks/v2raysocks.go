package v2raysocks

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/internal/panelrules"
	"github.com/Mtoly/XrayRP/api/internal/transportprofile"
	"github.com/Mtoly/XrayRP/common"
)

// APIClient create an api client to the panel.
type APIClient struct {
	client        *resty.Client
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
	eTags         map[string]string
}

// New create an api instance
func New(apiConfig *api.Config) *APIClient {

	client := resty.New()
	client.SetHeader("User-Agent", "XrayR/0.9.6")
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}

	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})

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
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		NodeType:      apiConfig.NodeType,
		EnableVless:   apiConfig.EnableVless,
		VlessFlow:     apiConfig.VlessFlow,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
		eTags:         make(map[string]string),
	}
	return apiClient
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: "", NodeType: c.NodeType}
}

// GetXrayRCertConfig is not provided by V2RaySocks panel; return nil to indicate absence.
func (c *APIClient) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	return nil, nil
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*simplejson.Json, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() >= 400 {
		return nil, fmt.Errorf("request %s failed: status %d", c.assembleURL(path), res.StatusCode())
	}
	rtn, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("request %s returned invalid JSON", c.assembleURL(path))
	}
	return rtn, nil
}

// GetNodeInfo will pull NodeInfo Config from panel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	var nodeType string
	switch strings.ToLower(c.NodeType) {
	case "v2ray", "vmess", "vless":
		nodeType = "v2ray"
	case "trojan", "shadowsocks":
		nodeType = strings.ToLower(c.NodeType)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["config"]).
		SetQueryParams(map[string]string{
			"act":       "config",
			"node_type": nodeType,
		}).
		ForceContentType("application/json").
		Get(c.APIHost)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, api.ErrNodeNotModified
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["config"] {
		c.eTags["config"] = res.Header().Get("Etag")
	}

	response, err := c.parseResponse(res, "", err)
	c.access.Lock()
	defer c.access.Unlock()
	c.ConfigResp = response
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

	return nodeInfo, nil
}

// GetUserList will pull user form panel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	var nodeType string
	switch c.NodeType {
	case "V2ray", "Vmess", "Vless", "Trojan", "Shadowsocks":
		nodeType = strings.ToLower(c.NodeType)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["user"]).
		SetQueryParams(map[string]string{
			"act":       "user",
			"node_type": nodeType,
		}).
		ForceContentType("application/json").
		Get(c.APIHost)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, api.ErrUserNotModified
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["user"] {
		c.eTags["user"] = res.Header().Get("Etag")
	}

	response, err := c.parseResponse(res, "", err)
	if err != nil {
		return nil, err
	}
	numOfUsers := len(response.Get("data").MustArray())
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
	return &userList, nil
}

// GetAliveList implements the API interface (not supported by V2RaySocks)
func (c *APIClient) GetAliveList() (map[int][]string, error) {
	return nil, nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {

	data := make([]UserTraffic, len(*userTraffic))
	for i, traffic := range *userTraffic {
		data[i] = UserTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download}
	}

	res, err := c.client.R().
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
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	systemload := NodeStatus{
		Uptime: int(nodeStatus.Uptime),
		CPU:    fmt.Sprintf("%d%%", int(nodeStatus.CPU)),
		Mem:    fmt.Sprintf("%d%%", int(nodeStatus.Mem)),
		Disk:   fmt.Sprintf("%d%%", int(nodeStatus.Disk)),
	}

	res, err := c.client.R().
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
	data := make([]NodeOnline, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = NodeOnline{UID: user.UID, IP: user.IP}
	}

	res, err := c.client.R().
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
	data := make([]IllegalItem, len(*detectResultList))
	for i, r := range *detectResultList {
		data[i] = IllegalItem{
			UID: r.UID,
		}
	}

	res, err := c.client.R().
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

func enrichTransportProfileWithXHTTPSettings(profile *transportprofile.Input, inboundInfo *simplejson.Json, transportProtocol string) {
	if profile == nil || inboundInfo == nil {
		return
	}
	if transportProtocol != "splithttp" && transportProtocol != "xhttp" {
		return
	}

	settingsKey := "splithttpSettings"
	if transportProtocol == "xhttp" {
		if _, ok := inboundInfo.Get("streamSettings").CheckGet("xhttpSettings"); ok {
			settingsKey = "xhttpSettings"
		}
	}
	ss := inboundInfo.Get("streamSettings").Get(settingsKey)
	profile.XHTTP.Mode = ss.Get("mode").MustString()
	profile.XHTTP.PaddingObfsMode = ss.Get("xPaddingObfsMode").MustBool()
	profile.XHTTP.PaddingKey = ss.Get("xPaddingKey").MustString()
	profile.XHTTP.PaddingHeader = ss.Get("xPaddingHeader").MustString()
	profile.XHTTP.PaddingPlacement = ss.Get("xPaddingPlacement").MustString()
	profile.XHTTP.PaddingMethod = ss.Get("xPaddingMethod").MustString()
	profile.XHTTP.UplinkHTTPMethod = ss.Get("uplinkHTTPMethod").MustString()
	profile.XHTTP.SessionPlacement = ss.Get("sessionPlacement").MustString()
	profile.XHTTP.SessionKey = ss.Get("sessionKey").MustString()
	profile.XHTTP.SeqPlacement = ss.Get("seqPlacement").MustString()
	profile.XHTTP.SeqKey = ss.Get("seqKey").MustString()
	profile.XHTTP.UplinkDataPlacement = ss.Get("uplinkDataPlacement").MustString()
	profile.XHTTP.UplinkDataKey = ss.Get("uplinkDataKey").MustString()
	profile.XHTTP.UplinkChunkSize = uint32(ss.Get("uplinkChunkSize").MustUint64())
	profile.XHTTP.NoGRPCHeader = ss.Get("noGRPCHeader").MustBool()
	profile.XHTTP.NoSSEHeader = ss.Get("noSSEHeader").MustBool()
	if extra := ss.Get("extra"); extra.Interface() != nil {
		if extraBytes, err := extra.MarshalJSON(); err == nil {
			profile.XHTTP.Extra = extraBytes
		}
	}
}

func enrichTransportProfileWithEndpoint(profile *transportprofile.Input, inboundInfo *simplejson.Json, transportProtocol string) error {
	if profile == nil || inboundInfo == nil {
		return nil
	}

	switch transportProtocol {
	case "ws":
		profile.Endpoints.WebSocket.Path = inboundInfo.Get("streamSettings").Get("wsSettings").Get("path").MustString()
		profile.Endpoints.WebSocket.Host = inboundInfo.Get("streamSettings").Get("wsSettings").Get("headers").Get("Host").MustString()
	case "httpupgrade":
		profile.Endpoints.HTTPUpgrade.Host = inboundInfo.Get("streamSettings").Get("httpupgradeSettings").Get("Host").MustString()
		profile.Endpoints.HTTPUpgrade.Path = inboundInfo.Get("streamSettings").Get("httpupgradeSettings").Get("path").MustString()
	case "splithttp":
		profile.Endpoints.SplitHTTP.Host = inboundInfo.Get("streamSettings").Get("splithttpSettings").Get("Host").MustString()
		profile.Endpoints.SplitHTTP.Path = inboundInfo.Get("streamSettings").Get("splithttpSettings").Get("path").MustString()
	case "xhttp":
		profile.Endpoints.XHTTP.Host = inboundInfo.Get("streamSettings").Get("xhttpSettings").Get("Host").MustString()
		if profile.Endpoints.XHTTP.Host == "" {
			profile.Endpoints.XHTTP.Host = inboundInfo.Get("streamSettings").Get("splithttpSettings").Get("Host").MustString()
		}
		profile.Endpoints.XHTTP.Path = inboundInfo.Get("streamSettings").Get("xhttpSettings").Get("path").MustString()
		if profile.Endpoints.XHTTP.Path == "" {
			profile.Endpoints.XHTTP.Path = inboundInfo.Get("streamSettings").Get("splithttpSettings").Get("path").MustString()
		}
	case "grpc":
		if data, ok := inboundInfo.Get("streamSettings").Get("grpcSettings").CheckGet("serviceName"); ok {
			profile.Endpoints.GRPC.ServiceName = data.MustString()
		}
	case "tcp":
		if data, ok := inboundInfo.Get("streamSettings").Get("tcpSettings").CheckGet("header"); ok {
			header, err := data.MarshalJSON()
			if err != nil {
				return err
			}
			profile.Endpoints.TCP.Header = header
		}
	}
	return nil
}

func enrichTransportProfileWithSecurity(profile *transportprofile.Input, inboundInfo *simplejson.Json, fallbackVlessFlow string) {
	if profile == nil || inboundInfo == nil {
		return
	}

	security := inboundInfo.Get("streamSettings").Get("security").MustString()
	profile.Security.EnableTLS = security == "tls"
	profile.Security.EnableVless = inboundInfo.Get("protocol").MustString() == "vless"
	profile.Security.EnableREALITY = security == "reality"

	profile.Security.REALITYConfig = new(api.REALITYConfig)
	if profile.Security.EnableVless {
		// parse reality config
		profile.Security.REALITYConfig = &api.REALITYConfig{
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
	if (profile.Protocol == "grpc" || profile.Protocol == "h2") && profile.Security.EnableREALITY {
		profile.Security.VlessFlow = ""
	} else if profile.Protocol == "tcp" && profile.Security.EnableREALITY {
		profile.Security.VlessFlow = "xtls-rprx-vision"
	} else {
		profile.Security.VlessFlow = fallbackVlessFlow
	}
}

func deriveTransportProfileFromInbound(inboundInfo *simplejson.Json, fallbackVlessFlow string) (transportprofile.Input, error) {
	if inboundInfo == nil {
		return transportprofile.Input{}, nil
	}

	transportProtocol := inboundInfo.Get("streamSettings").Get("network").MustString()
	profile := transportprofile.Input{
		Protocol: transportProtocol,
	}
	enrichTransportProfileWithSecurity(&profile, inboundInfo, fallbackVlessFlow)
	if err := enrichTransportProfileWithEndpoint(&profile, inboundInfo, transportProtocol); err != nil {
		return transportprofile.Input{}, err
	}
	enrichTransportProfileWithXHTTPSettings(&profile, inboundInfo, transportProtocol)
	return profile, nil
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
	profile, err := deriveTransportProfileFromInbound(inboundInfo, c.VlessFlow)
	if err != nil {
		return nil, err
	}

	// Create GeneralNodeInfo
	// AlterID will be updated after next sync
	nodeInfo := &api.NodeInfo{
		NodeType: c.NodeType,
		NodeID:   c.NodeID,
		Port:     port,
		AlterID:  0,
	}
	transportprofile.Apply(nodeInfo, profile)
	return nodeInfo, nil
}
