package sspanel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/internal/panelhttp"
)

func (c *APIClient) GetNodeSnapshot() (*api.NodeSnapshot, error) {
	return c.GetNodeSnapshotContext(context.Background())
}

func (c *APIClient) GetNodeSnapshotContext(ctx context.Context) (*api.NodeSnapshot, error) {
	path := fmt.Sprintf("/mod_mu/nodes/%d/info", c.NodeID)
	res, err := c.client.R().
		SetContext(ctx).
		SetResult(&Response{}).
		SetHeader("If-None-Match", c.eTags.Get("node")).
		ForceContentType("application/json").
		Get(path)
	if err := c.httpPolicy.CheckResponse(res, path, err); err != nil {
		return nil, err
	}
	if res.StatusCode() == 304 {
		return nil, api.ErrNodeNotModified
	}
	candidateETag := res.Header().Get("ETag")

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	nodeInfoResponse := new(NodeInfoResponse)
	if err := json.Unmarshal(response.Data, nodeInfoResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(nodeInfoResponse), err)
	}

	snapshot, err := c.parseNodeSnapshotResponse(ctx, nodeInfoResponse)
	if err != nil {
		return nil, panelhttp.NodeInfoParseError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.version = nodeInfoResponse.Version
	c.eTags.Publish("node", candidateETag)
	return snapshot, nil
}

func (c *APIClient) parseNodeSnapshotResponse(ctx context.Context, response *NodeInfoResponse) (*api.NodeSnapshot, error) {
	isExpired := compareVersion(response.Version, "2021.11") == -1
	if c.DisableCustomConfig || isExpired {
		if isExpired {
			logExpiredPanelVersion()
		}
		switch c.NodeType {
		case "V2ray":
			return c.parseV2rayNodeSnapshotResponse(response)
		case "Trojan":
			return c.parseTrojanNodeSnapshotResponse(response)
		case "Shadowsocks":
			return c.parseSSNodeSnapshotResponseContext(ctx, response)
		case "Shadowsocks-Plugin":
			return c.parseSSPluginNodeSnapshotResponse(response)
		default:
			return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
		}
	}
	return c.parseSSPanelNodeSnapshotInfo(response)
}

func (c *APIClient) parseV2rayNodeSnapshotResponse(response *NodeInfoResponse) (*api.NodeSnapshot, error) {
	if response.RawServerString == "" {
		return nil, errors.New("no server info in response")
	}
	serverConf := strings.Split(response.RawServerString, ";")
	if len(serverConf) < 6 {
		return nil, errors.New("invalid server info in response")
	}
	parsedPort, err := strconv.ParseInt(serverConf[1], 10, 32)
	if err != nil {
		return nil, err
	}
	if parsedPort < 1 || parsedPort > 65535 {
		return nil, fmt.Errorf("invalid port %d: must be between 1 and 65535", parsedPort)
	}
	parsedAlterID, err := strconv.ParseInt(serverConf[2], 10, 16)
	if err != nil {
		return nil, err
	}

	enableTLS := false
	transportProtocol := ""
	for _, value := range serverConf[3:5] {
		switch value {
		case "tls":
			enableTLS = true
		default:
			if value != "" {
				transportProtocol = value
			}
		}
	}
	host, path, serviceName, headerType := "", "", "", ""
	for _, item := range strings.Split(serverConf[5], "|") {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		switch parts[0] {
		case "path":
			path = parts[1]
		case "host":
			host = parts[1]
		case "servicename":
			serviceName = parts[1]
		case "headerType":
			headerType = parts[1]
		}
	}
	var header json.RawMessage
	if headerType != "" {
		header, err = json.Marshal(map[string]string{"type": headerType})
		if err != nil {
			return nil, fmt.Errorf("marshal Header Type %s into config failed: %w", headerType, err)
		}
	}
	return &api.NodeSnapshot{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(parsedPort),
		SpeedLimit:        c.speedLimit(response.SpeedLimit),
		AlterID:           uint16(parsedAlterID),
		TransportProtocol: transportProtocol,
		EnableTLS:         enableTLS,
		Path:              path,
		Host:              host,
		EnableVless:       c.EnableVless,
		VlessFlow:         c.VlessFlow,
		ServiceName:       serviceName,
		Header:            header,
	}, nil
}

func (c *APIClient) parseSSNodeSnapshotResponseContext(ctx context.Context, response *NodeInfoResponse) (*api.NodeSnapshot, error) {
	path := "/mod_mu/users"
	res, err := c.client.R().
		SetContext(ctx).
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)
	result, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	users := new([]UserResponse)
	if err := json.Unmarshal(result.Data, users); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(users), err)
	}
	var port uint32
	if len(*users) > 0 {
		port = (*users)[0].Port
	}
	return &api.NodeSnapshot{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		SpeedLimit:        c.speedLimit(response.SpeedLimit),
		TransportProtocol: "tcp",
	}, nil
}

func (c *APIClient) parseSSPluginNodeSnapshotResponse(response *NodeInfoResponse) (*api.NodeSnapshot, error) {
	serverConf := strings.Split(response.RawServerString, ";")
	if len(serverConf) < 6 {
		return nil, errors.New("invalid server info in response")
	}
	parsedPort, err := strconv.ParseInt(serverConf[1], 10, 32)
	if err != nil {
		return nil, err
	}
	port := parsedPort - 1
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("Shadowsocks-Plugin listen port must bigger than 1")
	}
	enableTLS, transportProtocol := false, ""
	for _, value := range serverConf[3:5] {
		switch value {
		case "tls":
			enableTLS = true
		case "ws":
			transportProtocol = "ws"
		case "obfs":
			transportProtocol = "tcp"
		}
	}
	host, path := "", ""
	for _, item := range strings.Split(serverConf[5], "|") {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		switch parts[0] {
		case "path":
			path = parts[1]
		case "host":
			host = parts[1]
		}
	}
	return &api.NodeSnapshot{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(port),
		SpeedLimit:        c.speedLimit(response.SpeedLimit),
		TransportProtocol: transportProtocol,
		EnableTLS:         enableTLS,
		Path:              path,
		Host:              host,
	}, nil
}

func (c *APIClient) parseTrojanNodeSnapshotResponse(response *NodeInfoResponse) (*api.NodeSnapshot, error) {
	if response.RawServerString == "" {
		return nil, errors.New("no server info in response")
	}
	outsidePort, insidePort, host := "", "", ""
	if result := firstPortRe.FindStringSubmatch(response.RawServerString); len(result) > 1 {
		outsidePort = result[1]
	}
	if result := secondPortRe.FindStringSubmatch(response.RawServerString); len(result) > 1 {
		insidePort = result[1]
	}
	if result := hostRe.FindStringSubmatch(response.RawServerString); len(result) > 1 {
		host = result[1]
	}
	portText := outsidePort
	if insidePort != "" {
		portText = insidePort
	}
	parsedPort, err := strconv.ParseInt(portText, 10, 32)
	if err != nil {
		return nil, err
	}
	if parsedPort < 1 || parsedPort > 65535 {
		return nil, fmt.Errorf("invalid port %d: must be between 1 and 65535", parsedPort)
	}
	serverConf := strings.Split(response.RawServerString, ";")
	if len(serverConf) < 2 {
		return nil, errors.New("invalid server info in response")
	}
	transportProtocol, serviceName := "tcp", ""
	for _, item := range strings.Split(serverConf[1], "|") {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		switch parts[0] {
		case "grpc":
			transportProtocol = "grpc"
		case "servicename":
			serviceName = parts[1]
		}
	}
	return &api.NodeSnapshot{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(parsedPort),
		SpeedLimit:        c.speedLimit(response.SpeedLimit),
		TransportProtocol: transportProtocol,
		EnableTLS:         true,
		Host:              host,
		ServiceName:       serviceName,
	}, nil
}

func (c *APIClient) parseSSPanelNodeSnapshotInfo(response *NodeInfoResponse) (*api.NodeSnapshot, error) {
	if len(response.CustomConfig) == 0 {
		return nil, errors.New("custom_config is empty, disable custom config")
	}
	nodeConfig := new(CustomConfig)
	if err := json.Unmarshal(response.CustomConfig, nodeConfig); err != nil {
		return nil, fmt.Errorf("custom_config format error: %v", err)
	}
	parsedPort, err := strconv.ParseInt(nodeConfig.OffsetPortNode, 10, 32)
	if err != nil {
		return nil, err
	}
	if parsedPort < 1 || parsedPort > 65535 {
		return nil, fmt.Errorf("invalid port %d: must be between 1 and 65535", parsedPort)
	}
	transportProtocol := nodeConfig.Network
	enableTLS, enableVless, enableREALITY := false, false, false
	switch c.NodeType {
	case "Shadowsocks":
		transportProtocol = "tcp"
	case "V2ray":
		tlsType := strings.ToLower(nodeConfig.Security)
		enableTLS = tlsType == "tls" || tlsType == "xtls"
		if tlsType == "reality" || nodeConfig.EnableREALITY {
			enableREALITY = true
			enableVless = true
		}
		if nodeConfig.EnableVless == "1" || strings.EqualFold(nodeConfig.EnableVless, "true") {
			enableVless = true
		}
	case "Trojan":
		enableTLS = true
		if transportProtocol == "" {
			transportProtocol = "tcp"
		}
	}
	if transportProtocol == "" {
		transportProtocol = "tcp"
	}
	realityConfig := new(api.REALITYConfig)
	if nodeConfig.RealityOpts != nil {
		reality := nodeConfig.RealityOpts
		proxyVer := reality.ProxyProtocolVer
		if proxyVer == 0 {
			proxyVer = nodeConfig.ProxyProtocolVer
		}
		realityConfig = &api.REALITYConfig{
			Dest:             reality.Dest,
			ProxyProtocolVer: proxyVer,
			ServerNames:      reality.ServerNames,
			PrivateKey:       reality.PrivateKey,
			MinClientVer:     reality.MinClientVer,
			MaxClientVer:     reality.MaxClientVer,
			MaxTimeDiff:      reality.MaxTimeDiff,
			ShortIds:         reality.ShortIds,
		}
	}
	sni := nodeConfig.Sni
	if sni == "" {
		sni = nodeConfig.ServerName
		if sni == "" {
			sni = nodeConfig.Host
		}
	}
	return &api.NodeSnapshot{
		NodeType:            c.NodeType,
		NodeID:              c.NodeID,
		Port:                uint32(parsedPort),
		SpeedLimit:          c.speedLimit(response.SpeedLimit),
		TransportProtocol:   transportProtocol,
		Host:                nodeConfig.Host,
		SNI:                 sni,
		Path:                nodeConfig.Path,
		EnableTLS:           enableTLS,
		EnableVless:         enableVless,
		VlessFlow:           nodeConfig.Flow,
		CypherMethod:        nodeConfig.Method,
		ServerKey:           nodeConfig.ServerKey,
		ServiceName:         nodeConfig.Servicename,
		Header:              nodeConfig.Header,
		EnableREALITY:       enableREALITY,
		REALITYConfig:       realityConfig,
		AcceptProxyProtocol: nodeConfig.EnableProxyProtocol,
		ProxyProtocolVer:    nodeConfig.ProxyProtocolVer,
		XHTTPMode:           nodeConfig.XHTTPMode,
		XHTTPExtra:          nodeConfig.XHTTPExtra,
		XPaddingBytes:       nodeConfig.XPaddingBytes,
		XPaddingObfsMode:    nodeConfig.XPaddingObfsMode,
		XPaddingKey:         nodeConfig.XPaddingKey,
		XPaddingHeader:      nodeConfig.XPaddingHeader,
		XPaddingPlacement:   nodeConfig.XPaddingPlacement,
		XPaddingMethod:      nodeConfig.XPaddingMethod,
		UplinkHTTPMethod:    nodeConfig.UplinkHTTPMethod,
		SessionPlacement:    nodeConfig.SessionPlacement,
		SessionKey:          nodeConfig.SessionKey,
		SeqPlacement:        nodeConfig.SeqPlacement,
		SeqKey:              nodeConfig.SeqKey,
		UplinkDataPlacement: nodeConfig.UplinkDataPlacement,
		UplinkDataKey:       nodeConfig.UplinkDataKey,
		UplinkChunkSize:     nodeConfig.UplinkChunkSize,
		NoGRPCHeader:        nodeConfig.NoGRPCHeader,
		NoSSEHeader:         nodeConfig.NoSSEHeader,
	}, nil
}

func (c *APIClient) speedLimit(panelSpeedLimit float64) uint64 {
	if c.SpeedLimit > 0 {
		return uint64((c.SpeedLimit * 1000000) / 8)
	}
	return uint64((panelSpeedLimit * 1000000) / 8)
}

func logExpiredPanelVersion() {
	log.Print("The panel version is expired, it is recommended to update immediately")
}
