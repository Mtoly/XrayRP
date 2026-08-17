package v2raysocks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bitly/go-simplejson"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"

	"github.com/Mtoly/XrayRP/api"
)

func (c *APIClient) GetNodeSnapshot() (*api.NodeSnapshot, error) {
	return c.GetNodeSnapshotContext(context.Background())
}

func (c *APIClient) GetNodeSnapshotContext(ctx context.Context) (*api.NodeSnapshot, error) {
	nodeType, err := c.snapshotNodeType()
	if err != nil {
		return nil, err
	}
	res, err := c.client.R().
		SetContext(ctx).
		SetHeader("If-None-Match", c.eTags.Get("config")).
		SetQueryParams(map[string]string{
			"act":       "config",
			"node_type": nodeType,
		}).
		ForceContentType("application/json").
		Get(c.APIHost)
	if err := c.httpPolicy.CheckResponse(res, "", err); err != nil {
		return nil, err
	}
	if res.StatusCode() == 304 {
		return nil, api.ErrNodeNotModified
	}
	candidateETag := res.Header().Get("Etag")
	response, err := c.parseResponse(res, "", err)
	if err != nil {
		return nil, err
	}

	var snapshot *api.NodeSnapshot
	switch strings.ToLower(c.NodeType) {
	case "v2ray", "vmess", "vless":
		snapshot, err = c.parseV2rayNodeSnapshotResponse(response)
	case "trojan":
		snapshot, err = c.parseTrojanNodeSnapshotResponse(response)
	case "shadowsocks":
		snapshot, err = c.parseSSNodeSnapshotResponse(response)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	if err != nil {
		// Keep the legacy public error prefix while exposing the wrapped cause.
		return nil, fmt.Errorf("parse node info failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.access.Lock()
	c.ConfigResp = response
	c.eTags.Publish("config", candidateETag)
	c.access.Unlock()
	return snapshot, nil
}

func (c *APIClient) snapshotNodeType() (string, error) {
	switch strings.ToLower(c.NodeType) {
	case "v2ray", "vmess", "vless":
		return "v2ray", nil
	case "trojan", "shadowsocks":
		return strings.ToLower(c.NodeType), nil
	default:
		return "", fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
}

func firstInboundSnapshot(response *simplejson.Json) (*simplejson.Json, error) {
	tmpInboundInfo := response.Get("inbounds").MustArray()
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
	return inboundInfo, nil
}

func (c *APIClient) parseTrojanNodeSnapshotResponse(response *simplejson.Json) (*api.NodeSnapshot, error) {
	inboundInfo, err := firstInboundSnapshot(response)
	if err != nil {
		return nil, err
	}
	return &api.NodeSnapshot{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(inboundInfo.Get("port").MustUint64()),
		TransportProtocol: "tcp",
		EnableTLS:         true,
		Host:              inboundInfo.Get("streamSettings").Get("tlsSettings").Get("serverName").MustString(),
	}, nil
}

func (c *APIClient) parseSSNodeSnapshotResponse(response *simplejson.Json) (*api.NodeSnapshot, error) {
	inboundInfo, err := firstInboundSnapshot(response)
	if err != nil {
		return nil, err
	}
	method := inboundInfo.Get("settings").Get("method").MustString()
	serverPsk := ""
	if C.Contains(shadowaead_2022.List, method) {
		serverPsk = inboundInfo.Get("settings").Get("password").MustString()
	}
	return &api.NodeSnapshot{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(inboundInfo.Get("port").MustUint64()),
		TransportProtocol: "tcp",
		CypherMethod:      method,
		ServerKey:         serverPsk,
	}, nil
}

func (c *APIClient) parseV2rayNodeSnapshotResponse(response *simplejson.Json) (*api.NodeSnapshot, error) {
	inboundInfo, err := firstInboundSnapshot(response)
	if err != nil {
		return nil, err
	}
	snapshot := &api.NodeSnapshot{
		NodeType: c.NodeType,
		NodeID:   c.NodeID,
		Port:     uint32(inboundInfo.Get("port").MustUint64()),
	}
	if err := enrichNodeSnapshotWithTransport(snapshot, inboundInfo, c.VlessFlow); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func enrichNodeSnapshotWithTransport(snapshot *api.NodeSnapshot, inboundInfo *simplejson.Json, fallbackVlessFlow string) error {
	if snapshot == nil || inboundInfo == nil {
		return nil
	}
	transportProtocol := inboundInfo.Get("streamSettings").Get("network").MustString()
	snapshot.TransportProtocol = transportProtocol
	enrichNodeSnapshotWithSecurity(snapshot, inboundInfo, fallbackVlessFlow)
	if err := enrichNodeSnapshotWithEndpoint(snapshot, inboundInfo, transportProtocol); err != nil {
		return err
	}
	return enrichNodeSnapshotWithXHTTPSettings(snapshot, inboundInfo, transportProtocol)
}

func enrichNodeSnapshotWithSecurity(snapshot *api.NodeSnapshot, inboundInfo *simplejson.Json, fallbackVlessFlow string) {
	security := inboundInfo.Get("streamSettings").Get("security").MustString()
	snapshot.EnableTLS = security == "tls"
	snapshot.EnableVless = inboundInfo.Get("protocol").MustString() == "vless"
	snapshot.EnableREALITY = security == "reality"
	snapshot.REALITYConfig = new(api.REALITYConfig)
	if snapshot.EnableVless {
		reality := inboundInfo.Get("streamSettings").Get("realitySettings")
		snapshot.REALITYConfig = &api.REALITYConfig{
			Dest:             reality.Get("dest").MustString(),
			ProxyProtocolVer: reality.Get("xver").MustUint64(),
			ServerNames:      reality.Get("serverNames").MustStringArray(),
			PrivateKey:       reality.Get("privateKey").MustString(),
			MinClientVer:     reality.Get("minClientVer").MustString(),
			MaxClientVer:     reality.Get("maxClientVer").MustString(),
			MaxTimeDiff:      reality.Get("maxTimeDiff").MustUint64(),
			ShortIds:         reality.Get("shortIds").MustStringArray(),
		}
	}
	if (snapshot.TransportProtocol == "grpc" || snapshot.TransportProtocol == "h2") && snapshot.EnableREALITY {
		snapshot.VlessFlow = ""
	} else if snapshot.TransportProtocol == "tcp" && snapshot.EnableREALITY {
		snapshot.VlessFlow = "xtls-rprx-vision"
	} else {
		snapshot.VlessFlow = fallbackVlessFlow
	}
}

func enrichNodeSnapshotWithEndpoint(snapshot *api.NodeSnapshot, inboundInfo *simplejson.Json, transportProtocol string) error {
	streamSettings := inboundInfo.Get("streamSettings")
	switch transportProtocol {
	case "ws":
		snapshot.Path = streamSettings.Get("wsSettings").Get("path").MustString()
		snapshot.Host = streamSettings.Get("wsSettings").Get("headers").Get("Host").MustString()
	case "httpupgrade":
		settings := streamSettings.Get("httpupgradeSettings")
		snapshot.Host = settings.Get("Host").MustString()
		snapshot.Path = settings.Get("path").MustString()
		headers, err := decodeOptionalTransportHeaders(settings)
		if err != nil {
			return err
		}
		snapshot.Headers = headers
	case "splithttp":
		settings := streamSettings.Get("splithttpSettings")
		snapshot.Host = settings.Get("Host").MustString()
		snapshot.Path = settings.Get("path").MustString()
		headers, err := decodeOptionalTransportHeaders(settings)
		if err != nil {
			return err
		}
		snapshot.Headers = headers
	case "xhttp":
		xhttpSettings := streamSettings.Get("xhttpSettings")
		splitHTTPSettings := streamSettings.Get("splithttpSettings")
		snapshot.Host = xhttpSettings.Get("Host").MustString()
		if snapshot.Host == "" {
			snapshot.Host = splitHTTPSettings.Get("Host").MustString()
		}
		snapshot.Path = xhttpSettings.Get("path").MustString()
		if snapshot.Path == "" {
			snapshot.Path = splitHTTPSettings.Get("path").MustString()
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
		snapshot.Headers = headers
	case "grpc":
		if data, ok := streamSettings.Get("grpcSettings").CheckGet("serviceName"); ok {
			snapshot.ServiceName = data.MustString()
		}
	case "tcp":
		if data, ok := streamSettings.Get("tcpSettings").CheckGet("header"); ok {
			header, err := data.MarshalJSON()
			if err != nil {
				return err
			}
			snapshot.Header = header
		}
	}
	return nil
}

func enrichNodeSnapshotWithXHTTPSettings(snapshot *api.NodeSnapshot, inboundInfo *simplejson.Json, transportProtocol string) error {
	if transportProtocol != "splithttp" && transportProtocol != "xhttp" {
		return nil
	}
	settingsKey := "splithttpSettings"
	if transportProtocol == "xhttp" {
		if _, ok := inboundInfo.Get("streamSettings").CheckGet("xhttpSettings"); ok {
			settingsKey = "xhttpSettings"
		}
	}
	settings := inboundInfo.Get("streamSettings").Get(settingsKey)
	paddingBytes, err := decodeOptionalXPaddingBytes(settings)
	if err != nil {
		return err
	}
	uplinkChunkSize, err := decodeOptionalUplinkChunkSize(settings)
	if err != nil {
		return err
	}
	snapshot.XHTTPMode = settings.Get("mode").MustString()
	snapshot.XPaddingBytes = paddingBytes
	snapshot.XPaddingObfsMode = settings.Get("xPaddingObfsMode").MustBool()
	snapshot.XPaddingKey = settings.Get("xPaddingKey").MustString()
	snapshot.XPaddingHeader = settings.Get("xPaddingHeader").MustString()
	snapshot.XPaddingPlacement = settings.Get("xPaddingPlacement").MustString()
	snapshot.XPaddingMethod = settings.Get("xPaddingMethod").MustString()
	snapshot.UplinkHTTPMethod = settings.Get("uplinkHTTPMethod").MustString()
	snapshot.SessionPlacement = settings.Get("sessionPlacement").MustString()
	snapshot.SessionKey = settings.Get("sessionKey").MustString()
	snapshot.SeqPlacement = settings.Get("seqPlacement").MustString()
	snapshot.SeqKey = settings.Get("seqKey").MustString()
	snapshot.UplinkDataPlacement = settings.Get("uplinkDataPlacement").MustString()
	snapshot.UplinkDataKey = settings.Get("uplinkDataKey").MustString()
	snapshot.UplinkChunkSize = uplinkChunkSize
	snapshot.NoGRPCHeader = settings.Get("noGRPCHeader").MustBool()
	snapshot.NoSSEHeader = settings.Get("noSSEHeader").MustBool()
	if extra := settings.Get("extra"); extra.Interface() != nil {
		if extraBytes, err := extra.MarshalJSON(); err == nil {
			snapshot.XHTTPExtra = extraBytes
		}
	}
	return nil
}
