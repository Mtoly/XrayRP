package bunpanel

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/internal/panelhttp"
)

func (c *APIClient) GetNodeSnapshot() (*api.NodeSnapshot, error) {
	return c.GetNodeSnapshotContext(context.Background())
}

func (c *APIClient) GetNodeSnapshotContext(ctx context.Context) (*api.NodeSnapshot, error) {
	return c.getNodeSnapshotContext(ctx)
}

func (c *APIClient) getNodeSnapshotContext(ctx context.Context) (snapshot *api.NodeSnapshot, err error) {
	server, candidateETag, err := c.fetchNodeResponseContext(ctx)
	if err != nil {
		return nil, err
	}

	snapshot, err = c.parseNodeSnapshotResponse(server)
	if err != nil {
		return nil, panelhttp.NodeInfoParseError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.eTags.Publish("node", candidateETag)
	return snapshot, nil
}

func (c *APIClient) fetchNodeResponseContext(ctx context.Context) (*Server, string, error) {
	path := fmt.Sprintf("/v2/server/%d/get", c.NodeID)
	res, err := c.client.R().
		SetContext(ctx).
		SetResult(&Response{}).
		SetHeader("If-None-Match", c.eTags.Get("node")).
		ForceContentType("application/json").
		Get(path)
	if err := c.httpPolicy.CheckResponse(res, path, err); err != nil {
		return nil, "", err
	}
	if res.StatusCode() == 304 {
		return nil, "", api.ErrNodeNotModified
	}
	candidateETag := res.Header().Get("ETag")

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, "", err
	}
	nodeInfoResponse := new(Server)
	if err := json.Unmarshal(response.Datas, nodeInfoResponse); err != nil {
		return nil, "", fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(nodeInfoResponse), err)
	}
	return nodeInfoResponse, candidateETag, nil
}

func (c *APIClient) parseNodeSnapshotResponse(nodeInfoResponse *Server) (*api.NodeSnapshot, error) {
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

	return &api.NodeSnapshot{
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
	}, nil
}
