package proxypanel

import (
	"context"
	"encoding/json"
	"fmt"
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
	response, err := c.fetchNodeResponseContext(ctx)
	if err != nil {
		return nil, err
	}

	snapshot, err = c.parseNodeSnapshotResponse(response)
	if err != nil {
		return nil, panelhttp.NodeInfoParseError(err)
	}
	return snapshot, nil
}

func (c *APIClient) fetchNodeResponseContext(ctx context.Context) (*json.RawMessage, error) {
	path := ""
	switch c.NodeType {
	case "V2ray", "Vmess", "Vless":
		path = fmt.Sprintf("/api/v2ray/v1/node/%d", c.NodeID)
	case "Trojan":
		path = fmt.Sprintf("/api/trojan/v1/node/%d", c.NodeID)
	case "Shadowsocks":
		path = fmt.Sprintf("/api/ss/v1/node/%d", c.NodeID)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}

	res, err := c.createCommonRequestContext(ctx).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)
	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	return &response.Data, nil
}

func (c *APIClient) parseNodeSnapshotResponse(nodeInfoResponse *json.RawMessage) (*api.NodeSnapshot, error) {
	switch c.NodeType {
	case "V2ray", "Vmess", "Vless":
		return c.parseV2rayNodeSnapshotResponse(nodeInfoResponse)
	case "Trojan":
		return c.parseTrojanNodeSnapshotResponse(nodeInfoResponse)
	case "Shadowsocks":
		return c.parseSSNodeSnapshotResponse(nodeInfoResponse)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
}

func (c *APIClient) parseV2rayNodeSnapshotResponse(nodeInfoResponse *json.RawMessage) (*api.NodeSnapshot, error) {
	v2rayNodeInfo := new(V2rayNodeInfo)
	if err := json.Unmarshal(*nodeInfoResponse, v2rayNodeInfo); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(*nodeInfoResponse), err)
	}
	if c.DeviceLimit == 0 && v2rayNodeInfo.ClientLimit > 0 {
		c.DeviceLimit = v2rayNodeInfo.ClientLimit
	}
	return &api.NodeSnapshot{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              v2rayNodeInfo.V2Port,
		SpeedLimit:        c.speedLimit(v2rayNodeInfo.SpeedLimit),
		AlterID:           v2rayNodeInfo.V2AlterID,
		TransportProtocol: v2rayNodeInfo.V2Net,
		FakeType:          v2rayNodeInfo.V2Type,
		EnableTLS:         v2rayNodeInfo.V2TLS,
		Path:              v2rayNodeInfo.V2Path,
		Host:              v2rayNodeInfo.V2Host,
		EnableVless:       c.EnableVless,
		VlessFlow:         c.VlessFlow,
	}, nil
}

func (c *APIClient) parseSSNodeSnapshotResponse(nodeInfoResponse *json.RawMessage) (*api.NodeSnapshot, error) {
	shadowsocksNodeInfo := new(ShadowsocksNodeInfo)
	if err := json.Unmarshal(*nodeInfoResponse, shadowsocksNodeInfo); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(*nodeInfoResponse), err)
	}
	if c.DeviceLimit == 0 && shadowsocksNodeInfo.ClientLimit > 0 {
		c.DeviceLimit = shadowsocksNodeInfo.ClientLimit
	}
	return &api.NodeSnapshot{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              shadowsocksNodeInfo.Port,
		SpeedLimit:        c.speedLimit(shadowsocksNodeInfo.SpeedLimit),
		TransportProtocol: "tcp",
		CypherMethod:      shadowsocksNodeInfo.Method,
	}, nil
}

func (c *APIClient) parseTrojanNodeSnapshotResponse(nodeInfoResponse *json.RawMessage) (*api.NodeSnapshot, error) {
	trojanNodeInfo := new(TrojanNodeInfo)
	if err := json.Unmarshal(*nodeInfoResponse, trojanNodeInfo); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(*nodeInfoResponse), err)
	}
	if c.DeviceLimit == 0 && trojanNodeInfo.ClientLimit > 0 {
		c.DeviceLimit = trojanNodeInfo.ClientLimit
	}
	return &api.NodeSnapshot{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              trojanNodeInfo.TrojanPort,
		SpeedLimit:        c.speedLimit(trojanNodeInfo.SpeedLimit),
		TransportProtocol: "tcp",
		EnableTLS:         true,
	}, nil
}

func (c *APIClient) speedLimit(panelSpeedLimit uint64) uint64 {
	if c.SpeedLimit > 0 {
		return uint64((c.SpeedLimit * 1000000) / 8)
	}
	return panelSpeedLimit * 1000000 / 8
}
