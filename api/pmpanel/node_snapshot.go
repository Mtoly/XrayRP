package pmpanel

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

func (c *APIClient) fetchNodeResponseContext(ctx context.Context) (*NodeInfoResponse, error) {
	path := "/api/node"
	nodeType := ""
	switch c.NodeType {
	case "Shadowsocks":
		nodeType = "ss"
	case "V2ray":
		nodeType = "v2ray"
	case "Trojan":
		nodeType = "trojan"
	default:
		return nil, fmt.Errorf("NodeType Error: %s", c.NodeType)
	}

	res, err := c.client.R().
		SetContext(ctx).
		SetQueryParams(map[string]string{
			"type":   nodeType,
			"nodeId": fmt.Sprint(c.NodeID),
		}).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)
	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	nodeInfoResponse := new(NodeInfoResponse)
	if err := json.Unmarshal(response.Data, nodeInfoResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(nodeInfoResponse), err)
	}
	return nodeInfoResponse, nil
}

func (c *APIClient) parseNodeSnapshotResponse(nodeInfoResponse *NodeInfoResponse) (*api.NodeSnapshot, error) {
	switch c.NodeType {
	case "V2ray":
		return c.parseV2rayNodeSnapshotResponse(nodeInfoResponse)
	case "Trojan":
		return c.parseTrojanNodeSnapshotResponse(nodeInfoResponse)
	case "Shadowsocks":
		return c.parseSSNodeSnapshotResponse(nodeInfoResponse)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
}

func (c *APIClient) parseV2rayNodeSnapshotResponse(nodeInfoResponse *NodeInfoResponse) (*api.NodeSnapshot, error) {
	var enableTLS bool
	var path, host, transportProtocol, serviceName string
	transportProtocol = nodeInfoResponse.Network
	switch transportProtocol {
	case "ws":
		host = nodeInfoResponse.Host
		path = nodeInfoResponse.Path
	case "grpc":
		serviceName = nodeInfoResponse.Sni
	case "tcp":
	case "splithttp", "xhttp", "httpupgrade":
		host = nodeInfoResponse.Host
		path = nodeInfoResponse.Path
	}
	enableTLS = nodeInfoResponse.Security == "tls"

	return &api.NodeSnapshot{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              nodeInfoResponse.Port,
		SpeedLimit:        c.speedLimit(nodeInfoResponse.SpeedLimit),
		AlterID:           nodeInfoResponse.AlterId,
		TransportProtocol: transportProtocol,
		EnableTLS:         enableTLS,
		Path:              path,
		Host:              host,
		EnableVless:       c.EnableVless,
		VlessFlow:         c.VlessFlow,
		ServiceName:       serviceName,
	}, nil
}

func (c *APIClient) parseSSNodeSnapshotResponse(nodeInfoResponse *NodeInfoResponse) (*api.NodeSnapshot, error) {
	return &api.NodeSnapshot{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              nodeInfoResponse.Port,
		SpeedLimit:        c.speedLimit(nodeInfoResponse.SpeedLimit),
		TransportProtocol: "tcp",
		CypherMethod:      nodeInfoResponse.Method,
	}, nil
}

func (c *APIClient) parseTrojanNodeSnapshotResponse(nodeInfoResponse *NodeInfoResponse) (*api.NodeSnapshot, error) {
	transportProtocol := "tcp"
	if nodeInfoResponse.Grpc {
		transportProtocol = "grpc"
	}
	return &api.NodeSnapshot{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              nodeInfoResponse.Port,
		SpeedLimit:        c.speedLimit(nodeInfoResponse.SpeedLimit),
		TransportProtocol: transportProtocol,
		EnableTLS:         true,
		Host:              nodeInfoResponse.Host,
		ServiceName:       nodeInfoResponse.Sni,
	}, nil
}

func (c *APIClient) speedLimit(panelSpeedLimit float64) uint64 {
	if c.SpeedLimit > 0 {
		return uint64((c.SpeedLimit * 1000000) / 8)
	}
	return uint64((panelSpeedLimit * 1000000) / 8)
}
