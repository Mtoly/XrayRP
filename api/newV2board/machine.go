package newV2board

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/go-resty/resty/v2"
)

const (
	machineNodesPath  = "/api/v2/server/machine/nodes"
	machineStatusPath = "/api/v2/server/machine/status"
)

type MachineNode struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type MachineNodesResponse struct {
	Nodes      []MachineNode  `json:"nodes"`
	BaseConfig api.BaseConfig `json:"base_config"`
}

type MachineDiscoveryConfig struct {
	APIHost   string
	MachineID int
	Token     string
	Timeout   time.Duration
}

type machineAuthRequest struct {
	MachineID int    `json:"machine_id"`
	Token     string `json:"token"`
}

type machineStatusPayload struct {
	MachineID int                        `json:"machine_id"`
	Token     string                     `json:"token"`
	CPU       float64                    `json:"cpu"`
	Mem       machineStatusResource      `json:"mem"`
	Swap      machineStatusResource      `json:"swap,omitempty"`
	Disk      machineStatusResource      `json:"disk,omitempty"`
	Net       *machineStatusNetworkSpeed `json:"net,omitempty"`
}

type machineStatusResource struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type machineStatusNetworkSpeed struct {
	InSpeed  float64 `json:"in_speed"`
	OutSpeed float64 `json:"out_speed"`
}

type machineNodesWireResponse struct {
	Nodes      json.RawMessage `json:"nodes"`
	BaseConfig api.BaseConfig  `json:"base_config"`
}

func validateMachineConfig(config MachineDiscoveryConfig) (string, string, error) {
	apiHost := strings.TrimSpace(config.APIHost)
	if apiHost == "" {
		return "", "", fmt.Errorf("APIHost must not be empty")
	}
	if config.MachineID <= 0 {
		return "", "", fmt.Errorf("MachineID must be greater than 0")
	}
	token := strings.TrimSpace(config.Token)
	if token == "" {
		return "", "", fmt.Errorf("Token must not be empty")
	}
	return apiHost, token, nil
}

func newMachineClient(apiHost string, timeout time.Duration) *resty.Client {
	client := resty.New().SetBaseURL(apiHost)
	if timeout > 0 {
		client.SetTimeout(timeout)
	}
	return client
}

func normalizeMachineNode(node MachineNode) MachineNode {
	node.Type = canonicalNodeType(node.Type)
	return node
}

func normalizeMachineNodes(nodes []MachineNode) []MachineNode {
	if len(nodes) == 0 {
		return nodes
	}
	for i := range nodes {
		nodes[i] = normalizeMachineNode(nodes[i])
	}
	return nodes
}

func DiscoverMachineNodes(config MachineDiscoveryConfig) (*MachineNodesResponse, error) {
	apiHost, token, err := validateMachineConfig(config)
	if err != nil {
		return nil, err
	}

	client := newMachineClient(apiHost, config.Timeout)

	res, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(machineAuthRequest{
			MachineID: config.MachineID,
			Token:     token,
		}).
		Post(machineNodesPath)
	if err != nil {
		return nil, fmt.Errorf("discover machine nodes request failed: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("discover machine nodes request failed: empty response")
	}
	if statusCode := res.StatusCode(); statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("discover machine nodes request failed: status %d", statusCode)
	}

	var payload machineNodesWireResponse
	if err := json.Unmarshal(res.Body(), &payload); err != nil {
		return nil, fmt.Errorf("discover machine nodes returned invalid JSON: %w", err)
	}

	nodesRaw := bytes.TrimSpace(payload.Nodes)
	if len(nodesRaw) == 0 || nodesRaw[0] != '[' {
		return nil, fmt.Errorf("malformed response: nodes must be an array")
	}

	var nodes []MachineNode
	if err := json.Unmarshal(nodesRaw, &nodes); err != nil {
		return nil, fmt.Errorf("malformed response: nodes must be an array: %w", err)
	}
	nodes = normalizeMachineNodes(nodes)

	return &MachineNodesResponse{
		Nodes:      nodes,
		BaseConfig: payload.BaseConfig,
	}, nil
}

func ReportMachineStatus(config MachineDiscoveryConfig, status api.MachineStatus) error {
	apiHost, token, err := validateMachineConfig(config)
	if err != nil {
		return err
	}

	payload := machineStatusPayload{
		MachineID: config.MachineID,
		Token:     token,
		CPU:       status.CPU,
		Mem: machineStatusResource{
			Total: status.MemTotal,
			Used:  status.MemUsed,
		},
		Swap: machineStatusResource{
			Total: status.SwapTotal,
			Used:  status.SwapUsed,
		},
		Disk: machineStatusResource{
			Total: status.DiskTotal,
			Used:  status.DiskUsed,
		},
	}
	if status.NetInSpeed >= 0 && status.NetOutSpeed >= 0 {
		payload.Net = &machineStatusNetworkSpeed{
			InSpeed:  status.NetInSpeed,
			OutSpeed: status.NetOutSpeed,
		}
	}

	res, err := newMachineClient(apiHost, config.Timeout).R().
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(machineStatusPath)
	if err != nil {
		return fmt.Errorf("report machine status request failed: %w", err)
	}
	if res == nil {
		return fmt.Errorf("report machine status request failed: empty response")
	}
	if statusCode := res.StatusCode(); statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("report machine status request failed: status %d", statusCode)
	}
	return nil
}
