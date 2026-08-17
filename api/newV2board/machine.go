package newV2board

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/internal/panelhttp"
	"github.com/go-resty/resty/v2"
)

const (
	machineNodesPath  = "/api/v2/server/machine/nodes"
	machineStatusPath = "/api/v2/server/machine/status"
)

// MachineNode and MachineNodesResponse remain aliases for source compatibility
// while the shared machine seam uses the neutral api package types.
type MachineNode = api.MachineNode
type MachineNodesResponse = api.MachineNodesResponse

type MachineDiscoveryConfig struct {
	APIHost   string
	MachineID int
	Token     string
	Timeout   time.Duration
}

var _ interface {
	DiscoverMachineNodes() (*api.MachineNodesResponse, error)
	ReportMachineStatus(api.MachineStatus) error
} = (*APIClient)(nil)

func (c *APIClient) machineDiscoveryConfig() MachineDiscoveryConfig {
	if c == nil {
		return MachineDiscoveryConfig{}
	}
	return MachineDiscoveryConfig{
		APIHost:   c.APIHost,
		MachineID: c.MachineID,
		Token:     c.Key,
		Timeout:   c.timeout,
	}
}

// DiscoverMachineNodes exposes NewV2board's machine discovery through the
// machine adapter capability used by the machine supervisor.
func (c *APIClient) DiscoverMachineNodes() (*api.MachineNodesResponse, error) {
	return DiscoverMachineNodes(c.machineDiscoveryConfig())
}

// DiscoverMachineNodesContext is the context-aware machine discovery seam.
func (c *APIClient) DiscoverMachineNodesContext(ctx context.Context) (*api.MachineNodesResponse, error) {
	return DiscoverMachineNodesContext(ctx, c.machineDiscoveryConfig())
}

// ReportMachineStatus exposes NewV2board's machine status endpoint through the
// machine adapter capability used by the machine supervisor.
func (c *APIClient) ReportMachineStatus(status api.MachineStatus) error {
	return ReportMachineStatus(c.machineDiscoveryConfig(), status)
}

// ReportMachineStatusContext is the context-aware machine status seam.
func (c *APIClient) ReportMachineStatusContext(ctx context.Context, status api.MachineStatus) error {
	return ReportMachineStatusContext(ctx, c.machineDiscoveryConfig(), status)
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

func newMachineClient(apiHost string, timeout time.Duration, credentials ...string) (*resty.Client, panelhttp.Policy) {
	client, policy := panelhttp.NewClient(panelhttp.ClientConfig{
		BaseURL:     apiHost,
		Credentials: credentials,
	})
	client.SetRetryCount(0)
	client.SetTimeout(timeout)
	return client, policy
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
	return DiscoverMachineNodesContext(context.Background(), config)
}

func DiscoverMachineNodesContext(ctx context.Context, config MachineDiscoveryConfig) (*MachineNodesResponse, error) {
	apiHost, token, err := validateMachineConfig(config)
	if err != nil {
		return nil, err
	}

	client, policy := newMachineClient(apiHost, config.Timeout, token)

	res, err := client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(machineAuthRequest{
			MachineID: config.MachineID,
			Token:     token,
		}).
		Post(machineNodesPath)
	if err := policy.CheckResponse(res, machineNodesPath, err); err != nil {
		return nil, fmt.Errorf("discover machine nodes request failed: %w", err)
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

type machineStatusReport struct {
	APIHost string
	Timeout time.Duration
	Payload machineStatusPayload
}

func materializeMachineStatusReport(config MachineDiscoveryConfig, status api.MachineStatus) (machineStatusReport, error) {
	apiHost, token, err := validateMachineConfig(config)
	if err != nil {
		return machineStatusReport{}, err
	}
	return machineStatusReport{
		APIHost: apiHost,
		Timeout: config.Timeout,
		Payload: materializeMachineStatusPayload(config.MachineID, token, status),
	}, nil
}

func materializeMachineStatusPayload(machineID int, token string, status api.MachineStatus) machineStatusPayload {
	payload := machineStatusPayload{
		MachineID: machineID,
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
	return payload
}

func ReportMachineStatus(config MachineDiscoveryConfig, status api.MachineStatus) error {
	return ReportMachineStatusContext(context.Background(), config, status)
}

func ReportMachineStatusContext(ctx context.Context, config MachineDiscoveryConfig, status api.MachineStatus) error {
	report, err := materializeMachineStatusReport(config, status)
	if err != nil {
		return err
	}

	client, policy := newMachineClient(report.APIHost, report.Timeout, report.Payload.Token)
	res, err := client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(report.Payload).
		Post(machineStatusPath)
	if err := policy.CheckResponse(res, machineStatusPath, err); err != nil {
		return fmt.Errorf("report machine status request failed: %w", err)
	}
	if statusCode := res.StatusCode(); statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("report machine status request failed: status %d", statusCode)
	}
	return nil
}
