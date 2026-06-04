package newV2board

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

const machineNodesPath = "/api/v2/server/machine/nodes"

type MachineNode struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type MachineBaseConfig struct {
	PushInterval int `json:"push_interval"`
	PullInterval int `json:"pull_interval"`
}

type MachineNodesResponse struct {
	Nodes      []MachineNode     `json:"nodes"`
	BaseConfig MachineBaseConfig `json:"base_config"`
}

type MachineDiscoveryConfig struct {
	APIHost   string
	MachineID int
	Token     string
	Timeout   time.Duration
}

type machineNodesRequest struct {
	MachineID int    `json:"machine_id"`
	Token     string `json:"token"`
}

type machineNodesWireResponse struct {
	Nodes      json.RawMessage   `json:"nodes"`
	BaseConfig MachineBaseConfig `json:"base_config"`
}

func DiscoverMachineNodes(config MachineDiscoveryConfig) (*MachineNodesResponse, error) {
	apiHost := strings.TrimSpace(config.APIHost)
	if apiHost == "" {
		return nil, fmt.Errorf("APIHost must not be empty")
	}
	if config.MachineID <= 0 {
		return nil, fmt.Errorf("MachineID must be greater than 0")
	}
	token := strings.TrimSpace(config.Token)
	if token == "" {
		return nil, fmt.Errorf("Token must not be empty")
	}

	client := resty.New().SetBaseURL(apiHost)
	if config.Timeout > 0 {
		client.SetTimeout(config.Timeout)
	}

	res, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(machineNodesRequest{
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

	return &MachineNodesResponse{
		Nodes:      nodes,
		BaseConfig: payload.BaseConfig,
	}, nil
}
