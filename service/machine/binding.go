package machine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Mtoly/XrayRP/api"
)

type NodeBinding struct {
	NodeID   int
	NodeType string
	Name     string
}

func NormalizeNodeBindings(nodes []api.MachineNode) ([]NodeBinding, error) {
	bindings := make([]NodeBinding, 0, len(nodes))
	seen := make(map[int]struct{}, len(nodes))

	for _, node := range nodes {
		if node.ID <= 0 {
			return nil, fmt.Errorf("machine node ID must be greater than 0: %d", node.ID)
		}

		nodeType := strings.TrimSpace(node.Type)
		if nodeType == "" {
			return nil, fmt.Errorf("machine node %d type must not be empty", node.ID)
		}

		if _, exists := seen[node.ID]; exists {
			return nil, fmt.Errorf("duplicate machine node ID: %d", node.ID)
		}
		seen[node.ID] = struct{}{}

		bindings = append(bindings, NodeBinding{
			NodeID:   node.ID,
			NodeType: nodeType,
			Name:     node.Name,
		})
	}

	sortNodeBindings(bindings)
	return bindings, nil
}

func sortNodeBindings(bindings []NodeBinding) {
	sort.Slice(bindings, func(i, j int) bool {
		return bindings[i].NodeID < bindings[j].NodeID
	})
}
