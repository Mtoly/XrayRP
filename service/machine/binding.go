package machine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Mtoly/XrayRP/api/newV2board"
)

type NodeBinding struct {
	NodeID   int
	NodeType string
	Name     string
}

type NodeBindingDiff struct {
	Added     []NodeBinding
	Removed   []NodeBinding
	Updated   []NodeBinding
	Unchanged []NodeBinding
}

func NormalizeNodeBindings(nodes []newV2board.MachineNode) ([]NodeBinding, error) {
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

func DiffNodeBindings(oldBindings, newBindings []NodeBinding) NodeBindingDiff {
	var diff NodeBindingDiff

	oldByID := make(map[int]NodeBinding, len(oldBindings))
	for _, binding := range oldBindings {
		oldByID[binding.NodeID] = binding
	}

	newByID := make(map[int]NodeBinding, len(newBindings))
	for _, binding := range newBindings {
		newByID[binding.NodeID] = binding
	}

	for nodeID, newBinding := range newByID {
		oldBinding, exists := oldByID[nodeID]
		if !exists {
			diff.Added = append(diff.Added, newBinding)
			continue
		}

		if oldBinding.NodeType != newBinding.NodeType || oldBinding.Name != newBinding.Name {
			diff.Updated = append(diff.Updated, newBinding)
		} else {
			diff.Unchanged = append(diff.Unchanged, newBinding)
		}
	}

	for nodeID, oldBinding := range oldByID {
		if _, exists := newByID[nodeID]; !exists {
			diff.Removed = append(diff.Removed, oldBinding)
		}
	}

	sortNodeBindings(diff.Added)
	sortNodeBindings(diff.Removed)
	sortNodeBindings(diff.Updated)
	sortNodeBindings(diff.Unchanged)
	return diff
}

func sortNodeBindings(bindings []NodeBinding) {
	sort.Slice(bindings, func(i, j int) bool {
		return bindings[i].NodeID < bindings[j].NodeID
	})
}
