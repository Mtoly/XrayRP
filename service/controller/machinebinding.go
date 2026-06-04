package controller

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Mtoly/XrayRP/api/newV2board"
)

type machineNodeBinding struct {
	NodeID   int
	NodeType string
	Name     string
}

type machineNodeBindingDiff struct {
	Added     []machineNodeBinding
	Removed   []machineNodeBinding
	Updated   []machineNodeBinding
	Unchanged []machineNodeBinding
}

func normalizeMachineNodeBindings(nodes []newV2board.MachineNode) ([]machineNodeBinding, error) {
	bindings := make([]machineNodeBinding, 0, len(nodes))
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

		bindings = append(bindings, machineNodeBinding{
			NodeID:   node.ID,
			NodeType: nodeType,
			Name:     node.Name,
		})
	}

	sortMachineNodeBindings(bindings)
	return bindings, nil
}

func diffMachineNodeBindings(oldBindings, newBindings []machineNodeBinding) machineNodeBindingDiff {
	var diff machineNodeBindingDiff

	oldByID := make(map[int]machineNodeBinding, len(oldBindings))
	for _, binding := range oldBindings {
		oldByID[binding.NodeID] = binding
	}

	newByID := make(map[int]machineNodeBinding, len(newBindings))
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

	sortMachineNodeBindings(diff.Added)
	sortMachineNodeBindings(diff.Removed)
	sortMachineNodeBindings(diff.Updated)
	sortMachineNodeBindings(diff.Unchanged)
	return diff
}

func sortMachineNodeBindings(bindings []machineNodeBinding) {
	sort.Slice(bindings, func(i, j int) bool {
		return bindings[i].NodeID < bindings[j].NodeID
	})
}
