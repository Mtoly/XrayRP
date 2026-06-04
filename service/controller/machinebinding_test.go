package controller

import (
	"reflect"
	"testing"

	"github.com/Mtoly/XrayRP/api/newV2board"
)

func TestNormalizeMachineNodeBindingsSortsAndTrims(t *testing.T) {
	nodes := []newV2board.MachineNode{
		{ID: 3, Type: "\tvless ", Name: " Gamma"},
		{ID: 1, Type: " vmess\n", Name: "  Alpha  "},
		{ID: 2, Type: "trojan", Name: "Beta"},
	}

	got, err := normalizeMachineNodeBindings(nodes)
	if err != nil {
		t.Fatalf("normalizeMachineNodeBindings returned error: %v", err)
	}

	want := []machineNodeBinding{
		{NodeID: 1, NodeType: "vmess", Name: "  Alpha  "},
		{NodeID: 2, NodeType: "trojan", Name: "Beta"},
		{NodeID: 3, NodeType: "vless", Name: " Gamma"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected bindings\n got: %#v\nwant: %#v", got, want)
	}
}

func TestNormalizeMachineNodeBindingsRejectsInvalidNodeID(t *testing.T) {
	tests := []struct {
		name string
		id   int
	}{
		{name: "zero", id: 0},
		{name: "negative", id: -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizeMachineNodeBindings([]newV2board.MachineNode{
				{ID: tc.id, Type: "vless", Name: "node"},
			})
			if err == nil {
				t.Fatalf("expected error for node ID %d", tc.id)
			}
		})
	}
}

func TestNormalizeMachineNodeBindingsRejectsEmptyNodeType(t *testing.T) {
	tests := []struct {
		name     string
		nodeType string
	}{
		{name: "empty", nodeType: ""},
		{name: "whitespace", nodeType: " \t\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizeMachineNodeBindings([]newV2board.MachineNode{
				{ID: 1, Type: tc.nodeType, Name: "node"},
			})
			if err == nil {
				t.Fatalf("expected error for node type %q", tc.nodeType)
			}
		})
	}
}

func TestNormalizeMachineNodeBindingsRejectsDuplicateNodeID(t *testing.T) {
	_, err := normalizeMachineNodeBindings([]newV2board.MachineNode{
		{ID: 2, Type: "vless", Name: "node-a"},
		{ID: 2, Type: "vmess", Name: "node-b"},
	})
	if err == nil {
		t.Fatal("expected error for duplicate node ID")
	}
}

func TestDiffMachineNodeBindingsClassifiesAddedRemovedUpdatedUnchanged(t *testing.T) {
	oldBindings := []machineNodeBinding{
		{NodeID: 1, NodeType: "vless", Name: "same"},
		{NodeID: 2, NodeType: "vmess", Name: "removed"},
		{NodeID: 3, NodeType: "trojan", Name: "old"},
	}
	newBindings := []machineNodeBinding{
		{NodeID: 1, NodeType: "vless", Name: "same"},
		{NodeID: 3, NodeType: "trojan", Name: "new"},
		{NodeID: 4, NodeType: "hysteria", Name: "added"},
	}

	got := diffMachineNodeBindings(oldBindings, newBindings)

	assertMachineNodeBindingsEqual(t, "added", got.Added, []machineNodeBinding{
		{NodeID: 4, NodeType: "hysteria", Name: "added"},
	})
	assertMachineNodeBindingsEqual(t, "removed", got.Removed, []machineNodeBinding{
		{NodeID: 2, NodeType: "vmess", Name: "removed"},
	})
	assertMachineNodeBindingsEqual(t, "updated", got.Updated, []machineNodeBinding{
		{NodeID: 3, NodeType: "trojan", Name: "new"},
	})
	assertMachineNodeBindingsEqual(t, "unchanged", got.Unchanged, []machineNodeBinding{
		{NodeID: 1, NodeType: "vless", Name: "same"},
	})
}

func TestDiffMachineNodeBindingsStableOrdering(t *testing.T) {
	oldBindings := []machineNodeBinding{
		{NodeID: 9, NodeType: "trojan", Name: "old"},
		{NodeID: 5, NodeType: "vless", Name: "removed-high"},
		{NodeID: 3, NodeType: "vmess", Name: "same"},
		{NodeID: 1, NodeType: "vless", Name: "removed-low"},
	}
	newBindings := []machineNodeBinding{
		{NodeID: 8, NodeType: "hysteria", Name: "added-high"},
		{NodeID: 3, NodeType: "vmess", Name: "same"},
		{NodeID: 2, NodeType: "vless", Name: "added-low"},
		{NodeID: 9, NodeType: "trojan", Name: "new"},
	}

	got := diffMachineNodeBindings(oldBindings, newBindings)

	assertMachineNodeBindingsEqual(t, "added", got.Added, []machineNodeBinding{
		{NodeID: 2, NodeType: "vless", Name: "added-low"},
		{NodeID: 8, NodeType: "hysteria", Name: "added-high"},
	})
	assertMachineNodeBindingsEqual(t, "removed", got.Removed, []machineNodeBinding{
		{NodeID: 1, NodeType: "vless", Name: "removed-low"},
		{NodeID: 5, NodeType: "vless", Name: "removed-high"},
	})
	assertMachineNodeBindingsEqual(t, "updated", got.Updated, []machineNodeBinding{
		{NodeID: 9, NodeType: "trojan", Name: "new"},
	})
	assertMachineNodeBindingsEqual(t, "unchanged", got.Unchanged, []machineNodeBinding{
		{NodeID: 3, NodeType: "vmess", Name: "same"},
	})
}

func assertMachineNodeBindingsEqual(t *testing.T, label string, got, want []machineNodeBinding) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected %s bindings\n got: %#v\nwant: %#v", label, got, want)
	}
}
