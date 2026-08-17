package machine

import (
	"reflect"
	"testing"

	"github.com/Mtoly/XrayRP/api/newV2board"
)

func TestNormalizeNodeBindingsSortsAndTrims(t *testing.T) {
	nodes := []newV2board.MachineNode{
		{ID: 3, Type: "\tvless ", Name: " Gamma"},
		{ID: 1, Type: " vmess\n", Name: "  Alpha  "},
		{ID: 2, Type: "trojan", Name: "Beta"},
	}

	got, err := NormalizeNodeBindings(nodes)
	if err != nil {
		t.Fatalf("NormalizeNodeBindings returned error: %v", err)
	}

	want := []NodeBinding{
		{NodeID: 1, NodeType: "vmess", Name: "  Alpha  "},
		{NodeID: 2, NodeType: "trojan", Name: "Beta"},
		{NodeID: 3, NodeType: "vless", Name: " Gamma"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected bindings\n got: %#v\nwant: %#v", got, want)
	}
}

func TestNormalizeNodeBindingsRejectsInvalidNodeID(t *testing.T) {
	tests := []struct {
		name string
		id   int
	}{
		{name: "zero", id: 0},
		{name: "negative", id: -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NormalizeNodeBindings([]newV2board.MachineNode{
				{ID: tc.id, Type: "vless", Name: "node"},
			})
			if err == nil {
				t.Fatalf("expected error for node ID %d", tc.id)
			}
		})
	}
}

func TestNormalizeNodeBindingsRejectsEmptyNodeType(t *testing.T) {
	tests := []struct {
		name     string
		nodeType string
	}{
		{name: "empty", nodeType: ""},
		{name: "whitespace", nodeType: " \t\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NormalizeNodeBindings([]newV2board.MachineNode{
				{ID: 1, Type: tc.nodeType, Name: "node"},
			})
			if err == nil {
				t.Fatalf("expected error for node type %q", tc.nodeType)
			}
		})
	}
}

func TestNormalizeNodeBindingsRejectsDuplicateNodeID(t *testing.T) {
	_, err := NormalizeNodeBindings([]newV2board.MachineNode{
		{ID: 2, Type: "vless", Name: "node-a"},
		{ID: 2, Type: "vmess", Name: "node-b"},
	})
	if err == nil {
		t.Fatal("expected error for duplicate node ID")
	}
}
