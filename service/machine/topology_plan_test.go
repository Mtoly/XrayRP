package machine

import (
	"reflect"
	"testing"
)

func TestDiffNodeBindingsClassifiesAddedRemovedUpdatedUnchanged(t *testing.T) {
	oldBindings := []NodeBinding{
		{NodeID: 1, NodeType: "vless", Name: "same"},
		{NodeID: 2, NodeType: "vmess", Name: "removed"},
		{NodeID: 3, NodeType: "trojan", Name: "old"},
	}
	newBindings := []NodeBinding{
		{NodeID: 1, NodeType: "vless", Name: "same"},
		{NodeID: 3, NodeType: "trojan", Name: "new"},
		{NodeID: 4, NodeType: "hysteria", Name: "added"},
	}

	got := DiffNodeBindings(oldBindings, newBindings)

	assertNodeBindingsEqual(t, "added", got.Added, []NodeBinding{
		{NodeID: 4, NodeType: "hysteria", Name: "added"},
	})
	assertNodeBindingsEqual(t, "removed", got.Removed, []NodeBinding{
		{NodeID: 2, NodeType: "vmess", Name: "removed"},
	})
	assertNodeBindingsEqual(t, "updated", got.Updated, []NodeBinding{
		{NodeID: 3, NodeType: "trojan", Name: "new"},
	})
	assertNodeBindingsEqual(t, "unchanged", got.Unchanged, []NodeBinding{
		{NodeID: 1, NodeType: "vless", Name: "same"},
	})
}

func TestDiffNodeBindingsStableOrdering(t *testing.T) {
	oldBindings := []NodeBinding{
		{NodeID: 9, NodeType: "trojan", Name: "old"},
		{NodeID: 5, NodeType: "vless", Name: "removed-high"},
		{NodeID: 3, NodeType: "vmess", Name: "same"},
		{NodeID: 1, NodeType: "vless", Name: "removed-low"},
	}
	newBindings := []NodeBinding{
		{NodeID: 8, NodeType: "hysteria", Name: "added-high"},
		{NodeID: 3, NodeType: "vmess", Name: "same"},
		{NodeID: 2, NodeType: "vless", Name: "added-low"},
		{NodeID: 9, NodeType: "trojan", Name: "new"},
	}

	got := DiffNodeBindings(oldBindings, newBindings)

	assertNodeBindingsEqual(t, "added", got.Added, []NodeBinding{
		{NodeID: 2, NodeType: "vless", Name: "added-low"},
		{NodeID: 8, NodeType: "hysteria", Name: "added-high"},
	})
	assertNodeBindingsEqual(t, "removed", got.Removed, []NodeBinding{
		{NodeID: 1, NodeType: "vless", Name: "removed-low"},
		{NodeID: 5, NodeType: "vless", Name: "removed-high"},
	})
	assertNodeBindingsEqual(t, "updated", got.Updated, []NodeBinding{
		{NodeID: 9, NodeType: "trojan", Name: "new"},
	})
	assertNodeBindingsEqual(t, "unchanged", got.Unchanged, []NodeBinding{
		{NodeID: 3, NodeType: "vmess", Name: "same"},
	})
}

func TestMaterializeMachineReconcilePlanClassifiesDecisions(t *testing.T) {
	keepRuntime := &nodeRuntime{binding: NodeBinding{NodeID: 1, NodeType: "vless", Name: "old"}, missingCount: 1}
	restartRuntime := &nodeRuntime{binding: NodeBinding{NodeID: 2, NodeType: "vmess", Name: "changed"}}
	missingRuntime := &nodeRuntime{binding: NodeBinding{NodeID: 3, NodeType: "trojan", Name: "missing"}}
	removeRuntime := &nodeRuntime{binding: NodeBinding{NodeID: 4, NodeType: "vless", Name: "remove"}, missingCount: removedNodeMissingThreshold - 1}
	running := map[int]*nodeRuntime{
		1: keepRuntime,
		2: restartRuntime,
		3: missingRuntime,
		4: removeRuntime,
	}
	bindings := []NodeBinding{
		{NodeID: 1, NodeType: "vless", Name: "new"},
		{NodeID: 2, NodeType: "trojan", Name: "changed"},
		{NodeID: 5, NodeType: "vless", Name: "added"},
	}

	plan := materializeMachineReconcilePlan(running, bindings)

	if len(plan.bindings) != 3 {
		t.Fatalf("expected 3 binding decisions, got %#v", plan.bindings)
	}
	wantActions := []machineReconcileAction{machineReconcileKeep, machineReconcileRestart, machineReconcileStart}
	for i, wantAction := range wantActions {
		if plan.bindings[i].action != wantAction || plan.bindings[i].binding != bindings[i] {
			t.Fatalf("unexpected binding decision %d: %#v", i, plan.bindings[i])
		}
	}
	if plan.bindings[0].runtime != keepRuntime {
		t.Fatalf("expected keep decision to reference existing runtime")
	}
	if plan.bindings[1].runtime != restartRuntime {
		t.Fatalf("expected restart decision to reference existing runtime")
	}
	if plan.bindings[2].runtime != nil {
		t.Fatalf("expected start decision not to reference a runtime, got %#v", plan.bindings[2].runtime)
	}

	if len(plan.missing) != 2 {
		t.Fatalf("expected 2 missing decisions, got %#v", plan.missing)
	}
	missingByID := make(map[int]machineMissingRuntimeDecision, len(plan.missing))
	for _, decision := range plan.missing {
		missingByID[decision.nodeID] = decision
	}
	missingDecision, ok := missingByID[3]
	if !ok {
		t.Fatalf("expected node 3 missing decision, got %#v", plan.missing)
	}
	if missingDecision.runtime != missingRuntime || missingDecision.nextMissingCount != 1 || missingDecision.remove {
		t.Fatalf("unexpected node 3 missing decision: %#v", missingDecision)
	}
	removeDecision, ok := missingByID[4]
	if !ok {
		t.Fatalf("expected node 4 remove decision, got %#v", plan.missing)
	}
	if removeDecision.runtime != removeRuntime || removeDecision.nextMissingCount != removedNodeMissingThreshold || !removeDecision.remove {
		t.Fatalf("unexpected node 4 remove decision: %#v", removeDecision)
	}
}

func TestMaterializeMachineReconcilePlanHandlesNilAndFailedOwnedRuntimes(t *testing.T) {
	failedRuntime := &nodeRuntime{
		binding: NodeBinding{NodeID: 1, NodeType: "vless"},
		state:   nodeRuntimeFailedOwned,
	}
	running := map[int]*nodeRuntime{
		1: failedRuntime,
		2: nil,
	}

	plan := materializeMachineReconcilePlan(running, []NodeBinding{
		{NodeID: 1, NodeType: "vless"},
		{NodeID: 2, NodeType: "vmess"},
	})

	if len(plan.bindings) != 2 {
		t.Fatalf("expected two binding decisions, got %#v", plan.bindings)
	}
	if plan.bindings[0].action != machineReconcileRecover || plan.bindings[0].runtime != failedRuntime {
		t.Fatalf("expected failed-owned runtime recovery, got %#v", plan.bindings[0])
	}
	if plan.bindings[1].action != machineReconcileStart || plan.bindings[1].runtime != nil {
		t.Fatalf("expected nil runtime start, got %#v", plan.bindings[1])
	}
}

func TestMaterializeMachineReconcilePlanDoesNotMutateInputs(t *testing.T) {
	runtime := &nodeRuntime{
		binding:      NodeBinding{NodeID: 1, NodeType: "vless", Name: "node"},
		missingCount: 2,
	}
	running := map[int]*nodeRuntime{1: runtime}
	bindings := []NodeBinding{{NodeID: 2, NodeType: "vmess", Name: "added"}}
	wantRunning := map[int]*nodeRuntime{1: {binding: runtime.binding, missingCount: runtime.missingCount}}
	wantBindings := append([]NodeBinding(nil), bindings...)

	_ = materializeMachineReconcilePlan(running, bindings)

	if !reflect.DeepEqual(running, wantRunning) {
		t.Fatalf("planning mutated running input: got %#v, want %#v", running, wantRunning)
	}
	if !reflect.DeepEqual(bindings, wantBindings) {
		t.Fatalf("planning mutated bindings input: got %#v, want %#v", bindings, wantBindings)
	}
}

func assertNodeBindingsEqual(t *testing.T, label string, got, want []NodeBinding) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected %s bindings\n got: %#v\nwant: %#v", label, got, want)
	}
}
