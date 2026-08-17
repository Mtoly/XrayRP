package machine

type NodeBindingDiff struct {
	Added     []NodeBinding
	Removed   []NodeBinding
	Updated   []NodeBinding
	Unchanged []NodeBinding
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

type machineReconcileAction int

const (
	machineReconcileStart machineReconcileAction = iota
	machineReconcileKeep
	machineReconcileRestart
	machineReconcileRecover
)

type machineReconcilePlan struct {
	missing  []machineMissingRuntimeDecision
	bindings []machineBindingDecision
}

type machineMissingRuntimeDecision struct {
	nodeID           int
	runtime          *nodeRuntime
	nextMissingCount int
	remove           bool
}

type machineBindingDecision struct {
	action  machineReconcileAction
	binding NodeBinding
	runtime *nodeRuntime
}

type machineReconcileTransaction struct {
	generation uint64
	running    map[int]*nodeRuntime
	plan       machineReconcilePlan
}

type machineReconcileResult struct {
	generation uint64
	running    map[int]*nodeRuntime
	started    []*nodeRuntime
	failure    error
}

func materializeMachineReconcilePlan(running map[int]*nodeRuntime, bindings []NodeBinding) machineReconcilePlan {
	newByID := make(map[int]NodeBinding, len(bindings))
	for _, binding := range bindings {
		newByID[binding.NodeID] = binding
	}

	plan := machineReconcilePlan{
		bindings: make([]machineBindingDecision, 0, len(bindings)),
	}
	for nodeID, runtime := range running {
		if _, exists := newByID[nodeID]; exists {
			continue
		}
		if runtime == nil {
			plan.missing = append(plan.missing, machineMissingRuntimeDecision{nodeID: nodeID, remove: true})
			continue
		}

		nextMissingCount := runtime.missingCount + 1
		plan.missing = append(plan.missing, machineMissingRuntimeDecision{
			nodeID:           nodeID,
			runtime:          runtime,
			nextMissingCount: nextMissingCount,
			remove:           runtime.state != nodeRuntimeRunning || nextMissingCount >= removedNodeMissingThreshold,
		})
	}

	for _, binding := range bindings {
		runtime, exists := running[binding.NodeID]
		if !exists || runtime == nil {
			plan.bindings = append(plan.bindings, machineBindingDecision{action: machineReconcileStart, binding: binding})
			continue
		}
		if runtime.state != nodeRuntimeRunning {
			plan.bindings = append(plan.bindings, machineBindingDecision{action: machineReconcileRecover, binding: binding, runtime: runtime})
			continue
		}
		if runtime.binding.NodeType == binding.NodeType {
			plan.bindings = append(plan.bindings, machineBindingDecision{action: machineReconcileKeep, binding: binding, runtime: runtime})
			continue
		}
		plan.bindings = append(plan.bindings, machineBindingDecision{action: machineReconcileRestart, binding: binding, runtime: runtime})
	}

	return plan
}
