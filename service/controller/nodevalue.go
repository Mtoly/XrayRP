package controller

import (
	"encoding/json"
	"reflect"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/internal/appliednode"
)

// nodeValue is the package-private representation owned by Node runtime state.
// Values produced by repository adapters are immutable because their mutable
// fields are cloned. Unknown xraynet.Address implementations are represented
// by immutable value adapters because the open interface has no clone contract.
// The raw compatibility value is never returned directly.
type nodeValue struct {
	set bool
	raw api.NodeSnapshot
}

func normalizeNodeInfo(nodeInfo *api.NodeInfo) nodeValue {
	return normalizeNodeSnapshot(api.NormalizeNodeInfo(nodeInfo))
}

func normalizeNodeSnapshot(snapshot *api.NodeSnapshot) nodeValue {
	if snapshot == nil {
		return nodeValue{}
	}
	cloned := appliednode.CloneSnapshot(snapshot)
	return nodeValue{
		set: true,
		raw: *cloned,
	}
}

func (value nodeValue) isSet() bool {
	return value.set
}

func (value nodeValue) snapshot() *api.NodeInfo {
	if !value.set {
		return nil
	}
	return value.raw.Clone().ToNodeInfo()
}

func (value nodeValue) normalizedSnapshot() *api.NodeSnapshot {
	if !value.set {
		return nil
	}
	return value.raw.Clone()
}

func (value nodeValue) equal(other nodeValue) bool {
	// This compatibility-value comparison retains legacy representation
	// identity for callers that still inspect NodeInfo materialization. Runtime
	// change detection uses api.NodeSnapshot.Equal instead.
	if value.set != other.set {
		return false
	}
	if !value.set {
		return true
	}
	return reflect.DeepEqual(value.raw, other.raw)
}

func cloneSlice[T any](values []T) []T {
	if values == nil {
		return nil
	}
	return append([]T{}, values...)
}

func cloneMap[K comparable, V any](values map[K]V) map[K]V {
	if values == nil {
		return nil
	}
	cloned := make(map[K]V, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneValue[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneRawMessage(value json.RawMessage) json.RawMessage {
	return cloneSlice(value)
}
