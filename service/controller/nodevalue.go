package controller

import (
	"encoding/json"
	"reflect"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/internal/appliednode"
)

// nodeValue is the package-private representation owned by Node runtime state.
// Values produced by repository adapters are immutable because their mutable
// fields are cloned. Custom xraynet.Address implementations are retained as a
// compatibility exception because the open interface has no clone contract.
// The raw compatibility value is never returned directly.
type nodeValue struct {
	set bool
	raw api.NodeInfo
}

func normalizeNodeInfo(nodeInfo *api.NodeInfo) nodeValue {
	if nodeInfo == nil {
		return nodeValue{}
	}
	cloned := appliednode.Clone(nodeInfo)
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
	return appliednode.Clone(&value.raw)
}

func (value nodeValue) equal(other nodeValue) bool {
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
