// Package appliednode owns the deep-clone contract for Applied node values.
package appliednode

import "github.com/Mtoly/XrayRP/api"

// Clone returns an independently owned compatibility NodeInfo value.
func Clone(nodeInfo *api.NodeInfo) *api.NodeInfo {
	return api.NormalizeNodeInfo(nodeInfo).ToNodeInfo()
}

// CloneSnapshot returns an independently owned normalized node snapshot.
func CloneSnapshot(snapshot *api.NodeSnapshot) *api.NodeSnapshot {
	return snapshot.Clone()
}
