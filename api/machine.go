package api

// MachineNode is the normalized identity returned by a machine-capable panel.
// It contains only the fields needed by machine composition and runtime
// selection; panel-specific wire fields stay inside the adapter.
type MachineNode struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

// MachineNodesResponse is the normalized machine discovery snapshot shared by
// machine-capable adapters and the machine supervisor.
type MachineNodesResponse struct {
	Nodes      []MachineNode `json:"nodes"`
	BaseConfig BaseConfig    `json:"base_config"`
}
