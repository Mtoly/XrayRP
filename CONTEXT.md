# XrayRP Context

XrayRP runs panel-managed proxy nodes on top of Xray, translating panel node data into local Xray runtime state and reporting runtime observations back to the panel.

## Language

**Node runtime state**:
The locally applied runtime snapshot for one panel node, including the node configuration, runtime tag, user list, and detect rules currently installed in Xray.
_Avoid_: Controller state, full controller state
