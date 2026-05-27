# XrayRP Context

XrayRP runs panel-managed proxy nodes on top of Xray, translating panel node data into local Xray runtime state and reporting runtime observations back to the panel.

## Language

**Node runtime state**:
The locally applied runtime snapshot for one panel node, including the node configuration, runtime tag, user list, and detect rules currently installed in Xray.
_Avoid_: Controller state, full controller state

**Sync action submission**:
The local control-plane entry point that submits sync actions from polling, websocket, reconnect, or manual triggers into the coordinator or directly into the apply pipeline.
_Avoid_: Sync control plane, websocket sync, polling sync

**Runtime config contract**:
The configuration surface that must parse from documented YAML into the runtime structures used to run panel-managed nodes.
_Avoid_: Config loader, example config, viper config
