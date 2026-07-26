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

**Runtime routing selection**:
The runtime decision that turns a node route policy and available outbound handlers into the outbound handler used for a connection.
_Avoid_: Route engine, Xray router, outbound policy only

**UniProxy snapshot**:
The Xboard/NewV2board server config snapshot fetched from the UniProxy config endpoint and normalized into node, route, rule, and certificate state.
_Avoid_: raw server config, v2board cache, API response

**Transport profile**:
The normalized transport and security shape derived from panel node data before it is applied to local Xray inbound and user configuration.
_Avoid_: protocol helper, transport config, node parser utility

**Specialized runtime lifecycle**:
The ownership of start, readiness, stop and join, replacement, rollback, and runtime failure state for AnyTLS, TUIC, and Hysteria2 runtimes.
_Avoid_: specialized service state, protocol restart flow, runtime helper

**Applied node value**:
The immutable, deeply cloned panel node value retained as the authoritative input for Node runtime state and compatibility snapshots.
_Avoid_: raw NodeInfo, normalized node pointer, controller node copy

**Runtime construction plan**:
The fully validated immutable choice of static or machine mode together with the inputs and factories required to construct panel-managed runtimes.
_Avoid_: panel config copy, runtime options, service factory arguments

**Panel transport mechanics**:
The protocol-independent HTTP request behavior shared by compatible panel adapters, including retry, timeout, response safety, typed-result validation, and credential redaction.
_Avoid_: panel protocol semantics, shared panel API, adapter request format
