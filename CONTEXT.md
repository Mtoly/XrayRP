# XrayRP Context

XrayRP runs panel-managed proxy nodes on top of Xray, translating panel node data into local Xray runtime state and reporting runtime observations back to the panel.

## Language

**Node runtime state**:
The locally applied runtime snapshot for one panel node, including the node configuration, runtime tag, user list, and detect rules currently installed in Xray.
_Avoid_: Controller state, full controller state

**Sync action submission**:
The local control-plane entry point that submits sync actions from polling, websocket, reconnect, or manual triggers into the coordinator or directly into the apply pipeline.
_Avoid_: Sync control plane, websocket sync, polling sync

**Authoritative snapshot synchronization**:
The bounded per-node submission and apply path that coalesces polling, WebSocket, reconnect, and parse-error triggers into complete REST node, user, and rule snapshots. A fetched candidate becomes an Applied node value only after its runtime apply succeeds.
_Avoid_: WebSocket payload apply, delta reconstruction, specialized event handler

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

**Runtime observability snapshot**:
The immutable, credential-free view of panel, topology, and per-node lifecycle state used by health, readiness, and bounded-label metrics.
_Avoid_: debug dump, runtime internals, raw error snapshot

**Global device cache**:
The optional per-inbound local TTL and Redis shared cache used to coordinate user IP observations across XrayRP instances. It is a bounded-staleness, fail-open supplement to admission state, not a strict distributed transaction or an authoritative panel snapshot.
_Avoid_: global device state, sync.Map cache, strict global limiter

**Release identity**:
The immutable mapping from a release tag and full source commit to build time, dirty state, release binary or archive digest, SBOM, signature, and provenance.
_Avoid_: hardcoded version, artifact filename, latest build
