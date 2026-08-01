# Xboard / NewV2board Compatibility

This document describes the Xboard/NewV2board backend compatibility contract implemented by XrayRP. It intentionally focuses on node operation and does not claim parity with panel UI, subscription-template, or future control-plane features.

## Supported operating modes

The `newV2board` adapter supports:

- Static-node mode through `Nodes`, with one managed runtime per configured node.
- Machine/server management mode through `MachineConfig`, with discovery of machine-bound servers, per-node lifecycle management, a shared WebSocket connection, and machine status reporting.
- REST synchronization for node, user, route, rule, certificate, and `base_config` state.
- WebSocket + polling dual-active synchronization.
- Xboard `/api/v2/server/report` with legacy UniProxy report fallback.

`MachineConfig` and static `Nodes` are mutually exclusive.

REST snapshots remain authoritative for complex runtime state. WebSocket events normally trigger the existing REST synchronization pipeline instead of directly publishing event payloads. The exception is `sync.devices`, which carries the panel-provided global device/IP snapshot used by limiter admission.

Machine mode keeps one shared WebSocket connection for ordinary Xray, AnyTLS, TUIC, and Hysteria2 nodes. Specialized runtimes receive only node-scoped synchronization triggers: `sync.config` refreshes the complete REST node snapshot, `sync.users` and `sync.user.delta` refresh the complete REST user snapshot, and reconnect or parse recovery refreshes node, user, and rule snapshots. They do not apply WebSocket delta payloads or create per-node WebSocket connections.

Each specialized node has one bounded synchronization executor. A fixed 250 ms window merges duplicate and mixed pending triggers, and only one apply may run for that node at a time. Periodic polling submits through the same executor and remains active when WebSocket delivery is unavailable. Traffic, online-user, status, and audit reporting retain their existing periodic ownership and are not amplified by WebSocket user events.

Fetched machine candidates are retained separately from confirmed Applied node values. Failed REST, rule, or runtime replacement attempts leave the last-known-good runtime and rollback snapshot unchanged. Shutdown unregisters the node mailbox, stops periodic producers, cancels and joins in-flight synchronization, and only then retires runtime resources.

Machine reconciliation preserves healthy node services when discovery or replacement fails. A `sync.nodes` event requests rediscovery; the normal reconciliation path then decides which node services must be started, stopped, or replaced.

## WebSocket compatibility

XrayRP accepts both legacy and current event envelopes:

- Legacy: `{"event":"node_changed","payload":{...}}`
- Current Xboard: `{"event":"sync.config","data":{...}}`

Important current events:

- `sync.config` triggers node configuration synchronization through REST.
- `sync.users` and `sync.user.delta` trigger a complete REST user synchronization. Delta payloads are not applied as independent partial state.
- `sync.nodes` triggers a full resync in static-node mode and machine rediscovery in machine mode.
- `sync.devices` applies the global device/IP snapshot while the WebSocket state is fresh. A malformed device snapshot triggers a full resync instead of publishing partial state.
- `ping` receives an application-level `pong`.
- `auth.success`, `pong`, and `error` are accepted without entering the apply pipeline.

### Endpoint resolution

Static-node mode resolves the WebSocket endpoint in this order:

1. `ControllerConfig.WebSocketConfig.Endpoint`, when explicitly configured.
2. Xboard `/api/v2/server/handshake` `websocket.ws_url`, when the handshake enables WebSocket.
3. `<ApiHost>/api/v1/server/UniProxy/ws`.

Machine mode uses one shared WebSocket endpoint:

1. `MachineConfig.ControllerConfig.WebSocketConfig.Endpoint`, when explicitly configured.
2. `<ApiHost>/api/v1/server/UniProxy/ws`.

Discovered handshake endpoints must remain on the panel origin. A secure panel endpoint cannot be downgraded from HTTPS/WSS to HTTP/WS. Explicit endpoint overrides are operator-controlled configuration.

If handshake discovery is unavailable, static-node mode falls back to the legacy UniProxy endpoint. If WebSocket startup or reconnect continues to fail, polling remains active and preserves eventual consistency.

### Connection safety and recovery

- Incoming WebSocket messages are limited to 1 MiB.
- Individual parse errors do not terminate the entire WebSocket runtime.
- Reconnect submits a full resync when `ResyncOnReconnect` is enabled.
- Parse recovery and reconnect are broadcast as bounded full-snapshot triggers to registered specialized node mailboxes; one node's synchronization failure does not stop delivery to other nodes.
- Disconnect clears panel-provided global device state so stale snapshots cannot reject new connections.
- Device reports are sent only when the snapshot changes, including the final empty snapshot after all devices disconnect.
- Tokens and other credential-bearing diagnostics are redacted by default.

Enable dual-active synchronization with:

```yaml
ControllerConfig:
  WebSocketConfig:
    Enable: true
    Endpoint:
    HeartbeatInterval: 30
    ReconnectBackoff: 5
    ResyncOnReconnect: true
```

`HeartbeatInterval: 0` disables runtime keepalive ticks. Disabling `WebSocketConfig.Enable` leaves the node polling-only.

## `base_config` scheduling

Xboard/NewV2board may return `base_config` in node configuration and machine discovery snapshots. These fields control scheduling and do not directly change Xray protocol configuration:

- `pull_interval` updates controller configuration/user/rule polling. In machine mode it also updates machine discovery.
- `push_interval` updates controller status, traffic, online-user, and device reporting. In machine mode it also updates machine status reporting.
- `ControllerConfig.UpdatePeriodic` and `MachineConfig.DiscoveryInterval` remain local fallbacks when the panel does not provide a positive value.

Minimum effective intervals are:

| Task | Minimum |
| --- | ---: |
| Controller reports (`push_interval`) | 5 seconds |
| Controller synchronization (`pull_interval`) | 30 seconds |
| Machine status reporting (`push_interval`) | 10 seconds |
| Machine discovery (`pull_interval`) | 30 seconds |

Changing only `base_config` reschedules periodic work without rebuilding inbound or outbound runtime state.

## Report endpoint fallback

XrayRP first attempts `/api/v2/server/report` for node status, online-user, and user-traffic reports. When the panel clearly reports that this endpoint is unsupported, the adapter falls back to:

- `/api/v1/server/UniProxy/status`
- `/api/v1/server/UniProxy/alive`
- `/api/v1/server/UniProxy/push`

Authentication failures, server failures, malformed successful responses, and transport errors are returned instead of being hidden by fallback.

## Route and outbound compatibility

XrayRP normalizes the supported Xboard UniProxy route/outbound subset into `PanelRoutePolicy`:

- Candidate outbound tags from `outbounds`.
- Include filters from `include_outbound`.
- Exclude filters from `exclude_outbound`.
- Exact fallback tags from `fallback`.
- Direct/bypass route detection and supported direct-domain extraction.

Include and exclude filters currently use exact, prefix, or substring matching. They are not regular expressions. If filtering leaves no valid candidate and no configured fallback can be resolved, dispatch fails closed.

Managed-node handoff also fails closed when the target handler is missing, has a mismatched tag, is not a managed data-path wrapper, or would recurse into the current wrapper. This prevents route selection from bypassing node limiter and rule enforcement.

## VLESS, Trojan, REALITY, and XHTTP

The Xboard adapter supports VLESS TLS/REALITY, Trojan TLS, and the tested XHTTP/splithttp fields, including mode, raw `extra`, padding/placement options, uplink chunk size, and header toggles.

Trojan REALITY is not currently materialized by the `newV2board` adapter. Advanced uTLS/xmux fields are also not guaranteed to map from every Xboard payload shape.

Start with a minimal panel-side XHTTP object:

```json
{
  "host": "cdn.cloudflare.steamstatic.com",
  "path": "/steam/apps/1063730/extras",
  "mode": "auto"
}
```

Keep `VlessFlow` empty for WS, gRPC, HTTPUpgrade, and XHTTP/splithttp. Use a flow such as `xtls-rprx-vision` only for compatible direct TCP TLS/REALITY deployments.

Raw `extra`, `xmux`, and `downloadSettings` shapes can vary between panel and Xray-core versions. Validate the minimal transport first, then add only fields supported by the exact deployed panel, adapter, and Xray-core versions.

## AnyTLS `padding_scheme`

Xboard sends AnyTLS `padding_scheme` as an array. The commonly used default shape is:

```json
[
  "stop=8",
  "0=30-30",
  "1=100-400",
  "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
  "3=9-9,500-1000",
  "4=500-1000",
  "5=500-1000",
  "6=500-1000",
  "7=500-1000"
]
```

Keep the panel value as an array and confirm the node is healthy before tuning the distribution.

## Integration tests

Default tests remain local and deterministic:

```bash
go test ./...
```

Enable the opt-in WebSocket integration tests in Linux or WSL:

```bash
XRAYRP_RUN_V2BOARD_WS_INTEGRATION=1 go test ./service/controller -run 'Integration|WS' -v
```

PowerShell:

```powershell
$env:XRAYRP_RUN_V2BOARD_WS_INTEGRATION = "1"
go test ./service/controller -run 'Integration|WS' -v
Remove-Item Env:XRAYRP_RUN_V2BOARD_WS_INTEGRATION
```
