# Xboard / NewV2board Notes

This document describes the current Xboard/NewV2board support scope in XrayRP 0.9-alpha.

## Support scope

The `newV2board` adapter targets the backend side of Xboard/NewV2board node operation. The current implementation follows the key backend integration path rather than every panel-side feature.

Currently covered backend-facing areas:

- Node config and user sync through REST snapshots.
- Route/outbound policy compatibility for the Xboard UniProxy config shape.
- Panel-provided certificate config (`cert_config`) where available.
- WebSocket + Polling dual-active control-plane skeleton.
- `/api/v2/server/report` compatibility for status, online-user, and traffic reports with legacy UniProxy fallback.
- Polling fallback for final consistency.

Not claimed as complete in this version:

- Machine mode.
- Panel UI behavior.
- Subscription template behavior.
- Full Xboard route engine parity.
- Every future Xboard control-plane event payload.

Complex runtime objects still use REST snapshots as the authoritative apply source. WebSocket events are treated as triggers to resync, not as trusted complete replacements for node, user, route, or certificate state.

## Current Xboard WebSocket compatibility

XrayRP supports the current Xboard WebSocket control-plane envelope:

- legacy: `{"event":"node_changed","payload":{...}}`
- current Xboard: `{"event":"sync.config","data":{...}}`

Handled events:

- `sync.config` triggers node config sync through the existing REST UniProxy snapshot path.
- `sync.users` triggers user list sync through the existing REST UniProxy user path.
- `sync.user.delta` currently triggers full user sync; XrayRP intentionally does not directly apply the delta payload in phase 1.
- `ping` receives an app-level `pong` response.
- `auth.success` and `error` are accepted and ignored by the sync pipeline.
- `sync.nodes` schedules a full REST resync in single-node mode. It is treated as a machine-mode invalidation signal and does not start or stop controllers.
- `sync.devices` applies panel-provided global device/IP state to limiter admission while the WebSocket state is fresh.

WebSocket endpoint resolution order:

1. `ControllerConfig.WebSocketConfig.Endpoint`, if configured.
2. Xboard `/api/v2/server/handshake` `websocket.ws_url`, when enabled.
3. Legacy `<ApiHost>/api/v1/server/UniProxy/ws` fallback.

The REST UniProxy snapshot remains the authoritative source for complex runtime state. WebSocket payloads are used as change notifications, except `sync.devices`, which is a panel-provided global device/IP snapshot for limiter admission.

### Xboard single-node device sync behavior

Single-node controllers treat `sync.devices` as panel-provided global device/IP state and apply it to limiter admission while the WebSocket state is fresh. WebSocket disconnect clears global device state so stale panel snapshots do not reject new connections. Controllers also send changed-only `report.devices` snapshots over WebSocket, including the empty snapshot after all devices go offline, while retaining REST alive reporting for compatibility.

`sync.nodes` is treated as a machine-mode invalidation signal. In single-node mode it does not start or stop controllers; it schedules a REST resync so the current node converges safely.

## Xboard `/api/v2/server/report` compatibility

XrayRP attempts the Xboard `/api/v2/server/report` endpoint for NewV2board node status, online-user, and user-traffic reports. If the endpoint is clearly unsupported by the panel, the adapter falls back to the legacy UniProxy report endpoints:

- `/api/v1/server/UniProxy/status`
- `/api/v1/server/UniProxy/alive`
- `/api/v1/server/UniProxy/push`

The fallback is only for unsupported endpoint responses. Authentication failures, server errors, malformed successful responses, and transport failures are returned as errors so real panel problems are not hidden.

Follow-up items not covered by this phase:

- machine mode;
- Trojan REALITY;
- outbound safe regex filters;
- uTLS/xmux advanced field completion.

## WebSocket + Polling dual-active sync

Enable WebSocket sync per node in `release/config/config.yml.example` style config:

```yaml
ControllerConfig:
  WebSocketConfig:
    Enable: true
    Endpoint:
    HeartbeatInterval: 30
    ReconnectBackoff: 5
    ResyncOnReconnect: true
```

Field notes:

- `Enable`: enables the websocket control-plane path for adapters that expose websocket capability. If disabled, the node remains polling-only.
- `Endpoint`: optional override. If empty, the runtime resolves the endpoint from Xboard `/api/v2/server/handshake` when available, then falls back to `<ApiHost>/api/v1/server/UniProxy/ws`.
- `HeartbeatInterval`: websocket keepalive interval in seconds. Set to `0` to disable runtime keepalive ticks.
- `ReconnectBackoff`: reconnect delay in seconds after websocket failure.
- `ResyncOnReconnect`: when true, submit a full resync after the websocket reconnects.

This mode is dual-active, not WS-only:

- WebSocket events submit sync actions quickly.
- Polling remains active and corrects state drift.
- Reconnect submits `ResyncAll` when configured.
- Handshake failures degrade to polling-only behavior.
- Parse errors in individual websocket messages do not kill the whole websocket channel.

## Route / outbound compatibility

The Xboard UniProxy config can provide custom route and outbound data. XrayRP currently normalizes a backend-focused subset into `PanelRoutePolicy`.

Supported outbound policy fields include:

- Candidate outbound tags from `outbounds`.
- Include filters from `include_outbound`.
- Exclude filters from `exclude_outbound`.
- Fallback tags from `fallback`.

Supported route behavior includes:

- Direct/bypass detection.
- Direct domain extraction for supported route entries.
- Runtime outbound handler selection with fallback.

The runtime still protects same-node routing. XrayR-managed inbound tags do not arbitrarily dispatch into another node's outbound handler.

## VLESS + REALITY + xhttp

For VLESS + REALITY + xhttp, start with the smallest panel-side xhttp object that matches the current tested path:

```json
{
  "host": "cdn.cloudflare.steamstatic.com",
  "path": "/steam/apps/1063730/extras",
  "mode": "auto"
}
```

Recommendations:

- Keep `VlessFlow` empty for ws, grpc, httpupgrade, and splithttp/xhttp transports.
- Use `VlessFlow` such as `xtls-rprx-vision` only for direct TLS/REALITY over TCP.
- Do not add complex `extra`, `xmux`, or `downloadSettings` fields first unless your Xray-core version and Xboard payload are known to match.
- Validate the minimal path before adding obfuscation or multiplexing options.

## AnyTLS `padding_scheme`

For AnyTLS, prefer the Xboard-style default array format instead of hand-tuning values first:

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

Keep this as an array/multi-line value in the panel configuration when possible. Avoid changing the distribution until the node is confirmed healthy with the default shape.

## Integration tests

Default tests do not require external panel or websocket services:

```bash
go test ./...
```

WebSocket integration coverage is opt-in:

```bash
XRAYRP_RUN_V2BOARD_WS_INTEGRATION=1 go test ./service/controller -run 'Integration|WS' -v
```

Other panel integration tests are also gated by environment variables so the default test path stays local and deterministic.
