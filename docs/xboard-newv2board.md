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

Enable dual-active synchronization for a static node with:

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

## Xboard deployment: machine-mode shared WebSocket

Current Xboard splits the control plane into separate services:

- `web` serves the panel HTTP API (PHP Octane or PHP-FPM), usually on `:7001`.
- `ws-server` is a standalone Workerman WebSocket server (`php artisan ws-server start`), usually on `:8076`. The public path is decided by the reverse proxy; Xboard's own guides use `/ws` or `/ws/`.
- `horizon` is the queue worker and never accepts WebSocket connections.

The PHP web service does not terminate the WebSocket upgrade. When Xboard runs the split or multi-container topology, the public reverse proxy must forward the upgrade request to the `ws-server` port.

### Required machine-mode configuration

Static-node mode can discover the WebSocket URL through Xboard `/api/v2/server/handshake` (`websocket.ws_url`). Machine mode does not use handshake discovery, so `Endpoint` must be set explicitly to the URL your Xboard deployment advertises:

```yaml
MachineConfig:
  Enable: true
  PanelType: "NewV2board"
  ApiHost: "https://panel.example.com"
  MachineID: 1
  Token: "machine-token"
  ControllerConfig:
    WebSocketConfig:
      Enable: true
      Endpoint: "wss://panel.example.com/ws"
      HeartbeatInterval: 30
      ReconnectBackoff: 5
      ResyncOnReconnect: true
```

XrayRP appends the `machine_id` and `token` query parameters itself, so the endpoint must not contain them. Explicit endpoints are operator-controlled, unlike handshake-discovered ones, so XrayRP does not enforce same-origin or downgrade protection here: point it at the panel origin, and use `wss://` whenever the panel itself is HTTPS.

### Reverse proxy for the Xboard ws-server

For an nginx or aaPanel site that terminates TLS in front of the panel, add a WebSocket location before the site's catch-all location:

```nginx
location /ws {
    proxy_pass http://127.0.0.1:8076;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 300s;
}
```

Replace `127.0.0.1:8076` when the ws-server runs on another host or port, including the Docker service name when the proxy itself runs in a container network. TLS can terminate on nginx even though the upstream is plain `http://`; clients still connect with `wss://`.

Two details decide whether the upgrade reaches the ws-server: keep the location prefix aligned with the path in `Endpoint` (`location /ws` matches the default `/ws`; a `location /ws/` block would not), and keep `proxy_pass` without a trailing slash so the `/ws` path is forwarded unchanged instead of being rewritten to `/`.

`proxy_read_timeout` must stay above `WebSocketConfig.HeartbeatInterval`, and above any CDN idle timeout in the path, or the proxy drops an idle connection between heartbeats. If Xboard runs as the all-in-one Docker image, the container's internal Caddy already routes `/ws` to its ws-server, so an external proxy only needs to forward the upgrade to the single published port.

### `/ws` versus the legacy fallback

When `Endpoint` is empty, machine mode falls back to `<ApiHost>/api/v1/server/UniProxy/ws`. That is the legacy UniProxy WebSocket endpoint this client historically used. Current Xboard does not register it as an HTTP route: Xboard exposes the standalone ws-server, and its handshake advertises `/ws` (or an admin-configured URL).

The practical difference:

- Static-node mode with an empty `Endpoint` first asks `/api/v2/server/handshake` and uses the advertised `/ws` URL, so it works with current Xboard as long as the reverse proxy forwards the upgrade.
- Machine mode with an empty `Endpoint` dials the legacy UniProxy path directly. Unless the reverse proxy maps that exact path to the ws-server, the connection never establishes, the `websocket` label stays `degraded` (or `disconnected` before the first successful dial), and machine-mode synchronization silently continues on polling only.

Setting `Endpoint` to the same `/ws` URL that Xboard advertises is the supported machine-mode configuration for current Xboard.

### Acceptance and troubleshooting

Start by enabling the local observability server in `config.yml` and restarting XrayRP:

```yaml
Observability:
  Enable: true
  Listen: "127.0.0.1:10085"
```

Then confirm both the machine runtime and its node controllers report a connected shared WebSocket:

```bash
curl -fsS http://127.0.0.1:10085/readyz
curl -fsS http://127.0.0.1:10085/metrics | grep 'xrayrp_runtime_state'
```

`/readyz` returns HTTP 200 while the process is running; its body reports `ready`, or `degraded` when only the WebSocket (or report backlog) is unhealthy. A lost WebSocket connection therefore degrades readiness instead of failing it, which is intended: polling keeps node configuration converging. In the metrics output, `kind="machine"` must show `websocket="connected"`. Ordinary Xray nodes appear as `kind="controller"` rows and mirror the shared connection state, so they must also show `websocket="connected"`. AnyTLS, TUIC, and Hysteria2 nodes appear under their own `kind` and keep `websocket="disabled"` because they receive node-scoped triggers through the shared machine connection without owning it; judge their latency behavior from the `kind="machine"` row instead. A machine without discovered nodes has no node rows yet; that is expected.

If `websocket` is not `connected`:

- `/ws` returns panel HTML or a 404: the reverse proxy is sending the upgrade to the PHP web service instead of the ws-server port.
- The upgrade fails immediately: the location is missing `proxy_http_version 1.1`, `Upgrade $http_upgrade`, or `Connection "upgrade"`. A CDN in front of nginx must also allow WebSocket upgrades.
- The connection drops on a fixed interval: `proxy_read_timeout` or a CDN idle timeout is shorter than `HeartbeatInterval`.
- Xboard logs `invalid machine credentials` or the client receives an `error` event right after the upgrade: `MachineID` or `Token` does not match the machine entry in the panel.

In all of these cases XrayRP keeps polling, so node configuration still converges; WebSocket only reduces synchronization latency.

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

For VLESS, Xboard exposes `protocol_settings.encryption.decryption` as the top-level `decryption` field in the per-node `/api/v2/server/config` response when encryption is enabled. XrayRP passes this server-side value to the Xray-core inbound; a missing, null, or blank value remains `none`. Client-side `encryption` is not used for the inbound. The pinned Xray-core does not allow encrypted VLESS decryption together with inbound fallbacks; disable fallbacks for encrypted nodes. Unencrypted VLESS fallbacks continue to work.

Trojan REALITY is not currently materialized by the `newV2board` adapter. Advanced uTLS/xmux fields are also not guaranteed to map from every Xboard payload shape.

Start with a minimal panel-side XHTTP object:

```json
{
  "host": "cdn.cloudflare.steamstatic.com",
  "path": "/steam/apps/1063730/extras",
  "mode": "auto"
}
```

For legacy unencrypted VLESS, keep `VlessFlow` empty for WS, gRPC, HTTPUpgrade, and XHTTP/splithttp. Use a flow such as `xtls-rprx-vision` only for compatible direct TCP TLS/REALITY deployments; XrayRP clears the flow for the other transports.

When server-side VLESS Encryption is enabled (a non-empty `decryption` other than `none`), XTLS Vision is no longer limited by the underlying transport, so XrayRP keeps a panel-provided `xtls-rprx-vision` for transports such as XHTTP, WS, or gRPC. XrayRP never adds the flow by itself: it only stops discarding the value the panel already sent, and it still clears an unencrypted non-TCP flow.

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
