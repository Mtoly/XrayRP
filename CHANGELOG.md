# Changelog

## 0.9-alpha

### Highlights
- Introduced a `newV2board` WebSocket + Polling dual-active sync skeleton.
- Added Xboard machine/server management mode for machine-bound node discovery and per-node service lifecycle.
- Completed route/outbounds compatibility follow-up and unified sync/apply behavior.
- Added dual-active behavior tests and opt-in websocket integration coverage.

### Added
- WebSocket event model and capability exposure for `newV2board`.
- Xboard `base_config` capability for remotely controlling sync/report intervals with local fallback intervals.
- Minimal WebSocket client lifecycle, runtime reconnect/degrade skeleton, and keepalive support.
- Unified sync action model, coordinator, and apply pipeline in `service/controller`.
- Opt-in websocket integration tests gated by `XRAYRP_RUN_V2BOARD_WS_INTEGRATION=1`.
- Xboard/NewV2board usage notes covering websocket dual-active sync, route/outbound compatibility, xhttp, and AnyTLS examples.

### Changed
- Polling and ws-triggered REST fetches now converge through the same sync action / coordinator / apply pipeline.
- Xboard `base_config.push_interval` and `base_config.pull_interval` can update controller report/sync intervals at runtime; machine discovery uses machine `base_config.pull_interval` when available.
- Complex objects such as node info, users, route policy/rules, and cert config continue to use REST snapshots as the authoritative apply source.
- Reconnect now forces `ResyncAll`, handshake failures degrade to polling-only, and parse errors no longer kill the entire ws channel.
- `HeartbeatInterval` now actively drives websocket keepalive behavior.
- Route/rule and same-tag rebuild safety paths were tightened to avoid half-applied runtime state.

### Testing
- Added behavior tests for dual-active convergence, duplicate suppression, degrade, parse-error isolation, and reconnect resync.
- Added gated mock websocket integration coverage while keeping the default `go test ./...` path independent of external services.
