# Changelog

## 0.9-alpha

### Highlights
- Introduced `newV2board` WebSocket + polling dual-active synchronization, including reconnect resync and polling-only degradation.
- Added Xboard single-node device synchronization and machine/server management with dynamic node discovery, per-node lifecycle, shared WebSocket transport, and machine status reporting.
- Added Xboard route/outbound, runtime interval, certificate-content, lowercase node type, and report fallback compatibility.
- Hardened credential logging, WebSocket input and endpoint discovery, Hysteria2 sniffing, runtime snapshot ownership, state commits, user rollback, and outbound routing.
- Expanded regression coverage across controller synchronization, machine reconciliation, limiter admission, panel configuration, and protocol transport profiles.

### Added
- WebSocket event envelopes, endpoint discovery capability, handshake compatibility, keepalive, reconnect/degrade lifecycle, and unified sync action processing for `newV2board`.
- Xboard single-node global device synchronization with changed-snapshot reporting, explicit clear/resync handling, admission serialization, and limiter snapshot/restore support.
- Xboard machine mode configuration, discovery adapters, binding diffs, supervisor reconciliation, shared WebSocket runtime, per-node services, device reporting, and machine load/status reporting.
- Xboard `base_config` support for remotely controlling sync/report intervals with local fallback intervals.
- Xboard route/outbound policy materialization, content certificate support, v2 machine endpoints, lowercase node type normalization, and report transport fallback.
- Local V2RaySocks transport profiles for inbound, endpoint, security, and XHTTP configuration derivation.
- Runtime controller scheduling, runtime certificate materialization, static/machine runtime plans, node service dispatch, and machine reporting adapters.
- A 1 MiB WebSocket message limit with oversized-frame regression coverage.
- Same-origin validation for discovered WebSocket endpoints, including HTTPS-to-WS downgrade prevention and nil-config handling.
- Immutable UniProxy snapshot ownership, last-known-good commit behavior, isolated certificate environment maps, atomic node runtime state snapshots, and centralized runtime dispatch decisions.
- Xboard/NewV2board usage documentation covering dual-active sync, device synchronization, machine mode, route/outbound compatibility, XHTTP, and AnyTLS examples.

### Changed
- Upgraded the Go toolchain and Docker builder image to Go 1.26.5 and refreshed Hysteria, sing-box, Redis, `x/net`, and `x/crypto` dependencies.
- Polling and WebSocket-triggered REST fetches now converge through the same sync action, coordinator, and apply pipeline; reconnect forces `ResyncAll`, handshake failures degrade to polling-only, and malformed events no longer terminate the channel.
- Complex node, user, route/rule, certificate, device, and base configuration objects use authoritative REST snapshots with explicit materialization and apply boundaries.
- Xboard runtime intervals now update controller report/sync schedules dynamically, while machine discovery consumes the machine pull interval when available.
- Runtime configuration is materialized once and shared by static-node and machine-mode builders.
- Node information, users, applied rules, and rule tags now live in one synchronized runtime state generation.
- Managed-node handoff, panel candidate filtering, fallback, handler lookup, and rejection reasons now converge through one routing decision path.
- Controller user updates distinguish limiter-only changes from runtime credential changes and restore limiter/runtime state when partial application fails.
- Machine reconciliation keeps healthy nodes running when discovery, start, or replacement operations fail, and exposes explicit discovery, decision, execution, and reporting boundaries.
- Error logging now redacts credential-bearing messages by default, with detailed diagnostics available only through the explicit detailed-error switch.

### Fixed
- Preserved local REALITY configuration when SSPPanel responses omit remote REALITY settings.
- Added Xboard report fallback compatibility and WebSocket device-report delivery for single-node and machine modes.
- Rejected malformed device identifiers and serialized global-device admission/state mutations.
- Kept healthy machine-managed nodes active when replacement services fail to start.
- Normalized lowercase Xboard machine node types for configuration, users, and runtime dispatch.
- Tightened route/rule and same-tag rebuild rollback so failed updates do not leave half-applied runtime state.

### Security
- Discovered WebSocket endpoints must remain on the panel origin and cannot downgrade a secure panel connection.
- Oversized WebSocket messages are rejected before unbounded payload processing.
- Managed outbound handoff rejects raw handlers, mismatched tags, missing handlers, and recursive self-handoffs so limiter and rule enforcement cannot be bypassed.
- Hysteria2 request sniffing remains explicitly disabled to isolate the trigger for `GO-2026-5288` while the upstream module has no fixed release.
- UniProxy cache reads and writes no longer expose shared mutable snapshot data.

### Testing
- Added behavior tests for dual-active convergence, duplicate suppression, polling degradation, parse-error isolation, reconnect resync, and opt-in WebSocket integration gated by `XRAYRP_RUN_V2BOARD_WS_INTEGRATION=1`.
- Added extensive machine-mode coverage for discovery, binding diffs, reconciliation decisions, shared WebSocket lifecycle, status/device reporting, replacement rollback, and healthy-node preservation.
- Added limiter tests for global device synchronization, admission serialization, inbound snapshot/restore, malformed identifiers, and limiter-only user changes.
- Added regression coverage for panel config examples, runtime config/certificate materialization, periodic schedules, UniProxy ownership, WebSocket limits/origin checks, atomic runtime state, routing handoff, credential redaction, Hysteria2 sniff isolation, and V2RaySocks transport profiles.
- Verified the release changes with `go test -count=1 ./...`, `go vet ./...`, `go build ./...`, and `govulncheck ./...`.
