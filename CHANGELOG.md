# Changelog

Notable user-facing, compatibility, security, performance, and operational changes are recorded here. Dates use `YYYY-MM-DD`. Internal test-only changes are included only when they alter the project's quality or release contract.

## Unreleased

### Security

- Release archives carry SPDX SBOMs, keyless Sigstore signatures, GitHub provenance attestations, and machine-readable source commit mappings.
- `govulncheck` blocks reachable findings except for a temporary, narrowly validated `GO-2026-5288` allowance: Hysteria core and extras must be at least v2.8.2 and the request-sniff hook must remain disabled.

### Added

- Added a shared release identity derived from canonical SemVer tag, full commit, build time, and dirty state, with Go VCS metadata fallback for local builds.
- Added traceability manifests for release executable and archive digests.
- Added `Limiter.StateSnapshot` as a detached read-only view of applied limiter state. The existing mutable compatibility fields remain supported and unchanged.
- Added `NodeHandlerBuilder` as an owned, opaque construction interface for inbound, embedded-user inbound, and outbound handlers. The legacy Builder functions remain supported and unchanged.

### Changed

- Initial startup and hot reload now use the same mode-specific runtime configuration validation: static mode requires at least one `Nodes` entry, while enabled `MachineConfig` is valid with no static `Nodes`.
- Added an opt-in observability server with `/livez`, `/readyz`, and bounded-label Prometheus `/metrics` for runtime lifecycle, topology generation, synchronization freshness, WebSocket degradation, cleanup ownership, traffic-report backlog, and certificate expiry.
- Observability listeners are restricted to loopback or private IP addresses because the endpoints do not provide authentication or TLS.
- The `version` command now prints the complete release identity, and V2RaySocks uses the same generated version in its User-Agent.
- Formal release and container builds now use one full `with_quic` distribution, preserving the historical protocol, ACME, registry, panel-adapter, archive-name, and image-tag behavior.
- Deprecated the partial-capability `WrapAPIWithReporter` and `WrapAPIWithStatusReporter` compatibility wrappers for machine runtimes; callers should migrate to the strict error-returning machine wrappers. No legacy behavior or implementation has been removed.
- Added `Panel.IsRunning`, `Panel.ServerInstance`, and `Panel.ServicesSnapshot` as read-only migration paths, and deprecated the mutable `Panel.Running`, `Panel.Server`, and `Panel.Service` compatibility projections without removing or changing them.
- Isolated GoV2Panel's GoFrame HTTP and JSON mechanics behind a private transport boundary while preserving request payloads, response limits, parsing, timeouts, and the adapter's effective zero-retry behavior. GoV2Panel and GoFrame remain available and are not deprecated.
- Isolated NewV2board's JSON response and transport-header parsing behind a private standard-library boundary while preserving report, snapshot, ETag, cancellation, alive-list, and obfuscation-header behavior. V2RaySocks still owns its public `go-simplejson` compatibility surface, so the dependency remains available and is not deprecated.
- Isolated lego's complete ACME DNS provider registry behind a private boundary while preserving all generated provider names, aliases, case sensitivity, and configuration behavior. No provider was removed or deprecated.
- Centralized AnyTLS and TUIC's complete sing-box registry context behind one private boundary and locked the complete Xray registry import set. Protocols, transports, loaders, and commands remain unchanged.
- Isolated the limiter's local TTL and Redis shared cache composition behind a private lifecycle-owned boundary while preserving local-first lookup, Redis backfill, expiry, and fail-open behavior. Cache dependencies and configuration remain supported and unchanged.
- Locked the complete static panel adapter alias set and the NewV2board/V2board machine-mode boundary; aligned translated support tables and configuration examples without changing adapter behavior.
- Machine-mode AnyTLS, TUIC, and Hysteria2 nodes now consume the existing shared WebSocket as bounded authoritative REST snapshot triggers. User and configuration bursts are coalesced per node, polling remains the fallback, and traffic reporting is not multiplied by WebSocket events.

### Fixed

- Restored release-page artifact builds and uploads for published GitHub Releases, including the repository's historical SemVer tags without a leading `v`.
- Removed the deleted `tools` source root from the panel adapter isolation check so required test, race, and coverage jobs pass in clean checkouts.
- Configuration hot reload now supports static-to-static and machine-to-machine updates, rejects static/machine mode changes before closing the current runtime, and restores the last-known-good runtime when a same-mode candidate fails to start.
- Removed unowned per-inbound cache backfill and local janitor goroutines so limiter replacement, deletion, and shutdown can reclaim local cache state and close Redis deterministically.
- Preserved the latest confirmed machine Applied node value across specialized runtime synchronization so failed REST, reload, cleanup, or replacement candidates cannot become rollback inputs.

## 0.9.1-alpha-3 - 2026-07-29

Contains committed changes on `master` after tag `0.9.1-alpha-2`. Uncommitted working-tree changes are not listed.

### Security

- Bounded untrusted panel response bodies before parsing and centralized shared HTTP response-safety behavior.
- Updated reachable dependencies with security fixes, including Hysteria, sing-box/sing, gRPC, Redis, `x/net`, and `x/crypto`.
- Made certificate acquisition, storage, renewal, and runtime replacement transactional so partial filesystem or reload failures preserve the last-known-good certificate and runtime.
- Hardened limiter ownership, special-protocol admission, audit identity, and managed-node routing so invalid or stale state fails closed instead of bypassing enforcement.

### Changed

- Specialized AnyTLS, TUIC, and Hysteria2 runtimes now start, reload, publish state, stop monitors, and shut down through explicit lifecycle ownership.
- Runtime replacement and configuration reload use transactional candidate construction and preserve the last-known-good generation on failure.
- WebSocket lifecycle, reconnect, restart, cancellation, and join behavior are centralized and deterministic.
- Machine topology reconciliation now separates discovery, decisions, execution, scheduling, and reporting while preserving healthy nodes during partial failures.
- Panel adapters, runtime plans, construction seams, and optional capabilities use explicit ownership and compatibility boundaries.
- Limiter state is privately owned while legacy public compatibility surfaces remain supported.

### Performance

- Reduced traffic-statistics contention for AnyTLS, TUIC, and Hysteria2 using shared counters with correctness and benchmark coverage.
- Kept limiter admission behavior measured against the single-node design target while strengthening synchronization and lifecycle ownership.

### Fixed

- Preserved pending certificate reloads, WebSocket restart state, port-hop cleanup, and periodic monitor retries across transient failures.
- Joined replaced machine scheduling loops and runtime-owned goroutines during shutdown.
- Returned special-protocol limiter and audit failures instead of silently accepting or losing them.
- Prevented half-published specialized runtime state and inconsistent managed-node identity during replacement.

## 0.9.1-alpha-2 - 2026-07-12

### Changed

- Made panel lifecycle transitions and partial-start rollback explicit.
- Narrowed optional panel capability seams and normalized not-modified outcomes.
- Moved controller runtime state into owned immutable snapshots.
- Added portable CI race and coverage acceptance gates plus local panel-adapter contract coverage.

### Fixed

- Preserved synchronization execution failures instead of reporting failed operations as successful.
- Rolled back partially started panel services when later startup steps failed.

## 0.9.1-alpha - 2026-07-10

### Security

- Limited incoming WebSocket messages to 1 MiB.
- Required discovered WebSocket endpoints to remain on the panel origin and prevented HTTPS-to-WS downgrade.
- Hardened managed outbound handoff against missing, mismatched, raw, or recursive handlers.
- Kept Hysteria2 request sniffing disabled as defense in depth for `GO-2026-5288`; the upstream parser fix is present, but the Go vulnerability record does not identify a fixed core version.
- Prevented UniProxy snapshots and certificate environment maps from exposing shared mutable state.

### Changed

- Upgraded the Go toolchain and Docker build path to Go 1.26.5 and synchronized Hysteria dependencies.
- Consolidated node state, synchronization commits, user rollback, and routing decisions behind explicit runtime boundaries.
- Redacted credential-bearing diagnostics by default while retaining the opt-in detailed-error mechanism.

## 0.9.1 - 2026-06-29

### Changed

- Introduced explicit runtime configuration, certificate, node-service dispatch, machine reporting, discovery, and reconciliation materialization boundaries.
- Centralized controller node-state application and tightened user, route, rule, and global-device rollback.
- Normalized NewV2board snapshots before runtime construction.

### Fixed

- Preserved healthy machine-managed nodes when discovery, startup, or replacement operations failed.
- Prevented partial runtime-state publication during controller updates.

## 0.9-alpha series - 2026-05-18 to 2026-06-28

Covers tags `0.9-alpha` through `0.9-alpha-10`.

### Added

- Added Xboard/NewV2board WebSocket + polling dual-active synchronization, endpoint discovery, keepalive, reconnect resync, and polling fallback.
- Added a unified synchronization action, coordinator, and apply pipeline using REST snapshots as the authoritative source for complex state.
- Added Xboard single-node device synchronization and changed-only WebSocket device reporting.
- Added Xboard machine/server management with machine-bound node discovery, shared WebSocket transport, per-node lifecycle, device reporting, and machine load/status reporting.
- Added Xboard `base_config` runtime scheduling, route/outbound policy support, content certificate support, v2 machine endpoints, report fallback, and lowercase node-type normalization.
- Added local V2RaySocks transport-profile derivation and opt-in integration-test gates for network-dependent behavior.

### Changed

- Polling and WebSocket triggers converge through one synchronization and apply path.
- Machine configuration is mutually exclusive with static `Nodes`.
- Credential-bearing errors are redacted by default, with detailed errors available through explicit configuration.

### Fixed

- Preserved local REALITY configuration when SSPPanel omitted remote REALITY settings.
- Rejected malformed Xboard device identifiers and serialized global-device admission updates.
- Preserved healthy machine-managed nodes when new node services failed to start.
- Tightened route/rule and same-tag runtime rebuild rollback.

See [Xboard / NewV2board Compatibility](./docs/xboard-newv2board.md) for the current compatibility contract.

## 0.9.8 - 2026-02-11

This tag predates the current changelog structure. Consult the Git history for detailed changes before the `0.9-alpha` series.
