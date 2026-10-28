# Changelog

Notable user-facing, compatibility, security, performance, and operational changes are recorded here. Dates use `YYYY-MM-DD`. Internal test-only changes are included only when they alter the project's quality or release contract.

## Unreleased

## 0.9.11 - 2026-10-28

### Added

- Added opt-in Redis global source-IP admission, configured through `ControllerConfig.GlobalDeviceLimitConfig`. When enabled, one source-IP quota follows the panel UID across XrayRP nodes, processes, and the Xray, AnyTLS, TUIC, and Hysteria2 paths. The same normalized address counts once even when it opens several connections, IPv4-mapped IPv6 addresses count as IPv4, and IPv6 addresses are grouped by `IPv6Prefix` (default `/64`; an explicit `0` counts the full address). `Mode: cache` is the default compatibility mode and reuses a confirmed reservation, while `Mode: strict` verifies every new connection against Redis. `FailMode: open` keeps serving with a process-local quota when Redis fails; `FailMode: closed` rejects new connections that cannot be verified. Leases renew while a connection stays open, including idle connections, and expire by TTL after a crash; lowering a limit does not disconnect addresses that are already admitted. While enabled, panel device snapshots no longer drive admission or online-IP cropping. The feature is disabled by default; configurations with `GlobalDeviceLimitConfig.Enable: false` keep local-only admission. Existing Redis-enabled deployments change behavior as described in the upgrade notes below. See [docs/redis-global-ip-limit.md](docs/redis-global-ip-limit.md).

### Upgrade notes

- If `GlobalDeviceLimitConfig.Enable` was already `true` on an older version, upgrading switches that deployment from the legacy Redis cache to shared panel-namespace/UID admission. Xray, AnyTLS, TUIC, and Hysteria2 now participate; specialized runtimes previously enforced only local device limits. Without an explicit `Namespace`, the panel type and `ApiHost` derive the shared namespace, so the same panel UID can share a quota across nodes without adding a new configuration switch. Review this behavior change before upgrading existing Redis-enabled deployments. The defaults remain `Mode: cache` and `FailMode: open`; cache mode is not a strict distributed guarantee.
- Redis global source-IP admission requires a coordinated upgrade. Nodes running an older version do not participate in the shared quota and keep their previous local and cache behavior, and participating nodes must use the same namespace, `Mode`, `IPv6Prefix`, and Redis database. New entries use a dedicated Redis key prefix and expire by TTL, so upgrading does not require deleting existing keys.

### Security

- Updated `github.com/go-jose/go-jose/v4` from `v4.1.4` to `v4.1.6`, including the JWK RSA parsing denial-of-service fix for GHSA-mgcc-cww5-fp2q. Upstream now caps parsed JWK RSA moduli at 4096 bits; XrayRP's existing certificate-account and DNS signing paths do not use that JWK parsing entry point.
- Updated `github.com/go-chi/chi/v5` from `v5.2.5` to `v5.4.0`, including the `ClientIPFromXFF` fix for GHSA-j6qf-3m9c-vwj3. XrayRP does not use this middleware for source-IP admission; the update does not change forwarded-header trust configuration.
- Updated `golang.org/x/net` from `v0.61.0` to `v0.62.0` to fix GO-2026-6860 (CVE-2026-78661), quadratic text-node coalescing in the HTML parser reachable through the Lego ddnss DNS provider. Existing vulnerability-gate exceptions are unchanged.

### Changed

- Updated the Docker runtime base from Alpine `3.24.2` to `3.24.3` and refreshed the digest-pinned Go `1.27.3-alpine` builder image. The Go version and full `with_quic` build remain unchanged.
- Updated both GHCR publishing jobs to `docker/login-action v4.7.0`, retaining commit-SHA pins and the existing registry inputs and permissions.

### Fixed

- Rejected an authenticated Xray connection whose source is not an IP address before device admission, instead of passing a missing or non-IP source into device checking.

## 0.9.10 - 2026-10-27

### Changed

- Updated the embedded sing-box runtime from `v1.14.3` to `v1.14.4` with its required dependency updates, including sing, sing-quic, sing-tun, and SagerNet quic-go. This brings upstream UDP/QUIC stability, routing, and connection cleanup fixes. The existing AnyTLS and TUIC runtime user-update integrations are retained.

## 0.9.9 - 2026-10-22

### Upgrade notes

- When upgrading from 0.9.7, Xray TLS outbounds use bundled root certificates by default instead of the operating system's trust store. Custom outbounds that rely on an OS-installed private or enterprise CA must configure that CA explicitly in their Xray TLS settings or select system roots with `"useSystemCA": true` in `tlsSettings`. Certificate and hostname verification remain enabled. Managed `freedom` outbounds do not themselves verify TLS server certificates.
- Version 0.9.8 remains retired; this release advances directly from 0.9.7 to 0.9.9.

### Changed

- Updated Xray-core from `v1.260327.1-0.20261021080731-ec73b73f5e2f` to `v1.260327.1-0.20261021115930-1b1647cd9ddf` (upstream `v26.10.21`), retaining the bundled-root security update below. This adds upstream fixes for SOCKS UDP connection timers, HTTP outbounds handling server-first traffic, Linux UDP process routing, and UDP dialer-controller destination addresses. It also includes upstream XDRIVE enhancements, inbound finalmask source-IP filters, Linux TUN read optimizations, and owner-only permissions for newly created TLS/REALITY key-log files. XrayRP's panel mappings and public YAML configuration are unchanged; upstream additions do not imply new panel-level support.
- Updated Xray-core from the `v1.260327.1-0.20261005035322-5121c28b855c` pin to `v1.260327.1-0.20261017152356-92ccc939aaf4` (upstream `v26.10.17`). The update brings the REALITY library refresh with standard-library ML-DSA, the VLESS Vision server crash fix for Go 1.27.3-and-later toolchains, the Shadowsocks 2022 UDP connection-reuse and interrupt fixes, and the Mux client UDP and race fixes. It also drops the `gvisor` dependency (`layeh.com/gopher-luar`, `github.com/yuin/gopher-lua`, and `golang.org/x/crypto/x509roots/fallback` are added as indirect dependencies; `cloudflare/circl` and `gvisor.dev/gvisor` are removed). Panel behavior, supported protocols, transports, configuration, and reporting are unchanged.

### Security

- Updated Xray-core to `v1.260327.1-0.20261021080731-ec73b73f5e2f`, including the bundled root-certificate update that removes emSign ECC Root CA - C3, emSign ECC Root CA - G3, and emSign Root CA - C1, and cpuid `v2.4.1`. Xray TLS outbounds using the default bundled roots no longer trust these roots; explicitly configured CA certificates and system-root selection remain supported.
- Raised the minimum Go version and the digest-pinned Docker builder to Go `1.27.3` to include the `crypto/x509` fix for `GO-2026-6809`. The runtime Alpine image is unchanged.

### Documentation

- Clarified that `/readyz` can return HTTP 200 for a ready but degraded runtime, while unready runtimes return HTTP 503. Corrected the reload and machine-node replacement descriptions: the old runtime closes before the replacement starts, so rollback does not guarantee uninterrupted existing connections. Runtime behavior is unchanged.

## 0.9.7 - 2026-10-16

### Changed

- Updated sing-box from `v1.14.2` to `v1.14.3` with its dependency graph, including sing `v0.9.7-0.20260929150544-0ad23b637bd4`, sing-quic `v0.7.2-0.20261002084117-75c3ac4fa12b`, and sing-tun `v0.9.7-0.20261009020158-bca4bf029237`. The XrayRP AnyTLS and TUIC listeners follow the upstream `v1.14.3` lifecycle, and TUIC listeners no longer force-enable UDP fragmentation, matching the upstream QUIC inbounds.
- Updated Hysteria core and extras from `v2.12.3` to `v2.13.0`.
- Updated sing-anytls from `v0.0.11` to `v0.0.13`.
- Updated `golang.org/x/net` to `v0.61.0`, `golang.org/x/crypto` to `v0.58.0`, `golang.org/x/mod` to `v0.42.0`, and go-redis to `v9.23.0`.

### Security

- Removed authentication credentials from Hysteria2 audit disconnect warnings. The warnings now identify known users by panel UID and omit user identity when the user is no longer present.

### Fixed

- Unified startup and certificate synchronization over the original local certificate configuration. Panel fields take precedence when supplied, while omitted DNS credentials and other fields fall back to local configuration; values removed from later panel snapshots no longer persist from earlier snapshots. Removing panel certificate configuration restores the local configuration.
- Preserved AnyTLS/TUIC device-limit reservations across online reports. Connections from the same IP now share one device slot until the last connection closes, including idle connections; closing a rejected, duplicate, or retired connection no longer releases another connection's slot.

## 0.9.6 - 2026-10-12

### Security

- Updated `golang.org/x/net` from `v0.59.0` to `v0.60.0` to fix the reachable advisories `GO-2026-6603`, `GO-2026-6610`, `GO-2026-6611`, `GO-2026-6612`, and `GO-2026-6617`.
- Updated the Docker builder image from Go `1.27.1` to `1.27.2` so container binaries include the Go standard-library security fixes released in `1.27.2`.

### Fixed

- Kept Xray node user traffic that arrives while a traffic report is in flight; a successful report now subtracts only the reported bytes instead of zeroing the counters.
- Applied panel user changes to running AnyTLS and TUIC listeners. Added users and changed credentials previously failed authentication until the node was rebuilt by a configuration change, certificate renewal, or restart; user updates now take effect without dropping established connections. The listeners are derived from the sing-box `v1.14.2` AnyTLS and TUIC inbounds.
- Bounded Xboard/NewV2board WebSocket event writes to 10 seconds. A panel connection that stops reading no longer blocks the WebSocket runtime and its shutdown until TCP gives up; the write fails and the runtime reconnects while polling continues.
- Retried the last known good configuration every 30 seconds when a hot reload fails to start both the new and the previous configuration, for example during a panel outage. Previously no node ran until the next configuration change or a manual restart.

## 0.9.5 - 2026-10-07

### Changed

- Advanced Xray-core to `v1.260327.1-0.20261005035322-5121c28b855c` and adapted XrayRP to the upstream error API changes.
- Updated sing-box from `v1.14.0` to `v1.14.2` with its dependency graph.
- Updated Hysteria core and extras from `v2.12.2` to `v2.12.3`.

### Security

- Pinned gRPC to `v1.85.0-dev.0.20260825072537-93e31b48545e` to retain the fix for `GO-2026-6443` across the Xray-core dependency update.

### Fixed

- Restricted Linux Hysteria2 port-hopping redirects to local destinations, preventing forwarded UDP traffic with overlapping destination ports from being redirected to the local listener.
- Preserved custom gRPC outbound reconnection after remote restarts by including the upstream reconnect fix in the Xray-core update.
- Corrected QUIC sniffing of fragmented Initial ClientHello packets with zero-filled datagram tails, allowing SNI recovery instead of premature `not initial packet` failures.

## 0.9.4 - 2026-10-01

### Added

- Documented the Xboard machine-mode shared WebSocket operator path: the standalone `ws-server` runs separately from the panel HTTP service, machine mode requires an explicit `Endpoint` because it does not use handshake discovery, the reverse proxy must forward the WebSocket upgrade to the ws-server port, and `/readyz` plus `xrayrp_runtime_state` metrics are the acceptance checks. The machine-mode installer examples now pass `--ws-endpoint` so they point at the path current Xboard actually serves instead of the legacy `UniProxy/ws` fallback.

### Security

- Updated OpenTelemetry dependencies to a patched version to address a low-severity dependency advisory.

### Fixed

- Controller shutdown now delivers stop signals to every periodic producer before joining any of them, keeps a producer that has not exited owned instead of tearing down the sync coordinator, rules, limiter, or node runtime underneath it, and lets a later close retry the join against the real runner instead of replaying the first deadline error. A periodic runner's first iteration now responds to both startup-context and lifecycle cancellation, preserving the caller's cancellation/deadline classification while still letting close stop it, and later iterations remain owned only by the lifecycle context.

- Hot reload now tolerates transient non-atomic configuration writes by observing a short bounded window before committing a file-based candidate, so a valid-but-incomplete intermediate snapshot is no longer applied as the writer's final state. The window is at most 5 snapshots, 50 ms apart, capped by the reload deadline; the candidate is classified from the tail of that window (stable and valid is accepted, stable and invalid returns the original validation error, and a file that never quiesces is reported as still being modified). Matching snapshots are a best-effort quiescence signal, not proof that the writer finished, so writing the configuration atomically (temporary file, fsync where appropriate, then rename/replace) remains the strong operator-side guarantee. Runtime-mode changes are still rejected, the last-known-good configuration is preserved, and configuration contents are never logged.

## 0.9.3 - 2026-09-27

### Added

- Docker releases explicitly publish the original release tag and `latest`, including legacy non-SemVer release tags, so `ghcr.io/mtoly/xrayrp:latest` always follows the most recently published release.

### Security

- Prevented panel user identifiers and credentials from entering Xray runtime user tags and debug-visible traffic counter names; authentication UUIDs remain confined to protocol account settings.

### Fixed

- Refreshed controller sync health after successful synchronization so an active runtime does not become `sync_stale` in `/readyz` while syncs continue.
- Passed Xboard/NewV2board VLESS server decryption through Machine and static node snapshots to Xray-core inbounds, retaining `none` for unencrypted nodes and redacting decryption validation errors.
- Kept a panel-provided `xtls-rprx-vision` flow for VLESS nodes with server-side VLESS Encryption enabled instead of clearing it for non-TCP transports such as XHTTP; unencrypted VLESS keeps the existing transport restriction.

## 0.9.2 - 2026-09-12

### Security

- Releases publish platform archives with one signed SHA256 index; per-platform SPDX SBOMs, source mappings, keyless signatures, and GitHub provenance attestations remain generated as workflow evidence.
- `govulncheck` fails closed on reachable vulnerabilities except for a temporary `GO-2026-5288` allowance when it is the sole reachable finding, Hysteria core and extras are at least v2.8.2, and the request-sniffing mitigation test passes.
- Runtime configuration now rejects plaintext HTTP for remote panel API hosts before publishing a candidate; HTTP remains available for loopback development endpoints.
- Panel adapter parsing errors no longer serialize node or user responses that may contain passwords, UUIDs, protocol keys, or certificate material.

### Added

- Added a shared release identity derived from canonical SemVer tag, full commit, build time, and dirty state, with Go VCS metadata fallback for local builds.
- Added traceability manifests for release executable and archive digests.
- Added `Limiter.StateSnapshot` as a detached read-only view of applied limiter state. The existing mutable compatibility fields remain supported and unchanged.
- Added `NodeHandlerBuilder` as an owned, opaque construction interface for inbound, embedded-user inbound, and outbound handlers. The legacy Builder functions remain supported and unchanged.

### Changed

- Updated the CI vulnerability scanner to govulncheck v1.8.0 so the security gate can analyze the Go 1.27 codebase.
- Upgraded supported Go, Redis, Hysteria core/extras to v2.12.0, sing, sing-box, artifact, container, stale-issue, and signing dependencies; GitHub Actions remain pinned to full commit SHAs.
- Updated the Go toolchain to 1.26.6, Hysteria core/extras to v2.12.1, sing to v0.8.13, sing-box to v1.13.18, and refreshed the pinned Alpine and CodeQL maintenance inputs.
- Updated Hysteria core/extras to v2.12.2; the vulnerability gate follows the temporary exception described above.
- Docker builds now pin both the Go builder and Alpine runtime images by readable version and multi-platform manifest digest.
- Controller and machine runtimes now share one Applied node value deep-clone module, preserving nil/empty collection and custom address compatibility semantics.
- Initial startup and hot reload now use the same mode-specific runtime configuration validation: static mode requires at least one `Nodes` entry, while enabled `MachineConfig` is valid with no static `Nodes`.
- Added an opt-in observability server with `/livez`, `/readyz`, and bounded-label Prometheus `/metrics` for runtime lifecycle, topology generation, synchronization freshness, WebSocket degradation, cleanup ownership, traffic-report backlog, and certificate expiry.
- Hot reload metrics now expose bounded candidate, stop, start, commit, rollback, attempt, outcome, and interruption-duration observations while keeping the existing last-known-good activation transaction.
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

- Restored Android/arm64 release builds under Go 1.23 and later by enabling the linker compatibility flag required by the Android network-interface dependency.
- Updated the pinned Docker builder image to Go 1.27.1 so release container builds satisfy the Go 1.27 module requirement.
- Preserved explicit XHTTP transport settings when advanced `extra` options are present under Xray-core v26, instead of silently replacing headers, padding, placement, and uplink fields with upstream defaults.
- Restored release-page artifact builds and uploads for published GitHub Releases, including the repository's historical SemVer tags without a leading `v`; release commands now identify the repository explicitly, and tag pushes no longer start a duplicate artifact workflow.
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

## Historical numbering note

An older `0.9.8` tag/release used a version number outside the current release sequence. Its GitHub Release and active remote and primary local tag references were intentionally retired in October 2026, while the underlying commits and Git history remain preserved.

The maintained release sequence continues from `0.9.4` through `0.9.5` and `0.9.6` to `0.9.7`.
