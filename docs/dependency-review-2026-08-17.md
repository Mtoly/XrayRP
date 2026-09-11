# XrayRP Dependency Review — 2026-08-17

## Scope

This review covers the current working tree against `b1fa359f`, the Go module
graph, Docker base images, GitHub Actions pins, and the existing Dependabot
configuration. The initial inventory was read-only; the follow-up maintenance
batch below applied the prioritized patch updates without changing Xray Core or
performing a major import-path migration.

## Local inventory

Commands and observed results:

- `go list -m -u -json all`: 961 modules, 536 available updates, 29 declared
  direct dependencies.
- `go mod tidy -diff`: no diff.
- `go mod verify`: `all modules verified`.
- `go version`: `go1.26.6`; `go.mod`: `go 1.26.6`.
- At the time of this review, the updated scan reported only reachable
  `GO-2026-5288`; the narrow CI exception described below was then in effect.

## Priority matrix (pre-update inventory)

| Area | Current | Candidate/evidence | Recommendation |
|---|---|---|---|
| Go toolchain | `1.26.5` | Official Go download/release channel lists `1.26.6` | Immediate patch update in `go.mod`, CI, and Docker builder. |
| Docker Go builder | `golang:1.26.5-alpine` with digest | Official image tags list `1.26.6-alpine` | Update tag and digest together with Go. |
| Hysteria core/extras | `v2.12.0` | Module proxy offers `v2.12.1`; upstream release page lists the release | Patch update candidate; rerun Hysteria tests, QUIC build, and the sniff-disabled exception test. |
| sing-box/sing | `v1.13.16` / `v0.8.12` | Module proxy offers `v1.13.18` / `v0.8.13` | Update as one runtime batch. |
| `x/crypto`, `x/net`, protobuf | `v0.54.0`, `v0.57.0`, `v1.36.11` | Module proxy offers `v0.55.0`, `v0.58.0`, `v1.36.12` | Routine patch batch after the toolchain fix. |
| Xray Core | module `v1.260327.0` | No newer module-proxy version; GitHub lists newer `v26.6.27` and `v26.7.28` release tags | Dedicated canary branch. Do not use blind `go get`; test XHTTP, REALITY, routing, synchronization, and release builds. |
| lego | `v4.35.2` | Latest v4 line is `v4.35.2`; repository also has v5.3.1 | Keep v4 for now; v5 is a major import-path migration. |
| Resty | `v2.17.2` | Latest v2 line observed as `v2.17.2` | No action. |
| Redis | `v9.22.0` | Latest v9 line observed as `v9.22.0` | No action. |
| Viper | `v1.21.0` | No newer module-proxy update | No action. |
| Prometheus client | indirect `v1.23.2` | Module proxy offers `v1.24.1` | Low-risk indirect update candidate; group with routine dependency maintenance. |
| Alpine runtime image | `3.22.1` with digest | Official Alpine tags list newer 3.22 patch releases | Refresh to the selected supported patch release and digest. |
| CodeQL Action | SHA comment `v4.37.3` | Official releases list `v4.37.7` | Routine Actions pin refresh. |

## Security interpretation

At the time of this review, the Go patch update to `1.26.6` cleared the seven
standard-library advisories from the initial scan. `GO-2026-5288` was the
remaining Hysteria sniff OOM advisory and had no fixed version in the
vulnerability database; the code kept the vulnerable sniff hook disabled, and
CI used a narrow exception while testing that invariant.

The CI policy recorded on 2026-08-17 accepted only `GO-2026-5288`. That policy
was superseded by the 2026-09-11 follow-up below.

## Primary sources

- [Go downloads and release information](https://go.dev/dl/)
- [Go vulnerability: GO-2026-6218](https://pkg.go.dev/vuln/GO-2026-6218)
- [Hysteria vulnerability: GO-2026-5288](https://pkg.go.dev/vuln/GO-2026-5288)
- [Hysteria releases](https://github.com/apernet/hysteria/releases)
- [sing-box releases](https://github.com/SagerNet/sing-box/releases)
- [Xray Core releases](https://github.com/XTLS/Xray-core/releases)
- [lego releases](https://github.com/go-acme/lego/releases)
- [Resty releases](https://github.com/go-resty/resty/releases)
- [go-redis releases](https://github.com/redis/go-redis/releases)
- [Prometheus client releases](https://github.com/prometheus/client_golang/releases)
- [CodeQL Action releases](https://github.com/github/codeql-action/releases)
- [Official Go Docker image tags](https://hub.docker.com/_/golang/tags)
- [Official Alpine Docker image tags](https://hub.docker.com/_/alpine/tags)

## Follow-up execution result

- [x] Go `1.26.6` applied to `go.mod`; the Docker builder now uses
  `golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83`.
- [x] Runtime image refreshed to
  `alpine:3.22.5@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce`.
- [x] CodeQL pins refreshed to commit
  `ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd` (`v4.37.7`).
- [x] Hysteria, sing, sing-box, `x/crypto`, `x/mod`, `x/net`, protobuf, and
  logrus patch updates applied.
- [x] `go mod tidy -diff`, `go mod verify`, focused tests, full tests, vet,
  normal build, QUIC build, and updated vulnerability scan passed.
- [!] Windows race execution still requires Linux CI because the environment
  has no `gcc` compiler.

## Validation matrix for the follow-up change

1. Update Go `1.26.6` in `go.mod`, CI, and `Dockerfile`; refresh image digests.
2. Run `go mod tidy -diff`, `go mod verify`, `go test -count=1 ./...`,
   `go vet ./...`, `go build ./...`, and `go build -tags with_quic .`.
3. Run the focused Linux race command and `govulncheck -format openvex ./...`.
4. Update Hysteria and sing-box in a separate dependency batch, then run
   protocol lifecycle, QUIC, reload, panel compatibility, and release tests.
5. Verify Docker image provenance and the pinned Action SHAs before merging.

## Patch follow-up — 2026-09-09

- Updated `github.com/apernet/hysteria/core/v2` and
  `github.com/apernet/hysteria/extras/v2` from `v2.12.1` to `v2.12.2`.
- `go test -count=1 ./service/hysteria2 ./service/controller` passed.
- `govulncheck v1.6.0 ./...` still reports only reachable `GO-2026-5288` for
  `core/v2@v2.12.2`; the database continues to publish no fixed version.
- The `RequestHook: nil` defense-in-depth test and exact CI exception remained
  in force at the time; the exception was superseded by the 2026-09-11 policy
  follow-up below.

## Policy follow-up — 2026-09-11

- PR #208 removed the expired `GO-2026-5288` exception after the Hysteria
  `v2.12.2` update still provided no fixed dependency version.
- `govulncheck` now fails closed on every reachable vulnerability reported with
  OpenVEX status `affected`; `GO-2026-5288` therefore remains release-blocking.
- The independent `RequestHook: nil` regression test remains in CI as
  defense-in-depth evidence, but it no longer permits an affected result to pass.
