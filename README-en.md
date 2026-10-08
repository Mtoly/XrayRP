<h1 align="center">XrayRP</h1>

<p align="center">A panel-managed proxy node runtime</p>

<div align="center">

[![Release](https://img.shields.io/github/v/release/Mtoly/XrayRP?style=flat-square)](https://github.com/Mtoly/XrayRP/releases/latest) [![Required checks](https://github.com/Mtoly/XrayRP/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/Mtoly/XrayRP/actions/workflows/test.yml) [![License](https://img.shields.io/badge/license-MPL--2.0-blue?style=flat-square)](./LICENSE)

[简体中文](./README.md) · **English** · [Tiếng Việt](./README-vi.md) · [فارسی](./README_Fa.md)

[Quick Start](#quick-start) · [Documentation](#documentation) · [Releases](https://github.com/Mtoly/XrayRP/releases) · [Docker](#docker)

</div>

## Overview

XrayRP applies panel-provided node, user and rule configuration on node hosts, then reports runtime status, traffic and online data back to the panel. It reduces configuration work on individual nodes.

The panel manages nodes and users; XrayRP owns synchronization and runtime lifecycle. Xray-core carries the main proxy protocols and transports. AnyTLS and TUIC use embedded sing-box instances; Hysteria2 uses Hysteria core/extras.

## Features

- **Panel integration**: Xboard / NewV2board use the `NewV2board` adapter. Other panels and their configuration names are listed in the [configuration example](./release/config/config.yml.example).
- **Protocol support**: VLESS, VMess, Trojan, Shadowsocks (including Plugin), AnyTLS, TUIC and Hysteria2. See the configuration example for the full `NodeType` list. Support depends on the panel, adapter and runtime versions.
- **Automatic synchronization**: Xboard / NewV2board support polling and WebSocket together. Configuration and user events use the shared REST snapshot synchronization path; polling continues when the connection drops.
- **Operations & reliability**: Traffic and online statistics, rate limits, certificate issuance and renewal, custom DNS, routing and audit rules; optional Redis device caching, health checks and Prometheus metrics. Failed configuration hot reloads preserve the last-known-good state.

Xboard VLESS Encryption uses the panel-provided server-side `decryption` value and requires inbound fallbacks to be disabled. See the [compatibility document](./docs/xboard-newv2board.md#vless-trojan-reality-and-xhttp) for VLESS REALITY, XHTTP and XTLS Vision combinations and field mappings.

AnyTLS, TUIC and Hysteria2 require certificate configuration. AnyTLS uses the panel-provided `padding_scheme`. Health checks and metrics are restricted to loopback or private addresses.

<a name="quick-start"></a>

## Quick Start

The current installation scripts require Linux, root privileges and systemd. Configure nodes or bind a machine in the panel first. Remote `ApiHost` values must use HTTPS; HTTP is reserved for loopback development addresses.

### One-click installation

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Mtoly/XrayRPS/main/install.sh)
```

After installation, edit `/etc/XrayR/config.yml` with your panel and node settings, then run `XrayR start`. See the [configuration example](./release/config/config.yml.example) for the fields.

### Xboard Machine Mode

Create and bind the machine in Xboard first, then obtain its `MachineID` and `Token`. Replace the example values below with your own. The script installs and configures the service; machine registration happens in the panel.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Mtoly/XrayRPS/main/install-machine.sh) \
  --api-host https://panel.example.com \
  --machine-id 1 \
  --token "machine-token" \
  --panel-type NewV2board \
  --ws-endpoint "wss://panel.example.com/ws"
```

Machine Mode does not use handshake discovery. Set `--ws-endpoint` explicitly to the actual public address of your deployment's `ws-server`, usually `/ws`; use `wss://` with an HTTPS panel. See the [deployment guide](./docs/xboard-newv2board.md#xboard-deployment-machine-mode-shared-websocket) for deployment and compatibility details.

`MachineConfig` and static `Nodes` are mutually exclusive. Static mode still synchronizes node configuration and users from the panel. Existing configuration is preserved by default; add `--force` only when you intend to overwrite it.

<a name="docker"></a>

### Docker

Save the [configuration example](./release/config/config.yml.example) as `/etc/XrayR/config.yml` and fill in your settings, or use an existing configuration. Then run this on the Linux node host:

```bash
docker run -d --name xrayrp --restart unless-stopped \
  --network host \
  -v /etc/XrayR:/etc/XrayR \
  ghcr.io/mtoly/xrayrp:latest
```

Images are published with the original Release tag and `latest`. Every release, including prereleases, updates `latest`; upgrading requires pulling the new image and recreating running containers. Production deployments can pin a stable Release tag.

<a name="documentation"></a>

## Documentation

| Entry | Contents |
| --- | --- |
| [Configuration example](./release/config/config.yml.example) | Panels, node types, certificates, limits and observability |
| [Xboard / NewV2board](./docs/xboard-newv2board.md) | Machine Mode, WebSocket deployment, protocol and field compatibility |
| [Architecture](./docs/architecture.md) | Module responsibilities, runtime boundaries and state invariants |
| [Releases](https://github.com/Mtoly/XrayRP/releases) · [Changelog](./CHANGELOG.md) | Downloads, version changes and release verification files |
| [go.mod](./go.mod) · [CI](./.github/workflows/test.yml) · [Release build](./.github/workflows/release.yml) | Go version requirements, tests and builds |

Source builds follow the Go version requirement in `go.mod`. Build with QUIC support using `CGO_ENABLED=0 go build -tags with_quic -o XrayR .`.

For manual downloads, verify archives against `SHA256SUMS` from the same Release. The signature bundle is `SHA256SUMS.sigstore.json`. SBOM and provenance records are retained as release workflow artifacts.

## Community & License

Report problems and suggest improvements through [GitHub Issues](https://github.com/Mtoly/XrayRP/issues).

Licensed under the [Mozilla Public License 2.0](./LICENSE).

Project history and upstream: [XrayR](https://github.com/XrayR-project/XrayR). Tool names and configuration paths retain the `XrayR` naming.

Thanks to [Project X](https://github.com/XTLS/), [V2Fly](https://github.com/v2fly), [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray) and [Air-Universe](https://github.com/crossfw/Air-Universe).
