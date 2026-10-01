# XrayRP

一个 **panel-managed Xray runtime framework**：面板下发节点与用户配置，XrayRP 在本地收敛为运行中的 Xray 实例，并把运行观测回传给面板。

当前版本：`0.9.3`（见 [CHANGELOG.md](./CHANGELOG.md)）

[![Release](https://github.com/Mtoly/XrayRP/actions/workflows/release.yml/badge.svg)](https://github.com/Mtoly/XrayRP/actions/workflows/release.yml)
[![Docker](https://github.com/Mtoly/XrayRP/actions/workflows/docker.yml/badge.svg)](https://github.com/Mtoly/XrayRP/actions/workflows/docker.yml)
[![Required checks](https://github.com/Mtoly/XrayRP/actions/workflows/test.yml/badge.svg)](https://github.com/Mtoly/XrayRP/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](./LICENSE)

[English](./README-en.md) | [فارسی](./README_Fa.md) | [Tiếng Việt](./README-vi.md)

- 面板操作者：Xboard / NewV2board、sspanel-uim、v2board 等面板下发配置，XrayRP 负责节点生命周期与上报。
- 自建节点维护者：单实例对接多面板多节点，静态 `Nodes` 模式或机器管理模式按需选择。
- 贡献者与审阅者：发布产物、CI 门禁与运行观测都可在本文件与文档中定位。

详细说明见 [架构文档](./docs/architecture.md) 与 [Xboard / NewV2board 兼容性文档](./docs/xboard-newv2board.md)。

## Features

### Panel & Control Plane

- Xboard / NewV2board：通过 `NewV2board` 适配器对接 Xboard 与 NewV2board。
- Machine Mode：`MachineConfig` 使用 `MachineID` + `Token` 对接，单实例自动发现本机器绑定的节点并动态启停。
- Node discovery：机器模式下按面板下发的 `base_config.pull_interval` 周期性发现节点（最小 30 秒，未下发时使用 `DiscoveryInterval`）。
- WebSocket sync：机器模式共用一条 WebSocket 连接接收 `sync.nodes` 并按 `node_id` 分发；断开后按 `ReconnectBackoff` 重连，`ResyncOnReconnect` 打开时触发全量重同步。普通 Xray 节点使用 `kind="controller"` 状态，AnyTLS / TUIC / Hysteria2 使用各自的 `kind` 且 `websocket="disabled"`，它们接收节点级触发但不独占连接。
- 收敛语义：轮询、WebSocket、重连与手动触发收敛到同一条同步与 apply 路径；候选配置只有在运行时 apply 成功后才成为 Applied 值。

### Protocols & Transports

- VLESS（含 REALITY / XHTTP / WS / gRPC / HTTPUpgrade）
- VMess
- Trojan
- Shadowsocks（含 Shadowsocks-Plugin）
- AnyTLS（专用运行时，使用面板下发的 `padding_scheme`）
- TUIC（专用运行时，需要本地证书配置）
- Hysteria2（专用运行时，需要本地证书配置）

节点类型清单与其他传输能力（含 Socks、HTTP）见 [config.yml.example](./release/config/config.yml.example) 中的 `NodeType` 注释。

### Advanced VLESS

- VLESS Encryption：Xboard 通过 `/api/v2/server/config` 的顶层 `decryption` 字段下发服务端密钥，XrayRP 原样传给 Xray-core inbound；缺失、`null` 或空值保持 `none`。启用加密解密时 Xray-core 不允许叠加 inbound fallback，需关闭 fallback。
- XTLS Vision：面板下发 `xtls-rprx-vision` 时，未加密 VLESS 仅在直连 TCP TLS / REALITY 下生效；其他传输会被清除。
- XHTTP / WS / gRPC：当服务端 VLESS Encryption 生效时（`decryption` 非空且不为 `none`），XrayRP 不再按传输清除 `xtls-rprx-vision`，而是保留面板下发的值。XrayRP 不会自行添加该 flow。

### Operations

- 用户流量统计与节点状态上报，report 端点回退链见兼容性文档。
- 在线 IP 限制、在线用户限制、节点端口限速、用户限速；可选 Redis 全局设备缓存用于多实例协同。
- 证书自动申请与续签（`common/mylego`，支持 ACME DNS/HTTP/TLS 等方式与自定义文件）。
- 自定义 DNS、路由与审计规则（`DnsConfigPath`、`RouteConfigPath`、`RuleListPath`）。
- 可观测性：可选的本地 `/livez`、`/readyz`、`/metrics`（`Observability` 配置，默认关闭且仅允许回环或私有地址），输出 `xrayrp_runtime_state` 等指标。
- 热重载：配置变更后重新加载候选配置，在校验与 apply 成功后才替换运行中的实例。

### Release & Security

- CodeQL 静态分析（`codeql-analysis.yml`，push / PR / 每周计划）。
- govulncheck 可达漏洞扫描，仅允许已被记录并有版本下限约束的例外（`test.yml`）。
- Dependabot 依赖与基础镜像更新。
- 签名发布产物：发布页提供各平台归档与 `SHA256SUMS`，并附带 `SHA256SUMS.sigstore.json` Sigstore 签名。
- SPDX SBOM、发布清单与 provenance attestation 由发布工作流生成，并作为 workflow evidence 保留。
- Docker PR 验证：改动 `Dockerfile` 或 docker workflow 的 PR 会构建镜像并执行 `version` 冒烟测试（`docker-test.yml`）。

## Architecture

```mermaid
flowchart TD
    P[Panel<br/>Xboard / NewV2board / sspanel-uim / v2board] -->|节点与用户快照| G[XrayRP]
    G -->|apply| C[Xray Core<br/>inbound / outbound / routing]
    C -->|运行状态| G
    G -->|状态、流量、在线数据上报| P
```

- Panel：下发节点、用户、路由与审计规则，并接收上报。
- XrayRP：把面板快照收敛为本地运行状态，负责运行时生命周期（启动、就绪、停止与回收、替换、失败状态）、限速与规则执行、证书管理，以及上报。
- Xray Core：实际承载协议与传输，XrayRP 通过 `app/` 与其交互。

代码位置与不变量见 [架构文档](./docs/architecture.md)。

## Installation

### 一键安装脚本

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Mtoly/XrayRPS/main/install.sh)
```

### Xboard Machine Mode 安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Mtoly/XrayRPS/main/install-machine.sh) \
  --api-host https://panel.example.com \
  --machine-id 1 \
  --token "machine-token" \
  --panel-type NewV2board \
  --ws-endpoint "wss://panel.example.com/ws"
```

- 该脚本只生成 `MachineConfig` 并安装 / 启动服务，不会在 Xboard 中创建或注册机器，请先在 Xboard 创建 / 绑定机器。
- `MachineConfig` 与静态 `Nodes` 互斥；启用机器模式时不会生成静态 `Nodes`。
- 机器模式不使用 handshake 自动发现，请用 `--ws-endpoint` 显式填写 Xboard `ws-server` 对外地址（通常为 `/ws`）；省略时回退到旧版 `<ApiHost>/api/v1/server/UniProxy/ws`，当前 Xboard 不再提供该路由。
- 已有 `/etc/XrayR/config.yml` 时脚本默认不覆盖，确认覆盖再加 `--force`。

### Docker（GHCR）

镜像：`ghcr.io/mtoly/xrayrp`，发布时同时打上原始 release tag 与 `latest`。

```bash
mkdir -p /etc/XrayR
cp release/config/config.yml.example /etc/XrayR/config.yml
# 编辑 /etc/XrayR/config.yml 后启动
docker run -d --name xrayrp --restart unless-stopped \
  --network host \
  -v /etc/XrayR:/etc/XrayR \
  ghcr.io/mtoly/xrayrp:latest
```

容器入口为 `XrayR --config /etc/XrayR/config.yml`，容器内监听地址由 `config.yml` 的 `ListenIP` 决定；`Observability.Listen` 默认绑定 `127.0.0.1`，需要从容器外访问时请改为容器内可访问的私有地址并映射端口。

## Configuration

配置参考 [release/config/config.yml.example](./release/config/config.yml.example)，该文件带逐项注释，覆盖 `Log`、`DnsConfigPath`、`RouteConfigPath`、`ConnectionConfig`、`Observability`、`MachineConfig` 与 `Nodes`。

- 远程面板地址（`ApiHost`）必须使用 HTTPS；仅回环开发地址可以使用 HTTP。
- `MachineConfig` 与静态 `Nodes` 二选一，不能同时启用。
- 细节说明见 [Xboard / NewV2board 兼容性文档](./docs/xboard-newv2board.md)。

## Development

要求 Go 版本以 [go.mod](./go.mod) 中的 `go` 指令为准（当前为 `1.27`）。

```bash
git clone https://github.com/Mtoly/XrayRP.git
cd XrayRP

go build ./...
go test ./...
go vet ./...

# 与发布产物一致的构建（包含 QUIC 支持）
CGO_ENABLED=0 go build -tags with_quic -o XrayR .
```

## License

[Mozilla Public License Version 2.0](./LICENSE)

## Thanks

- [Project X](https://github.com/XTLS/)
- [V2Fly](https://github.com/v2fly)
- [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray)
- [Air-Universe](https://github.com/crossfw/Air-Universe)

## Telegram

- [XrayR 讨论群](https://t.me/XrayR_project)
- [XrayR 通知频道](https://t.me/XrayR_channel)
