<h1 align="center">XrayRP</h1>

<p align="center">面板管理的代理节点运行时</p>

<div align="center">

[![Release](https://img.shields.io/github/v/release/Mtoly/XrayRP?style=flat-square)](https://github.com/Mtoly/XrayRP/releases/latest) [![Required checks](https://github.com/Mtoly/XrayRP/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/Mtoly/XrayRP/actions/workflows/test.yml) [![License](https://img.shields.io/badge/license-MPL--2.0-blue?style=flat-square)](./LICENSE)

**简体中文** · [English](./README-en.md) · [Tiếng Việt](./README-vi.md) · [فارسی](./README_Fa.md)

[Quick Start](#quick-start) · [Documentation](#documentation) · [Releases](https://github.com/Mtoly/XrayRP/releases) · [Docker](#docker)

</div>

## 概览

XrayRP 在节点机上应用面板下发的节点、用户和规则配置，并回报运行状态、流量与在线数据，减少逐节点维护配置的工作。

面板负责节点与用户管理，XrayRP 负责同步和运行时生命周期。Xray-core 承载主要代理协议与传输；AnyTLS、TUIC 使用内嵌 sing-box，Hysteria2 使用 Hysteria core/extras。

## 核心能力

- **面板对接**：Xboard / NewV2board 使用 `NewV2board` 适配器；其他面板与配置名称见[配置示例](./release/config/config.yml.example)。
- **协议支持**：VLESS、VMess、Trojan、Shadowsocks（含 Plugin）、AnyTLS、TUIC、Hysteria2；完整 `NodeType` 清单见配置示例。具体支持取决于面板、适配器和运行时版本。
- **自动同步**：Xboard / NewV2board 支持轮询与 WebSocket 双活，配置与用户事件通过共享的 REST 快照同步路径处理；连接中断后轮询继续工作。
- **运维与可靠性**：流量与在线统计、限速、证书申请与续签、自定义 DNS、路由和审计规则；可选 Redis 设备缓存、健康检查与 Prometheus 指标。配置热重载失败时保留上次可用状态。

Xboard 的 VLESS Encryption 使用面板下发的服务端 `decryption`，须关闭 inbound fallback。VLESS 的 REALITY、XHTTP 与 XTLS Vision 组合及字段映射见[兼容文档](./docs/xboard-newv2board.md#vless-trojan-reality-and-xhttp)。

AnyTLS、TUIC、Hysteria2 需配置证书；AnyTLS 使用面板下发的 `padding_scheme`。健康检查与指标仅面向回环或私有地址。

<a name="quick-start"></a>

## 快速开始

当前脚本安装要求 Linux、root 权限和 systemd。先在面板配置节点或绑定机器；远程 `ApiHost` 必须使用 HTTPS，HTTP 仅用于回环开发地址。

### 一键安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Mtoly/XrayRPS/main/install.sh)
```

安装后编辑 `/etc/XrayR/config.yml`，填写面板与节点信息，再运行 `XrayR start`。配置字段见[配置示例](./release/config/config.yml.example)。

### Xboard Machine Mode

先在 Xboard 创建并绑定机器，取得 `MachineID` 和 `Token`。以下示例需替换为实际值；脚本用于安装与配置，机器注册在面板中完成。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Mtoly/XrayRPS/main/install-machine.sh) \
  --api-host https://panel.example.com \
  --machine-id 1 \
  --token "machine-token" \
  --panel-type NewV2board \
  --ws-endpoint "wss://panel.example.com/ws"
```

Machine Mode 不使用 handshake 自动发现：请明确配置 `--ws-endpoint`，指向本部署实际公开的 `ws-server` 地址，通常为 `/ws`，HTTPS 面板应使用 `wss://`。部署与兼容细节见[部署说明](./docs/xboard-newv2board.md#xboard-deployment-machine-mode-shared-websocket)。

`MachineConfig` 与静态 `Nodes` 互斥；静态模式仍从面板同步节点配置与用户。已有配置默认保留，确认覆盖时才加 `--force`。

<a name="docker"></a>

### Docker

先将[配置示例](./release/config/config.yml.example)保存为 `/etc/XrayR/config.yml` 并填写实际配置；已有配置可直接使用。然后在 Linux 节点机运行：

```bash
docker run -d --name xrayrp --restart unless-stopped \
  --network host \
  -v /etc/XrayR:/etc/XrayR \
  ghcr.io/mtoly/xrayrp:latest
```

镜像发布原始 Release 标签与 `latest`；`latest` 随每次发布更新，包括预发布，升级时需重新拉取镜像并重建容器。生产部署可固定正式 Release 标签。

<a name="documentation"></a>

## 文档

| 入口 | 内容 |
| --- | --- |
| [配置示例](./release/config/config.yml.example) | 面板、节点类型、证书、限速与观测配置 |
| [Xboard / NewV2board](./docs/xboard-newv2board.md) | Machine Mode、WebSocket 部署、协议与字段兼容边界 |
| [架构说明](./docs/architecture.md) | 模块职责、运行时边界与状态约束 |
| [Releases](https://github.com/Mtoly/XrayRP/releases) · [Changelog](./CHANGELOG.md) | 下载、版本变化与发布校验文件 |
| [go.mod](./go.mod) · [CI](./.github/workflows/test.yml) · [发布构建](./.github/workflows/release.yml) | Go 版本要求、测试与构建入口 |

源码构建遵循 `go.mod` 的 Go 版本要求；包含 QUIC 支持的构建命令为 `CGO_ENABLED=0 go build -tags with_quic -o XrayR .`。

手动下载时使用同一 Release 的 `SHA256SUMS` 校验归档；签名包为 `SHA256SUMS.sigstore.json`。SBOM 与 provenance 记录保存在发布工作流产物中。

## 社区与许可

问题与改进建议请提交至 [GitHub Issues](https://github.com/Mtoly/XrayRP/issues)。

采用 [Mozilla Public License 2.0](./LICENSE)。

项目历史与上游：[XrayR](https://github.com/XrayR-project/XrayR)。工具命名和配置路径沿用 `XrayR`。

感谢 [Project X](https://github.com/XTLS/)、[V2Fly](https://github.com/v2fly)、[VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray) 与 [Air-Universe](https://github.com/crossfw/Air-Universe)。
