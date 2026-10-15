<h1 align="center">XrayRP</h1>

<p align="center">Runtime cho node proxy do panel quản lý</p>

<div align="center">

[![Release](https://img.shields.io/github/v/release/Mtoly/XrayRP?style=flat-square)](https://github.com/Mtoly/XrayRP/releases/latest) [![Required checks](https://github.com/Mtoly/XrayRP/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/Mtoly/XrayRP/actions/workflows/test.yml) [![License](https://img.shields.io/badge/license-MPL--2.0-blue?style=flat-square)](./LICENSE)

[简体中文](./README.md) · [English](./README-en.md) · **Tiếng Việt** · [فارسی](./README_Fa.md)

[Quick Start](#quick-start) · [Documentation](#documentation) · [Releases](https://github.com/Mtoly/XrayRP/releases) · [Docker](#docker)

</div>

## Tổng quan

XrayRP chạy trên máy node, áp dụng cấu hình node, người dùng và quy tắc từ panel, rồi gửi lại trạng thái vận hành, lưu lượng và dữ liệu trực tuyến. Nhờ đó, bạn bớt phải cấu hình thủ công từng node.

Panel quản lý node và người dùng. XrayRP đồng bộ cấu hình và quản lý runtime. Xray-core xử lý các giao thức proxy và phương thức truyền tải chính. AnyTLS và TUIC dùng sing-box nhúng; Hysteria2 dùng Hysteria core/extras.

## Tính năng

- Xboard / NewV2board dùng adapter `NewV2board`. Các panel khác và tên cấu hình tương ứng có trong [cấu hình mẫu](./release/config/config.yml.example).
- Hỗ trợ VLESS, VMess, Trojan, Shadowsocks (bao gồm Plugin), AnyTLS, TUIC và Hysteria2. Danh sách `NodeType` đầy đủ có trong cấu hình mẫu. Khả năng hỗ trợ phụ thuộc vào phiên bản panel, adapter và runtime.
- Xboard / NewV2board có thể dùng polling và WebSocket cùng lúc. Sự kiện cấu hình và người dùng đi qua cùng một luồng đồng bộ snapshot REST. Polling vẫn tiếp tục khi WebSocket bị ngắt.
- XrayRP cung cấp thống kê lưu lượng và dữ liệu trực tuyến, giới hạn tốc độ, cấp và gia hạn chứng chỉ, cùng DNS, định tuyến và quy tắc kiểm toán tùy chỉnh. Bạn có thể bật thêm bộ đệm thiết bị Redis, kiểm tra sức khỏe và chỉ số Prometheus. Nếu tải lại nóng cấu hình thất bại, XrayRP giữ trạng thái hoạt động tốt gần nhất.

VLESS Encryption của Xboard dùng giá trị `decryption` phía máy chủ do panel cung cấp và yêu cầu tắt fallback inbound. Xem [tài liệu tương thích](./docs/xboard-newv2board.md#vless-trojan-reality-and-xhttp) để biết các tổ hợp REALITY, XHTTP, XTLS Vision của VLESS và cách ánh xạ trường.

AnyTLS, TUIC và Hysteria2 cần cấu hình chứng chỉ. AnyTLS dùng `padding_scheme` do panel cung cấp. Kiểm tra sức khỏe và chỉ số chỉ phục vụ trên địa chỉ loopback hoặc địa chỉ riêng.

<a name="quick-start"></a>

## Bắt đầu nhanh

Các script cài đặt yêu cầu Linux, quyền root và systemd. Trước khi cài đặt, cấu hình node hoặc gắn máy trong panel. `ApiHost` từ xa phải dùng HTTPS; HTTP chỉ dành cho địa chỉ loopback khi phát triển.

### Cài đặt bằng một lệnh

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Mtoly/XrayRPS/main/install.sh)
```

Sau khi cài đặt, điền thông tin panel và node vào `/etc/XrayR/config.yml`, rồi chạy `XrayR start`. Xem các trường trong [cấu hình mẫu](./release/config/config.yml.example).

### Xboard Machine Mode

Trước tiên, tạo và gắn máy trong Xboard, rồi lấy `MachineID` và `Token`. Thay các giá trị mẫu bên dưới bằng giá trị thực tế. Script cài đặt và cấu hình dịch vụ; việc đăng ký máy được thực hiện trong panel.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Mtoly/XrayRPS/main/install-machine.sh) \
  --api-host https://panel.example.com \
  --machine-id 1 \
  --token "machine-token" \
  --panel-type NewV2board \
  --ws-endpoint "wss://panel.example.com/ws"
```

Machine Mode không tự tìm địa chỉ kết nối qua handshake. Đặt `--ws-endpoint` thành địa chỉ công khai của `ws-server` trong hệ thống của bạn, thường có đường dẫn `/ws`. Dùng `wss://` khi panel dùng HTTPS. Xem chi tiết triển khai và tương thích trong [hướng dẫn triển khai](./docs/xboard-newv2board.md#xboard-deployment-machine-mode-shared-websocket).

Chọn một trong hai: `MachineConfig` hoặc `Nodes` tĩnh. Chế độ tĩnh cũng đồng bộ cấu hình node và người dùng từ panel. Script mặc định giữ cấu hình hiện có; thêm `--force` nếu muốn ghi đè.

<a name="docker"></a>

### Docker

Lưu [cấu hình mẫu](./release/config/config.yml.example) thành `/etc/XrayR/config.yml` và điền cấu hình thực tế, hoặc dùng cấu hình hiện có. Sau đó chạy trên máy node Linux:

```bash
docker run -d --name xrayrp --restart unless-stopped \
  --network host \
  -v /etc/XrayR:/etc/XrayR \
  ghcr.io/mtoly/xrayrp:latest
```

Image dùng tag Release gốc và `latest`. Mọi lần phát hành đều cập nhật `latest`, kể cả bản phát hành trước. Để nâng cấp, pull image mới và tạo lại container. Khi triển khai production, bạn có thể ghim tag Release ổn định.

<a name="documentation"></a>

## Tài liệu

| Mục | Nội dung |
| --- | --- |
| [Cấu hình mẫu](./release/config/config.yml.example) | Panel, loại node, chứng chỉ, giới hạn và quan sát hệ thống |
| [Xboard / NewV2board](./docs/xboard-newv2board.md) | Machine Mode, triển khai WebSocket, tương thích giao thức và trường |
| [Kiến trúc](./docs/architecture.md) | Trách nhiệm module, ranh giới runtime và bất biến trạng thái |
| [Releases](https://github.com/Mtoly/XrayRP/releases) · [Changelog](./CHANGELOG.md) | Tải xuống, thay đổi phiên bản và tệp xác minh bản phát hành |
| [go.mod](./go.mod) · [CI](./.github/workflows/test.yml) · [Build bản phát hành](./.github/workflows/release.yml) | Yêu cầu phiên bản Go, kiểm thử và build |

Khi build từ mã nguồn, dùng phiên bản Go đáp ứng yêu cầu trong `go.mod`. Để bật hỗ trợ QUIC, chạy `CGO_ENABLED=0 go build -tags with_quic -o XrayR .`.

Khi tải thủ công, xác minh gói nén bằng `SHA256SUMS` của cùng Release. Gói chữ ký là `SHA256SUMS.sigstore.json`. Bản ghi SBOM và provenance được giữ trong artifact của workflow phát hành.

## Cộng đồng & Giấy phép

Báo lỗi và đề xuất cải tiến qua [GitHub Issues](https://github.com/Mtoly/XrayRP/issues).

Sử dụng [Mozilla Public License 2.0](./LICENSE).

XrayRP dựa trên [XrayR](https://github.com/XrayR-project/XrayR) và giữ tên `XrayR` cho công cụ và đường dẫn cấu hình.

Cảm ơn [Project X](https://github.com/XTLS/), [V2Fly](https://github.com/v2fly), [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray) và [Air-Universe](https://github.com/crossfw/Air-Universe).
