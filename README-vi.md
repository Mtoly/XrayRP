# XrayR

[![](https://img.shields.io/badge/TgChat-@XrayR讨论-blue.svg)](https://t.me/XrayR_project)
[![](https://img.shields.io/badge/Channel-@XrayR通知-blue.svg)](https://t.me/XrayR_channel)
![](https://img.shields.io/github/stars/Mtoly/XrayRP)
![](https://img.shields.io/github/forks/Mtoly/XrayRP)
![](https://github.com/Mtoly/XrayRP/actions/workflows/release.yml/badge.svg)
![](https://github.com/Mtoly/XrayRP/actions/workflows/docker.yml/badge.svg)
[![Github All Releases](https://img.shields.io/github/downloads/Mtoly/XrayRP/total.svg)]()

[Iranian(farsi) README](https://github.com/Mtoly/XrayRP/blob/master/README_Fa.md), [Vietnamese(vi) README](https://github.com/Mtoly/XrayRP/blob/master/README-vi.md), [English(en) README](https://github.com/Mtoly/XrayRP/blob/master/README-en.md)

A Xray backend framework that can easily support many panels.

Khung trở lại dựa trên XRay hỗ trợ các giao thức V2Ray, Trojan, Shadowsocks, dễ dàng mở rộng và hỗ trợ kết nối nhiều người.

Nếu bạn thích dự án này, bạn có thể nhấp vào Star+Watch ở góc trên bên phải để tiếp tục chú ý đến tiến trình của dự án này.

## Tài liệu
Sử dụng hướng dẫn: [Hướng dẫn chi tiết](https://xrayr-project.github.io/XrayR-doc/) ( Tiếng Trung )

Tài liệu về khả năng tương thích Xboard / NewV2board, WebSocket, chế độ máy và cấu hình: [Hướng dẫn tương thích](./docs/xboard-newv2board.md).

## Tuyên bố miễn trừ

Dự án này chỉ là học tập và phát triển và bảo trì cá nhân của tôi. Tôi không đảm bảo bất kỳ sự sẵn có nào và không chịu trách nhiệm cho bất kỳ hậu quả nào do việc sử dụng phần mềm này.

## Đặt điểm nổi bật

* Nguồn mở vĩnh viễn và miễn phí.
* Hỗ trợ V2Ray, Trojan, Shadowsocks nhiều giao thức.
* Hỗ trợ các tính năng mới như Vless và XTL.
* Hỗ trợ trường hợp đơn lẻ kết nối Multi -Panel và Multi -Node, không cần phải bắt đầu nhiều lần.
* Hỗ trợ hạn chế IP trực tuyến
* Hỗ trợ cấp cổng nút và giới hạn tốc độ cấp người dùng.
* Cấu hình đơn giản và rõ ràng.
* Sửa đổi phiên bản khởi động lại tự động.
* Dễ dàng biên dịch và nâng cấp, bạn có thể nhanh chóng cập nhật phiên bản cốt lõi và hỗ trợ các tính năng mới của Xray-Core.

## Chức năng

| Chức năng        | v2ray | trojan | shadowsocks |
|-----------|-------|--------|-------------|
| Nhận thông tin Node    | √     | √      | √           |
| Nhận thông tin người dùng    | √     | √      | √           |
| Thống kê lưu lượng người dùng    | √     | √      | √           |
| Báo cáo thông tin máy chủ   | √     | √      | √           |
| Tự động đăng ký chứng chỉ TLS | √     | √      | √           |
| Chứng chỉ TLS gia hạn tự động | √     | √      | √           |
| Số người trực tuyến    | √     | √      | √           |
| Hạn chế người dùng trực tuyến    | √     | √      | √           |
| Quy tắc kiểm toán      | √     | √      | √           |
| Giới hạn tốc độ cổng nút    | √     | √      | √           |
| Theo giới hạn tốc độ người dùng    | √     | √      | √           |
| DNS tùy chỉnh    | √     | √      | √           |

## Hỗ trợ Panel 

| Panel                                                     | v2ray | trojan | shadowsocks             |
|--------------------------------------------------------|-------|--------|-------------------------|
| sspanel-uim                                            | √     | √      | √ (Nhiều người dùng cuối và v2ray-plugin) |
| v2board                                                | √     | √      | √                       |
| [PMPanel](https://github.com/ByteInternetHK/PMPanel)   | √     | √      | √                       |
| [ProxyPanel](https://github.com/ProxyPanel/ProxyPanel) | √     | √      | √                       |
| [WHMCS (V2RaySocks)](https://v2raysocks.doxtex.com/)   | √     | √      | √                       |
| [GoV2Panel](https://github.com/pingProMax/gov2panel)   | √     | √      | √                       |
| [BunPanel](https://github.com/pennyMorant/bunpanel-release)   | √     | √      | √                       |

## Cài đặt phần mềm

### Một cài đặt chính

```
wget -N https://raw.githubusercontent.com/Mtoly/XrayRP-release/master/install.sh && bash install.sh
```

### Sử dụng phần mềm triển khai Docker

[Hướng dẫn cài đặt thông qua Docker](https://xrayr-project.github.io/XrayR-doc/xrayr-xia-zai-he-an-zhuang/install/docker)

### Hướng dẫn cài đặt

[Hướng dẫn cài đặt thủ công](https://xrayr-project.github.io/XrayR-doc/xrayr-xia-zai-he-an-zhuang/install/manual)

## Tệp cấu hình và hướng dẫn sử dụng chi tiết

[Hướng dẫn chi tiết](https://xrayr-project.github.io/XrayR-doc/)

## Thanks

* [Project X](https://github.com/XTLS/)
* [V2Fly](https://github.com/v2fly)
* [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray)
* [Air-Universe](https://github.com/crossfw/Air-Universe)

## Licence

[Mozilla Public License Version 2.0](https://github.com/Mtoly/XrayRP/blob/master/LICENSE)

## Telegram

[Xrayr Back-end Thảo luận](https://t.me/XrayR_project)

[Thông báo Xrayr](https://t.me/XrayR_channel)

## Stargazers over time

[![Stargazers over time](https://starchart.cc/Mtoly/XrayRP.svg)](https://starchart.cc/Mtoly/XrayRP)
