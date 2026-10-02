# XrayRP

گره‌های Xray خود را از طریق پنل مدیریت کنید. پنل مدیریت را انجام می‌دهد، Xray Core اجرا را انجام می‌دهد و XrayRP این دو را به هم متصل می‌کند: پیکربندی ارسالی پنل را روی سرور شما به گره‌های در حال اجرا تبدیل می‌کند و وضعیت، ترافیک و داده‌های آنلاین را به پنل گزارش می‌دهد.

نسخه فعلی: `0.9.4` (به [CHANGELOG.md](./CHANGELOG.md) مراجعه کنید)

[![Stars](https://img.shields.io/github/stars/Mtoly/XrayRP.svg)](https://github.com/Mtoly/XrayRP/stargazers)
[![Release](https://github.com/Mtoly/XrayRP/actions/workflows/release.yml/badge.svg)](https://github.com/Mtoly/XrayRP/actions/workflows/release.yml)
[![Docker](https://github.com/Mtoly/XrayRP/actions/workflows/docker.yml/badge.svg)](https://github.com/Mtoly/XrayRP/actions/workflows/docker.yml)
[![Required checks](https://github.com/Mtoly/XrayRP/actions/workflows/test.yml/badge.svg)](https://github.com/Mtoly/XrayRP/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](./LICENSE)

[中文](./README.md) | [English](./README-en.md) | [Tiếng Việt](./README-vi.md)

## چرا XrayRP

اگر گره‌های خود را روی سرور خودتان اجرا می‌کنید و نمی‌خواهید پیکربندی و فرایند هر گره را دستی نگه‌داری کنید، XrayRP پیکربندی موجود در پنل را روی ماشین گره اعمال می‌کند و وضعیت اجرا و اطلاعات ترافیک را به پنل گزارش می‌دهد. پیکربندی روزمره گره و کاربر از طریق پنل مدیریت می‌شود و کار نگه‌داری دستی گره را کاهش می‌دهد. ترافیک پایه توسط Xray Core و زمان اجرای مربوط به هر پروتکل پردازش می‌شود.

پیش از شروع، به یک پنل با گره‌های پیکربندی‌شده و دسترسی root روی ماشین گره نیاز دارید.

برای جزئیات، [سند معماری](./docs/architecture.md) و [سند سازگاری Xboard / NewV2board](./docs/xboard-newv2board.md) را ببینید.

## ویژگی‌ها

### پنل و مدیریت گره

- **Xboard / NewV2board**: یکپارچه‌سازی Xboard و NewV2board از طریق آداپتور `NewV2board`.
- **حالت ماشین**: `MachineConfig` با `MachineID` + `Token` احراز هویت می‌کند؛ یک نمونه گره‌های متصل به این ماشین را کشف و به‌صورت پویا راه‌اندازی و متوقف می‌کند.
- **همگام‌سازی خودکار گره**: نظرسنجی و WebSocket در یک مسیر همگام‌سازی ادغام می‌شوند، تغییرات پیکربندی تنها پس از موفقیت apply در زمان اجرا اعمال می‌شوند و WebSocket قطع‌شده خودش دوباره وصل می‌شود.
- **حفظ آخرین وضعیت سالم**: هنگام بارگذاری مجدد گرم، پیکربندی‌ای که در اعتبارسنجی یا apply شکست بخورد، جایگزین پیکربندی در حال اجرا نمی‌شود.
- **حالت `Nodes` ثابت**: گره‌ها در فایل پیکربندی قرار می‌گیرند و به کشف پنل وابسته نیستند؛ جایگزینی برای حالت ماشین.

### پروتکل‌ها و انتقال‌ها

- VLESS (شامل REALITY / XHTTP / WS / gRPC / HTTPUpgrade / VLESS Encryption)
- VMess
- Trojan
- Shadowsocks (شامل Shadowsocks-Plugin)
- AnyTLS (از `padding_scheme` ارسالی پنل استفاده می‌کند)
- TUIC (نیازمند پیکربندی گواهی محلی)
- Hysteria2 (نیازمند پیکربندی گواهی محلی)

فهرست کامل انواع گره و سایر انتقال‌ها (شامل Socks و HTTP) در توضیح `NodeType` در [config.yml.example](./release/config/config.yml.example) آمده است.

### VLESS پیشرفته

- **رمزنگاری VLESS**: کلید سمت سرور ارسالی Xboard را به Xray-core می‌دهد؛ گره‌های رمزنگاری‌شده باید fallback ورودی را غیرفعال کنند.
- **XTLS Vision**: از `xtls-rprx-vision` ارسالی پنل پشتیبانی می‌کند. رفتار دقیق ترکیب انتقال و رمزنگاری در [سند سازگاری](./docs/xboard-newv2board.md) آمده است.

### عملیات

- آمار ترافیک کاربران و گزارش وضعیت گره.
- محدودیت IP آنلاین، محدودیت کاربر آنلاین، محدودیت سرعت پورت گره و محدودیت سرعت هر کاربر؛ کش دستگاه جهانی Redis (اختیاری) چند نمونه را هماهنگ می‌کند.
- صدور و تمدید خودکار گواهی، با پشتیبانی از ACME DNS/HTTP/TLS و فایل‌های سفارشی.
- DNS، مسیریابی و قوانین حسابرسی سفارشی.
- مشاهده‌پذیری: مسیرهای محلی اختیاری `/livez`، `/readyz` و `/metrics` (پیکربندی `Observability`، به‌صورت پیش‌فرض غیرفعال و محدود به آدرس loopback یا خصوصی) که معیارهایی مانند `xrayrp_runtime_state` را ارائه می‌دهد.
- بارگذاری مجدد گرم: تغییر پیکربندی، یک پیکربندی کاندید را بارگذاری می‌کند و نمونه در حال اجرا تنها پس از موفقیت اعتبارسنجی و apply جایگزین می‌شود.

### انتشار و امنیت

- تحلیل ایستا با CodeQL (`codeql-analysis.yml`، در push / PR / زمان‌بندی هفتگی).
- اسکن آسیب‌پذیری‌های قابل‌دسترس با govulncheck، تنها با یک استثنای مستند که کف نسخه دارد (`test.yml`).
- به‌روزرسانی وابستگی‌ها و ایمیج‌های پایه با Dependabot.
- مصنوعات امضاشده انتشار: صفحه انتشار آرشیوهای هر پلتفرم و `SHA256SUMS` را همراه با امضای Sigstore در `SHA256SUMS.sigstore.json` ارائه می‌دهد.
- SBOM های SPDX، مانیفست انتشار و provenance attestation توسط workflow انتشار تولید و به‌عنوان شواهد workflow نگهداری می‌شوند.
- اعتبارسنجی Docker در PR: PR هایی که `Dockerfile` یا workflow های docker را تغییر می‌دهند، ایمیج را می‌سازند و تست دود `version` را اجرا می‌کنند (`docker-test.yml`).

## معماری

```mermaid
flowchart TD
    P[Panel<br/>Xboard / NewV2board / sspanel-uim / v2board] -->|node / user snapshot| G[XrayRP]
    G -->|apply| C[Xray Core<br/>inbound / outbound / routing]
    C -->|runtime state| G
    G -->|status / traffic / online data| P
```

- Panel: گره‌ها، کاربران، مسیریابی و قوانین حسابرسی را ارسال می‌کند و گزارش‌ها را دریافت می‌کند.
- XrayRP: عکس‌های لحظه‌ای پنل را به وضعیت زمان اجرای محلی تبدیل می‌کند؛ مالک چرخه عمر زمان اجرا (شروع، آمادگی، توقف و آزادسازی، جایگزینی، وضعیت خطا)، اعمال محدودیت‌ها و قوانین، مدیریت گواهی و گزارش‌دهی است.
- Xray Core: حامل واقعی پروتکل‌ها و انتقال‌ها است؛ XrayRP از طریق `app/` با آن تعامل می‌کند.

مکان کد و ناورداها در [سند معماری](./docs/architecture.md) آمده است.

## نصب

### اسکریپت نصب یک‌کلیکی

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Mtoly/XrayRPS/main/install.sh)
```

### نصب حالت ماشین Xboard

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Mtoly/XrayRPS/main/install-machine.sh) \
  --api-host https://panel.example.com \
  --machine-id 1 \
  --token "machine-token" \
  --panel-type NewV2board \
  --ws-endpoint "wss://panel.example.com/ws"
```

- این اسکریپت فقط `MachineConfig` را می‌نویسد و سرویس را نصب / اجرا می‌کند. ماشینی در Xboard ایجاد یا ثبت نمی‌کند، پس ابتدا ماشین را در Xboard ایجاد و متصل کنید.
- `MachineConfig` و `Nodes` ثابت متقابلاً انحصاری هستند؛ فعال کردن حالت ماشین، `Nodes` ثابت تولید نمی‌کند.
- حالت ماشین از کشف handshake استفاده نمی‌کند. `--ws-endpoint` را روی آدرسی که `ws-server` در Xboard روی آن منتشر شده است تنظیم کنید (معمولاً `/ws`). در صورت حذف آن، مسیر قدیمی `<ApiHost>/api/v1/server/UniProxy/ws` استفاده می‌شود که Xboard فعلی دیگر ارائه نمی‌کند.
- اگر `/etc/XrayR/config.yml` از قبل وجود داشته باشد، اسکریپت به‌صورت پیش‌فرض آن را بازنویسی نمی‌کند؛ برای بازنویسی `--force` را اضافه کنید.

### داکر (GHCR)

ایمیج: `ghcr.io/mtoly/xrayrp`، همراه با تگ اصلی انتشار و `latest` منتشر می‌شود.

```bash
mkdir -p /etc/XrayR
cp release/config/config.yml.example /etc/XrayR/config.yml
# edit /etc/XrayR/config.yml, then start
docker run -d --name xrayrp --restart unless-stopped \
  --network host \
  -v /etc/XrayR:/etc/XrayR \
  ghcr.io/mtoly/xrayrp:latest
```

ورودی کانتینر `XrayR --config /etc/XrayR/config.yml` است. آدرس‌های شنود داخل کانتینر از `ListenIP` در `config.yml` می‌آید؛ مقدار پیش‌فرض `Observability.Listen` روی `127.0.0.1` است، پس برای دسترسی از بیرون کانتینر آن را به یک آدرس خصوصی قابل‌دسترس در کانتینر تغییر دهید و پورت را نگاشت کنید.

## پیکربندی

مرجع همراه با توضیحات: [release/config/config.yml.example](./release/config/config.yml.example) که `Log`، `DnsConfigPath`، `RouteConfigPath`، `ConnectionConfig`، `Observability`، `MachineConfig` و `Nodes` را پوشش می‌دهد.

- آدرس پنل راه دور (`ApiHost`) باید از HTTPS استفاده کند؛ فقط آدرس‌های توسعه loopback می‌توانند HTTP داشته باشند.
- `MachineConfig` و `Nodes` ثابت دو گزینه جایگزین هستند؛ هر دو را همزمان فعال نکنید.
- جزئیات در [سند سازگاری Xboard / NewV2board](./docs/xboard-newv2board.md) آمده است.

## توسعه

نسخه Go موردنیاز همان دستور `go` در [go.mod](./go.mod) است (اکنون `1.27`).

```bash
git clone https://github.com/Mtoly/XrayRP.git
cd XrayRP

go build ./...
go test ./...
go vet ./...

# build matching the release artifacts (includes QUIC support)
CGO_ENABLED=0 go build -tags with_quic -o XrayR .
```

## مجوز

[Mozilla Public License Version 2.0](./LICENSE)

## قدردانی

- [Project X](https://github.com/XTLS/)
- [V2Fly](https://github.com/v2fly)
- [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray)
- [Air-Universe](https://github.com/crossfw/Air-Universe)

## تلگرام

- [گروه بحث XrayR](https://t.me/XrayR_project)
- [کانال اطلاع‌رسانی XrayR](https://t.me/XrayR_channel)
