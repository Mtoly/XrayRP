<h1 align="center">XrayRP</h1>

<p align="center" dir="rtl">محیط اجرای گره‌های پروکسی تحت مدیریت پنل</p>

<div align="center" dir="ltr">

[![Release](https://img.shields.io/github/v/release/Mtoly/XrayRP?style=flat-square)](https://github.com/Mtoly/XrayRP/releases/latest) [![Required checks](https://github.com/Mtoly/XrayRP/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/Mtoly/XrayRP/actions/workflows/test.yml) [![License](https://img.shields.io/badge/license-MPL--2.0-blue?style=flat-square)](./LICENSE)

[简体中文](./README.md) · [English](./README-en.md) · [Tiếng Việt](./README-vi.md) · **فارسی**

[Quick Start](#quick-start) · [Documentation](#documentation) · [Releases](https://github.com/Mtoly/XrayRP/releases) · [Docker](#docker)

</div>

<div dir="rtl">

## نمای کلی

روی میزبان گره، XrayRP پیکربندی گره‌ها، کاربران و قواعد دریافتی از پنل را اعمال می‌کند و وضعیت اجرا، ترافیک و داده‌های آنلاین را به پنل گزارش می‌دهد تا کار پیکربندی جداگانهٔ گره‌ها کمتر شود.

پنل، گره‌ها و کاربران را مدیریت می‌کند؛ XrayRP مسئول همگام‌سازی و چرخهٔ عمر محیط اجرا است. Xray-core پروتکل‌های اصلی پروکسی و روش‌های انتقال را اجرا می‌کند. AnyTLS و TUIC از sing-box تعبیه‌شده و Hysteria2 از Hysteria core/extras استفاده می‌کنند.

## قابلیت‌ها

- **اتصال به پنل**: Xboard / NewV2board از آداپتور <span dir="ltr">`NewV2board`</span> استفاده می‌کنند. پنل‌های دیگر و نام‌های پیکربندی آن‌ها در [نمونهٔ پیکربندی](./release/config/config.yml.example) آمده‌اند.
- **پشتیبانی از پروتکل‌ها**: VLESS، VMess، Trojan، Shadowsocks (شامل Plugin)، AnyTLS، TUIC و Hysteria2. فهرست کامل <span dir="ltr">`NodeType`</span> در نمونهٔ پیکربندی آمده است. پشتیبانی به نسخه‌های پنل، آداپتور و محیط اجرا بستگی دارد.
- **همگام‌سازی خودکار**: Xboard / NewV2board از polling و WebSocket به‌صورت هم‌زمان پشتیبانی می‌کنند. رویدادهای پیکربندی و کاربران از مسیر مشترک همگام‌سازی snapshotهای REST عبور می‌کنند؛ هنگام قطع اتصال، polling ادامه می‌یابد.
- **عملیات و قابلیت اطمینان**: آمار ترافیک و وضعیت آنلاین، محدودیت سرعت، صدور و تمدید گواهی، DNS، مسیریابی و قواعد حسابرسی سفارشی؛ کش دستگاه Redis، بررسی سلامت و معیارهای Prometheus به‌صورت اختیاری. در صورت شکست بارگذاری مجدد پیکربندی، آخرین وضعیت سالم حفظ می‌شود.

در Xboard، قابلیت VLESS Encryption از مقدار سمت سرور <span dir="ltr">`decryption`</span> ارسالی پنل استفاده می‌کند و نیازمند غیرفعال کردن fallback ورودی است. ترکیب‌های REALITY، XHTTP و XTLS Vision در VLESS و نگاشت فیلدها در [سند سازگاری](./docs/xboard-newv2board.md#vless-trojan-reality-and-xhttp) آمده‌اند.

پروتکل‌های AnyTLS، TUIC و Hysteria2 به پیکربندی گواهی نیاز دارند. AnyTLS از <span dir="ltr">`padding_scheme`</span> ارسالی پنل استفاده می‌کند. بررسی سلامت و معیارها فقط روی آدرس‌های loopback یا خصوصی ارائه می‌شوند.

<a name="quick-start"></a>

## شروع سریع

اسکریپت‌های نصب فعلی به Linux، دسترسی root و systemd نیاز دارند. ابتدا گره‌ها را در پنل پیکربندی کنید یا ماشین را به آن متصل کنید. <span dir="ltr">`ApiHost`</span> راه دور باید از HTTPS استفاده کند؛ HTTP فقط برای آدرس‌های loopback در محیط توسعه است.

### نصب با یک فرمان

<div dir="ltr" align="left">

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Mtoly/XrayRPS/main/install.sh)
```

</div>

پس از نصب، اطلاعات پنل و گره را در <span dir="ltr">`/etc/XrayR/config.yml`</span> وارد کنید و سپس <span dir="ltr">`XrayR start`</span> را اجرا کنید. فیلدها در [نمونهٔ پیکربندی](./release/config/config.yml.example) توضیح داده شده‌اند.

### Xboard Machine Mode

ابتدا ماشین را در Xboard ایجاد و متصل کنید، سپس <span dir="ltr">`MachineID`</span> و <span dir="ltr">`Token`</span> آن را دریافت کنید. مقادیر نمونهٔ زیر را با مقادیر واقعی جایگزین کنید. اسکریپت، سرویس را نصب و پیکربندی می‌کند؛ ثبت ماشین در پنل انجام می‌شود.

<div dir="ltr" align="left">

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Mtoly/XrayRPS/main/install-machine.sh) \
  --api-host https://panel.example.com \
  --machine-id 1 \
  --token "machine-token" \
  --panel-type NewV2board \
  --ws-endpoint "wss://panel.example.com/ws"
```

</div>

حالت Machine Mode از کشف خودکار handshake استفاده نمی‌کند. <span dir="ltr">`--ws-endpoint`</span> را صریحاً روی آدرس عمومی واقعی <span dir="ltr">`ws-server`</span> در استقرار خود تنظیم کنید که معمولاً <span dir="ltr">`/ws`</span> است؛ برای پنل HTTPS از <span dir="ltr">`wss://`</span> استفاده کنید. جزئیات استقرار و سازگاری در [راهنمای استقرار](./docs/xboard-newv2board.md#xboard-deployment-machine-mode-shared-websocket) آمده است.

دو حالت <span dir="ltr">`MachineConfig`</span> و <span dir="ltr">`Nodes`</span> ثابت متقابلاً انحصاری هستند. حالت ثابت همچنان پیکربندی گره و کاربران را از پنل همگام می‌کند. پیکربندی موجود به‌صورت پیش‌فرض حفظ می‌شود؛ فقط پس از تأیید بازنویسی، <span dir="ltr">`--force`</span> را اضافه کنید.

<a name="docker"></a>

### Docker

[نمونهٔ پیکربندی](./release/config/config.yml.example) را در <span dir="ltr">`/etc/XrayR/config.yml`</span> ذخیره و با مقادیر واقعی تکمیل کنید، یا از پیکربندی موجود استفاده کنید. سپس روی میزبان گره Linux اجرا کنید:

<div dir="ltr" align="left">

```bash
docker run -d --name xrayrp --restart unless-stopped \
  --network host \
  -v /etc/XrayR:/etc/XrayR \
  ghcr.io/mtoly/xrayrp:latest
```

</div>

ایمیج‌ها با تگ اصلی Release و <span dir="ltr">`latest`</span> منتشر می‌شوند. هر انتشار، از جمله پیش‌انتشار، <span dir="ltr">`latest`</span> را به‌روزرسانی می‌کند؛ برای ارتقا باید ایمیج را دوباره pull کرده و کانتینر در حال اجرا را دوباره ایجاد کنید. در محیط عملیاتی می‌توانید تگ یک Release پایدار را ثابت نگه دارید.

<a name="documentation"></a>

## مستندات

| ورودی | محتوا |
| --- | --- |
| [نمونهٔ پیکربندی](./release/config/config.yml.example) | پنل‌ها، انواع گره، گواهی‌ها، محدودیت‌ها و مشاهده‌پذیری |
| [Xboard / NewV2board](./docs/xboard-newv2board.md) | Machine Mode، استقرار WebSocket و سازگاری پروتکل‌ها و فیلدها |
| [معماری](./docs/architecture.md) | مسئولیت ماژول‌ها، مرزهای محیط اجرا و قواعد ثابت وضعیت |
| [Releases](https://github.com/Mtoly/XrayRP/releases) · [Changelog](./CHANGELOG.md) | دریافت فایل‌ها، تغییرات نسخه‌ها و فایل‌های تأیید انتشار |
| [go.mod](./go.mod) · [CI](./.github/workflows/test.yml) · [ساخت انتشار](./.github/workflows/release.yml) | نسخهٔ موردنیاز Go، آزمون‌ها و ساخت |

ساخت از کد منبع تابع نسخهٔ موردنیاز Go در <span dir="ltr">`go.mod`</span> است. فرمان ساخت با پشتیبانی QUIC: <span dir="ltr">`CGO_ENABLED=0 go build -tags with_quic -o XrayR .`</span>.

برای دریافت دستی، آرشیوها را با <span dir="ltr">`SHA256SUMS`</span> همان Release بررسی کنید. بستهٔ امضا <span dir="ltr">`SHA256SUMS.sigstore.json`</span> است. سوابق SBOM و provenance در مصنوعات workflow انتشار نگهداری می‌شوند.

## جامعه و مجوز

مشکلات و پیشنهادهای بهبود را در [GitHub Issues](https://github.com/Mtoly/XrayRP/issues) مطرح کنید.

این پروژه تحت [Mozilla Public License 2.0](./LICENSE) منتشر می‌شود.

تاریخچهٔ پروژه و بالادست: [XrayR](https://github.com/XrayR-project/XrayR). نام ابزارها و مسیرهای پیکربندی، نام‌گذاری <span dir="ltr">`XrayR`</span> را حفظ کرده‌اند.

با سپاس از [Project X](https://github.com/XTLS/)، [V2Fly](https://github.com/v2fly)، [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray) و [Air-Universe](https://github.com/crossfw/Air-Universe).

</div>
