# mxtr-proxy

**Matrix, который работает там, где Matrix заблокирован.**

mxtr-proxy - обфусцированный relay для Matrix-клиентов на
matrix-rust-sdk. Он прячет трафик внутрь обычного HTTPS так, что для DPI
(РКН ТСПУ, иранский чебурнет) сервер неотличим от заурядного VPS с
веб-сервером по умолчанию.

Почему это держится:

- **Настоящий TLS 1.3, а не имитация.** MTProto-прокси сейчас валят по
  поддельному TLS-отпечатку (JA3). У mxtr такого отпечатка нет в
  принципе: он ходит по реальному TLS, как любой сайт.
- **Активный зонд видит скучный веб-сервер.** `curl` к серверу отдаёт
  обычную 403/404/500 одного из 6 семейств (nginx, Apache, Caddy и др.),
  `/robots.txt` - реалистичный 200. Следов прокси нет.
- **Внутри - белый шум.** После TLS поток неотличим от случайного:
  AEAD-фреймы с padding-лесенкой размазывают размеры пакетов.
- **Нечего блокировать оптом.** Ни публичных списков, ни центрального
  сервера. Каждый поднимает свой VPS за минуту и раздаёт ссылку только
  своему кругу.

Заточен под форк Element X+ (наш Android-клиент). Это **не** VPN, **не**
general-purpose-прокси и **не** конкурент MTProto - только Matrix через
matrix-rust-sdk.

**Производительность на разных VPS** (типичная Matrix-нагрузка - /sync
long-poll + редкие burst'ы):

| VPS spec                      | Цена $/мес | Одновременных юзеров          |
|-------------------------------|-----------|--------------------------------|
| 1 vCPU / 256 МБ / без тюнинга | $1-3      | 300-500                        |
| 1 vCPU / 256 МБ + ulimit/sysctl | $1-3    | 800-1200                       |
| 1 vCPU / 512 МБ + тюнинг      | $3-5      | 1500-2500                      |
| 2 vCPU / 1 ГБ + тюнинг        | $5-10     | 5000-8000                      |

Узкое место - RAM (Go runtime + goroutine stacks), не CPU. ChaCha20
поверх sync.Pool жрёт <1% ядра на сотнях conn/сек. Тюнинг на eле-еле-VPS:
`ulimit -n 65536` и `sysctl net.netfilter.nf_conntrack_max=131072` -
сразу 2x потолок.

## Что в репозитории

- **`cmd/mxtr-server`** - single-binary Go-relay. ~10 МБ distroless
  Docker-image. Self-signed TLS по умолчанию, опциональный LE.
- **`cmd/mxtr-testclient-v2`** - dev-инструмент. Говорит на протоколе
  напрямую, поднимает SOCKS5 на localhost для curl-тестов.
- Android-клиент - часть форка
  [element-x-experimental-plus](https://github.com/manfrommedan/element-x-experimental-plus)
  (matrix-rust-sdk + in-app HTTP CONNECT listener + WebView
  ProxyController + premium settings).

## Quick start

Одной строкой на VPS (Docker required). Замени `<vps-ip>` на свой публичный
IPv4 и `<port>` на любой свободный порт (примеры ниже используют `<port>` как
placeholder - выбирай нестандартный, не 443/80/22):

```bash
docker run -d --name mxtr-proxy --restart unless-stopped --network host -v /opt/mxtr-proxy/state:/state ghcr.io/manfrommedan/mxtr-proxy:latest -tcp :<port> -public-ip <vps-ip> -psk-file /state/psk.hex
sleep 2 && docker logs mxtr-proxy 2>&1 | grep share-string
```

На выходе - готовая share-string в формате
`mxtr://<base58-PSK>@<vps-ip>:<port>?sni=<edge-name>`. PSK на первом
запуске генерится и пишется в `/state/psk.hex` (`chmod 600`); cert CN +
cloak family тоже персистятся туда же, рестарт identity сохраняет.

Вставить в `Настройки -> Расширенные -> АнтиЦензурный прокси` в форке
Element X+, перезапустить app, готово.

Не забудь открыть порт: `ufw allow <port>/tcp` (или
`iptables -A INPUT -p tcp --dport <port> -j ACCEPT`).

Для production-сетапа с hardening (read-only fs, cap_drop, ротация
PSK, target-allowlist, compose, LE-сертификат) - см.
[docs/INSTALL-SERVER.md](docs/INSTALL-SERVER.md).

## Документация

- [INSTALL-SERVER.md](docs/INSTALL-SERVER.md) - Docker и сборка из
  исходников, share-string, ротация PSK, TLS, файрвол.
- [INTEGRATE-ANDROID.md](docs/INTEGRATE-ANDROID.md) - как встроить
  клиентскую часть в свой форк Element X / SchildiChat / любой
  Android-клиент на matrix-rust-sdk. Что копировать, куда вешать
  hooks.
- [PROTOCOL.md](docs/PROTOCOL.md) - wire-формат: TLS, handshake,
  AEAD-фреймы, stream-мультиплексирование, camouflage HTTP (6 семейств,
  random 403/404/500, path-aware /robots.txt, persisted identity), per-PSK
  config.
- [THREAT-MODEL.md](docs/THREAT-MODEL.md) - от кого защищает (пассивный
  DPI, активное зондирование, утечка PSK, IP-блокировка), и чего НЕ умеет
  (UDP-медиа, push, метаданные DNS до старта).
- [COMPARISON.md](docs/COMPARISON.md) - честное сравнение с
  MTProto-проксями 2026 (mtg / telemt / alexbers).

## Что даёт

- Forward secrecy на трёх слоях: внешний TLS-1.3 ECDHE до сервера,
  внутренний HTTPS до matrix.org, Matrix E2EE поверх. Утечка PSK
  старый трафик не расшифровывает: AEAD-ключи привязаны к nonce,
  которые внутри outer-TLS, без TLS-ключей их не достать.
- ТСПУ не банит «класс mxtr-серверов» одним правилом. PSK через HKDF
  выводит cadence heartbeat. Cloak family (одно из 6:
  nginx/Apache/LiteSpeed/Caddy/cloudflare/Go-stdlib) и cert CN
  (нейтральный синтетический из ~6.7 млн имён, не под конкретный CDN)
  выбираются на первом старте и персистятся - у каждого деплоя свой
  fingerprint, restart не меняет identity.
- Полная децентрализация. Нет центрального сервера, нет публичных
  списков IP, нет CDN-точки отказа. Каждый поднимает свой VPS, сам
  раздаёт share-string своему кругу. РКН нечего блокировать оптом -
  только заходить per-IP, а они между собой ничем не связаны.
- Устойчив к зондированию: `curl https://<vps-ip>:<port>/` отдаёт
  случайно-выбранную 403/404/500-страницу одного из 6 семейств
  (nginx/Apache/LiteSpeed/Caddy/Cloudflare/Go-stdlib) с family-specific
  headers (HSTS у Caddy, Cache-Control+Vary у Cloudflare и т.д.) без
  светящихся версий. `/robots.txt` отвечает 200 c `User-agent: *\nDisallow:\n`
  как реальный public-facing сервер. Cloak family
  и cert CN выбраны один раз и персистятся, restart identity не
  меняет (real nginx тоже не меняет 500-страницу при рестарте).
  Не-HTTP байты и неверный PSK получают `400 Bad Request` выбранного
  семейства + close - как реальный nginx/Apache на кривой запрос. Зонд
  не получает положительного сигнала ни на одном пути.
- Один long-lived TLS-сокет на всю сессию, N параллельных потоков
  внутри (stream mux). Handshake платится один раз, дальше /sync,
  /messages, /upload идут поверх.
- Батарея: reader thread blocking (никаких polling-loop'ов),
  heartbeat 20-90 сек, ChaCha20-Poly1305 на ARM-у ~150 МБ/с/core.
  Поверх того, что Element X уже жрёт на /sync, оверхед нулевой.
- `-allow=matrix.org,element.io` на сервере. Утечка PSK даёт
  атакующему доступ только в whitelist'нутые домены, не
  general-purpose-прокси.
- Деплой: `docker compose up -d --build`. Без LE, без публичного
  DNS, без сертификатов.

## Чего НЕ умеет

- Не VPN. UDP через прокси не ходит. Это не мешает аудио и видео:
  Matrix-серверы для звонков (LiveKit, TURN) принимают TCP-fallback,
  и Element Call через mxtr подключается по TCP - звонки и
  конференции работают как обычно, просто без прямого UDP-media.
  Мимо реально идёт только OS push (FCM / UnifiedPush), на это app
  не влияет.
- Не general-purpose. Заточен под matrix-rust-sdk и форк Element X+.
  Адаптация под другой клиент описана в
  [INTEGRATE-ANDROID.md](docs/INTEGRATE-ANDROID.md), но руками.
- Не shared-сервис в смысле multi-tenancy: один PSK на деплой. Но
  1000+ пользователей под одним PSK на одной VPS - норма.
- Оверхед по трафику есть: 16 байт AEAD-tag на фрейм + PADME-style
  13-rung padding с size-scaled bump (обфускация размеров стоит ~10-25%
  поверх payload, заметно меньше чем pure power-of-2 у предыдущих версий).
  На LTE заметно, на Wi-Fi нет.
- Нет TCP-splice до реального cloak-домена (как у `telemt`). Для
  личного использования (свой VPS, свой круг, обход цензуры и
  чебурнета без публичной светимости) - избыточно. РКН и иранский
  чебурнет активно обходят публичные шеренги proxy-IP; у нас IP
  знают только те, кому ты сам выдал share-string. Массовых
  зондирований по такому IP не будет, синтетического cloak'а
  (рандомизированные 403/404/500 + path-aware /robots.txt + persisted
  identity) хватает закрыть случайного зеваку.

## Совместимость

- Сервер: Linux/amd64, Linux/arm64, macOS, Windows. Релизы собираются
  GitHub Actions под все четыре.
- Клиент: Android 8+ через форк Element X+. SchildiChat и любой
  matrix-rust-sdk-клиент совместимы при интеграции по
  [INTEGRATE-ANDROID.md](docs/INTEGRATE-ANDROID.md).
- Go 1.26+ для сборки из исходников.

## Релизы

Релизы тегом `vX.Y.Z`. GitHub Actions автоматически:

- собирает бинарь под linux/{amd64,arm64,armv7}, darwin/{amd64,arm64},
  windows/amd64;
- считает SHA-256 для каждого;
- собирает multi-arch Docker-image и пушит в `ghcr.io/<owner>/mxtr-proxy`;
- создаёт GitHub Release с бинарями, сертификатами и
  auto-generated release notes.

См. [.github/workflows/release.yml](.github/workflows/release.yml).

## Лицензия

Public domain (Unlicense). Берите, меняйте, форкайте, продавайте,
встраивайте. Атрибуция не требуется. См. [LICENSE](LICENSE).
