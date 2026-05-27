# mxtr-proxy

Обфусцированный TCP-relay для Matrix-клиентов на matrix-rust-sdk.
Сервер выглядит для пассивного DPI и активного зондирования как
неправильно сконфигурированный CDN-edge (Cloudflare / Fastly /
BunnyCDN-стиль): тот же IP при `curl https://...` отдаёт
правдоподобную 500-страницу, внутренний протокол неотличим от
случайного TLS-шума.

Создавался под форк Element X+ (наш Android-клиент Matrix). Это **не**
general-purpose-прокси, **не** замена VPN, **не** конкурент MTProto.
Применимость - своя ниша: Matrix через matrix-rust-sdk + один-два
пользователя на personal-VPS.

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

```bash
git clone https://github.com/<you>/mxtr-proxy /opt/mxtr-proxy
cd /opt/mxtr-proxy

# 1. PSK
docker run --rm $(docker build -q .) -gen-psk

# 2. .env (chmod 600)
cat >.env <<'EOF'
MXTR_PSK=<paste-hex-from-step-1>
MXTR_PUBLIC_HOST=your-vps.example.com
# MXTR_ALLOW=matrix.org,element.io   # опционально, см. docs/THREAT-MODEL.md
EOF
chmod 600 .env

# 3. Поднять
docker compose up -d --build

# 4. Share-string в логе
docker compose logs | grep share-string
# mxtr://<base58-PSK>@<host>:9290
```

Эту share-string вставить в `Настройки → Расширенные → АнтиЦензурный
прокси` в форке Element X+. Перезапустить app. Готово.

Подробности - в [docs/INSTALL-SERVER.md](docs/INSTALL-SERVER.md).

## Документация

- [INSTALL-SERVER.md](docs/INSTALL-SERVER.md) - Docker и сборка из
  исходников, share-string, ротация PSK, TLS, файрвол.
- [INTEGRATE-ANDROID.md](docs/INTEGRATE-ANDROID.md) - как встроить
  клиентскую часть в свой форк Element X / SchildiChat / любой
  Android-клиент на matrix-rust-sdk. Что копировать, куда вешать
  hooks.
- [PROTOCOL.md](docs/PROTOCOL.md) - wire-формат: TLS, handshake,
  AEAD-фреймы, stream-мультиплексирование, camouflage 500, per-PSK
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
  выводит свою camouflage server-family (nginx / Apache / LiteSpeed),
  порядок ALPN и cadence heartbeat - у каждого деплоя свой fingerprint.
- Полная децентрализация. Нет центрального сервера, нет публичных
  списков IP, нет CDN-точки отказа. Каждый поднимает свой VPS, сам
  раздаёт share-string своему кругу. РКН нечего блокировать оптом -
  только заходить per-IP, а они между собой ничем не связаны.
- Устойчив к зондированию: `curl https://<vps>:9290/` отдаёт
  500-страницу с правдоподобным `Server:` и текущим `Date:`.
  Не-HTTP байты висят 60 секунд. Зонд не получает ни одного
  положительного сигнала.
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
- Не shared-сервис. Один оператор - один VPS - один PSK.
- Оверхед по трафику есть: 16 байт AEAD-tag на фрейм + power-of-2
  padding (обфускация размеров стоит обычно 30-50% поверх payload).
  На LTE заметно, на Wi-Fi нет.
- Нет TCP-splice до реального cloak-домена (как у `telemt`). Для
  личного использования (свой VPS, свой круг, обход цензуры и
  чебурнета без публичной светимости) - избыточно. РКН и иранский
  чебурнет активно обходят публичные шеренги proxy-IP; у нас IP
  знают только те, кому ты сам выдал share-string. Массовых
  зондирований по такому IP не будет, синтетической 500-страницы
  хватает закрыть случайного зеваку.

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
