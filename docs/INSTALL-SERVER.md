# Установка сервера

Сервер - один Go-бинарь без зависимостей. Запускается на любом VPS с
открытым TCP-портом. Рекомендуемая площадка: Hetzner, OVH, Vultr, DO -
любой не-RU/CIS провайдер, который не обязан отвечать на запросы РКН.

Минимум: 1 vCPU, 256 МБ RAM, 1 ГБ диска. Сервер одинаково тянет 10 и
2000 одновременных клиентов: вся работа per-conn это AEAD-копия буфера.

## Вариант 1. Docker (рекомендуется)

```bash
git clone https://github.com/<you>/mxtr-proxy /opt/mxtr-proxy
cd /opt/mxtr-proxy

# 1. Сгенерировать PSK (32 случайных байта в hex).
docker run --rm $(docker build -q .) -gen-psk
# вывод: 64-символьная hex-строка. Сохрани, она же пойдёт в .env и
# в share-string для каждого клиента.

# 2. Положить .env (chmod 600, в нём секрет).
cat >.env <<'EOF'
MXTR_PSK=PASTE_64_HEX_CHARS_HERE
MXTR_PUBLIC_HOST=your-vps.example.com
# опционально: ограничить proxy списком целевых доменов
# (поддомены включаются автоматически, без вилдкардов)
# MXTR_ALLOW=matrix.org,element.io
EOF
chmod 600 .env

# 3. Поднять.
docker compose up -d --build

# 4. Проверить.
docker compose logs --tail=20
# в логе должно быть: "PSK-derived config" и "TLS listening on :9290"
curl -ksv https://<vps-ip>:9290/
# должно отдать HTTP/2 500 с заголовком server: nginx (или Apache, или
# LiteSpeed - выбирается из PSK, у разных деплоев разные).
```

Контейнер запускается под `nonroot`, с `cap_drop: ALL`, `read_only`,
`no-new-privileges`, `network_mode: host` (чтобы TLS-сокет был прямой,
без docker NAT) и ротируемыми JSON-логами (1 МБ × 3).

### Share-string

При старте сервер печатает в лог:

```
share-string: mxtr://<base58-PSK>@<MXTR_PUBLIC_HOST>:9290
```

Эту строку (и только её) надо передать на устройство клиента. Канал
передачи - такой же, как для пароля от почты: Signal, PGP, бумажка.
Base58 PSK - единственный долговременный секрет.

### Ротация PSK

```bash
docker run --rm mxtr-proxy:dev -gen-psk   # новый ключ
nano .env                                  # обновить MXTR_PSK
docker compose up -d                       # рестарт
```

Старые share-string перестают работать сразу - всем клиентам нужно
вставить новую строку.

### TLS-сертификат

По умолчанию self-signed cert с CN под Cloudflare/Fastly/BunnyCDN/прочее
(выбирается из PSK). Клиент аутентифицирует сервер через PSK-HMAC,
сертификат не проверяет - так удобнее: нет лимитов Let's Encrypt и нет
записи в Certificate Transparency, которая бы засветила host.

Если всё-таки нужен LE, override через `docker-compose.override.yml`:

```yaml
services:
  mxtr:
    volumes:
      - /etc/letsencrypt/live/your-domain/fullchain.pem:/run/secrets/cert.pem:ro
      - /etc/letsencrypt/live/your-domain/privkey.pem:/run/secrets/key.pem:ro
    command:
      - "-tcp"
      - ":9290"
      - "-cert"
      - "/run/secrets/cert.pem"
      - "-key"
      - "/run/secrets/key.pem"
      - "-log-level"
      - "warn"
```

### Файрвол

```bash
ufw allow 9290/tcp
# или
iptables -A INPUT -p tcp --dport 9290 -j ACCEPT
```

Если провайдер запрещает нестандартные порты, поменяй `-tcp :9290` и
`EXPOSE` на `:443`. На том же IP больше ничего на 443 висеть не должно.

### Операционка

```bash
docker compose ps              # статус
docker compose logs -f         # хвост
docker compose restart         # перезапуск
docker compose down            # остановить + снести

docker compose up -d --build   # обновить после git pull
```

`restart: unless-stopped` переживает перезагрузку - systemd-юнит не
нужен.

## Вариант 2. Сборка из исходников

Нужен Go 1.26+.

```bash
git clone https://github.com/<you>/mxtr-proxy
cd mxtr-proxy
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o mxtr-server ./cmd/mxtr-server

# PSK
./mxtr-server -gen-psk
# 64 hex-символа в stdout

# Запуск
MXTR_PSK=<paste-hex> ./mxtr-server -tcp :9290 -public-host your-vps.example.com
```

Все флаги:

```
-tcp string          адрес TCP-листенера (default ":9290")
-cert string         путь к TLS cert (PEM); пусто = self-signed
-key string          путь к TLS key (PEM); пусто = self-signed
-public-host string  hostname для share-string (по умолчанию hostname машины)
-allow string        whitelist целевых доменов через запятую
-log-level string    silent | warn | info | debug (default "info")
-gen-psk             выводит новый PSK в stdout и выходит
```

systemd-юнит, если очень нужно:

```ini
# /etc/systemd/system/mxtr-proxy.service
[Unit]
Description=mxtr-proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mxtr
EnvironmentFile=/etc/mxtr-proxy.env
ExecStart=/usr/local/bin/mxtr-server -tcp :9290 -public-host your-vps.example.com
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mxtr
sudo install -m 755 mxtr-server /usr/local/bin/
echo "MXTR_PSK=<hex>" | sudo tee /etc/mxtr-proxy.env
sudo chmod 600 /etc/mxtr-proxy.env
sudo systemctl daemon-reload
sudo systemctl enable --now mxtr-proxy
```

## Проверка работы

```bash
# 1. Активное зондирование: сервер должен прикинуться нормальным веб-сервером.
curl -ksv https://<vps-ip>:9290/
# HTTP/2 500
# server: nginx/1.27.4
# date: Mon, 27 May 2026 ...

# 2. Туннель: testclient через SOCKS5 на localhost:1984.
go build -o mxtr-testclient ./cmd/mxtr-testclient-v2
MXTR_PSK=<hex> ./mxtr-testclient -server <vps-ip>:9290 -socks :1984 &
curl --socks5 127.0.0.1:1984 https://matrix.org/_matrix/client/versions
# должен прийти JSON со списком версий
```

## Что НЕ делает сервер

- Не мультиплексирует разные PSK на одном порту. Один PSK на деплой.
  Хочешь изоляцию между пользователями - запусти несколько контейнеров
  на разных портах или IP.
- Не лимитит per-IP. На уровне PSK это не нужно (PSK уже гейтит
  доступ). Если хочешь публично - ставь `iptables --hashlimit` спереди.
- Не делает domain fronting. DPI-resistance держится на camouflage 500
  и per-PSK fingerprint, а не на чужом CDN.
- Не экспортит метрики и не телеметрит. Никаких outbound-соединений,
  кроме тех, что инициировал клиент через CONNECT.
