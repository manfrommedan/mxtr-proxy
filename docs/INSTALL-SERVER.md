# Установка сервера

Сервер - один Go-бинарь без зависимостей. Запускается на любом VPS с
открытым TCP-портом. Площадка: Hetzner, OVH, Vultr, DO - любой не-RU/CIS
провайдер, который не обязан отвечать на запросы РКН.

Минимум **рабочий**: 1 vCPU / 256 МБ RAM / 10 ГБ диска - такие сейчас
продаются за $1-3/мес у low-end-провайдеров.

**Сколько тянет** (на типичной Matrix-нагрузке /sync long-poll):

- 1 vCPU / 256 МБ, defaults: 300-500 одновременных юзеров.
  Упирается в `ulimit -n` (по умолчанию 1024 на большинстве дистров).
- 1 vCPU / 256 МБ + тюнинг ниже: 800-1200.
- 1 vCPU / 512 МБ + тюнинг: 1500-2500.
- 2 vCPU / 1 ГБ + тюнинг: 5000-8000.

Узкое место - RAM (Go heap + goroutine stacks), не CPU. AEAD-копии
буфера идут через sync.Pool, на горячих аллокациях GC pressure ~10x
ниже чем без пула. maxConcurrentConns по умолчанию 8192 (запас на
reconnect-churn + probe storms).

**Тюнинг для еле-еле-VPS** (даёт +2-3x потолок):

```bash
# /etc/security/limits.conf или /etc/systemd/system.conf:
*   soft   nofile   65536
*   hard   nofile   65536

# /etc/sysctl.d/99-mxtr.conf:
net.core.somaxconn = 8192
net.ipv4.ip_local_port_range = 10000 65535
net.netfilter.nf_conntrack_max = 131072
net.ipv4.tcp_max_orphans = 32768
fs.file-max = 200000

sysctl -p /etc/sysctl.d/99-mxtr.conf
```

Применить через `docker compose down && docker compose up -d` или
рестарт VPS.

## Вариант 1. Docker (рекомендуется)

```bash
git clone https://github.com/<you>/mxtr-proxy /opt/mxtr-proxy
cd /opt/mxtr-proxy

# 1. Создать persistent volume для state.
mkdir -p /opt/mxtr-proxy/state
chmod 700 /opt/mxtr-proxy/state

# 2. Поднять. PSK сгенерится на первом старте и запишется в state/psk.hex.
docker run -d --name mxtr-proxy \
  --restart unless-stopped \
  --network host \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -v /opt/mxtr-proxy/state:/state \
  --log-driver json-file --log-opt max-size=1m --log-opt max-file=3 \
  ghcr.io/<you>/mxtr-proxy:latest \
  -tcp :<port> -public-ip <vps-ip> -psk-file /state/psk.hex

# 3. Проверить.
docker logs mxtr-proxy 2>&1 | grep -E 'cert-cn|cloak|share-string|listening'
curl -ksv https://<vps-ip>:<port>/
# должен отдать случайно 403/404/500 одного из 6 cloak-семейств
# (nginx/Apache/LiteSpeed/Caddy/cloudflare/Go-stdlib) - выбирается
# на первом старте и персистится в state/mxtr-cloak.idx
```

Контейнер запускается под `nonroot:nonroot`, с `cap_drop: ALL`,
`read_only` (`/state` единственный writable mount), `no-new-privileges`,
`network_mode: host` (TLS-сокет прямой, без docker NAT).

### Share-string

При первом старте сервер печатает:

```
share-string: mxtr://<base58-PSK>@<vps-ip>:<port>?sni=<edge-name>
```

Эту строку надо передать на устройство клиента. Канал: Signal, PGP,
бумажка. PSK + SNI - вместе один секрет (SNI публично, но привязан к
конкретному cert subject на сервере, рассылать оба обязательно).

На последующих рестартах share-string печатается тот же самый: PSK +
cloak family + cert CN персистятся в `/state/` и переживают рестарт.
Реальный nginx тоже не меняет 500-страницу при рестарте.

### State directory layout

```
/opt/mxtr-proxy/state/
├── psk.hex            # PSK, 64 hex chars + \n, chmod 600
├── mxtr-cloak.idx     # camouflage family index (0..5)
└── mxtr-cert.cn       # нейтральный synthetic CN для self-signed cert
```

Все файлы создаются с `O_CREATE|O_EXCL|O_NOFOLLOW` + atomic rename -
подменить symlink'ом нельзя.

### Ротация cloak identity

Если хочется сменить Server-header и cert CN (не PSK):

```bash
docker stop mxtr-proxy
docker rm mxtr-proxy
# тот же docker run с дополнительным флагом -rotate-cloak
docker run -d --name mxtr-proxy ... -rotate-cloak ...
# выберет новый cloak family + новый cert CN, перепишет state
# выдаст НОВУЮ share-string (новый ?sni= в ней) - надо разослать
```

### Ротация PSK

```bash
docker stop mxtr-proxy
rm /opt/mxtr-proxy/state/psk.hex   # удалить старый
docker start mxtr-proxy            # auto-генерит новый
docker logs mxtr-proxy | grep share-string  # получить новый
```

Старые share-string перестают работать сразу. Всем клиентам нужно
вставить новую строку (включая новый PSK).

### Реальный LE-cert

По умолчанию self-signed cert с нейтральным synthetic CN
(`srv<N>-<region>.hosted-edge.net` и т.д., не под конкретный CDN). Если хочется реальный
Let's Encrypt - получи cert на свой домен, прокинь файлы внутрь
контейнера, добавь `-cert/-key/-sni`:

```bash
docker stop mxtr-proxy && docker rm mxtr-proxy
docker run -d --name mxtr-proxy ... \
  -v /etc/letsencrypt/live/<домен>/fullchain.pem:/secrets/cert.pem:ro \
  -v /etc/letsencrypt/live/<домен>/privkey.pem:/secrets/key.pem:ro \
  ghcr.io/<you>/mxtr-proxy:latest \
  -tcp :443 -public-ip <vps-ip> \
  -psk-file /state/psk.hex \
  -cert /secrets/cert.pem -key /secrets/key.pem \
  -sni <домен>
```

На 443 + real LE + SNI=твой-домен сервер выглядит как обычный
HTTPS-сайт. Это самый сильный антидпи-режим: живём в haystack'е HTTPS.

Renewal certbot'ом: добавь в его deploy-hook
`docker restart mxtr-proxy` (контейнер перечитает cert на старте).

### Файрвол

```bash
ufw allow <port>/tcp
# или
iptables -A INPUT -p tcp --dport <port> -j ACCEPT
```

Если провайдер запрещает нестандартные порты, ставь 443 - но на нём
больше ничего не должно слушать (nginx/caddy на том же IP конфликтуют).

### Allowlist целевых доменов

По умолчанию proxy тоннелит куда угодно. Если хочется ограничить (чтобы
PSK-leak не превратил тебя в open-relay):

```bash
docker stop mxtr-proxy && docker rm mxtr-proxy
docker run -d --name mxtr-proxy ... \
  -allow matrix.org,element.io,call.matrix.org,turn.livekit.cloud
```

Поддомены включаются автоматически (`matrix.org` покроет
`matrix-client.matrix.org`, `account.matrix.org` и т.д.). Без вилдкардов.

## Вариант 2. Сборка из исходников

Нужен Go 1.26+.

```bash
git clone https://github.com/<you>/mxtr-proxy
cd mxtr-proxy
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o mxtr-server ./cmd/mxtr-server

mkdir -p /var/lib/mxtr && chmod 700 /var/lib/mxtr

./mxtr-server -tcp :<port> -public-ip <vps-ip> -psk-file /var/lib/mxtr/psk.hex
# PSK сгенерится и запишется автоматически.
```

Все флаги:

```
-tcp string           TCP-листенер (default ":9290")
-psk string           PSK как hex (override env и -psk-file)
-psk-file string      путь к PSK файлу (default "./mxtr-psk.hex");
                      создаётся с random 32-byte PSK на первом запуске
-cert string          путь к TLS cert (PEM); пусто = self-signed
-key string           путь к TLS key (PEM); требуется при -cert
-sni string           hostname для ClientHello SNI и share-string;
                      пусто = берётся из cert CN
-public-ip string     публичный IPv4/IPv6 literal для share-string;
                      hostnames refused; пусто = auto-detect
-cloak-state string   путь к persisted cloak idx (default <psk-file dir>/mxtr-cloak.idx)
-rotate-cloak         форсировать fresh cloak family + cert CN
-allow string         whitelist целевых доменов через запятую
-log-level string     off | error | warn | info | debug (default "info")
-quiet                shorthand для -log-level=off (PSK не попадёт в stderr)
-gen-psk              выводит новый PSK в stdout и выходит
```

## Проверка работы

```bash
# 1. Активное зондирование: сервер должен прикинуться обычным веб-сервером с 4xx/5xx.
curl -ksv https://<vps-ip>:<port>/
# HTTP/2 403 (или 404, или 500) + server: nginx (или один из 6 семейств)
# date: <текущее UTC>

# 1b. /robots.txt - 200, реалистичный.
curl -ksv https://<vps-ip>:<port>/robots.txt
# HTTP/2 200
# User-agent: *
# Disallow:

# 2. Туннель: testclient через SOCKS5 на localhost:1984.
go build -o mxtr-testclient ./cmd/mxtr-testclient-v2
SHARE='<скопируй из docker logs grep share-string>'
./mxtr-testclient -share "$SHARE" -socks-addr :1984 -method socks5 &
curl --socks5 127.0.0.1:1984 https://matrix.org/_matrix/client/versions
# должен прийти JSON со списком версий
```

## Что НЕ делает сервер

- Не мультиплексирует разные PSK на одном порту. Один PSK на деплой.
  Хочешь изоляцию между пользователями - запусти несколько контейнеров
  на разных портах или IP.
- Не лимитит per-IP. Поставь `iptables --hashlimit` или nginx-фронт
  если нужен публичный shared-сервис.
- Не делает domain fronting. Domain fronting - это когда клиент шлёт
  в TLS ClientHello SNI=`<популярный-домен>` (например, `cloudflare.com`),
  а сервер за ним отдаёт cert на совсем другой домен. Идея в том чтобы
  пассивный DPI считал что соединение идёт к популярному домену и не
  блокировал. Проблема: РКН ТСПУ с 2022 года активно ищет именно этот
  паттерн "SNI не совпадает с cert subject" - и режет такие соединения
  быстрее обычных. Мы намеренно делаем наоборот: SNI=cert subject, оба -
  наш нейтральный synthetic hostname (не под конкретный CDN). Снаружи это
  выглядит как обычный мелкий VPS с дефолт-cert на своём собственном
  hostname - тех миллионы. Имитировать конкретный CDN мы намеренно
  перестали: имя вроде `*.fastly.net` резолвится в чужой anycast-ASN и
  даёт цензору проверяемую SNI-vs-ASN ложь. DPI-устойчивость держится не
  на маскировке под чужой домен, а на нейтральном synthetic CN
  (~6.7M space) + camouflage HTTP + persisted identity.
- Не экспортит метрики и не телеметрит. Никаких outbound-соединений,
  кроме тех, что инициировал клиент через CONNECT.
