# Установка сервера

Сервер - один Go-бинарь без зависимостей. Запускается на любом VPS с
открытым TCP-портом. Площадка: Hetzner, OVH, Vultr, DO - любой не-RU/CIS
провайдер, который не обязан отвечать на запросы РКН.

Минимум: 1 vCPU, 512 МБ RAM, 1 ГБ диска. Сервер тянет 1000+
одновременных клиентов на 1 vCPU: AEAD-копии буфера идут через
sync.Pool, на горячих аллокациях GC pressure ~10x ниже чем без пула.
maxConcurrentConns по умолчанию 8192 (запас на reconnect-churn + probe
storms). Для 1000+ юзеров поставь `ulimit -n 65536` и
`sysctl -w net.netfilter.nf_conntrack_max=131072` на хосте.

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
└── mxtr-cert.cn       # synthetic CDN-edge CN для self-signed cert
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

По умолчанию self-signed cert с synthetic CN
(`<region><N>.edge.fastly.net` и т.д.). Если хочется реальный
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
# 1. Активное зондирование: сервер должен прикинуться cdn-edge с 4xx/5xx.
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
- Не делает domain fronting. DPI-resistance держится на synthetic CN +
  camouflage HTTP + SNI совпадает с cert. Domain fronting (SNI≠cert) -
  это классический tell, мы его специально избегаем.
- Не экспортит метрики и не телеметрит. Никаких outbound-соединений,
  кроме тех, что инициировал клиент через CONNECT.
