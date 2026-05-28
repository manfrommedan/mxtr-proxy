# Протокол mxtr v2

Stream-multiplexed обфусцированный транспорт поверх TLS-1.3. Один
long-lived TCP-сокет несёт N логических потоков, мультиплексированных
4-байтным `stream_id`. Все байты после TLS-handshake зашифрованы
ChaCha20-Poly1305 с per-session ключами, выведенными из PSK + двух
nonce.

```
[matrix-rust-sdk / WebView]
       │ HTTP CONNECT host:port
       ▼
[in-app listener 127.0.0.1:1984]    (auto-fallback на 1984..1993 если 1984 занят)
       │ mxtr v2 stream-multiplexed
       ▼ TLS 1.3 (SNI = persisted CN)
[mxtr-server, port из share-string]
       │ plain TCP
       ▼
[matrix.org / element.io / OIDC IdP]
```

## TLS layer

TLS-1.3 only (`enabledProtocols=["TLSv1.3"]` на клиенте и сервере). По
умолчанию self-signed cert; опционально - реальный LE-cert через
`-cert/-key` (RSA или EC, клиент принимает оба).

**Self-signed CN** генерится из синтетического пула ~1.8 млн имён по 7
реальным CDN-шаблонам (`<region><N>.edge.fastly.net`,
`node-<city>-<N>.bunnycdn.com`, `a<N>.<city>.edge.akamaiedge.net` и
т.д.). RKN не может составить словарь - сетку из ~10 fixed имён мы
выбросили. Выбранное имя **персистится** в файл рядом с PSK (по умолчанию
`./mxtr-cert.cn`), рестарт сохраняет identity. `-rotate-cloak` форсирует
переброс.

**SNI в ClientHello** = тот же CN (передаётся через `?sni=<cn>` в
share-string). Сервер представляет cert с тем же subject. Совпадение
SNI/cert на wire - нет "SNI≠cert" тели, которую TSPU отслеживает с 2022.

ALPN: server предлагает `h2,http/1.1` (порядок выбирается из PSK).
Так пассивный наблюдатель видит обычный CDN, отдающий HTTP/2.

Аутентификация - **не** через X509, а через PSK-HMAC внутри handshake
(см. ниже). Клиент проверяет в cert только: chain не пустой, не
просрочен, алгоритм EC или RSA. PSK гарантирует mutual auth.

## Handshake (после TLS)

```
Client -> Server: nonce_c(16) || padlen_c(1) || pad_c(padlen_c) || mac_c(16)
Server -> Client: nonce_s(16) || padlen_s(1) || pad_s(padlen_s) || mac_s(16)

  mac_c = HMAC-SHA256(PSK, nonce_c || padlen_c || pad_c || "c2s-hs")[:16]
  mac_s = HMAC-SHA256(PSK, nonce_s || padlen_s || pad_s || "s2c-hs")[:16]

  padlen ∈ [0, 255], pad - случайные байты той же длины
```

Обе стороны хешируют **только своё**: клиент в первом пакете ещё не
знает `nonce_s`, поэтому в его MAC его нет. Label `"c2s-hs"` /
`"s2c-hs"` отличает client-handshake и server-handshake friends-or-foes
по направлению, чтобы reflected-MAC из одной стороны не валидировался
другой.

`pad` рандомной длины убивает фиксированный fingerprint первого пакета
после TLS. На стороне сервера ответ дополнительно задерживается на
случайные 5-50 мс (`jitterMinMS..jitterMaxMS`, константы) - чтобы не
было характерного «мгновенного reply».

После handshake обе стороны выводят AEAD-ключи:

```
K_c2s = HKDF-SHA256(PSK, nonce_c || nonce_s, info="c2s-key")[:32]
K_s2c = HKDF-SHA256(PSK, nonce_c || nonce_s, info="s2c-key")[:32]
seq_c = 0, seq_s = 0
```

Если HMAC сервера не совпал у клиента (или наоборот) - сторона рвёт
TLS-соединение **без** ответного сообщения. Активный зонд получит
60-секундный hang (`probeHangDuration`) и не узнает, что попал на mxtr.

## Frame format

После handshake поток - последовательность AEAD-фреймов:

```
on wire:    [len(2) BE] [ciphertext_with_tag(len)]
plaintext:  [real_len(2) BE] [data(real_len)] [random pad до ладдер-рунги]
nonce:      [0(4)] [seq(8) BE]
            seq инкрементируется на каждый отправленный фрейм
            (отдельный счётчик seqWrite/seqRead в каждую сторону)
```

`len` - 16-bit BE, и это длина **всего** ciphertext'а, который ChaCha20-
Poly1305 возвращает одним блобом `ciphertext || poly1305_tag` (16 байт
tag'а уже сидят в конце). Соответственно `maxCiphertextLen = 16400`
(16384 padded plaintext + 16 tag).

`real_len` - сколько байт в plaintext'е настоящие, остальное в
inner-фрейме - случайный padding до выбранной рунги PADME-style лесенки:
`{256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384}`
(13 рунг с 1.5x половинными шагами вместо строгих power-of-2). Размер
выбирается **size-scaled probabilistic bump**: для payload <1KB с 30%
шансом padder прыгает на следующую рунгу, для 1-4KB - 18%, для >4KB - 8%.
Так гистограмма размеров на wire размазана по 13 buckets вместо 7 spike'ов,
без overhead'а на больших фреймах. Bump - независимое решение клиента и
сервера, согласовывать не нужно (wire несёт только ciphertext-длину).

Reuse nonce, обрезка фрейма, или decrypt при несовпадающем seq - сразу
teardown сессии.

## Stream frames

Внутри plaintext - stream-frame:

```
[stream_id(4) BE] [type(1)] [payload_len(2) BE] [payload]
```

Типы:

| code | name      | направление    | payload                          |
|------|-----------|----------------|----------------------------------|
| 0x01 | OPEN      | client -> server| `addr_type(1) || addr || port(2)`|
| 0x02 | DATA      | bidir          | произвольные байты               |
| 0x03 | CLOSE     | bidir          | пусто                            |
| 0x04 | PING      | bidir          | случайный padding                |
| 0x05 | PONG      | bidir          | случайный padding                |
| 0x06 | OPEN_OK   | server -> client| пусто                            |
| 0x07 | OPEN_ERR  | server -> client| utf8-причина                     |

`addr_type`:

```
0x01 IPv4    addr = 4 bytes
0x02 domain  addr = len(1) || string(len)
0x03 IPv6    addr = 16 bytes
```

`stream_id` 32-bit BE. Клиент использует нечётные id (1, 3, 5, ...),
сервер не назначает id (только OPEN_OK/OPEN_ERR на клиентские).
Адресное пространство 2^31 нечётных id - на мобильном клиенте это
"никогда" (даже при 10 streams/sec - тысячелетия).

`stream_id <= 0` - signal exhausted, клиент должен закрыть сессию и
переоткрыть.

## Keepalive

Каждая сторона держит свой heartbeat-таймер. Если за последние
`heartbeatMinMs..heartbeatMaxMs` (выводятся из PSK, диапазон ~20-70с) не
было исходящего фрейма - шлём PING со случайным padding (0-256 байт).
Получатель отвечает PONG с независимым padding-размером.

SO_TIMEOUT на TLS-сокете = `heartbeatMaxMs + 30_000`. Если за это время
ни одного байта не прилетело - сессия мёртвая, рвём.

## Camouflage HTTP

Если на тот же порт пришёл запрос, который **не** прошёл mxtr-handshake
(пустой read, или валидный HTTP/1.1/HTTP/2) - сервер отвечает как
обычный, плохо сконфигурированный web-сервер. Шесть семейств шаблонов,
по одному на startup, **выбор персистится** (`mxtr-cloak.idx` рядом с
PSK, restart сохраняет identity):

- nginx
- Apache
- LiteSpeed
- Caddy
- cloudflare
- generic Go-stdlib (пустой Server header)

**Версии скрыты**: только family name, как `server_tokens off` /
`ServerSignature Off` на реальном production. На каждый probe **статус
выбирается случайно** из {403, 404, 500} - не статичный "всегда 500" tell.

Path-aware ответы:

| Path                  | Ответ                                |
|-----------------------|--------------------------------------|
| `/robots.txt`         | 200, `User-agent: *\nDisallow:\n`    |
| любой другой          | случайно из 403/404/500 + family body|

Headers совпадают с тем что реально отдаёт каждый family
(`Cache-Control` у Cloudflare, `Strict-Transport-Security` у Caddy и т.д.).
`Date:` всегда текущий UTC.

`curl -ksv https://<vps-ip>:<port>/` от любого зеваки увидит ровно это.
`curl https://<vps-ip>:<port>/robots.txt` - реалистичный 200.

## Per-PSK runtime config

Из PSK выводится не только ключевая иерархия, но и набор параметров,
которые иначе были бы общим fingerprint'ом всех деплоев:

```
HKDF-SHA256(
  IKM  = PSK,
  salt = "mxtr-config-v1-salt",
  info = "mxtr-config-v1",
)  ->  16 bytes  ->  разбивается на:

  out[0]                     -> camouflage_template_idx  (nginx|apache|litespeed|caddy|cloudflare|stdlib)
  out[1] & 1                 -> alpn_order               (h2,http/1.1 | http/1.1,h2)
  20_000 + out[2]*100        -> heartbeat_min_ms         (20.0-45.5s)
  45_000 + out[3]*100        -> heartbeat_max_ms         (45.0-70.5s)
  32 + out[4]                -> heartbeat_pad_min        (32-287 bytes)
  512 + (uint16(out[5..7]) % 3584) -> heartbeat_pad_max  (512-4095 bytes)
  10_000 + out[8]*50         -> idle_threshold_ms        (10.0-22.75s)
```

Два разных деплоя, разные PSK -> разный порядок ALPN, разная cadence
heartbeat. Pattern-detector, обученный на одном deployment'е, не
покрывает другой.

Camouflage family НЕ PSK-derived в текущей версии: выбор делается
crypto/rand на первом startup и **персистится** на диск. Это нужно
чтобы restart не менял Server-header (real nginx так не делает).
`out[0]` всё ещё доступен в коде для будущего fallback на PSK-derived
выбор, но в активном пути не используется.

**Handshake jitter** (5-50 мс на server-hello): фиксированные константы
`jitterMinMS`/`jitterMaxMS`. Отдельно есть **PING-PONG jitter** 0-15 мс:
сервер отвечает PONG с дополнительной случайной задержкой через goroutine,
чтобы убить "every PING matched by PONG within 1ms" timing tell, который
читает flow-shape ML.

## Активный зонд: что увидит

| Зонд                                | Ответ сервера                                |
|-------------------------------------|----------------------------------------------|
| `curl https://host:<port>/`         | TLS-1.3 + h2 + случайно 403/404/500 одного из 6 семейств, headers совпадают с тем что реально отдаёт это family |
| `curl https://host:<port>/robots.txt` | TLS-1.3 + h2 + 200 + `User-agent: *\nDisallow:\n` |
| `nc host <port>` + случайные байты  | TLS-1.3 handshake -> дальше hang 60с          |
| Правильный mxtr-handshake (wrong PSK)| TLS -> читает MAC -> fail -> hang 60с          |
| TLS handshake без SNI               | принимаем, отдаём cert (SNI tolerant)        |
| TLS handshake с любым SNI           | принимаем, отдаём cert (один cert на listener)|

## Security properties

- **Confidentiality**: AEAD на каждом фрейме. Реплей старого фрейма
  декриптится с неверным seq и рвёт сессию.
- **Mutual auth**: обе стороны доказывают знание PSK через handshake-HMAC.
- **Forward secrecy на сессию**: per-session AEAD-ключи привязаны к
  двум одноразовым nonce. Утечка ключей одной сессии не раскрывает
  другую.
- **Forward secrecy на PSK**: **нет**. PSK долговременный. При утечке
  PSK захваченный заранее траффик (зашифрованный AEAD-ом, ключи
  которого выведены из PSK + nonce) расшифровывается.

PSK - единая точка отказа. Ротировать при подозрении на утечку. PSK
никогда не покидает device локально - кроме того момента, когда
оператор раздаёт share-string по защищённому каналу.

## Persisted state

Все длительные параметры сохраняются на диск рядом с PSK file:

- `psk.hex` - 64 hex char PSK. Auto-генерится при первом запуске если
  ни `-psk`, ни `MXTR_PSK`, ни существующий файл не дают значения.
  Hardening: создаётся через `O_CREATE|O_EXCL|O_NOFOLLOW` + atomic rename;
  symlink на путь файла защищён (rename подменяет inode, target не
  трогаем). chmod 600 после write.
- `mxtr-cloak.idx` - индекс выбранного camouflage family (0..5).
- `mxtr-cert.cn` - сгенерированное CN для self-signed cert.

Restart сохраняет cloak family и cert CN - реальный nginx тоже не
меняет 500-страницу при рестарте. `-rotate-cloak` явно ротирует обе
(и cloak idx, и cert CN) одновременно: оператор выбирает когда менять
identity.

## Что протокол НЕ делает

- Не делает GREASE TLS extensions (хорошо: меньше fingerprint surface,
  плохо: чистая TLS-1.3 без GREASE сама по себе чуть-чуть выделяется
  на фоне Chrome/Firefox). На Android API 29+ JSSE = Conscrypt, который
  GREASE отдаёт - но не на всех версиях ровно.
- Не делает domain fronting через CDN. Камуфляж - synthetic CN +
  camouflage HTTP + persisted identity. SNI совпадает с cert: domain
  fronting (SNI≠cert) - **классический tell**, мы его избегаем.
- Не делает TCP-splice cloak до реального сайта (как `telemt`). Для
  personal-VPS избыточно.
- Не имеет congestion-control сверх TCP. Один сокет = одно окно. При
  20+ потоках с разными RTT возможны head-of-line stalls. Для матрикс
  это нормально (REST + sync-loop, не bulk).
- Не делает пер-conn rotating PSK. Это сознательное решение: трафик
  Element X идёт пачками с длинными паузами; новый handshake на
  каждую пачку добавил бы 2 RTT латентности к каждому /sync.
