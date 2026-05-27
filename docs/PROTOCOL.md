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
[in-app listener 127.0.0.1:1984]
       │ mxtr v2 stream-multiplexed
       ▼ TLS 1.3
[mxtr-server, port 9290]
       │ plain TCP
       ▼
[matrix.org / element.io / OIDC IdP]
```

## TLS layer

TLS-1.3 only (`enabledProtocols=["TLSv1.3"]` на клиенте и сервере). По
умолчанию self-signed cert. CN ротируется из набора plausible CDN-edge
имён (Cloudflare, Fastly, BunnyCDN и т.д.), выбор детерминирован от
PSK через HKDF - каждый деплой выглядит чуть-чуть по-разному.

ALPN: server проксирует `h2,http/1.1` (порядок тоже выбирается из PSK).
Так пассивный наблюдатель видит обычный CDN, отдающий HTTP/2.

Аутентификация - **не** через X509, а через PSK-HMAC внутри handshake
(см. ниже). Клиент игнорирует cert: PSK гарантирует mutual auth.

## Handshake (после TLS)

```
Client → Server: nonce_c(16) || padlen_c(1) || pad_c(padlen_c) || mac_c(16)
Server → Client: nonce_s(16) || padlen_s(1) || pad_s(padlen_s) || mac_s(16)

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
inner-фрейме - случайный padding до следующей рунги фиксированной
лесенки: `{256, 512, 1024, 2048, 4096, 8192, 16384}`. То есть даже
4-байтный полезный payload идёт на проводе в виде 256-байтного inner
плюс 16 байт tag'а. Реальное распределение длин превращается в этот
дискретный набор и пропадает как сигнал для DPI.

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
| 0x01 | OPEN      | client → server| `addr_type(1) || addr || port(2)`|
| 0x02 | DATA      | bidir          | произвольные байты               |
| 0x03 | CLOSE     | bidir          | пусто                            |
| 0x04 | PING      | bidir          | случайный padding                |
| 0x05 | PONG      | bidir          | случайный padding                |
| 0x06 | OPEN_OK   | server → client| пусто                            |
| 0x07 | OPEN_ERR  | server → client| utf8-причина                     |

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

## Camouflage 500

Если на тот же порт пришёл запрос, который **не** прошёл mxtr-handshake
(пустой read, или валидный HTTP/1.1/HTTP/2 без CONNECT) - сервер
отвечает правдоподобной 500-страницей одного из трёх вариантов
(nginx/Apache/LiteSpeed). Выбор по PSK, плюс корректные заголовки:

- `Server: nginx/1.27.4` (или `Apache/2.4.62`, или `LiteSpeed`)
- `Date: <Tue, 27 May 2026 12:34:56 GMT>` (текущее UTC в формате
  HTTP-date)
- `Content-Type: text/html`
- `Connection: close`

Тело - стилизованный под выбранный сервер HTML с 500. Сам сервер тогда
ничего не знает о PSK зонда: он просто прикинулся плохо
сконфигурированным веб-сервером.

`curl -ksv https://<vps-ip>:9290/` от любого зеваки увидит ровно это.

## Per-PSK runtime config

Из PSK выводится не только ключевая иерархия, но и набор параметров,
которые иначе были бы общим fingerprint'ом всех деплоев:

```
HKDF-SHA256(
  IKM  = PSK,
  salt = "mxtr-config-v1-salt",
  info = "mxtr-config-v1",
)  ->  16 bytes  ->  разбивается на:

  out[0]                     -> camouflage_template_idx  (nginx | apache | litespeed)
  out[1] & 1                 -> alpn_order               (h2,http/1.1 | http/1.1,h2)
  20_000 + out[2]*100        -> heartbeat_min_ms         (20.0-45.5s)
  45_000 + out[3]*100        -> heartbeat_max_ms         (45.0-70.5s)
  32 + out[4]                -> heartbeat_pad_min        (32-287 bytes)
  512 + (uint16(out[5..7]) % 3584) -> heartbeat_pad_max  (512-4095 bytes)
  10_000 + out[8]*50         -> idle_threshold_ms        (10.0-22.75s)
```

Два разных деплоя, разные PSK → разный camouflage server-header,
разный порядок ALPN, разная cadence heartbeat. Pattern-detector,
обученный на одном deployment'е, не покрывает другой.

Handshake jitter (5-50 мс), наоборот, **не** PSK-derived - это
фиксированные константы `jitterMinMS`/`jitterMaxMS`. Если когда-нибудь
понадобится развести и его - расширить структуру `pskDerivedConfig`.

## Активный зонд: что увидит

| Зонд                             | Ответ сервера                          |
|----------------------------------|----------------------------------------|
| `curl https://host:9290/`        | TLS-1.3, h2, HTML 500 nginx/Apache/LSWS|
| `nc host 9290` + случайные байты | TLS-1.3 handshake → дальше hang 60с    |
| Правильный mxtr-handshake (wrong PSK) | TLS → mxtr ack → HMAC fail → RST  |
| Telnet до timeout                | пустой TLS-handshake (no SNI) → drop   |

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

## Что протокол НЕ делает

- Не делает GREASE TLS extensions (хорошо: меньше fingerprint surface,
  плохо: чистая TLS-1.3 без GREASE сама по себе чуть-чуть выделяется
  на фоне Chrome/Firefox).
- Не делает domain fronting через CDN. Камуфляж - только camouflage
  500 + per-PSK fingerprint randomisation.
- Не имеет congestion-control сверх TCP. Один сокет = одно окно. При
  20+ потоках с разными RTT возможны head-of-line stalls. Для матрикс
  это нормально (REST + sync-loop, не bulk).
- Не делает пер-conn rotating PSK. Это сознательное решение: трафик
  Element X идёт пачками с длинными паузами; новый handshake на
  каждую пачку добавил бы 2 RTT латентности к каждому /sync.
