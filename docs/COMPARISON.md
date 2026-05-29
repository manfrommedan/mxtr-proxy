# mxtr-proxy vs MTProto Proxy

## Дисклеймер сразу

mxtr-proxy создан **только** для форка Element X+ (Android Matrix-клиент
на matrix-rust-sdk). Это не general-purpose-прокси и не "убийца
MTProxy". MTProto Proxy решает свою задачу (Telegram), mxtr - свою
(Matrix), они не конкурируют. Цель этого документа - честно сравнить
инженерные решения, чтобы было понятно, какие свойства mxtr
скопировал, какие отбросил сознательно, и где он действительно лучше.

Источники - в [конце документа](#источники).

## Что такое MTProto Proxy образца 2026

Telegram-овский официальный сервер - C-код в репозитории
[TelegramMessenger/MTProxy](https://github.com/TelegramMessenger/MTProxy).
Со стороны Telegram - **проект фактически заброшен**: с января 2023 по
май 2026 в master ушло **3 коммита**, все в ноябре 2025:

| Commit  | Дата       | Что меняет |
|---------|-----------|---|
| `34fe0e7` | 2025-11-03 | fix compile warnings |
| `0613f76` | 2025-11-03 | принимать длинные ClientHello (length high-byte стал минимумом, не равенством) |
| `cafc338` | 2025-11-04 | version bump |

Никаких работ по ALPN, ciphersuites, JA3/JA4, SNI, новой
obfuscation mode. fake-TLS-реализация не менялась структурно с 2019
года.

Живёт MTProxy за счёт трёх активных форков:

- **alexbers/mtprotoproxy** (Python, 1.6k stars) - активный, последний
  коммит 2026-02-17. Добавляет: multi-secret, Prometheus-метрики,
  IPv6, eager upstream connect.
- **9seconds/mtg** v2 (Go) - активный. Добавляет: replay-protection
  через encrypted-timestamp, domain-fronting fallback (зонд
  проксируется на реальный cloak-домен), proxy chaining через
  Shadowsocks/Trojan upstream. **Ad-tag (sponsored channel) выпилен из
  v2** - keep v1 если нужен ad-revenue.
- **telemt/telemt** (Rust+Tokio, 3.8k stars) - самый свежий, создан в
  декабре 2025, релизится несколько раз в неделю. Поддерживает все
  три MTProto-моды (Classic / Secure-dd / FakeTLS-ee + SNI fronting).
  Главное у них - **transparent TCP splice** на cloak-хост для
  зонда без правильного secret. Зонд видит настоящий TLS-handshake до
  указанного `mask_host` с настоящим сертификатом и настоящей
  chain-of-trust - не MITM, не fake-cert. На сегодня это эталон cloak
  quality в MTProxy-мире.

## Серьёзное обновление 2026

**Произошло 2026-04**: РКН ТСПУ выкатил signature `TELEGRAM_TLS`,
который файнгерпринтит MTProto fake-TLS по JA3/JA4. Конкретные tells:

1. **Нестандартный TLS-extension `0xfe02`** в ClientHello.
2. **20-байтный random** вместо стандартного для TLS-1.3 32-байтного
   X25519 key share.

В течение часов после raceout - массовые отключения MTProxy в RU.

Фикс выкатили **только в клиенты** (не в сервер):

- tdesktop: коммит [`407bf19`](https://github.com/telegramdesktop/tdesktop/commit/407bf196417b80c903f6ae65d4c3202be72286d5)
  ([PR #30513](https://github.com/telegramdesktop/tdesktop/pull/30513)),
  2026-04-03 - extension `0xfe02 -> 0xfe0d` (под ECH draft ID),
  `Op::random(20) -> Op::random(32)`.
- Telegram Android: [PR DrKLO/Telegram #1949](https://github.com/DrKLO/Telegram/pull/1949)
  (`37708d4`), Google Play 2026-04-06.
- iOS - в то же окно.

Серверный код MTProxy **не менялся**. Это значит: старый клиент на
обновлённом сервере по-прежнему детектится. Сервер не знает, какой
ClientHello клиент сейчас отправит, и не отвечает на это (потому что
сервер живёт в C-коде 2019 года).

## Что mxtr делает не так, как MTProxy

### 1. Не маскируется под TLS, а реально TLS

MTProxy: 4 байта magic-byte + свой handshake, *стилизованный* под
TLS ClientHello/ServerHello. Любая структурная странность в этой
стилизации (extension type, длина random) - готовый JA3.

mxtr: настоящий TLS-1.3 как внешний слой. Стандартный JSSE на
Android, стандартный Go `crypto/tls` на сервере. Ничего не имитируем -
кладём mxtr-payload в обычный TLS-туннель.

Минус честный: JSSE по умолчанию не добавляет GREASE-расширения
(RFC 8701) - это тот мусорный экстеншен, который Chrome и Firefox
суют в каждый ClientHello, чтобы middlebox'ы научились не падать на
неизвестных tag'ах. Браузеры его добавляют, всё остальное обычно нет.
Чистый TLS-1.3 без GREASE на фоне Chrome выделяется.

Почему этот минус скорее теоретический: если ТСПУ начнёт банить
«TLS-1.3 без GREASE», под раздачу попадёт пол-интернета: весь
backend-трафик на Go (RU-сервисы, Yandex Cloud, Kubernetes-control
plane, любой REST на golang/net/http), вся внутрикорпоративная
Java-инфраструктура с JSSE, всё что ходит через OpenSSL без явного
включения GREASE, embedded-стеки в IoT, curl на половине дистрибутивов.
Такой блок выкосит банковские app'ы, госуслуги, корп-VPN и собственные
ТСПУ-сервисы РКН. Это «too big to ban» уровня TLS-1.3 целиком.
mxtr оказывается в стае, а не одиночкой.

### 2. Per-PSK runtime config + persisted per-deploy identity

MTProxy: один статичный fingerprint на все деплойменты. РКН увидел
`0xfe02` extension - забанил весь класс.

mxtr из PSK через HKDF выводит:

- порядок ALPN (h2,http/1.1 или http/1.1,h2)
- cadence heartbeat (~20-70с разброс, разный per PSK)
- размеры padding в heartbeat'е (32-287 min, 512-4095 max)

Плюс **persisted at first startup**:

- camouflage family - один из 6 (nginx/Apache/LiteSpeed/Caddy/cloudflare/Go-stdlib),
  выбирается crypto/rand на первом запуске и сохраняется в файл
  рядом с PSK. Restart сохраняет identity (реальный nginx тоже не меняет
  500-страницу при рестарте, ротация identity на каждый запуск -
  сама по себе признак подмены).
- TLS cert CN - нейтральный синтетический hostname из ~6.7 млн комбинаций
  (16 apex-доменов × 7 форм субдомена × 60 регионов × 999 чисел), не под
  конкретный CDN, персистится. Restart не меняет subject - cert тоже
  выглядит стабильным.
- `-rotate-cloak` форсирует пересборку обоих одновременно: оператор
  выбирает когда менять identity.

Два деплоя с разными PSK выглядят по-разному. РКН не может забанить
"класс mxtr-серверов" одним правилом. Если кто-то поднимет много
деплоев с тем же PSK - cert/cloak всё равно разные per host, потому
что персистенция идёт через crypto/rand на каждом отдельном диске.

### 3. Camouflage HTTP - 6 семейств, random 403/404/500, path-aware

MTProxy: при зондировании без правильного secret - молчит / timeout /
RST. Поведение характерно (Frolov NDSS 2020 как раз про это: timeout +
порог байтов - надёжный признак «proxy, устойчивый к зондированию»).

mxtr: при HTTP-зондировании отвечает как обычный, плохо
сконфигурированный web-сервер. 6 семейств шаблонов (nginx, Apache,
LiteSpeed, Caddy, cloudflare, generic Go-stdlib), один выбирается на
первом старте и **сохраняется**. На каждый отдельный probe статус
выбирается случайно из {403, 404, 500} с family-specific body и
headers (`Cache-Control`+`Vary` у Cloudflare,
`Strict-Transport-Security` у Caddy и т.д.). **Версии скрыты**: только
`server: nginx` / `server: Apache` без минорных версий - matches
production `server_tokens off`/`ServerSignature Off`.

Path-aware: `/robots.txt` отвечает 200 с реалистичным телом
`User-agent: *\nDisallow:\n`. Реальный public-facing сервер всегда так
делает, и мы тоже отвечаем.

`curl -ksv https://<vps-ip>:<port>/` от зеваки даёт случайно
выбранный 4xx/5xx правдоподобной структуры. Если зондирование
приходит как НЕ-HTTP байтопоток (или mxtr-handshake с неверным PSK) -
`400 Bad Request` выбранного семейства + close, ровно как реальный
nginx/Apache на кривой запрос. Раньше тут был 60-секундный silent-hang,
но молчание само по себе отличало нас от заявленного сервера - убрали.

### 4. Stream multiplexing на один TLS-сокет

MTProxy: connection-oriented. Каждое подключение к серверу - отдельный
TCP+handshake.

mxtr: один long-lived TCP+TLS-сокет несёт N логических потоков.
Handshake амортизируется. Для Matrix важно: matrix-rust-sdk делает
много параллельных REST-запросов, плюс long-poll `/sync` - все они
делят один outer сокет. С точки зрения DPI это **одна** TLS-сессия
с переменным application-data flow.

### 5. PADME-style padding ladder + size-scaled bump

MTProxy: paddы есть, но не отбивают размеры до фиксированной решётки -
обычно +0..15 случайных байт.

mxtr: 13-rung PADME-style ladder с 1.5x половинными шагами вместо
строгих power-of-2: `{256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096,
6144, 8192, 12288, 16384}`. Размер выбирается **size-scaled probabilistic
bump**: для payload <1KB с 30% шансом padder прыгает на следующую
рунгу, для 1-4KB - 18%, для >4KB - 8%. Гистограмма размеров на wire
размазана по 13 buckets вместо 7 spike'ов, без overhead'а на больших
фреймах. Bump-решение делается independently на каждой стороне (wire
видит только зашифрованную длину) - синхронизировать не нужно.

### 6. SNI совпадает с cert (избегаем признака domain fronting)

TSPU с 2022 активно отслеживает "SNI≠ServerHello.cert.subject" -
классический паттерн domain fronting. mxtr **специально избегает**:
share-string несёт `?sni=<hostname>` который сервер записал в
generated cert CN. Клиент шлёт этот hostname в ClientHello, сервер
представляет cert с тем же subject. Согласованно.

Кроме того mxtr не шлёт **пустой SNI** или **IP-литерал в SNI**: оба
эти варианта - яркое палево (90%+ реального HTTPS-трафика SNI шлёт
нормальным hostname'ом, "TLS без SNI на VPS" моментально
маркируется ML как probable proxy). Без `?sni=` в share-string fall
back на IP - но это режим, когда оператор сам решил пожертвовать
скрытностью.

## Что mxtr делает так же или хуже

### Не делает

| Свойство | MTProxy (mtg v2 / telemt) | mxtr |
|---|---|---|
| Domain fronting (cloak host) | да | **намеренно нет** (SNI≠cert это признак, который ТСПУ отслеживает) |
| Transparent TCP splice до реального сайта | telemt - да | нет |
| Forward secrecy на уровне PSK | нет | нет |
| Per-conn PSK rotation | нет | нет |
| Replay-protection через encrypted timestamp | mtg v2 / telemt - да | через AEAD seq counter |
| Multi-secret на одном порту | да | нет |
| Sponsored-channel (ad-tag revenue) | mtg v1 / alexbers / telemt - да | нет (не Telegram) |
| Prometheus-метрики | alexbers - да | нет |
| CDN-mode | никогда не было | нет |

**Domain fronting / cloak host** в `mtg v2` и особенно в `telemt` -
реальное преимущество MTProxy-сообщества. У `telemt` это сделано
лучше всех: зонд без правильного secret прозрачно spliceит TCP к
указанному `mask_host` (например, `petrovich.ru`), и зонд видит
настоящий TLS-handshake с настоящим cert, настоящей chain-of-trust,
настоящими encrypted extensions. Никакой имитации. У mxtr этого нет
вообще - вместо TCP splice стоит синтетическая 500-страница со
self-signed cert. Это проще (не нужен второй upstream), но
валидность сертификата ниже. Решение осознанное: для личного
использования (свой VPS, свой круг, обход цензуры без публичной
светимости) per-PSK randomisation работает лучше, чем один real cert
на всех - устойчивость к зондированию важна, когда proxy торчит в
публичном списке и любой может его пощупать. У нас IP знают только
владельцы share-string.

**Replay-protection**: mtg v2 использует encrypted timestamp с окном
tolerance (5с по умолчанию) - умеет fail-closed на устаревший пакет.
mxtr использует deterministic seq counter в AEAD-nonce - реплей
старого фрейма расшифровывается с неверным nonce, AEAD fail рвёт
сессию. Функционально эквивалентно для активного канала, но mtg
покрывает ещё и реплей самого начального handshake-фрейма.

### Делает хуже

**Производительность**. Серверный код MTProxy 2019 года был оптимизирован
до десятков тысяч conn/sec на одно ядро (без CGo, без GC pauses).
Go-сервер mxtr с 2026-05 имеет sync.Pool на inner/ct frame буферах -
~10x меньше allocations/sec при ~2-5k frames/sec нагрузке (1000+
конкурентных сессий). На 1 vCPU / 1 GB VPS тянет 1000+ одновременных
пользователей при типичной Matrix-нагрузке (/sync long-poll + редкие
burst'ы). До C-производительности не дотягивает, но для personal-VPS
с десятками-сотнями людей вокруг себя - запас.

**Multi-secret на одном порту**. У mxtr один PSK = один деплой. Для
изоляции 10 пользователей нужно 10 контейнеров или 10 портов.
alexbers/mtprotoproxy умеет 1 порт = N secrets. Это пока в roadmap,
вопрос приоритета.

## Академические weaknesses (бьют обоих)

Несколько fingerprint-методов работают на любой обфусцированный
прокси, не специфика MTProxy:

- **Nested-TLS fingerprint** (Xue et al., USENIX Security 2024) - если
  внутри обфусцированного транспорта летит ещё одна TLS-сессия (как у
  нас в OIDC: WebView -> mxtr -> TLS до IdP), вложенный handshake
  оставляет timing/byte-pattern. MTProxy тоже подвержен, когда клиент
  гоняет TLS поверх MTProxy.
- **Cross-layer RTT distinguishing** (Xue et al., NDSS 2025, DOI
  [10.14722/ndss.2025.240966](https://doi.org/10.14722/ndss.2025.240966))
  - паттерн RTT между уровнями выдаёт 80% top-5k сайтов через
  обфусцированный прокси. От этого не защищает ничего, кроме шафа
  траффика (добавление латентности, что для матрикса неприемлемо).
- **Probe-resistant proxy detection** (Frolov et al., NDSS 2020) -
  timeout + byte threshold распознают proxies, которые молчат при
  невалидном зонде. MTProxy уязвим. mxtr на любой невалидный зонд отвечает
  как реальный сервер: HTTP-проба -> 403/404/500, не-HTTP мусор и неверный
  PSK -> `400 Bad Request` + close (раньше тут был silent-hang - убрали,
  молчание само по себе и есть тот сигнал по Frolov). path-aware
  /robots.txt отвечает 200. Остаточный риск: статичный camouflage активный
  probe всё равно может отличить от полноценного веб-стека.

## Сводная таблица

| Свойство | MTProto (mtg v2 / telemt / alexbers) | mxtr |
|---|---|---|
| Целевой клиент | Telegram | Element X+ / matrix-rust-sdk |
| Серверный язык / runtime | C (offic.) / Go (mtg) / Rust+Tokio (telemt) / Python (alexbers) | Go |
| Стейт серверного code-base | официальный заброшен Telegram, живут форки | актив |
| Outer layer | fake-TLS (имитация) | настоящий TLS-1.3 |
| Ответ на зондирование | timeout / hang (offic., alexbers) -> real TLS splice (telemt) | HTTP-проба: 403/404/500 одного из 6 семейств; не-HTTP / неверный PSK: 400 Bad Request + close; /robots.txt=200 |
| Cert subject | один на весь deploy | нейтральный synthetic из ~6.7M space (не под CDN), persisted per host |
| SNI tracking | не явно адресовано | SNI=cert subject в share-string, нет признака domain fronting |
| Stream mux | нет | да |
| Padding | случайный +0..15B (mtg) | 13-rung PADME ladder + size-scaled bump (30/18/8%) |
| Domain fronting / cloak | mtg v2 + telemt - да | намеренно нет |
| Настоящий cert chain в ответ на зонд | telemt - да | optional через -cert/-key (RSA или EC), default self-signed |
| Replay-protection | encrypted timestamp (mtg / telemt) | AEAD seq counter |
| Forward secrecy (PSK) | нет | нет |
| Persisted identity (cloak + cert + PSK на диск) | не явно | да, atomic write + O_NOFOLLOW + O_EXCL |
| Multi-secret | да | нет |
| Ad-tag / monetisation | mtg v1 / telemt / alexbers - да | n/a |
| sync.Pool на AEAD frames | n/a | да (масштаб 1000+ conn без GC pressure) |
| Conn/sec потолок (1 vCPU) | десятки тысяч (offic. C, telemt Rust) | сотни-тысячи (Go GC-bound, но pool снижает) |
| Что блокировано в RU 2026 | JA3 detected 2026-04, fix client-only | в дикой природе единицы deploy'ев, ниже радара |

## Когда использовать что

- Нужен прокси для Telegram - **MTProxy** (`mtg v2`).
- Нужен прокси для Matrix через Element X+ или fork - **mxtr-proxy**.
- Нужен general-purpose обфусцированный прокси для произвольного TCP -
  ни тот, ни другой, смотри **Shadowsocks-2022** или **Hysteria2**.
- Нужен VPN - вообще не сюда (WireGuard / Tor).

## Источники

- Активность TelegramMessenger/MTProxy:
  <https://github.com/TelegramMessenger/MTProxy/commits/master>
- telemt/telemt (Rust+Tokio, transparent TCP splice):
  <https://github.com/telemt/telemt>
- Фикс длинного ClientHello (2025-11):
  <https://github.com/TelegramMessenger/MTProxy/commit/0613f7616c7094725d71224b221b90c17b7e23ed>
- 2026-04 TSPU JA3 detect, фикс tdesktop:
  <https://github.com/telegramdesktop/tdesktop/commit/407bf196417b80c903f6ae65d4c3202be72286d5>,
  PR <https://github.com/telegramdesktop/tdesktop/pull/30513>
- Telegram Android fix: <https://github.com/DrKLO/Telegram/pull/1949>
- alexbers/mtprotoproxy: <https://github.com/alexbers/mtprotoproxy>
- mtg v2: <https://github.com/9seconds/mtg>
- Frolov et al., *Detecting Probe-resistant Proxies*, NDSS 2020:
  <https://www.ndss-symposium.org/wp-content/uploads/2020/02/23087.pdf>
- Xue et al., *Fingerprinting Obfuscated Proxy Traffic with Encapsulated
  TLS Handshakes*, USENIX Security 2024:
  <https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting>
- Xue et al., *Cross-layer RTT-based fingerprinting*, NDSS 2025:
  <https://www.ndss-symposium.org/wp-content/uploads/2025-966-paper.pdf>
- Обзор censorship-measurement 2025:
  <https://arxiv.org/html/2502.14945v1>

Неопределённости: цифры по conn/sec и RAM/conn для MTProxy - operator
anecdote, независимых benchmark'ов с 2022 нет. Атрибуция ТСПУ к
конкретному вендору (VAS Expert / RDP-Ru) - из narrative PR #30513,
не из primary RKN document. По иранским блокировкам публичных
IRGC-attributed papers нет - только «иранский государственный
DPI» в общем виде.
