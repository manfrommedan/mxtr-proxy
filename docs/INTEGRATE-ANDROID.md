# Интеграция в Android-клиент Matrix

mxtr-proxy задумывался как server-side компонент. Клиент - **не** общий
SOCKS-прокси и **не** VPN: это in-process HTTP CONNECT-листенер, в
который пробрасывается весь HTTP-траффик matrix-rust-sdk и WebView.

Этот документ описывает, как встроить клиентскую сторону в Android-app
на matrix-rust-sdk. В качестве референса - наш форк Element X+
([element-x-experimental-plus](https://github.com/manfrommedan/element-x-experimental-plus)).
То же должно работать в SchildiChat, FluffyChat-android (если они
когда-нибудь перейдут на matrix-rust-sdk), и в собственных приложениях
поверх SDK.

## Что встраиваем

1. **mxtr-клиент в Kotlin** - крипто, share-string, TLS-обвязка, stream
   multiplexing. Один long-lived TCP+TLS-сокет до сервера, поверх него
   N одновременных потоков.
2. **In-app HTTP CONNECT-листенер** на `127.0.0.1:1984`. Принимает
   `CONNECT host:port HTTP/1.1`, открывает поток через mxtr-сессию,
   проксирует байты.
3. **ProxyProvider hook** в matrix-rust-sdk - чтобы Rust-клиент пошёл
   через локальный CONNECT, когда mxtr включён.
4. **WebView ProxyController** - чтобы OIDC/SSO/embedded-pages через
   WebView тоже шли через тот же листенер.
5. **Settings UI** - переключатель + поле share-string + диагностика.
6. **MxtrBridge** - сервис-локатор без DI-зависимости, чтобы
   `androidutils` мог спросить статус mxtr, не подцепляя `matrix/impl`.

## Файлы в референс-форке

```
libraries/matrix/impl/src/main/kotlin/io/element/android/libraries/matrix/impl/mxtr/
├── Base58.kt                  # base58 encode/decode для PSK в share-string
├── MxtrConfig.kt              # PREFERRED_LOCAL_PROXY_PORT=1984 + activeLocalPort
│                              #   (auto-fallback 1984..1993 если первый занят)
├── MxtrCrypto.kt              # HKDF, AEAD wrap/unwrap, TLS-1.3 SSLContext;
│                              #   trust manager принимает EC + RSA leaf (для real LE-cert)
├── MxtrHttpProxy.kt           # HTTP CONNECT-листенер + bindWithFallback по портам
├── MxtrPreferencesStore.kt    # DataStore с enabled/share-string
├── MxtrPskDerivedConfig.kt    # из PSK выводим ALPN/heartbeat (camouflage больше не PSK-derived)
├── MxtrSession.kt             # TLS+handshake, reader/heartbeat threads;
│                              #   connect(sni=...) ставит SNI в outer ClientHello;
│                              #   13-rung PADME padding ladder + size-scaled bump
├── MxtrShareString.kt         # parse/emit mxtr://psk@ip:port?sni=hostname;
│                              #   IP-literal validated regex'ом (no DNS lookup)
├── MxtrStats.kt               # счётчики для диагностики
└── MxtrStream.kt              # один поток внутри сессии (OPEN/DATA/CLOSE)

libraries/matrix/impl/src/main/kotlin/io/element/android/libraries/matrix/impl/proxy/
└── DefaultProxyProvider.kt    # ОДНА правка: если mxtr.enabled -> MxtrConfig.proxyUrl()

libraries/androidutils/src/main/kotlin/io/element/android/libraries/androidutils/mxtr/
└── MxtrBridge.kt              # 10-строчный сервис-локатор, см. ниже

libraries/androidutils/src/main/kotlin/io/element/android/libraries/androidutils/browser/
└── ChromeCustomTab.kt         # добавлен openUrlInMxtrAwareCustomTab(...)

app/src/main/kotlin/io/element/android/x/mxtr/
└── MxtrWebViewProxy.kt        # ProxyController.setProxyOverride(...)

app/src/main/kotlin/io/element/android/x/
└── ElementXApplication.kt     # 3 строки в onCreate (порядок важен)

features/login/impl/src/main/kotlin/io/element/android/features/login/impl/mxtr/
├── MxtrBrowserActivity.kt     # WebView для OIDC через mxtr (заменяет CCT)
└── MxtrSettingsActivity.kt    # premium settings для onboarding (до логина)

features/preferences/impl/src/main/kotlin/io/element/android/features/preferences/impl/mxtr/
├── MxtrSettingsNode.kt
└── MxtrSettingsView.kt         # тот же экран, но в Advanced settings (после логина)
```

Плюс точечные правки в call-sites: 11 файлов, где
`openUrlInChromeCustomTab` заменено на `openUrlInMxtrAwareCustomTab`
(см. ниже).

## Хук 1. matrix-rust-sdk ProxyProvider

matrix-rust-sdk умеет ходить через HTTP-прокси. В Element X это
абстрагировано интерфейсом `ProxyProvider`. Дефолтная реализация
смотрит на системный прокси - её надо расширить так, чтобы mxtr
выигрывал.

```kotlin
// libraries/matrix/impl/.../proxy/DefaultProxyProvider.kt
@ContributesBinding(AppScope::class)
class DefaultProxyProvider(
    @ApplicationContext private val context: Context
) : ProxyProvider {
    override fun provides(): String? {
        val mxtr = MxtrPreferencesStore(context).snapshotBlocking()
        if (mxtr.enabled && mxtr.data != null) {
            return MxtrConfig.proxyUrl()    // "http://127.0.0.1:1984"
        }
        // fallback к системному прокси
        val cm = context.getSystemService<ConnectivityManager>()
        if (cm?.defaultProxy == null) return null
        return Settings.Global.getString(context.contentResolver, Settings.Global.HTTP_PROXY)
    }
}
```

В SchildiChat / собственном клиенте найди эквивалентную точку - это
обычно `ClientBuilder.proxy(url)` или одноимённое поле в SDK-биндинге.

## Хук 2. WebView для OIDC и in-app страниц

matrix-rust-sdk пробрасывает HTTP, но WebView - своя история. Element X
показывает OIDC-форму через Chrome Custom Tab (CCT), которое работает в
отдельном процессе Chrome и в наш прокси не пойдёт никогда.

Решение - две части:

**а) ProxyController для in-app WebView** (если форк использует
embedded WebView где-то ещё):

```kotlin
// app/src/main/kotlin/.../mxtr/MxtrWebViewProxy.kt
object MxtrWebViewProxy {
    fun applyGlobally(context: Context) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) return
        // activeLocalPort() возвращает фактически забинденный порт. Если
        // 1984 был занят при старте, MxtrHttpProxy.bindWithFallback взял
        // следующий свободный из 1984..1993 и обновил атомик.
        val proxy = "${MxtrConfig.LOCAL_PROXY_HOST}:${MxtrConfig.activeLocalPort()}"
        val config = ProxyConfig.Builder()
            .addProxyRule(proxy)
            .addDirect("localhost", "127.0.0.1")
            .build()
        ProxyController.getInstance().setProxyOverride(config, ContextCompat.getMainExecutor(context)) {
            Timber.d("WebView proxy active: %s", proxy)
        }
    }
}
```

**б) Замена CCT на собственный WebView для OIDC**. CCT нельзя
проксировать (он в другом процессе). Поэтому когда mxtr включён,
открываем OIDC в собственном `MxtrBrowserActivity` поверх WebView, на
который уже наложен ProxyController.

В call-sites вместо `openUrlInChromeCustomTab(...)` зовём
`openUrlInMxtrAwareCustomTab(...)`. Сама функция диспатчит сама:

```kotlin
// libraries/androidutils/.../browser/ChromeCustomTab.kt
fun Activity.openUrlInMxtrAwareCustomTab(
    session: CustomTabsSession?,
    darkTheme: Boolean,
    url: String,
) {
    val mxtrOn = MxtrBridge.state?.isEnabled(applicationContext) == true
    if (mxtrOn) {
        try {
            startActivity(Intent().apply {
                setClassName(packageName, MXTR_BROWSER_FQCN)
                putExtra(MXTR_BROWSER_EXTRA_URL, url)
            })
            return
        } catch (e: Throwable) {
            Timber.w(e, "fallback to CCT")
        }
    }
    openUrlInChromeCustomTab(session, darkTheme, url)
}
```

Список 11 call-sites в нашем форке (грепни `openUrlInChromeCustomTab`
в исходниках своего форка - под капотом такой же набор):

```
features/login/impl/.../LoginFlowNode.kt
features/login/impl/.../createaccount/CreateAccountNode.kt
features/analytics/impl/.../AnalyticsOptInNode.kt
features/messages/impl/.../MessagesNode.kt
features/messages/impl/.../threads/ThreadedMessagesNode.kt
features/preferences/impl/.../root/PreferencesRootNode.kt
features/preferences/impl/.../about/AboutNode.kt
features/preferences/impl/.../OpenUrlInTabView.kt
features/securebackup/impl/.../reset/ResetIdentityFlowNode.kt
features/linknewdevice/impl/.../LinkNewDeviceFlowNode.kt
features/securityandprivacy/impl/.../SecurityAndPrivacyNode.kt
```

В каждом - один импорт и один вызов меняются. Диффы минимальные.

## Хук 3. MxtrBridge - сервис-локатор в обход DI-графа

В Element X модули изолированы на уровне Gradle, и `androidutils` НЕ
зависит от `matrix/impl` (иначе словишь круговую зависимость). А
`MxtrPreferencesStore` (где хранится `enabled` флаг) живёт именно в
`matrix/impl`. Без bridge `androidutils` физически не достучится до
статуса mxtr из `openUrlInMxtrAwareCustomTab`.

DI-framework (Metro в Element X, Hilt в SchildiChat) тут не поможет -
он не умеет инжектить через Gradle-границу, которую сам не видит.
Поэтому простой volatile-singleton, который выставляется один раз в
`Application.onCreate`:

```kotlin
// libraries/androidutils/.../mxtr/MxtrBridge.kt
object MxtrBridge {
    interface State { fun isEnabled(context: Context): Boolean }
    @Volatile var state: State? = null
}
```

Реализация ставится в `Application.onCreate`:

```kotlin
MxtrBridge.state = object : MxtrBridge.State {
    override fun isEnabled(context: Context): Boolean {
        return MxtrPreferencesStore(context).snapshotBlocking().enabled
    }
}
```

## Хук 4. Application.onCreate

Порядок критический:

```kotlin
// app/src/main/kotlin/.../ElementXApplication.kt
override fun onCreate() {
    super.onCreate()

    // 1. Сначала прогреваем кэш DataStore. Иначе первый snapshotBlocking()
    //    из шага 2/3 уйдёт в runBlocking на main thread.
    MxtrPreferencesStore.startCacheCollector(this)

    // 2. Регистрируем bridge до того, как что-то ещё его дёрнет.
    MxtrBridge.state = ...

    // 3. Поднимаем local listener.
    MxtrHttpProxy.start(this)

    // 4. Конфигурим WebView ProxyController.
    MxtrWebViewProxy.applyGlobally(this)

    // ... остальная инициализация app
}
```

Если в форке `Application` использует hilt/koin/metro - все четыре
вызова влезают до DI graph initialization, никаких injections не
нужно.

## Хук 5. Settings UI

Два экрана для одного и того же DataStore - один для onboarding (до
логина, отдельная Activity), второй внутри Advanced settings (после
логина, Compose node в navigation graph).

`MxtrSettingsView` целиком композебельный, не привязан к Appyx или
Element X-овой архитектуре - можно перенести в любой Compose-app.

Минимум для своего UI:

```kotlin
val store = remember(context) { MxtrPreferencesStore(context.applicationContext) }
val snapshot = remember(context) { store.snapshotBlocking() }

var enabled by remember { mutableStateOf(snapshot.enabled) }
var shareString by remember { mutableStateOf(snapshot.data?.toShareString().orEmpty()) }

// switch + текстовое поле + кнопка "Применить":
scope.launch {
    store.setShareString(shareString)       // ВАЖНО: сначала share-string
    store.setEnabled(enabled)               // потом enabled (см. HI-04 в коде)
    // подсказать пользователю перезапустить app (proxy подцепляется в onCreate)
}
```

Сброс:

```kotlin
scope.launch {
    store.clearShareString()
    store.setEnabled(false)
}
```

## Что НЕ нужно делать

- Не пытайся проксировать UDP. WebRTC media-streams пойдут direct.
  Это не баг - голос/видео шифруются E2EE и метаданные о подключении
  утекают на STUN-сервер, который у тебя есть собственный.
- Не пытайся проксировать FCM/UnifiedPush. Push идут через OS
  network stack, на который мы влиять не можем. Если хочется
  push-через-proxy - надо переходить на NTFY / собственный
  push-gateway.
- Не пытайся проверять TLS-cert сервера через стандартный X509.
  Сертификат сервера self-signed by design (CN из ~6.7 млн
  нейтральных synthetic hostname'ов, не под конкретный CDN, выбирается
  на первом старте и персистится). Аутентификация - через PSK-HMAC, она происходит
  **после** TLS handshake. Trust manager делает только sanity-check:
  chain не пустой, не просрочен, алгоритм EC или RSA (RSA нужен
  чтобы реальный LE-cert через `-cert/-key` тоже работал, дефолтный
  certbot отдаёт RSA-2026). См. `MxtrCrypto.kt`.

## Тестирование

```bash
# 1. Поднять локальный сервер
go build -o mxtr-server ./cmd/mxtr-server
mkdir -p /tmp/mxtr-state && chmod 700 /tmp/mxtr-state
./mxtr-server -tcp :<port> -public-ip 127.0.0.1 -psk-file /tmp/mxtr-state/psk.hex -log-level debug &
echo $!  # запомнить pid для kill
# в stderr появится готовая share-string mxtr://...@127.0.0.1:<port>?sni=...

# 2. В DataStore приложения положить эту share-string целиком
# (через UI или adb shell run-as). ?sni= обязательно копировать -
# без него ClientHello не приложит SNI extension и заходящий пакет
# будет легче распознать.

# 3. Запустить app, открыть Settings -> Расширенные -> АнтиЦензурный прокси,
#    включить, перезапустить app.

# 4. Логи приложения: должно быть "MxtrProxy: listening on 127.0.0.1:<port>"
#    (или 1985..1993 если 1984 был занят) и "mxtr-session-reader" thread.

# 5. Логи сервера: при login должно появиться "session established from <ip>",
#    "stream <N> -> matrix.org:443".
```

Если matrix-rust-sdk ругается на `Bad Gateway 502` - значит CONNECT
дошёл до листенера, а `MxtrSession` не подняла поток. Часто это:
- share-string не парсится: hostname в host position (новый парсер
  принимает только IP-литерал), отсутствует ?sni= когда server его
  ждёт, base58-PSK не 32 байта;
- сервер не доступен (telnet vps-ip <port>);
- TLS не поднялся (включи `-log-level debug` на сервере).

Если matrix-rust-sdk не делает CONNECT вообще - `ProxyProvider.provides()`
вернул null или системный URL. Проверь, что `enabled=true` И
`data != null` в `MxtrRuntimeConfig` (если share-string не парсится,
`data=null` и proxy выключается даже при `enabled=true`).
