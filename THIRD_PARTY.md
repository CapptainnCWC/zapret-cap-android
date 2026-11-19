# Сторонние компоненты

| Компонент | Откуда | Лицензия | Где используется |
| :--- | :--- | :--- | :--- |
| ByeDPI 0.17.3 (`ciadpi`) | github.com/hufrea/byedpi | MIT | движок обхода |
| hev-socks5-tunnel 2.19.3 | github.com/heiher/hev-socks5-tunnel | MIT | VPN |
| lwIP, libyaml, hev-task-system | вместе с hev-socks5-tunnel | см. `native/third_party/hev-socks5-tunnel/third-part/*/LICENSE` | VPN |
| Стратегии, списки, фейки, IPSet, hosts | github.com/Flowseal/zapret-discord-youtube | MIT | обход |
| tg-ws-proxy (логика перенесена на Java) | github.com/Flowseal/tg-ws-proxy | MIT, см. `app/src/main/java/org/zapretcap/tgproxy/LICENSE-tg-ws-proxy.txt` | прокси Telegram |
| Список целей проверки фризов 16-20 КБ (`assets/freeze/suite.v2.json`) | github.com/hyperion-cs/dpi-checkers | Apache-2.0 | Подобрать |
| nfqws2 и Lua-скрипты zapret2 1.0.7 | github.com/bol-van/zapret2 | MIT | режим root |
| Стратегии для nfqws2 (`assets/root/strategies`, `zapret-cap.lua`) | Zapret Cap для Linux, перевод стратегий zapret-discord-youtube | MIT | режим root |
| Lua 5.5.1 | lua.org | MIT | режим root, внутри nfqws2 |
| libnetfilter_queue, libnfnetlink | netfilter.org | GPL-2.0 | режим root, внутри nfqws2 |
| libmnl | netfilter.org | LGPL-2.1 | режим root, внутри nfqws2 |
| youtubedl-android 0.18.1 (Python, QuickJS, yt-dlp), только arm64 | github.com/yausername/youtubedl-android | GPL-3.0; yt-dlp - Unlicense; Python - PSF; QuickJS - MIT | тест видео в Подобрать |
| OkHttp 4.12.0, Okio, Kotlin stdlib | github.com/square/okhttp | Apache-2.0 | прокси Telegram |

## Что важно при публикации APK

С версии 1.5.3 в APK обеих веток входит youtubedl-android под GPL-3.0: это библиотека Java внутри приложения, поэтому APK целиком распространяется на условиях GPL-3.0. Исходники приложения открыты в этом репозитории, исходники библиотеки - на github.com/yausername/youtubedl-android. Собственный код приложения по-прежнему под MIT, см. LICENSE.txt: MIT совместима с GPL-3.0.

**Ветка `root`.** Кроме того, в APK этой ветки входит `libnfqws2.so`: `nfqws2`, статически собранный с libnetfilter_queue и libnfnetlink под GPL-2.0 и libmnl под LGPL-2.1. Поэтому сам этот файл распространяется на условиях GPL-2.0. Он работает отдельной программой, а не внутри приложения. Его полные исходники лежат в репозитории (`native/nfq2`, `native/third_party`, скрипт сборки `native/build-native.sh`), и их нужно публиковать вместе с каждым APK этой ветки.

**Ветка `main`.** `nfqws2` и библиотеки netfilter не собираются.

Эта таблица не заменяет консультацию юриста.
