# Сторонние компоненты

| Компонент | Откуда | Лицензия | Где используется |
| :--- | :--- | :--- | :--- |
| ByeDPI 0.17.3 (`ciadpi`) | github.com/hufrea/byedpi | MIT | движок обхода |
| hev-socks5-tunnel 2.19.3 | github.com/heiher/hev-socks5-tunnel | MIT | VPN |
| lwIP, libyaml, hev-task-system | вместе с hev-socks5-tunnel | см. `native/third_party/hev-socks5-tunnel/third-part/*/LICENSE` | VPN |
| Стратегии, списки, фейки, IPSet, hosts | github.com/Flowseal/zapret-discord-youtube | MIT | обход |
| tg-ws-proxy (логика перенесена на Java) | github.com/Flowseal/tg-ws-proxy | MIT, см. `app/src/main/java/org/zapretcap/tgproxy/LICENSE-tg-ws-proxy.txt` | прокси Telegram |
| OkHttp 4.12.0, Okio, Kotlin stdlib | github.com/square/okhttp | Apache-2.0 | прокси Telegram |

## Что важно при публикации APK

В APK больше нет компонентов под GPL: режим root с `nfqws2` и библиотеками netfilter убран. Их исходники остались в `native/nfq2` и `native/third_party`, но в сборку не входят.

Эта таблица не заменяет консультацию юриста.
