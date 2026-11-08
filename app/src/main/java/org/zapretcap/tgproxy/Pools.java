package org.zapretcap.tgproxy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Два пула: прямые WebSocket к доменам Telegram и соединения через Cloudflare Worker. */
final class Pools {
    private Pools() {
    }

    static final class WsKey {
        final int dc;
        final boolean media;
        final boolean test;

        WsKey(int dc, boolean media, boolean test) {
            this.dc = dc;
            this.media = media;
            this.test = test;
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof WsKey)) {
                return false;
            }
            WsKey key = (WsKey) other;
            return dc == key.dc && media == key.media && test == key.test;
        }

        @Override
        public int hashCode() {
            return Objects.hash(dc, media, test);
        }

        @Override
        public String toString() {
            return "DC" + dc + (test ? "t" : "") + (media ? "m" : "");
        }
    }

    static final class WsPool extends IdlePool<WsKey> {
        private static final String FRONTING_SNI = "sprinthost.ru";
        /** Какой способ сработал в прошлый раз, с него и начинаем. */
        private volatile boolean frontingFirst;
        /** Сервер закрывает простаивающее соединение через 60 с. В исходном проекте здесь 120 с. */
        private static final int MAX_AGE_SECONDS = 50;
        private static final int NO_REPLY_LIMIT = 2;
        private static final long COOLDOWN_INITIAL_MS = 60_000;
        private static final long COOLDOWN_MAX_MS = 600_000;

        private static final class Health {
            int noReply;
            long cooldownMs = COOLDOWN_INITIAL_MS;
            long coolUntil;
        }

        private final Map<WsKey, Health> health = new HashMap<>();

        WsPool(TgWsProxy proxy) {
            super(proxy, MAX_AGE_SECONDS);
        }

        /** Сервер ответил: маршрут исправен. */
        synchronized void sessionReplied(WsKey key) {
            health.remove(key);
        }

        /**
         * Соединение установилось, но ответа нет. Так выглядит DPI, который пропускает рукопожатие и режет данные:
         * клиент переподключался бы по кругу через один и тот же маршрут, поэтому на время уходим с него.
         */
        synchronized void sessionUnanswered(WsKey key) {
            Health state = health.get(key);
            if (state == null) {
                state = new Health();
                health.put(key, state);
            }
            state.noReply++;
            if (state.noReply >= NO_REPLY_LIMIT) {
                state.noReply = 0;
                state.coolUntil = System.nanoTime() + state.cooldownMs * 1_000_000L;
                ProxyLog.w(key + ": WebSocket подключается, но ответа нет. На " + state.cooldownMs / 1000
                        + " с переходим на запасной маршрут");
                state.cooldownMs = Math.min(state.cooldownMs * 2, COOLDOWN_MAX_MS);
            }
        }

        private synchronized boolean coolingDown(WsKey key) {
            Health state = health.get(key);
            return state != null && System.nanoTime() < state.coolUntil;
        }

        /** Сеть сменилась: прошлые неудачи ничего не значат. */
        @Override
        void flush() {
            synchronized (this) {
                health.clear();
            }
            super.flush();
        }

        @Override
        int targetSize() {
            return proxy.config().poolSize;
        }

        Idle get(WsKey key) throws InterruptedException {
            if (proxy.config().dcRedirects.get(key.dc) == null || proxy.config().poolSize <= 0 || coolingDown(key)) {
                return null;
            }
            Idle idle = take(key);
            (idle != null ? proxy.stats().poolHits : proxy.stats().poolMisses).incrementAndGet();
            return idle;
        }

        @Override
        Idle connect(WsKey key) {
            ProxyConfig config = proxy.config();
            String target = config.dcRedirects.get(key.dc);
            if (target == null) {
                return null;
            }
            String path = key.test ? Mtproto.WS_PATH_TEST : Mtproto.WS_PATH;
            for (String domain : Mtproto.wsDomains(key.dc, key.media)) {
                boolean first = frontingFirst;
                for (boolean fronted : new boolean[]{first, !first}) {
                    try {
                        RawWebSocket ws = RawWebSocket.connect(config, target, domain, fronted ? 7000 : 8000, path,
                                fronted ? FRONTING_SNI : null, true);
                        frontingFirst = fronted;
                        if (fronted) {
                            proxy.stats().connectionsFronting.incrementAndGet();
                        }
                        ProxyLog.d("WS pool connected " + domain + " via " + target + " fronting=" + fronted);
                        return new Idle(ws, domain);
                    } catch (IOException | RuntimeException e) {
                        proxy.stats().wsErrors.incrementAndGet();
                        ProxyLog.d("WS pool connect " + domain + " via " + target + " fronting=" + fronted + ": " + e);
                    }
                }
            }
            return null;
        }
    }

    static final class WorkerKey {
        final int dc;
        final String destination;

        WorkerKey(int dc, String destination) {
            this.dc = dc;
            this.destination = destination;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof WorkerKey && ((WorkerKey) other).dc == dc;
        }

        @Override
        public int hashCode() {
            return dc;
        }

        @Override
        public String toString() {
            return "worker DC" + dc;
        }
    }

    static final class CfWorkerPool extends IdlePool<WorkerKey> {
        CfWorkerPool(TgWsProxy proxy) {
            super(proxy, 100);
        }

        @Override
        int targetSize() {
            ProxyConfig config = proxy.config();
            return config.cfproxyWorkerDomains.isEmpty() ? 0 : Math.min(config.poolSize, 1);
        }

        Idle get(int dc, String destination) throws InterruptedException {
            if (targetSize() <= 0) {
                return null;
            }
            return take(new WorkerKey(dc, destination));
        }

        static String path(int dc, String destination) {
            return "/apiws?dst=" + destination + "&dc=" + dc;
        }

        List<String> availableDomains() {
            List<String> domains = new ArrayList<>(new LinkedHashSet<>(proxy.config().cfproxyWorkerDomains));
            Collections.shuffle(domains);
            return domains;
        }

        @Override
        Idle connect(WorkerKey key) {
            ProxyConfig config = proxy.config();
            for (String domain : availableDomains()) {
                try {
                    RawWebSocket ws = RawWebSocket.connect(config, domain, domain, 8000,
                            path(key.dc, key.destination), null, !config.disableSecure);
                    return new Idle(ws, domain);
                } catch (IOException | RuntimeException e) {
                    ProxyLog.d("CF worker connect DC" + key.dc + " failed: " + e);
                }
            }
            return null;
        }
    }
}
