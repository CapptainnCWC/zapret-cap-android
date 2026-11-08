package org.zapretcap.tgproxy;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Локальный MTProto-прокси для Telegram: перенос proxy/tg_ws_proxy.py из tg-ws-proxy.
 * Клиент подключается к 127.0.0.1 и говорит на MTProto, а наружу трафик идёт через WebSocket к доменам Telegram.
 */
public final class TgWsProxy {
    private static final int HANDSHAKE_TIMEOUT_MS = 10_000;
    private static final int BAD_HANDSHAKE_DRAIN_LIMIT = 64 * 1024;
    private static final long LISTENER_RESTART_DELAY_MS = 1000;

    private final ProxyConfig config;
    private final byte[] secret;
    private final Stats stats = new Stats();
    private final CfDomains cfDomains = new CfDomains();
    private final Bridge bridge = new Bridge(this);
    private final Pools.WsPool wsPool = new Pools.WsPool(this);
    private final Pools.CfWorkerPool workerPool = new Pools.CfWorkerPool(this);
    private final CfH2Pool h2Pool;
    private final Set<Socket> clients = Collections.synchronizedSet(new HashSet<>());
    private final AtomicInteger threadNumber = new AtomicInteger();

    private final ThreadFactory threads = runnable -> {
        Thread thread = new Thread(runnable, "tgproxy-" + threadNumber.incrementAndGet());
        thread.setDaemon(true);
        // на Android необработанное исключение в любом потоке завершает весь процесс, а с ним и VPN
        thread.setUncaughtExceptionHandler((failed, error) -> ProxyLog.w("Сбой потока " + failed.getName() + ": " + error));
        return thread;
    };
    private final ExecutorService executor = Executors.newCachedThreadPool(threads);
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1, threads);

    private ServerSocket server;
    private volatile boolean stopping;

    public TgWsProxy(ProxyConfig config) {
        this.config = config;
        this.secret = ProxyConfig.fromHex(config.secret);
        this.h2Pool = config.h2Enabled() ? new CfH2Pool(this) : null;
    }

    ProxyConfig config() {
        return config;
    }

    public Stats stats() {
        return stats;
    }

    CfDomains cfDomains() {
        return cfDomains;
    }

    Pools.CfWorkerPool workerPool() {
        return workerPool;
    }

    CfH2Pool h2Pool() {
        return h2Pool;
    }

    ExecutorService executor() {
        return executor;
    }

    ScheduledExecutorService scheduler() {
        return scheduler;
    }

    /**
     * Сменилась сеть, например Wi-Fi на мобильную. Все соединения через старую сеть мертвы, а сокеты об этом узнают
     * нескоро. Закрываем их сразу: клиент тут же подключится заново через новую сеть.
     */
    public void networkChanged() {
        if (stopping) {
            return;
        }
        ProxyLog.i("Сеть сменилась, соединения открываются заново");
        executor.execute(() -> {
            wsPool.flush();
            workerPool.flush();
            bridge.resetBackoff();
            Socket[] active;
            synchronized (clients) {
                active = clients.toArray(new Socket[0]);
            }
            for (Socket client : active) {
                Dialer.closeQuietly(client);
            }
            if (h2Pool != null) {
                h2Pool.resetLanes();
            }
        });
    }

    /** Занимает порт и возвращает управление, ошибка привязки сразу видна вызывающему. */
    public void start() throws IOException {
        server = bind();
        if (config.cfproxyUserDomains.isEmpty()) {
            cfDomains.update(CfDomains.defaults());
            // обновление списка не должно задерживать первое подключение клиента
            scheduler.scheduleWithFixedDelay(cfDomains::refresh, 0, 1, TimeUnit.HOURS);
        } else {
            cfDomains.update(config.cfproxyUserDomains);
        }
        ProxyLog.i("Прокси слушает " + config.host + ":" + config.port);
        for (Integer dc : config.dcRedirects.keySet()) {
            ProxyLog.i("  DC" + dc + ": " + config.dcRedirects.get(dc));
        }
        ProxyLog.i("  CF-прокси: " + (config.fallbackCfproxy ? "включён" : "выключен")
                + ", свои домены: " + config.cfproxyUserDomains.size()
                + ", Worker: " + config.cfproxyWorkerDomains.size()
                + ", HTTP/2: " + (h2Pool != null ? "включён" : "выключен"));
        scheduler.scheduleWithFixedDelay(() -> safely(wsPool::tick), 5, 5, TimeUnit.SECONDS);
        scheduler.scheduleWithFixedDelay(() -> safely(workerPool::tick), 5, 5, TimeUnit.SECONDS);
        scheduler.scheduleWithFixedDelay(() -> ProxyLog.i("Статистика: " + stats.summary()), 60, 60, TimeUnit.SECONDS);
        executor.execute(this::acceptLoop);
    }

    private static void safely(Runnable task) {
        try {
            task.run();
        } catch (RuntimeException e) {
            // исключение отменило бы все следующие запуски периодической задачи
            ProxyLog.w("Ошибка фоновой задачи: " + e);
        }
    }

    private ServerSocket bind() throws IOException {
        ServerSocket socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(config.host, config.port), 128);
        return socket;
    }

    private void acceptLoop() {
        while (!stopping) {
            try {
                Socket client = server.accept();
                if (stopping) {
                    client.close();
                    return;
                }
                clients.add(client);
                executor.execute(() -> handleClient(client));
            } catch (IOException e) {
                if (stopping) {
                    return;
                }
                // Android может закрыть сокет при смене сети: порт нужно занять заново
                ProxyLog.w("Слушающий сокет закрылся, перезапуск: " + e);
                Dialer.closeQuietly(server);
                try {
                    Thread.sleep(LISTENER_RESTART_DELAY_MS);
                    server = bind();
                } catch (IOException | InterruptedException failed) {
                    ProxyLog.w("Не удалось занять порт снова: " + failed);
                    if (failed instanceof InterruptedException) {
                        return;
                    }
                }
            }
        }
    }

    private void handleClient(Socket client) {
        stats.connectionsTotal.incrementAndGet();
        stats.connectionsActive.incrementAndGet();
        String label = "127.0.0.1:" + client.getPort();
        try {
            RawWebSocket.setSocketOptions(client, config.bufferSize);
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();

            client.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            byte[] init = new byte[Mtproto.HANDSHAKE_LEN];
            new DataInputStream(in).readFully(init);

            Mtproto.Handshake handshake = Mtproto.tryHandshake(init, secret);
            if (handshake == null) {
                stats.badKey();
                ProxyLog.w("[" + label + "] неверное приветствие: другой ключ или протокол");
                drain(in);
                return;
            }
            client.setSoTimeout(0);

            int dc = handshake.dc;
            boolean test = config.forceTestDc || dc >= 10000;
            if (dc >= 10000) {
                dc -= 10000;
            }
            boolean media = handshake.media;
            int dcIdx = media ? -dc : dc;

            byte[] relayInit = Mtproto.generateRelayInit(handshake.protoTag, dcIdx);
            Mtproto.CryptoCtx ctx = Mtproto.buildCryptoCtx(handshake.prekeyAndIv, secret, relayInit);
            MsgSplitter splitter = new MsgSplitter(handshake.protoTag);

            Pools.WsKey key = new Pools.WsKey(dc, media, test);
            IdlePool.Idle pooled = wsPool.get(key);
            if (pooled == null) {
                if (!bridge.fallback(client, in, out, relayInit, label, dc, test, media, ctx, splitter, handshake.protoTag)) {
                    ProxyLog.w("[" + label + "] DC" + dc + (media ? " media" : "") + ": нет доступного маршрута");
                }
                return;
            }
            ProxyLog.i("[" + label + "] DC" + dc + (media ? " media" : "") + " -> WebSocket");
            stats.connectionsWs.incrementAndGet();
            pooled.ws.send(relayInit);
            bridge.bridgeWs(client, in, out, pooled.ws, label, ctx, dc, media, splitter, new Bridge.Watch(pooled.suspect()) {
                @Override
                void replied() {
                    wsPool.sessionReplied(key);
                }

                @Override
                void unanswered() {
                    wsPool.sessionUnanswered(key);
                    wsPool.discard(key);
                }
            });
        } catch (SocketTimeoutException e) {
            ProxyLog.w("[" + label + "] клиент не прислал приветствие вовремя");
        } catch (EOFException e) {
            ProxyLog.d("[" + label + "] client disconnected");
        } catch (IOException e) {
            ProxyLog.d("[" + label + "] " + e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException e) {
            ProxyLog.w("[" + label + "] непредвиденная ошибка: " + e);
        } finally {
            stats.connectionsActive.decrementAndGet();
            clients.remove(client);
            Dialer.closeQuietly(client);
        }
    }

    /** Неверному клиенту не отвечаем и держим соединение: так порт не выдаёт себя за прокси при сканировании. */
    private static void drain(InputStream in) {
        byte[] buffer = new byte[4096];
        int left = BAD_HANDSHAKE_DRAIN_LIMIT;
        try {
            int n;
            while (left > 0 && (n = in.read(buffer, 0, Math.min(buffer.length, left))) > 0) {
                left -= n;
            }
        } catch (IOException ignored) {
            // таймаут или разрыв: разговор всё равно окончен
        }
    }

    public void stop() {
        stopping = true;
        Dialer.closeQuietly(server);
        scheduler.shutdownNow();
        Socket[] active;
        synchronized (clients) {
            active = clients.toArray(new Socket[0]);
        }
        for (Socket client : active) {
            Dialer.closeQuietly(client);
        }
        wsPool.close();
        workerPool.close();
        if (h2Pool != null) {
            h2Pool.close();
        }
        executor.shutdown();
        ProxyLog.i("Прокси остановлен. " + stats.summary());
    }
}
