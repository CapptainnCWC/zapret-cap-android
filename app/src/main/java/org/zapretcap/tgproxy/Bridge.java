package org.zapretcap.tgproxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Передача данных между клиентом и Telegram с перешифрованием, а также выбор запасного маршрута. */
final class Bridge {
    private static final long TCP_BACKOFF_INITIAL_MS = 30_000;
    private static final long TCP_BACKOFF_MAX_MS = 3_600_000;

    private final TgWsProxy proxy;
    private final Map<String, Integer> tcpFailures = new HashMap<>();
    private final Map<String, Long> tcpRetryAfter = new HashMap<>();
    private final Set<String> tcpConnecting = new HashSet<>();

    /** Сколько ждать первый ответ через соединение, которое могло умереть, пока простаивало в запасе. */
    private static final long SUSPECT_REPLY_TIMEOUT_MS = 4000;
    /** Сессия короче этого без ответа ни о чём не говорит: клиент мог закрыть её сам. */
    private static final double NO_REPLY_MIN_SECONDS = 3;

    /** Что делать с маршрутом, если сессия через него так и не получила ответа. */
    abstract static class Watch {
        final boolean suspect;

        Watch(boolean suspect) {
            this.suspect = suspect;
        }

        void replied() {
        }

        abstract void unanswered();
    }

    Bridge(TgWsProxy proxy) {
        this.proxy = proxy;
    }

    void resetBackoff() {
        synchronized (tcpConnecting) {
            tcpFailures.clear();
            tcpRetryAfter.clear();
        }
    }

    /** Порядок как в исходном проекте: Worker, затем Cloudflare (для медиа сначала HTTP/2), затем напрямую. */
    boolean fallback(Socket client, InputStream in, OutputStream out, byte[] relayInit, String label, int dc,
                     boolean test, boolean media, Mtproto.CryptoCtx ctx, MsgSplitter splitter, byte[] protoTag)
            throws IOException, InterruptedException {
        ProxyConfig config = proxy.config();
        String destination = (test ? Mtproto.DC_TEST_IPS : Mtproto.DC_DEFAULT_IPS).get(dc);

        if (!config.cfproxyWorkerDomains.isEmpty() && destination != null
                && workerFallback(client, in, out, relayInit, label, ctx, dc, test, media, destination)) {
            return true;
        }
        if (config.fallbackCfproxy && !test) {
            CfH2Pool h2 = proxy.h2Pool();
            if (media && h2 != null) {
                CfH2Pool.Channel channel = h2.open(dc, label);
                if (channel != null) {
                    proxy.stats().connectionsH2.incrementAndGet();
                    proxy.stats().connectionsCfproxy.incrementAndGet();
                    h2.bridge(client, in, out, channel, ctx, protoTag);
                    return true;
                }
            }
            if (cfFallback(client, in, out, relayInit, label, ctx, dc, media, splitter)) {
                return true;
            }
        }
        return destination != null && tcpFallback(client, in, out, destination, relayInit, label, ctx);
    }

    private boolean workerFallback(Socket client, InputStream in, OutputStream out, byte[] relayInit, String label,
                                   Mtproto.CryptoCtx ctx, int dc, boolean test, boolean media, String destination)
            throws IOException, InterruptedException {
        ProxyConfig config = proxy.config();
        Pools.CfWorkerPool pool = proxy.workerPool();
        IdlePool.Idle pooled = test ? null : pool.get(dc, destination);
        RawWebSocket ws = pooled != null ? pooled.ws : null;
        if (ws == null) {
            for (String domain : pool.availableDomains()) {
                try {
                    ws = RawWebSocket.connect(config, domain, domain, 10000,
                            Pools.CfWorkerPool.path(dc, destination), null, !config.disableSecure);
                    break;
                } catch (IOException | RuntimeException e) {
                    ProxyLog.w("[" + label + "] DC" + dc + " CF Worker недоступен: " + e);
                }
            }
            if (ws == null) {
                return false;
            }
        }
        ProxyLog.i("[" + label + "] DC" + dc + (media ? " media" : "") + " -> CF Worker");
        proxy.stats().connectionsCfproxy.incrementAndGet();
        ws.send(relayInit);
        bridgeWs(client, in, out, ws, label, ctx, dc, media, null, null);
        return true;
    }

    private boolean cfFallback(Socket client, InputStream in, OutputStream out, byte[] relayInit, String label,
                               Mtproto.CryptoCtx ctx, int dc, boolean media, MsgSplitter splitter)
            throws IOException, InterruptedException {
        ProxyConfig config = proxy.config();
        RawWebSocket ws = null;
        String chosen = null;
        for (String base : proxy.cfDomains().forDc(dc)) {
            String domain = "kws" + dc + "." + base;
            try {
                ws = RawWebSocket.connect(config, domain, domain, 10000, Mtproto.WS_PATH, null, !config.disableSecure);
                chosen = base;
                break;
            } catch (IOException | RuntimeException e) {
                ProxyLog.w("[" + label + "] DC" + dc + " CF-прокси не отвечает: " + e.getClass().getSimpleName());
            }
        }
        if (ws == null) {
            return false;
        }
        ProxyLog.i("[" + label + "] DC" + dc + (media ? " media" : "") + " -> CF-прокси");
        proxy.cfDomains().setDomainForDc(dc, chosen);
        proxy.stats().connectionsCfproxy.incrementAndGet();
        ws.send(relayInit);
        String domain = chosen;
        bridgeWs(client, in, out, ws, label, ctx, dc, media, splitter, new Watch(false) {
            @Override
            void unanswered() {
                proxy.cfDomains().forgetDomainForDc(dc, domain);
            }
        });
        return true;
    }

    private boolean tcpFallback(Socket client, InputStream in, OutputStream out, String destination, byte[] relayInit,
                                String label, Mtproto.CryptoCtx ctx) throws IOException, InterruptedException {
        synchronized (tcpConnecting) {
            Long retryAfter = tcpRetryAfter.get(destination);
            if (tcpConnecting.contains(destination) || (retryAfter != null && System.nanoTime() < retryAfter)) {
                return false;
            }
            tcpConnecting.add(destination);
        }
        Socket remote;
        try {
            ProxyLog.i("[" + label + "] напрямую к " + destination);
            remote = Dialer.tcp(destination, 443, 10000);
            RawWebSocket.setSocketOptions(remote, proxy.config().bufferSize);
            remote.getOutputStream().write(relayInit);
            remote.getOutputStream().flush();
        } catch (IOException | RuntimeException e) {
            synchronized (tcpConnecting) {
                tcpConnecting.remove(destination);
                Integer previous = tcpFailures.get(destination);
                int failures = previous == null ? 1 : previous + 1;
                tcpFailures.put(destination, failures);
                long delay = Math.min(TCP_BACKOFF_INITIAL_MS << Math.min(failures - 1, 7), TCP_BACKOFF_MAX_MS);
                tcpRetryAfter.put(destination, System.nanoTime() + delay * 1_000_000L);
                ProxyLog.w("[" + label + "] напрямую не удалось, повтор через " + delay / 1000 + " с");
            }
            return false;
        }
        synchronized (tcpConnecting) {
            tcpConnecting.remove(destination);
            tcpFailures.remove(destination);
            tcpRetryAfter.remove(destination);
        }
        proxy.stats().connectionsTcpFallback.incrementAndGet();
        bridgeTcp(client, in, out, remote, ctx);
        return true;
    }

    /**
     * Клиент -> расшифровать -> зашифровать для Telegram -> WebSocket и обратно.
     *
     * @param watch кому сообщить, ответил ли сервер. null - следить не нужно
     */
    void bridgeWs(Socket client, InputStream in, OutputStream out, RawWebSocket ws, String label, Mtproto.CryptoCtx ctx,
                  int dc, boolean media, MsgSplitter splitter, Watch watch) throws InterruptedException {
        CountDownLatch downDone = new CountDownLatch(1);
        long started = System.nanoTime();
        AtomicLong up = new AtomicLong();
        AtomicLong down = new AtomicLong();
        AtomicReference<String> closedBy = new AtomicReference<>();
        ScheduledFuture<?>[] replyCheck = new ScheduledFuture<?>[1];

        Runnable stop = () -> {
            ws.close();
            Dialer.closeQuietly(client);
        };
        proxy.executor().execute(() -> {
            try {
                byte[] data;
                while ((data = ws.recv()) != null) {
                    proxy.stats().bytesDown.addAndGet(data.length);
                    down.addAndGet(data.length);
                    out.write(ctx.cltEnc.update(ctx.tgDec.update(data)));
                    out.flush();
                }
                closedBy.compareAndSet(null, "сервер");
            } catch (IOException | RuntimeException e) {
                closedBy.compareAndSet(null, "сервер: " + e.getClass().getSimpleName());
                ProxyLog.d("[" + label + "] ws->tcp ended: " + e);
            } finally {
                stop.run();
                downDone.countDown();
            }
        });
        try {
            byte[] buffer = new byte[65536];
            int n;
            while ((n = in.read(buffer)) >= 0) {
                if (n == 0) {
                    continue;
                }
                proxy.stats().bytesUp.addAndGet(n);
                up.addAndGet(n);
                if (watch != null && watch.suspect && replyCheck[0] == null) {
                    // клиент ждёт ответ дольше и столько же будет ждать через следующее мёртвое соединение
                    replyCheck[0] = proxy.scheduler().schedule(() -> {
                        if (down.get() == 0 && closedBy.compareAndSet(null, "нет ответа через старое соединение")) {
                            proxy.executor().execute(stop);
                        }
                    }, SUSPECT_REPLY_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                }
                byte[] plain = ctx.cltDec.update(buffer, 0, n);
                byte[] chunk = ctx.tgEnc.update(plain);
                if (splitter == null) {
                    ws.send(chunk);
                    continue;
                }
                List<byte[]> parts = splitter.split(chunk, plain);
                if (parts.size() == 1) {
                    ws.send(parts.get(0));
                } else if (!parts.isEmpty()) {
                    ws.sendBatch(parts);
                }
            }
            closedBy.compareAndSet(null, "клиент");
            if (splitter != null) {
                List<byte[]> tail = splitter.flush();
                if (!tail.isEmpty()) {
                    ws.send(tail.get(0));
                }
            }
        } catch (IOException | RuntimeException e) {
            closedBy.compareAndSet(null, "клиент: " + e.getClass().getSimpleName());
            ProxyLog.d("[" + label + "] tcp->ws ended: " + e);
        } finally {
            stop.run();
        }
        downDone.await();
        if (replyCheck[0] != null) {
            replyCheck[0].cancel(false);
        }
        double seconds = (System.nanoTime() - started) / 1e9;
        boolean unanswered = up.get() > 0 && down.get() == 0 && seconds >= NO_REPLY_MIN_SECONDS;
        if (watch != null) {
            if (down.get() > 0) {
                watch.replied();
            } else if (unanswered) {
                watch.unanswered();
            }
        }
        String line = String.format(java.util.Locale.ROOT, "[%s] DC%d%s закрыто (%s): вверх %s, вниз %s за %.1f с", label, dc,
                media ? "m" : "", closedBy.get(), Stats.humanBytes(up.get()), Stats.humanBytes(down.get()), seconds);
        if (unanswered) {
            ProxyLog.w(line + ", ответа не было");
        } else {
            ProxyLog.i(line);
        }
    }

    private void bridgeTcp(Socket client, InputStream in, OutputStream out, Socket remote, Mtproto.CryptoCtx ctx)
            throws IOException, InterruptedException {
        CountDownLatch downDone = new CountDownLatch(1);
        InputStream remoteIn = remote.getInputStream();
        OutputStream remoteOut = remote.getOutputStream();
        Runnable stop = () -> {
            Dialer.closeQuietly(remote);
            Dialer.closeQuietly(client);
        };
        proxy.executor().execute(() -> {
            try {
                byte[] buffer = new byte[65536];
                int n;
                while ((n = remoteIn.read(buffer)) >= 0) {
                    proxy.stats().bytesDown.addAndGet(n);
                    out.write(ctx.cltEnc.update(ctx.tgDec.update(Arrays.copyOf(buffer, n))));
                    out.flush();
                }
            } catch (IOException | RuntimeException ignored) {
                // разрыв с любой стороны завершает обе
            } finally {
                stop.run();
                downDone.countDown();
            }
        });
        try {
            byte[] buffer = new byte[65536];
            int n;
            while ((n = in.read(buffer)) >= 0) {
                proxy.stats().bytesUp.addAndGet(n);
                remoteOut.write(ctx.tgEnc.update(ctx.cltDec.update(buffer, 0, n)));
                remoteOut.flush();
            }
        } catch (IOException | RuntimeException ignored) {
            // разрыв с любой стороны завершает обе
        } finally {
            stop.run();
        }
        downDone.await();
    }
}
