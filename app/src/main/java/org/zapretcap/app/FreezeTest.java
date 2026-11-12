package org.zapretcap.app;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.zapretcap.tgproxy.Dialer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Проверка замирания на 16-20 КБ, как DPI-тест Linux- и Windows-версий (цели из hyperion-cs/dpi-checkers).
 * На сервер хостинга отправляется 64 КБ. Если данные ушли, а ответа нет до таймаута, соединение застыло:
 * так цензор режет соединения с зарубежными хостингами после первых 16-20 КБ.
 */
final class FreezeTest {
    private static final String SUITE_URL = "https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json";
    private static final String SUITE_ASSET = "freeze/suite.v2.json";
    /** Как MONITOR_TIMEOUT и MONITOR_RANGE в других версиях. */
    private static final int TIMEOUT_MS = 5000;
    private static final int CONNECT_TIMEOUT_MS = 3000;
    private static final int PAYLOAD = 64 * 1024;
    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "freeze-watchdog");
        thread.setDaemon(true);
        return thread;
    });

    enum Probe {HTTP, TLS12, TLS13}

    enum Status {OK, FAIL, FROZEN}

    static final class Target {
        final String id;
        final String provider;
        final String host;
        final InetAddress address;

        Target(String id, String provider, String host, InetAddress address) {
            this.id = id;
            this.provider = provider;
            this.host = host;
            this.address = address;
        }
    }

    /** Итог по всем целям: сколько запросов прошло, сколько не удалось иначе и сколько застыло. */
    static final class Score {
        final int ok;
        final int fail;
        final int frozen;

        Score(int ok, int fail, int frozen) {
            this.ok = ok;
            this.fail = fail;
            this.frozen = frozen;
        }

        int total() {
            return ok + fail + frozen;
        }

        /** Доля застывших в тысячных: по ней сравниваются конфиги. Без проверок - худшее значение. */
        int frozenPermille() {
            return total() == 0 ? 1001 : frozen * 1000 / total();
        }
    }

    interface Resolver {
        InetAddress resolve(String host) throws IOException;
    }

    private final byte[] payload = new byte[PAYLOAD];
    private final List<Target> targets;
    private final Probe[] probes;

    /**
     * @param light для мобильной сети: по одной цели на провайдера и только TLS 1.3. Полная проверка отправляет
     *              около 7 МБ на каждый конфиг, на мобильном тарифе это слишком дорого
     */
    FreezeTest(Context context, Resolver resolver, boolean light) throws IOException {
        ThreadLocalRandom.current().nextBytes(payload);
        probes = light ? new Probe[]{Probe.TLS13} : Probe.values();
        targets = resolve(load(context, light), resolver);
    }

    int targets() {
        return targets.size();
    }

    int probesPerRun() {
        return targets.size() * probes.length;
    }

    /** Все запросы сразу: каждый ограничен таймаутом, поэтому прогон занимает около 5 секунд. */
    Score run(int socksPort) throws InterruptedException {
        ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, probesPerRun()));
        List<Future<Status>> results = new ArrayList<>();
        for (Target target : targets) {
            for (Probe probe : probes) {
                results.add(pool.submit(() -> probe(target, probe, socksPort)));
            }
        }
        int ok = 0;
        int fail = 0;
        int frozen = 0;
        for (Future<Status> result : results) {
            Status status;
            try {
                status = result.get();
            } catch (ExecutionException e) {
                status = Status.FAIL;
            }
            if (status == Status.OK) {
                ok++;
            } else if (status == Status.FROZEN) {
                frozen++;
            } else {
                fail++;
            }
        }
        pool.shutdownNow();
        pool.awaitTermination(1, TimeUnit.SECONDS);
        return new Score(ok, fail, frozen);
    }

    private Status probe(Target target, Probe probe, int socksPort) {
        long deadline = System.currentTimeMillis() + TIMEOUT_MS;
        Socket[] open = new Socket[2];
        // запись может встать навсегда, если цензор перестал пропускать пакеты: по таймауту сокет просто закрываем
        ScheduledFuture<?> watchdog = WATCHDOG.schedule(() -> {
            Dialer.closeQuietly(open[1]);
            Dialer.closeQuietly(open[0]);
        }, TIMEOUT_MS, TimeUnit.MILLISECONDS);
        long sent = 0;
        long received = 0;
        try {
            int port = probe == Probe.HTTP ? 80 : 443;
            open[0] = Dialer.tcp(target.address.getHostAddress(), port, CONNECT_TIMEOUT_MS, socksPort);
            Socket socket = open[0];
            if (probe != Probe.HTTP) {
                SSLSocket tls = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                        .createSocket(open[0], target.host, 443, true);
                open[1] = tls;
                tls.setEnabledProtocols(new String[]{probe == Probe.TLS12 ? "TLSv1.2" : "TLSv1.3"});
                SSLParameters parameters = tls.getSSLParameters();
                parameters.setServerNames(java.util.Collections.singletonList(new SNIHostName(target.host)));
                tls.setSSLParameters(parameters);
                tls.setSoTimeout(remaining(deadline));
                tls.startHandshake();
                socket = tls;
            }
            OutputStream out = socket.getOutputStream();
            byte[] head = ("POST / HTTP/1.1\r\nHost: " + target.host + "\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n"
                    + "Range: bytes=0-" + (PAYLOAD - 1) + "\r\nContent-Length: " + PAYLOAD + "\r\n"
                    + "Content-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII);
            out.write(head);
            sent += head.length;
            for (int offset = 0; offset < payload.length; offset += 8192) {
                int size = Math.min(8192, payload.length - offset);
                out.write(payload, offset, size);
                sent += size;
            }
            out.flush();
            socket.setSoTimeout(remaining(deadline));
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[8192];
            int n;
            // как curl: успех - ответ целиком до таймаута. Сервер закрывает соединение после ответа (Connection: close)
            while ((n = in.read(buffer)) >= 0) {
                received += n;
                if (received > 1024 * 1024) {
                    break;
                }
            }
            return received > 0 ? Status.OK : Status.FAIL;
        } catch (IOException | RuntimeException e) {
            // данные ушли, ответа нет, упёрлись в таймаут: это и есть замирание
            boolean timedOut = System.currentTimeMillis() >= deadline - 100;
            return sent > 0 && received == 0 && timedOut ? Status.FROZEN : Status.FAIL;
        } finally {
            watchdog.cancel(false);
            Dialer.closeQuietly(open[1]);
            Dialer.closeQuietly(open[0]);
        }
    }

    private static int remaining(long deadline) {
        return (int) Math.max(1, deadline - System.currentTimeMillis());
    }

    /** Свежий список с сайта автора, без сети - копия из APK. */
    private static List<String[]> load(Context context, boolean light) throws IOException {
        String json;
        try {
            json = download();
        } catch (IOException e) {
            try (InputStream in = context.getAssets().open(SUITE_ASSET)) {
                json = read(in);
            }
        }
        List<String[]> entries = new ArrayList<>();
        Set<String> providers = new HashSet<>();
        try {
            JSONArray array = new JSONArray(json);
            for (int i = 0; i < array.length(); i++) {
                JSONObject item = array.getJSONObject(i);
                String host = item.optString("host");
                String provider = item.optString("provider");
                if (host.isEmpty() || (light && !providers.add(provider))) {
                    continue;
                }
                entries.add(new String[]{item.optString("id"), provider, host});
            }
        } catch (JSONException e) {
            throw new IOException("список целей проверки фризов повреждён", e);
        }
        return entries;
    }

    private static List<Target> resolve(List<String[]> entries, Resolver resolver) throws IOException {
        ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, entries.size()));
        List<Future<InetAddress>> lookups = new ArrayList<>();
        for (String[] entry : entries) {
            lookups.add(pool.submit(() -> resolver.resolve(entry[2])));
        }
        List<Target> result = new ArrayList<>();
        for (int i = 0; i < entries.size(); i++) {
            try {
                InetAddress address = lookups.get(i).get();
                if (address != null) {
                    String[] entry = entries.get(i);
                    result.add(new Target(entry[0], entry[1], entry[2], address));
                }
            } catch (ExecutionException | InterruptedException e) {
                // цель, у которой нет адреса, проверить нельзя: она просто не участвует
            }
        }
        pool.shutdownNow();
        return result;
    }

    private static String download() throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(SUITE_URL).openConnection();
        connection.setConnectTimeout(TIMEOUT_MS);
        connection.setReadTimeout(TIMEOUT_MS);
        try (InputStream in = connection.getInputStream()) {
            return read(in);
        } finally {
            connection.disconnect();
        }
    }

    private static String read(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int n;
        while ((n = in.read(buffer)) >= 0) {
            out.write(buffer, 0, n);
        }
        return out.toString("UTF-8");
    }
}
