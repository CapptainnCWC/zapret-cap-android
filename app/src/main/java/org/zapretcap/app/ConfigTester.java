package org.zapretcap.app;

import android.content.Context;
import android.content.SharedPreferences;

import org.zapretcap.tgproxy.Dialer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLSocket;

/**
 * Подбор конфига: то же, что тест конфигураций в service.bat. Для каждого конфига запускает отдельный ciadpi
 * и открывает через него те же сайты, что и тест Windows-версии. Разрешение на VPN не нужно, и работающему
 * обходу проверка не мешает: само приложение исключено из VPN, а у каждого ciadpi свой порт.
 */
final class ConfigTester {
    /**
     * Сайты, которые обход должен открыть, и те, которые он не должен сломать. Поисковики и их ресурсы часто
     * работают и без обхода, а фейк с малым TTL доходит до их близких серверов и ломает соединение. Конфиг,
     * который открыл YouTube ценой поиска, не должен выигрывать.
     */
    private static final String[] TARGETS = {
            "discord.com", "gateway.discord.gg", "cdn.discordapp.com", "updates.discord.com",
            "www.youtube.com", "youtu.be", "i.ytimg.com", "redirector.googlevideo.com",
            "www.google.com", "www.google.ru", "www.gstatic.com", "fonts.googleapis.com",
            "ya.ru", "yandex.ru", "duckduckgo.com", "www.bing.com",
            "www.cloudflare.com", "cdnjs.cloudflare.com",
            // Ответ больше 24 КБ: на части сетей обманка у адреса Cloudflare замораживает соединение после
            // первых ~23 КБ, а мелкие страницы при этом открываются. Такой конфиг ломает загрузки с сайтов на Cloudflare
            "speed.cloudflare.com/__down?bytes=100000",
    };
    /** Сколько добавленных человеком доменов проверять: длинный список сделал бы подбор слишком долгим. */
    private static final int MAX_USER_TARGETS = 6;
    /** Сколько лучших конфигов перепроверять и сколько раз: случайная удача не должна решать выбор. */
    private static final int RECHECK_CONFIGS = 5;
    private static final int RECHECK_TIMES = 2;
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 5000;
    /**
     * Сколько читать ответ. DPI часто пропускает рукопожатие и первые 16-20 КБ, а затем останавливает соединение.
     * Ради этого и читаем больше: страница, застывшая на середине, считается ошибкой.
     */
    private static final int READ_LIMIT = 64 * 1024;
    /** TTL фейков, которые стоит попробовать: сервер может быть ближе 8 прыжков, а DPI дальше. */
    private static final int[] TTL_CANDIDATES = {4, 6, 10, 12};
    private static final int TTL_CONFIGS = 3;

    static final class Result {
        final String name;
        final int ttl;
        final int ok;
        final long millis;
        /** Замирание на 16-20 КБ. Null, пока не проверено. */
        final FreezeTest.Score freeze;

        Result(String name, int ttl, int ok, long millis) {
            this(name, ttl, ok, millis, null);
        }

        Result(String name, int ttl, int ok, long millis, FreezeTest.Score freeze) {
            this.name = name;
            this.ttl = ttl;
            this.ok = ok;
            this.millis = millis;
            this.freeze = freeze;
        }

        Result withFreeze(FreezeTest.Score score) {
            return new Result(name, ttl, ok, millis, score);
        }

        int frozenPermille() {
            return freeze == null ? 1001 : freeze.frozenPermille();
        }
    }

    private static ConfigTester current;

    private final Context context;
    private final String kind;
    private final List<String> targets = new ArrayList<>(Arrays.asList(TARGETS));
    private final List<Result> results = new ArrayList<>();
    private final Map<String, InetAddress> addresses = new LinkedHashMap<>();
    private final DnsForwarder dns = new DnsForwarder();
    private volatile boolean cancelled;
    private volatile boolean finished;
    private volatile boolean shown;
    private volatile String progress = "";
    private volatile String error;
    private volatile Result baseline;
    private FreezeTest freezeTest;

    private ConfigTester(Context context) {
        this.context = context.getApplicationContext();
        kind = NetKind.current(context);
    }

    /** Запускает проверку, а если она уже идёт, возвращает её. */
    static synchronized ConfigTester start(Context context) {
        if (current == null || current.finished) {
            current = new ConfigTester(context);
            Thread thread = new Thread(current::run, "config-tester");
            thread.setDaemon(true);
            thread.start();
        }
        return current;
    }

    /** Проверка, результат которой ещё не показан: экран могли закрыть, пока она шла. */
    static synchronized ConfigTester pending() {
        return current != null && !current.shown ? current : null;
    }

    void cancel() {
        cancelled = true;
    }

    boolean cancelled() {
        return cancelled;
    }

    boolean finished() {
        return finished;
    }

    void markShown() {
        shown = true;
    }

    String progress() {
        return progress;
    }

    String error() {
        return error;
    }

    Result baseline() {
        return baseline;
    }

    int total() {
        return targets.size();
    }

    /** Сколько адресов хостингов в проверке фризов. */
    int freezeTargets() {
        return freezeTest == null ? 0 : freezeTest.targets();
    }

    /** Сколько запросов проверки фризов в одном прогоне. */
    int freezeTotal() {
        return freezeTest == null ? 0 : freezeTest.probesPerRun();
    }

    /** Для какой сети подобран конфиг: пока шла проверка, телефон мог перейти на другую. */
    String kind() {
        return kind;
    }

    /** От лучшего к худшему. Читать только после завершения. */
    List<Result> results() {
        return results;
    }

    private void run() {
        try {
            test();
        } catch (IOException | RuntimeException e) {
            error = String.valueOf(e.getMessage());
        } catch (InterruptedException e) {
            cancelled = true;
        } finally {
            dns.stop();
            finished = true;
        }
    }

    private void test() throws IOException, InterruptedException {
        Data.extract(context);
        Data.applyLists(context);
        addUserTargets();
        resolveTargets();

        progress = context.getString(R.string.test_progress_freeze_targets);
        // в мобильной сети облегчённая проверка: полная отправляет по 7 МБ на каждый конфиг
        freezeTest = new FreezeTest(context, this::resolve, NetKind.CELL.equals(kind));

        progress = context.getString(R.string.test_progress_direct);
        Result direct = measure("", 0, 0);
        progress = context.getString(R.string.test_progress_direct) + "\n" + context.getString(R.string.test_progress_freeze);
        baseline = direct.withFreeze(freezeTest.run(0));

        List<String> names = Data.strategies(context);
        // часть конфигов после перевода совпадает: незачем проверять одно и то же дважды
        Map<String, Result> byArgs = new HashMap<>();
        Result best = null;
        for (int i = 0; i < names.size(); i++) {
            if (cancelled) {
                return;
            }
            String name = names.get(i);
            String bestText = best == null ? "" : context.getString(R.string.test_progress_best, best.name, best.ok,
                    targets.size(), best.freeze == null ? 0 : best.freeze.frozen, freezeTotal());
            progress = context.getString(R.string.test_progress, i + 1, names.size(), name) + bestText;
            List<String> args = args(name, 0);
            String key = String.join(" ", args);
            Result known = byArgs.get(key);
            Result result = known != null
                    ? new Result(name, known.ttl, known.ok, known.millis, known.freeze)
                    : withEngine(name, args, freezeArgs(name, 0), 0);
            byArgs.put(key, result);
            results.add(result);
            if (best == null || better(result, best)) {
                best = result;
            }
        }
        sort();
        // прежние значения убираем только сейчас: отменённая проверка не должна их терять.
        // TTL, выбранный человеком, подбор не меняет
        if (BypassSettings.fakeTtl(context, kind) == 0) {
            clearSavedTtl();
            tryOtherTtl();
        }
        sort();
        recheckBest();
        sort();
        saveScores();
    }

    /** Аргументы конфига для проверки: с TTL, выбранным человеком для этой сети, если он есть. */
    private List<String> args(String name, int ttl) throws IOException {
        int chosen = BypassSettings.fakeTtl(context, kind);
        return chosen > 0 ? Data.vpnArgs(context, name, chosen, true) : Data.vpnArgs(context, name, ttl);
    }

    /** Те же аргументы, но группы IPSet ловят любой адрес: фризы проверяются на адресах хостингов, как в Linux-версии. */
    private List<String> freezeArgs(String name, int ttl) throws IOException {
        int chosen = BypassSettings.fakeTtl(context, kind);
        return chosen > 0 ? Data.vpnArgs(context, name, chosen, true, true) : Data.vpnArgs(context, name, ttl, false, true);
    }

    private void addUserTargets() throws IOException {
        for (UserLists.Kind list : new UserLists.Kind[]{UserLists.Kind.GENERAL, UserLists.Kind.GOOGLE}) {
            for (String domain : UserLists.added(context, list)) {
                if (targets.size() < TARGETS.length + MAX_USER_TARGETS && !targets.contains(domain)) {
                    targets.add(domain);
                }
            }
        }
    }

    /** Лучшие конфиги проверяются ещё раз, в счёт идёт худший результат: нужен конфиг, который работает всегда. */
    private void recheckBest() throws IOException, InterruptedException {
        int count = Math.min(RECHECK_CONFIGS, results.size());
        for (int i = 0; i < count; i++) {
            Result base = results.get(i);
            int worst = base.ok;
            long slowest = base.millis;
            FreezeTest.Score frozenMost = base.freeze;
            for (int pass = 0; pass < RECHECK_TIMES; pass++) {
                if (cancelled) {
                    return;
                }
                progress = context.getString(R.string.test_progress_recheck, base.name, i + 1, count);
                Result again = withEngine(base.name, args(base.name, base.ttl), freezeArgs(base.name, base.ttl), base.ttl);
                worst = Math.min(worst, again.ok);
                slowest = Math.max(slowest, again.millis);
                if (frozenMost == null || (again.freeze != null && again.freeze.frozenPermille() > frozenMost.frozenPermille())) {
                    frozenMost = again.freeze;
                }
            }
            results.set(i, new Result(base.name, base.ttl, worst, slowest, frozenMost));
        }
    }

    private void saveScores() {
        SharedPreferences.Editor editor = BypassVpnService.prefs(context).edit();
        for (Result result : results) {
            editor.putString(Data.scoreKey(kind, result.name), result.ok + "/" + targets.size());
            if (result.freeze != null) {
                editor.putString(Data.freezeKey(kind, result.name), result.freeze.frozen + "/" + result.freeze.total());
            } else {
                editor.remove(Data.freezeKey(kind, result.name));
            }
        }
        editor.apply();
    }

    /** Если даже лучшие конфиги не открыли всё, причина может быть в TTL фейков: он зависит от провайдера. */
    private void tryOtherTtl() throws IOException, InterruptedException {
        // TTL подбирается, если лучший конфиг открыл не всё или на нём есть фризы: фейк, дошедший до сервера,
        // тоже может останавливать соединение
        if (results.isEmpty() || (results.get(0).ok >= targets.size()
                && results.get(0).freeze != null && results.get(0).freeze.frozen == 0)) {
            return;
        }
        List<Result> candidates = new ArrayList<>();
        for (Result result : results) {
            if (candidates.size() < TTL_CONFIGS && Data.vpnArgs(context, result.name, 0).contains(Data.FAKE_TTL)) {
                candidates.add(result);
            }
        }
        SharedPreferences prefs = BypassVpnService.prefs(context);
        for (int i = 0; i < candidates.size(); i++) {
            Result base = candidates.get(i);
            Result improved = base;
            for (int ttl : TTL_CANDIDATES) {
                if (cancelled) {
                    return;
                }
                progress = context.getString(R.string.test_progress_ttl, base.name, ttl);
                Result attempt = withEngine(base.name, Data.vpnArgs(context, base.name, ttl),
                        Data.vpnArgs(context, base.name, ttl, false, true), ttl);
                // разница в скорости здесь случайна: другой TTL стоит сохранять, только если открылось больше
                // сайтов или при том же числе сайтов меньше фризов
                if (attempt.ok > improved.ok
                        || (attempt.ok == improved.ok && attempt.frozenPermille() < improved.frozenPermille())) {
                    improved = attempt;
                }
            }
            if (improved != base) {
                results.set(results.indexOf(base), improved);
                prefs.edit().putInt(Data.ttlKey(kind, base.name), improved.ttl).apply();
            }
        }
    }

    private void clearSavedTtl() {
        SharedPreferences prefs = BypassVpnService.prefs(context);
        SharedPreferences.Editor editor = prefs.edit();
        for (String key : prefs.getAll().keySet()) {
            if (key.startsWith(Data.TTL_KEY_PREFIX + kind + ":")) {
                editor.remove(key);
            }
        }
        editor.apply();
    }

    /** Как в Linux-версии: главное - открытые сайты, при равенстве меньше фризов, затем быстрее. */
    private static final Comparator<Result> ORDER = Comparator.<Result>comparingInt(r -> -r.ok)
            .thenComparingInt(Result::frozenPermille)
            .thenComparingLong(r -> r.millis);

    private static boolean better(Result a, Result b) {
        return ORDER.compare(a, b) < 0;
    }

    private void sort() {
        Collections.sort(results, ORDER);
    }

    /** Сайты с обычными аргументами, затем фризы с IPSet на любой адрес. Если аргументы совпадают, движок один. */
    private Result withEngine(String name, List<String> args, List<String> freezeArgs, int ttl)
            throws IOException, InterruptedException {
        String base = progress;
        Result sites;
        FreezeTest.Score freeze;
        Engine engine = Engine.start(context, args);
        try {
            if (engine == null) {
                // конфиг, который движок не принял, ничего не откроет
                return new Result(name, ttl, 0, Long.MAX_VALUE, new FreezeTest.Score(0, 0, 0));
            }
            sites = measure(name, ttl, engine.port);
            if (cancelled) {
                return sites;
            }
            progress = base + "\n" + context.getString(R.string.test_progress_freeze);
            if (freezeArgs.equals(args)) {
                freeze = freezeTest.run(engine.port);
                return sites.withFreeze(freeze);
            }
        } finally {
            if (engine != null) {
                engine.stop();
            }
        }
        Engine freezeEngine = Engine.start(context, freezeArgs);
        try {
            freeze = freezeEngine == null ? new FreezeTest.Score(0, 0, 0) : freezeTest.run(freezeEngine.port);
        } finally {
            if (freezeEngine != null) {
                freezeEngine.stop();
            }
            progress = base;
        }
        return sites.withFreeze(freeze);
    }

    /** Отдельный ciadpi на свободном порту. Null, если движок не принял аргументы. */
    private static final class Engine {
        final Process process;
        final int port;

        private Engine(Process process, int port) {
            this.process = process;
            this.port = port;
        }

        static Engine start(Context context, List<String> args) throws IOException, InterruptedException {
            int port;
            try (ServerSocket socket = new ServerSocket(0)) {
                port = socket.getLocalPort();
            }
            Process process = new ProcessBuilder(Data.ciadpiCommand(context, port, 0, args)).redirectErrorStream(true).start();
            drain(process);
            if (!waitForPort(process, port)) {
                process.destroy();
                process.waitFor();
                return null;
            }
            return new Engine(process, port);
        }

        void stop() throws InterruptedException {
            process.destroy();
            process.waitFor();
        }
    }

    private static void drain(Process process) {
        Thread thread = new Thread(() -> {
            byte[] buffer = new byte[4096];
            try (InputStream in = process.getInputStream()) {
                while (in.read(buffer) >= 0) {
                    // вывод движка здесь не нужен, но без чтения он остановился бы на полном буфере
                }
            } catch (IOException ignored) {
                // процесс завершён
            }
        }, "tester-drain");
        thread.setDaemon(true);
        thread.start();
    }

    private static boolean waitForPort(Process process, int port) throws InterruptedException {
        for (int attempt = 0; attempt < 50; attempt++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 100);
                return true;
            } catch (IOException notYet) {
                if (!Data.isAlive(process)) {
                    return false;
                }
                Thread.sleep(50);
            }
        }
        return false;
    }

    private Result measure(String name, int ttl, int socksPort) throws InterruptedException {
        long started = System.nanoTime();
        ExecutorService pool = Executors.newFixedThreadPool(targets.size());
        List<Future<Boolean>> checks = new ArrayList<>();
        for (Map.Entry<String, InetAddress> target : addresses.entrySet()) {
            checks.add(pool.submit(() -> opens(target.getKey(), target.getValue(), socksPort)));
        }
        int ok = 0;
        for (Future<Boolean> check : checks) {
            try {
                if (check.get()) {
                    ok++;
                }
            } catch (ExecutionException e) {
                // исключение проверки значит только, что сайт не открылся
            }
        }
        pool.shutdownNow();
        pool.awaitTermination(1, TimeUnit.SECONDS);
        return new Result(name, ttl, ok, (System.nanoTime() - started) / 1_000_000L);
    }

    /** Открывается ли сайт: TLS с проверкой сертификата, ответ HTTP и данные, которые не застывают на середине. */
    private static boolean opens(String target, InetAddress address, int socksPort) {
        String host = hostOf(target);
        String path = target.substring(host.length());
        if (path.isEmpty()) {
            path = "/";
        }
        Socket plain = null;
        Socket tls = null;
        try {
            plain = Dialer.tcp(address.getHostAddress(), 443, CONNECT_TIMEOUT_MS, socksPort);
            SSLSocket secure = Dialer.tls(plain, host, 443, true, CONNECT_TIMEOUT_MS);
            tls = secure;
            secure.setSoTimeout(READ_TIMEOUT_MS);
            OutputStream out = secure.getOutputStream();
            out.write(("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0 (Android)\r\nAccept: */*\r\n"
                    + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            InputStream in = secure.getInputStream();
            byte[] buffer = new byte[8192];
            int received = 0;
            byte[] start = new byte[5];
            int n;
            while (received < READ_LIMIT && (n = in.read(buffer)) >= 0) {
                if (received < start.length) {
                    System.arraycopy(buffer, 0, start, received, Math.min(n, start.length - received));
                }
                received += n;
            }
            return received >= start.length && new String(start, StandardCharsets.US_ASCII).equals("HTTP/");
        } catch (IOException | RuntimeException e) {
            return false;
        } finally {
            Dialer.closeQuietly(tls);
            Dialer.closeQuietly(plain);
        }
    }

    /**
     * Адреса те же, что получат приложения через VPN: через локальный DNS. Системный DNS спросили бы только
     * в крайнем случае: у провайдера он может отвечать заглушкой, и тогда не открылся бы ни один конфиг.
     */
    private void resolveTargets() throws IOException, InterruptedException {
        ExecutorService pool = Executors.newFixedThreadPool(targets.size());
        List<Future<InetAddress>> lookups = new ArrayList<>();
        for (String target : targets) {
            lookups.add(pool.submit(() -> resolve(hostOf(target))));
        }
        for (int i = 0; i < targets.size(); i++) {
            try {
                addresses.put(targets.get(i), lookups.get(i).get());
            } catch (ExecutionException e) {
                // такой сайт нельзя открыть ни с одним конфигом: в проверке он останется закрытым
                addresses.put(targets.get(i), InetAddress.getByAddress(new byte[]{(byte) 203, 0, 113, 1}));
            }
        }
        pool.shutdownNow();
    }

    /** Цель - домен или домен с путём запроса. */
    private static String hostOf(String target) {
        int slash = target.indexOf('/');
        return slash < 0 ? target : target.substring(0, slash);
    }

    private InetAddress resolve(String host) throws IOException {
        InetAddress address = dns.lookupIpv4(host);
        return address != null ? address : InetAddress.getByName(host);
    }
}
