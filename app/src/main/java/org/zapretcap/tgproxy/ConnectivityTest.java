package org.zapretcap.tgproxy;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Кнопка «Проверить» в настройках: перенос ui/connectivity.py. Отвечают ли домены по всем датацентрам. */
public final class ConnectivityTest {
    private static final int[] DCS = {1, 2, 3, 4, 5, 203};
    private static final int TIMEOUT_MS = 5000;

    private ConnectivityTest() {
    }

    private interface Case {
        void connect(int dc) throws Exception;
    }

    /** Датацентр и ошибка: null - отвечает. */
    private static Map<Integer, String> runAll(Case testCase) throws InterruptedException {
        ExecutorService pool = Executors.newFixedThreadPool(DCS.length);
        Map<Integer, Future<String>> futures = new LinkedHashMap<>();
        for (int dc : DCS) {
            futures.put(dc, pool.submit(() -> {
                try {
                    testCase.connect(dc);
                    return null;
                } catch (Exception e) {
                    String message = e.getMessage();
                    return message != null ? message : e.getClass().getSimpleName();
                }
            }));
        }
        Map<Integer, String> results = new LinkedHashMap<>();
        for (Map.Entry<Integer, Future<String>> entry : futures.entrySet()) {
            try {
                results.put(entry.getKey(), entry.getValue().get());
            } catch (java.util.concurrent.ExecutionException e) {
                results.put(entry.getKey(), String.valueOf(e.getCause()));
            }
        }
        pool.shutdownNow();
        return results;
    }

    private static Map<Integer, String> testCfProxy(ProxyConfig config, String domain) throws InterruptedException {
        return runAll(dc -> {
            String host = "kws" + dc + "." + domain;
            RawWebSocket.connect(config, host, host, TIMEOUT_MS, Mtproto.WS_PATH, null, !config.disableSecure).close();
        });
    }

    private static Map<Integer, String> testWorker(ProxyConfig config, String domain) throws InterruptedException {
        return runAll(dc -> {
            String path = Pools.CfWorkerPool.path(dc, Mtproto.DC_DEFAULT_IPS.get(dc)) + "&media=0";
            RawWebSocket.connect(config, domain, domain, TIMEOUT_MS, path, null, !config.disableSecure).close();
        });
    }

    private static String summarize(String title, Map<Integer, String> results) {
        List<String> ok = new ArrayList<>();
        StringBuilder failed = new StringBuilder();
        for (Map.Entry<Integer, String> entry : results.entrySet()) {
            if (entry.getValue() == null) {
                ok.add("DC" + entry.getKey());
            } else {
                failed.append("\n  DC").append(entry.getKey()).append(": ").append(entry.getValue());
            }
        }
        if (failed.length() == 0) {
            return "✓ " + title + ": все " + results.size() + " датацентров отвечают";
        }
        if (ok.isEmpty()) {
            return "✗ " + title + ": не отвечает" + failed;
        }
        return "~ " + title + ": отвечают " + ok + ", не отвечают:" + failed;
    }

    /** Текст для окна с результатом. Вызывать не из главного потока: может идти до полуминуты. */
    public static String run(ProxyConfig config) throws InterruptedException {
        List<String> blocks = new ArrayList<>();

        for (Map.Entry<Integer, String> redirect : config.dcRedirects.entrySet()) {
            int dc = redirect.getKey();
            String domain = Mtproto.wsDomains(dc, false)[0];
            try {
                RawWebSocket.connect(config, redirect.getValue(), domain, TIMEOUT_MS, Mtproto.WS_PATH, null, true).close();
                blocks.add("✓ Напрямую, DC" + dc + " через " + redirect.getValue());
            } catch (Exception e) {
                blocks.add("✗ Напрямую, DC" + dc + " через " + redirect.getValue() + ": " + e.getMessage());
            }
        }

        if (config.fallbackCfproxy) {
            if (config.cfproxyUserDomains.isEmpty()) {
                blocks.add(autoCfProxy(config));
            } else {
                for (String domain : config.cfproxyUserDomains) {
                    blocks.add(summarize("CF-прокси " + domain, testCfProxy(config, domain)));
                }
            }
        }
        for (String domain : config.cfproxyWorkerDomains) {
            blocks.add(summarize("CF Worker " + domain, testWorker(config, domain)));
        }
        return String.join("\n\n", blocks);
    }

    private static String autoCfProxy(ProxyConfig config) throws InterruptedException {
        // встроенные домены не показываем, как и в исходном проекте: важно только, работают ли они
        List<String> domains = CfDomains.defaults();
        int best = -1;
        for (int i = domains.size() - 1; i >= 0 && i >= domains.size() - 4; i--) {
            int ok = 0;
            for (String error : testCfProxy(config, domains.get(i)).values()) {
                if (error == null) {
                    ok++;
                }
            }
            best = Math.max(best, ok);
            if (ok == DCS.length) {
                break;
            }
        }
        return best > 0
                ? "✓ CF-прокси: отвечает датацентров: " + best + " из " + DCS.length
                : "✗ CF-прокси: встроенные домены не отвечают";
    }
}
