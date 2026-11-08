package org.zapretcap.tgproxy;

import java.util.ArrayList;
import java.util.List;

/** Запуск ядра прокси на компьютере для проверок: те же опции, что у tg_ws_proxy.py. */
public final class TgProxyCli {
    public static void main(String[] args) throws Exception {
        ProxyConfig config = new ProxyConfig();
        config.secret = "00112233445566778899aabbccddeeff";
        List<String> dcIps = new ArrayList<>();
        boolean dcGiven = false;
        boolean verbose = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port": config.port = Integer.parseInt(args[++i]); break;
                case "--secret": config.secret = args[++i]; break;
                case "--dc-ip": dcGiven = true; dcIps.add(args[++i]); break;
                case "--no-dc-ip": dcGiven = true; break;
                case "--pool-size": config.poolSize = Integer.parseInt(args[++i]); break;
                case "--no-h2": config.cfproxyH2Media = false; break;
                case "--no-cfproxy": config.fallbackCfproxy = false; break;
                case "--worker": config.cfproxyWorkerDomains = ProxyConfig.coerceDomainList(args[++i]); break;
                case "--socks": Dialer.setSocksPort(Integer.parseInt(args[++i])); break;
                case "-v": verbose = true; break;
                default: throw new IllegalArgumentException(args[i]);
            }
        }
        if (dcGiven) {
            config.dcRedirects = ProxyConfig.parseDcIpList(dcIps);
        }
        boolean debug = verbose;
        ProxyLog.setSink((level, message) -> {
            if (debug || !"D".equals(level)) {
                System.err.println(level + " " + message);
            }
        });
        TgWsProxy proxy = new TgWsProxy(config);
        proxy.start();
        Runtime.getRuntime().addShutdownHook(new Thread(proxy::stop));
        System.err.println("READY " + config.link());
        Thread.currentThread().join();
    }
}
