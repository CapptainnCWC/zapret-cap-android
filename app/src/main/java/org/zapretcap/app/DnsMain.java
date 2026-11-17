package org.zapretcap.app;

import android.util.Log;

import java.net.InetAddress;

/**
 * DNS режима root. Запускается от root отдельной программой (app_process с APK приложения в CLASSPATH), поэтому
 * не зависит от того, работает ли само приложение: прошивка может его заморозить, а DNS телефона останется.
 * Правило iptables перенаправляет на этот порт обычные DNS-запросы всех приложений, кроме его собственных.
 *
 * Порядок как просили: Cloudflare, затем Google, и только потом Яндекс. DoH идёт первым: обычный DNS на
 * 1.1.1.1 провайдер подделывает.
 */
public final class DnsMain {
    static final int PORT = 15353;
    private static final String[] DOH = {"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query",
            "https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"};
    private static final String[] UDP = {"1.1.1.1", "8.8.8.8", "77.88.8.8", "77.88.8.1"};
    /** Все адреса, куда программа ходит сама: правило перенаправления DNS их пропускает. */
    static final String UPSTREAM_V4 = "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,77.88.8.8,77.88.8.1";

    private DnsMain() {
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : PORT;
        DnsForwarder forwarder = new DnsForwarder(DOH, UDP, true);
        forwarder.listen(InetAddress.getByName("127.0.0.1"), port);
        boolean ipv6 = false;
        try {
            forwarder.listen(InetAddress.getByName("::1"), port);
            ipv6 = true;
        } catch (Exception noIpv6) {
            Log.w("ZapretCapDns", "::1 недоступен", noIpv6);
        }
        Log.i("ZapretCapDns", "DNS root mode on port " + port);
        // вывод идёт в файл, а там Java его копит: без flush скрипт запуска не увидел бы эту строку
        System.out.println("ZC: DNS ready on port " + port + (ipv6 ? "" : " (no v6)"));
        if (ipv6) {
            System.out.println("ZC: DNS ready v6");
        }
        System.out.flush();
        forwarder.warmUp();
        // потоки DnsForwarder - демоны: основной поток держит программу живой
        while (true) {
            Thread.sleep(Long.MAX_VALUE);
        }
    }
}
