package org.zapretcap.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/**
 * Режим без root. Трафик телефона идёт в VPN-интерфейс, оттуда через hev-socks5-tunnel в ciadpi,
 * а ciadpi открывает обычные соединения с сайтами и применяет к ним приёмы обхода.
 * Само приложение исключено из VPN, иначе соединения ciadpi снова попадали бы в него.
 */
public class BypassVpnService extends VpnService {
    private static final String TAG = "ZapretCap";
    static final String ACTION_START = "org.zapretcap.app.START";
    static final String ACTION_STOP = "org.zapretcap.app.STOP";

    private static final String TUN_IPV4 = "198.18.0.1";
    private static final String TUN_IPV6 = "fc00::1";
    /**
     * Адрес DNS для приложений. Ничего по нему не слушает: движок перехватывает всё, что идёт на порт 53.
     * Публичные адреса здесь не подходят: Chrome увидел бы 1.1.1.1 и сам ушёл бы на свой DoH мимо локального DNS.
     */
    private static final String TUN_DNS = "198.18.0.2";
    private static final int TUN_MTU = 8500;
    private static final int TCP_IDLE_TIMEOUT_MS = 30 * 60 * 1000;
    /** Приложения, которые идут мимо VPN: сервисы Google Play, через них приходят пуш-уведомления. */
    private static final String[] DIRECT_APPS = {"com.google.android.gms"};
    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL = "bypass";

    /** Запуск, смена стратегии и остановка идут строго по очереди. */
    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    /** Сеть меняется рывками, особенно при переходе Wi-Fi - мобильная: реагируем, когда она успокоилась. */
    private static final long NETWORK_SETTLE_MS = 1500;
    /** Движок перезапускается сам, но падение чаще раза в 20 секунд значит, что конфиг ему не подходит. */
    private static final int MAX_QUICK_RESTARTS = 3;
    private static final long QUICK_RESTART_MS = 20_000;
    private static final long HEALTH_INTERVAL_MS = 30_000;

    private final Handler main = new Handler(Looper.getMainLooper());
    private final Runnable networkSettled = () -> runOnWorker(this::onNetworkSettled);
    private final Runnable healthTick = new Runnable() {
        @Override
        public void run() {
            runOnWorker(BypassVpnService.this::checkHealth);
            main.postDelayed(this, HEALTH_INTERVAL_MS);
        }
    };

    /** События только будят проверку: какая сеть настоящая, решает NetKind.physical. */
    private final ConnectivityManager.NetworkCallback networkCallback = new ConnectivityManager.NetworkCallback() {
        @Override
        public void onAvailable(Network network) {
            onNetworkEvent();
        }

        @Override
        public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
            onNetworkEvent();
        }

        @Override
        public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
            onNetworkEvent();
        }

        @Override
        public void onLost(Network network) {
            onNetworkEvent();
        }
    };

    private ParcelFileDescriptor tun;
    private volatile Process ciadpi;
    private int port;
    private String strategy;
    /** Сеть, для которой запущен движок: соединения движка привязаны к ней и умирают вместе с ней. */
    private Network network;
    private boolean tunHasIpv6;
    private boolean networkCallbackRegistered;
    /** Порт работающего движка обхода. Нужен самому приложению, например чтобы скачать списки, когда GitHub закрыт. */
    static volatile int enginePort;
    private DnsForwarder dns;
    private int dnsPort;
    private int quickRestarts;
    private long lastEngineStart;

    static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences("settings", MODE_PRIVATE);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        CrashLog.install(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            runOnWorker(() -> stop(null));
            return START_NOT_STICKY;
        }
        // Без intent и без ACTION_START служба поднята системой: постоянная VPN или перезапуск после сбоя
        String kind = NetKind.current(this);
        String name = Data.strategyFor(this, kind);
        showNotification(name);
        runOnWorker(() -> start(name));
        return START_STICKY;
    }

    private void runOnWorker(Runnable task) {
        try {
            worker.execute(task);
        } catch (RejectedExecutionException serviceAlreadyDestroyed) {
            Log.i(TAG, "worker stopped");
        }
    }

    private void onNetworkEvent() {
        main.removeCallbacks(networkSettled);
        main.postDelayed(networkSettled, NETWORK_SETTLE_MS);
    }

    /**
     * Без этого соединения остаются привязаны к пропавшей сети: приложения ждут ответа минутами. После перезапуска
     * движка они сразу получают обрыв и переподключаются, а выбор конфига и кэш движка соответствуют новой сети.
     */
    private void onNetworkSettled() {
        Network next = NetKind.physical(this);
        if (ciadpi == null || next == null || next.equals(network)) {
            return;
        }
        Log.i(TAG, "network changed: " + network + " -> " + next);
        String name = Data.strategyFor(this, NetKind.current(this));
        start(name);
    }

    /** Движок может зависнуть, не завершившись. Тогда приложения остались бы без сети, а служба считала бы, что всё хорошо. */
    private void checkHealth() {
        Process process = ciadpi;
        if (process == null || port == 0) {
            return;
        }
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 3000);
        } catch (IOException e) {
            if (process == ciadpi) {
                Log.e(TAG, "ciadpi not responding, restarting");
                restartAfterFailure("Движок не отвечает");
            }
        }
    }

    private void restartAfterFailure(String reason) {
        long now = System.currentTimeMillis();
        quickRestarts = now - lastEngineStart < QUICK_RESTART_MS ? quickRestarts + 1 : 0;
        if (quickRestarts >= MAX_QUICK_RESTARTS) {
            stop(reason);
            return;
        }
        start(strategy != null ? strategy : Data.strategyFor(this, NetKind.current(this)));
    }

    @Override
    public void onRevoke() {
        // VPN включили у другого приложения или отозвали разрешение
        runOnWorker(() -> stop(null));
    }

    @Override
    public void onDestroy() {
        main.removeCallbacksAndMessages(null);
        unregisterNetwork();
        worker.execute(this::releaseEngines);
        worker.shutdown();
        super.onDestroy();
    }

    private void start(String name) {
        AppState.set(AppState.Phase.STARTING, name, null);
        try {
            registerNetwork();
            Data.extract(this);
            Data.applyLists(this);
            ConnectivityManager manager = getSystemService(ConnectivityManager.class);
            Network active = NetKind.physical(this);
            String kind = NetKind.current(this);
            startDns(manager, active);
            startCiadpi(name, kind);
            lastEngineStart = System.currentTimeMillis();
            network = active;
            enginePort = port;
            boolean ipv6 = hasGlobalIpv6(manager, active);
            if (tun != null && ipv6 != tunHasIpv6) {
                // другой набор адресов требует нового интерфейса
                closeTunnel();
            }
            if (tun == null) {
                tun = establish(ipv6);
                tunHasIpv6 = ipv6;
                writeTunnelConfig(ipv6);
                if (!TunBridge.TProxyStartService(tunnelConfig().getPath(), tun.getFd())) {
                    throw new IOException("Не запустился hev-socks5-tunnel");
                }
            }
            if (active != null) {
                // иначе система не знает, какая сеть под VPN, и может считать её недоступной или лимитной
                setUnderlyingNetworks(new Network[]{active});
            }
            strategy = name;
            showNotification(name);
            main.removeCallbacks(healthTick);
            main.postDelayed(healthTick, HEALTH_INTERVAL_MS);
            AppState.set(AppState.Phase.ON, name, null);
        } catch (Exception e) {
            Log.e(TAG, "start failed", e);
            stop(e.getMessage());
        }
    }

    private void startDns(ConnectivityManager manager, Network active) throws IOException {
        if (dns == null) {
            dns = new DnsForwarder();
            dnsPort = dns.start();
        }
        boolean changedNetwork = active == null || !active.equals(network);
        if (changedNetwork) {
            dns.onNetworkChanged();
        }
        LinkProperties properties = active == null ? null : manager.getLinkProperties(active);
        dns.setNetworkServers(properties == null ? java.util.Collections.emptyList() : properties.getDnsServers());
        dns.setHosts(BypassSettings.hosts(this));
        if (tun == null || changedNetwork) {
            dns.warmUp();
        }
    }

    private void registerNetwork() {
        if (!networkCallbackRegistered) {
            getSystemService(ConnectivityManager.class).registerDefaultNetworkCallback(networkCallback);
            networkCallbackRegistered = true;
        }
    }

    private void unregisterNetwork() {
        if (networkCallbackRegistered) {
            getSystemService(ConnectivityManager.class).unregisterNetworkCallback(networkCallback);
            networkCallbackRegistered = false;
        }
    }

    /**
     * Маршрут IPv6 в туннель нужен, только если он есть у настоящей сети. Иначе приложения ждут от каждого
     * адреса IPv6 отказа через туннель, прежде чем перейти на IPv4. Без адреса IPv6 в туннеле система сразу
     * отвечает, что такой сети нет, и утечки нет: VPN блокирует семейство адресов, которого у него нет.
     */
    private static boolean hasGlobalIpv6(ConnectivityManager manager, Network active) {
        LinkProperties properties = active == null ? null : manager.getLinkProperties(active);
        if (properties == null) {
            return false;
        }
        for (LinkAddress address : properties.getLinkAddresses()) {
            java.net.InetAddress ip = address.getAddress();
            // fc00::/7 ходит только внутри локальной сети, в интернет через него не выйти
            boolean uniqueLocal = ip instanceof Inet6Address && (ip.getAddress()[0] & 0xfe) == 0xfc;
            if (ip instanceof Inet6Address && !uniqueLocal && !ip.isLinkLocalAddress()
                    && !ip.isLoopbackAddress() && !ip.isSiteLocalAddress()) {
                return true;
            }
        }
        return false;
    }

    private void stop(String error) {
        main.removeCallbacksAndMessages(null);
        unregisterNetwork();
        releaseEngines();
        strategy = null;
        network = null;
        AppState.set(AppState.Phase.OFF, null, error);
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private void releaseEngines() {
        enginePort = 0;
        closeTunnel();
        stopCiadpi();
        if (dns != null) {
            dns.stop();
            dns = null;
            dnsPort = 0;
        }
    }

    private void closeTunnel() {
        if (tun != null) {
            TunBridge.TProxyStopService();
            try {
                tun.close();
            } catch (IOException e) {
                Log.w(TAG, "tun close", e);
            }
            tun = null;
        }
    }

    private void stopCiadpi() {
        Process process = ciadpi;
        ciadpi = null;
        if (process != null) {
            process.destroy();
            try {
                process.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void startCiadpi(String name, String kind) throws IOException {
        stopCiadpi();
        // порт не меняется при смене стратегии: hev-socks5-tunnel продолжает работать с тем же
        if (port == 0) {
            port = freePort();
        }
        Process process = new ProcessBuilder(Data.ciadpiCommand(this, port, dnsPort, Data.vpnArgs(this, kind, name)))
                .redirectErrorStream(true).start();
        ciadpi = process;
        StringBuffer output = new StringBuffer();
        watchCiadpi(process, output);
        waitForPort(process, output);
    }

    /** Если движок упал, VPN без него оставил бы телефон без интернета: запускаем заново, а при повторах выключаем всё. */
    private void watchCiadpi(Process process, StringBuffer output) {
        Thread thread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    Log.i(TAG, "ciadpi: " + line);
                    if (output.length() < 2000) {
                        output.append(line).append('\n');
                    }
                }
            } catch (IOException ignored) {
                // поток закрылся вместе с процессом
            }
            int code = -1;
            try {
                code = process.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            final int exit = code;
            try {
                worker.execute(() -> {
                    if (process == ciadpi) {
                        Log.e(TAG, "ciadpi exited: " + exit);
                        restartAfterFailure("Движок завершился с кодом " + exit + ". " + output.toString().trim());
                    }
                });
            } catch (RejectedExecutionException serviceAlreadyDestroyed) {
                Log.i(TAG, "ciadpi exited after the service");
            }
        }, "ciadpi-watch");
        thread.setDaemon(true);
        thread.start();
    }

    private void waitForPort(Process process, StringBuffer output) throws IOException {
        for (int attempt = 0; attempt < 100; attempt++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 100);
                return;
            } catch (IOException notYet) {
                if (!Data.isAlive(process)) {
                    throw new IOException("Движок не запустился. " + output.toString().trim());
                }
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted");
                }
            }
        }
        throw new IOException("Движок не отвечает");
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private ParcelFileDescriptor establish(boolean ipv6) throws Exception {
        Builder builder = new Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(TUN_MTU)
                .addAddress(TUN_IPV4, 32)
                .addRoute("0.0.0.0", 0);
        if (ipv6) {
            builder.addAddress(TUN_IPV6, 128).addRoute("::", 0);
        }
        builder.addDnsServer(TUN_DNS)
                .addDisallowedApplication(getPackageName());
        // Пуш-уведомления всех приложений приходят через сервисы Google Play. Они не заблокированы, а через
        // туннель их постоянное соединение рвётся при каждом перезапуске обхода и на обманках: уведомления
        // перестают приходить. Напрямую оно работает так же, как без обхода
        for (String app : DIRECT_APPS) {
            try {
                builder.addDisallowedApplication(app);
            } catch (android.content.pm.PackageManager.NameNotFoundException e) {
                // на телефонах без сервисов Google их просто нет
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false);
        }
        ParcelFileDescriptor descriptor = builder.establish();
        if (descriptor == null) {
            throw new IOException(getString(R.string.error_vpn_denied));
        }
        return descriptor;
    }

    private File tunnelConfig() {
        return new File(getCacheDir(), "tunnel.yml");
    }

    private void writeTunnelConfig(boolean ipv6) throws IOException {
        String config = "tunnel:\n"
                + "  mtu: " + TUN_MTU + "\n"
                + "  ipv4: " + TUN_IPV4 + "\n"
                + (ipv6 ? "  ipv6: '" + TUN_IPV6 + "'\n" : "")
                + "socks5:\n"
                + "  port: " + port + "\n"
                + "  address: 127.0.0.1\n"
                + "  udp: 'udp'\n"
                + "misc:\n"
                // постоянные соединения пушей молчат между проверками связи дольше 5 минут, принятых по умолчанию:
                // туннель рвал бы их, и уведомления приходили бы с задержкой
                + "  tcp-read-write-timeout: " + TCP_IDLE_TIMEOUT_MS + "\n"
                + "  log-level: error\n";
        try (FileOutputStream out = new FileOutputStream(tunnelConfig())) {
            out.write(config.getBytes(StandardCharsets.UTF_8));
        }
    }

    private void showNotification(String name) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(new NotificationChannel(
                    CHANNEL, getString(R.string.channel_name), NotificationManager.IMPORTANCE_LOW));
            builder = new Notification.Builder(this, CHANNEL);
        } else {
            builder = new Notification.Builder(this);
        }
        PendingIntent open = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop = PendingIntent.getService(this, 1,
                new Intent(this, BypassVpnService.class).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE);
        Notification notification = builder
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(getString(R.string.status_on, name))
                .setContentText(getString(NetKind.CELL.equals(NetKind.current(this)) ? R.string.net_cell : R.string.net_wifi))
                .setContentIntent(open)
                .setOngoing(true)
                .addAction(new Notification.Action.Builder(null, getString(R.string.notification_stop), stop).build())
                .build();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }
}
