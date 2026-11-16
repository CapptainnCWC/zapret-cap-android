package org.zapretcap.app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * К какой сети подключён телефон. Домашний Wi-Fi и оператор блокируют по-разному, поэтому конфиг и TTL
 * выбираются отдельно для мобильной сети и для каждой Wi-Fi сети. Само приложение исключено из VPN, поэтому система отвечает про
 * настоящую сеть, даже когда обход включён.
 */
final class NetKind {
    static final String WIFI = "wifi";
    static final String CELL = "cell";

    private NetKind() {
    }

    /**
     * Настоящая сеть телефона. Само приложение исключено из VPN, но система всё равно присылает ему события и про
     * наш туннель, поэтому им нельзя верить на слово: туннель принимался бы за новую сеть при каждом событии.
     */
    static Network physical(Context context) {
        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        Network active = manager.getActiveNetwork();
        if (isPhysical(manager.getNetworkCapabilities(active))) {
            return active;
        }
        Network fallback = null;
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
            if (isPhysical(capabilities)) {
                if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    return network;
                }
                fallback = network;
            }
        }
        return fallback;
    }

    private static boolean isPhysical(NetworkCapabilities capabilities) {
        return capabilities != null && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
    }

    /** Вид текущей сети. Без сети считается Wi-Fi: выбор конфига всё равно уточнится, когда сеть появится. */
    static String current(Context context) {
        Network network = physical(context);
        return of(network == null ? null
                : context.getSystemService(ConnectivityManager.class).getNetworkCapabilities(network));
    }

    /**
     * Какая именно Wi-Fi сеть: у разных провайдеров и роутеров разные рабочие конфиги. Имя сети Android отдаёт
     * только с доступом к местоположению, поэтому сеть узнаётся по тому, что видно без разрешений: шлюз, подсеть,
     * DNS, домен и DHCP-сервер. Две сети с одинаковыми адресами роутера будут считаться одной. Null - не Wi-Fi.
     */
    static WifiId wifiId(Context context) {
        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        Network network = physical(context);
        NetworkCapabilities capabilities = network == null ? null : manager.getNetworkCapabilities(network);
        if (capabilities == null || !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            return null;
        }
        LinkProperties properties = manager.getLinkProperties(network);
        if (properties == null) {
            return null;
        }
        String gateway = null;
        for (RouteInfo route : properties.getRoutes()) {
            if (route.isDefaultRoute() && route.getGateway() instanceof Inet4Address) {
                gateway = route.getGateway().getHostAddress();
                break;
            }
        }
        StringBuilder print = new StringBuilder("gw=").append(gateway);
        for (LinkAddress address : properties.getLinkAddresses()) {
            if (address.getAddress() instanceof Inet4Address) {
                print.append(";net=").append(network(address.getAddress().getAddress(), address.getPrefixLength()))
                        .append('/').append(address.getPrefixLength());
            }
        }
        List<String> dns = new ArrayList<>();
        for (InetAddress server : properties.getDnsServers()) {
            dns.add(server.getHostAddress());
        }
        Collections.sort(dns);
        print.append(";dns=").append(dns).append(";domain=").append(properties.getDomains());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && properties.getDhcpServerAddress() != null) {
            print.append(";dhcp=").append(properties.getDhcpServerAddress().getHostAddress());
        }
        String ssid = ssid(context);
        if (gateway == null && dns.isEmpty() && ssid == null) {
            return null;
        }
        return new WifiId(hash(print.toString()), gateway != null ? gateway : dns.isEmpty() ? "?" : dns.get(0), ssid);
    }

    /** Wi-Fi сеть: имя, если Android его отдал, и отпечаток по адресам на случай, когда имени нет. */
    static final class WifiId {
        final String id;
        final String gateway;
        /** Имя сети или null: без доступа к местоположению или с выключенной геолокацией Android его скрывает. */
        final String ssid;

        WifiId(String id, String gateway, String ssid) {
            this.id = id;
            this.gateway = gateway;
            this.ssid = ssid;
        }
    }

    /**
     * Имя Wi-Fi сети. Большинство роутеров раздают одну и ту же подсеть, поэтому имя - главный признак сети.
     * Android отдаёт его только при доступе к местоположению (в фоне - «Разрешить всегда») и включённой геолокации.
     */
    @SuppressWarnings("deprecation")
    static String ssid(Context context) {
        try {
            WifiManager wifi = context.getApplicationContext().getSystemService(WifiManager.class);
            WifiInfo info = wifi == null ? null : wifi.getConnectionInfo();
            String ssid = info == null ? null : info.getSSID();
            if (ssid == null || ssid.isEmpty() || WifiManager.UNKNOWN_SSID.equals(ssid) || "0x".equals(ssid)) {
                return null;
            }
            if (ssid.length() >= 2 && ssid.startsWith("\"") && ssid.endsWith("\"")) {
                ssid = ssid.substring(1, ssid.length() - 1);
            }
            return ssid.isEmpty() ? null : ssid;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String network(byte[] address, int prefix) {
        byte[] masked = address.clone();
        for (int i = 0; i < masked.length; i++) {
            int bits = Math.max(0, Math.min(8, prefix - i * 8));
            masked[i] &= (byte) (0xff << (8 - bits));
        }
        try {
            return InetAddress.getByAddress(masked).getHostAddress();
        } catch (java.net.UnknownHostException e) {
            return "?";
        }
    }

    private static String hash(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 6; i++) {
                hex.append(String.format(Locale.ROOT, "%02x", digest[i]));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(text.hashCode());
        }
    }

    /**
     * Где хранится выбор: у Wi-Fi своя запись для каждой сети, у мобильной сети одна. Для вкладки Wi-Fi, когда
     * телефон не в Wi-Fi, - общая запись Wi-Fi: она же служит выбором по умолчанию для новых сетей.
     */
    static String scope(Context context, String kind) {
        return scopes(context, kind).get(0);
    }

    /**
     * Записи, в которых ищется выбор, от самой точной: по имени сети, по адресам роутера, общая для Wi-Fi.
     * Запись по адресам остаётся запасной: имя бывает недоступно, если выключить геолокацию.
     */
    static List<String> scopes(Context context, String kind) {
        List<String> scopes = new ArrayList<>();
        if (WIFI.equals(kind)) {
            WifiId id = wifiId(context);
            if (id != null) {
                if (id.ssid != null) {
                    scopes.add(WIFI + "#" + hash("ssid:" + id.ssid));
                }
                scopes.add(WIFI + "@" + id.id);
            }
        }
        scopes.add(kind);
        if (BypassSettings.rootMode(context)) {
            // у режима root свои стратегии и свои итоги подбора: записи не должны смешиваться с режимом VPN
            for (int i = 0; i < scopes.size(); i++) {
                scopes.set(i, "root/" + scopes.get(i));
            }
        }
        return scopes;
    }

    static String of(NetworkCapabilities capabilities) {
        return capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ? CELL : WIFI;
    }
}
