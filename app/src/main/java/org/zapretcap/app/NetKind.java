package org.zapretcap.app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;

/**
 * К какой сети подключён телефон. Домашний Wi-Fi и оператор блокируют по-разному, поэтому конфиг и TTL
 * выбираются отдельно для каждого вида. Само приложение исключено из VPN, поэтому система отвечает про
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

    static String of(NetworkCapabilities capabilities) {
        return capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ? CELL : WIFI;
    }
}
