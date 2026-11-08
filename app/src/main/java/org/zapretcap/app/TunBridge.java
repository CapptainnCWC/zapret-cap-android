package org.zapretcap.app;

/**
 * hev-socks5-tunnel: забирает пакеты из VPN-интерфейса и отдаёт соединения в ciadpi.
 * Имя класса задано при сборке библиотеки (PKGNAME и CLSNAME в native/build-native.sh),
 * а функции она регистрирует сама при загрузке.
 */
final class TunBridge {
    static {
        System.loadLibrary("hev-socks5-tunnel");
    }

    private TunBridge() {
    }

    static native boolean TProxyStartService(String configPath, int fd);

    static native boolean TProxyStopService();

    static native boolean TProxyIsRunning();

    static native long[] TProxyGetStats();
}
