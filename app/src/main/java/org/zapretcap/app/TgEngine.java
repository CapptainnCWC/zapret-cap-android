package org.zapretcap.app;

import android.content.Context;
import android.util.Log;

import org.zapretcap.tgproxy.Dialer;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Свой движок обхода для прокси Telegram. Прокси не зависит от основного обхода, как tg-ws-proxy на Windows:
 * конфиг, хороший для YouTube, бывает плох для серверов Telegram и Cloudflare. По умолчанию прокси ходит напрямую,
 * а если в его настройках выбран конфиг, запускается отдельный ciadpi только для него.
 */
final class TgEngine {
    private static final String TAG = "ZapretCapTg";
    /** Значение настройки «без обхода». */
    static final String DIRECT = "";
    private static final long RESTART_DELAY_MS = 2000;

    private Process process;
    private volatile boolean wanted;

    /** Запускает движок по настройкам прокси или выключает его. Вызывать с потока службы. */
    synchronized void start(Context context) {
        stop();
        String strategy = TgProxySettings.strategy(context);
        if (DIRECT.equals(strategy)) {
            Log.i(TAG, "Обход для прокси: без обхода");
            return;
        }
        wanted = true;
        try {
            Data.extract(context);
            Data.applyLists(context);
            int port;
            try (ServerSocket socket = new ServerSocket(0)) {
                port = socket.getLocalPort();
            }
            Process started = new ProcessBuilder(Data.ciadpiCommand(context, port, 0,
                    Data.vpnArgs(context, NetKind.current(context), strategy))).redirectErrorStream(true).start();
            process = started;
            drain(started);
            if (!waitForPort(started, port)) {
                throw new IOException("движок не запустился");
            }
            Dialer.setSocksPort(port);
            Log.i(TAG, "Обход для прокси: " + strategy);
            watch(context, started);
        } catch (IOException | RuntimeException e) {
            // без движка прокси работает напрямую, это лучше, чем совсем без связи
            Log.w(TAG, "Обход для прокси не запустился, прокси идёт напрямую: " + e.getMessage());
            stop();
        }
    }

    synchronized void stop() {
        wanted = false;
        Dialer.setSocksPort(0);
        Process old = process;
        process = null;
        if (old != null) {
            old.destroy();
            try {
                old.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** Если движок упал, прокси сразу переходит на прямые соединения, а движок запускается заново. */
    private void watch(Context context, Process started) {
        Thread thread = new Thread(() -> {
            try {
                started.waitFor();
            } catch (InterruptedException e) {
                return;
            }
            synchronized (this) {
                if (process != started || !wanted) {
                    return;
                }
                Dialer.setSocksPort(0);
                process = null;
            }
            Log.w(TAG, "Движок прокси завершился, перезапуск");
            try {
                Thread.sleep(RESTART_DELAY_MS);
            } catch (InterruptedException e) {
                return;
            }
            synchronized (this) {
                if (wanted && process == null) {
                    start(context);
                }
            }
        }, "tg-engine-watch");
        thread.setDaemon(true);
        thread.start();
    }

    private static void drain(Process process) {
        Thread thread = new Thread(() -> {
            byte[] buffer = new byte[4096];
            try (InputStream in = process.getInputStream()) {
                while (in.read(buffer) >= 0) {
                    // вывод не нужен, но без чтения движок остановился бы на полном буфере
                }
            } catch (IOException ignored) {
                // процесс завершён
            }
        }, "tg-engine-drain");
        thread.setDaemon(true);
        thread.start();
    }

    private static boolean waitForPort(Process process, int port) {
        for (int attempt = 0; attempt < 60; attempt++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 100);
                return true;
            } catch (IOException notYet) {
                if (!Data.isAlive(process)) {
                    return false;
                }
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return false;
    }
}
