package org.zapretcap.tgproxy;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/** Журнал прокси: последние строки в памяти для экрана настроек и внешний приёмник (logcat или консоль). */
public final class ProxyLog {
    public interface Sink {
        void line(String level, String message);
    }

    private static final int KEEP_LINES = 300;
    private static final ArrayDeque<String> LINES = new ArrayDeque<>();
    private static volatile Sink sink;

    private ProxyLog() {
    }

    public static void setSink(Sink newSink) {
        sink = newSink;
    }

    static void i(String message) {
        write("I", message);
    }

    static void w(String message) {
        write("W", message);
    }

    static void d(String message) {
        Sink current = sink;
        if (current != null) {
            current.line("D", message);
        }
    }

    private static void write(String level, String message) {
        synchronized (LINES) {
            if (LINES.size() >= KEEP_LINES) {
                LINES.removeFirst();
            }
            // время нужно, чтобы по журналу было видно, как часто рвутся соединения
            LINES.addLast(new SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(new Date()) + " " + level + " " + message);
        }
        Sink current = sink;
        if (current != null) {
            current.line(level, message);
        }
    }

    public static List<String> recent() {
        synchronized (LINES) {
            return new ArrayList<>(LINES);
        }
    }
}
