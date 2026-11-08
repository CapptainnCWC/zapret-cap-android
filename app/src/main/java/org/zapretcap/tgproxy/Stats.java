package org.zapretcap.tgproxy;

import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

public final class Stats {
    final AtomicLong connectionsTotal = new AtomicLong();
    final AtomicLong connectionsActive = new AtomicLong();
    final AtomicLong connectionsWs = new AtomicLong();
    final AtomicLong connectionsH2 = new AtomicLong();
    final AtomicLong h2Requests = new AtomicLong();
    final AtomicLong h2Errors = new AtomicLong();
    final AtomicLong connectionsTcpFallback = new AtomicLong();
    final AtomicLong connectionsCfproxy = new AtomicLong();
    final AtomicLong connectionsFronting = new AtomicLong();
    final AtomicLong connectionsBad = new AtomicLong();
    final AtomicLong wsErrors = new AtomicLong();
    final AtomicLong bytesUp = new AtomicLong();
    final AtomicLong bytesDown = new AtomicLong();
    final AtomicLong poolHits = new AtomicLong();
    final AtomicLong poolMisses = new AtomicLong();

    private volatile long lastBadKeyNanos;

    void badKey() {
        connectionsBad.incrementAndGet();
        lastBadKeyNanos = System.nanoTime();
    }

    /** Клиент недавно пришёл с чужим ключом: такое бывает, если в Telegram сохранён прокси со старым ключом. */
    public boolean recentBadKey() {
        return lastBadKeyNanos != 0 && System.nanoTime() - lastBadKeyNanos < 30_000_000_000L;
    }

    public long active() {
        return connectionsActive.get();
    }

    public long bytesUp() {
        return bytesUp.get();
    }

    public long bytesDown() {
        return bytesDown.get();
    }

    public String summary() {
        return "total=" + connectionsTotal + " active=" + connectionsActive + " ws=" + connectionsWs
                + " h2=" + connectionsH2 + " h2_req=" + h2Requests + " h2_err=" + h2Errors
                + " tcp_fb=" + connectionsTcpFallback + " cf=" + connectionsCfproxy
                + " front=" + connectionsFronting + " bad=" + connectionsBad + " err=" + wsErrors
                + " pool=" + poolHits + "/" + (poolHits.get() + poolMisses.get())
                + " up=" + humanBytes(bytesUp.get()) + " down=" + humanBytes(bytesDown.get());
    }

    public static String humanBytes(long n) {
        double value = n;
        for (String unit : new String[]{"Б", "КБ", "МБ", "ГБ"}) {
            if (value < 1024) {
                return String.format(Locale.ROOT, "%.1f %s", value, unit);
            }
            value /= 1024;
        }
        return String.format(Locale.ROOT, "%.1f ТБ", value);
    }
}
