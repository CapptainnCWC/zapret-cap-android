package org.zapretcap.tgproxy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Запас готовых соединений, чтобы клиент не ждал подключения к серверу.
 *
 * Запас держится, только пока клиент им пользуется. Телефон нельзя будить ради соединений, которые никто не берёт:
 * сервер закрывает их через минуту, и пул открывал бы десятки новых в час. К тому же простаивающее соединение может
 * умереть молча (NAT оператора, DPI, сон телефона): сокет выглядит живым, а данные пропадают, и клиент
 * раз за разом получал бы мёртвые соединения. Поэтому первым отдаётся самое свежее.
 */
abstract class IdlePool<K> {
    private static final long BACKOFF_INITIAL_MS = 1000;
    private static final long BACKOFF_MAX_MS = 3600_000;
    /** Сколько после последнего запроса поддерживать запас. */
    private static final long ACTIVE_WINDOW_NANOS = 180_000_000_000L;
    /** Сколько клиент ждёт новое соединение, прежде чем уйти на запасной маршрут. */
    private static final long MISS_WAIT_NANOS = 3_000_000_000L;
    /** Соединение старше этого могло незаметно умереть, поэтому его ответ проверяется строже. */
    static final long SUSPECT_AGE_NANOS = 10_000_000_000L;

    static final class Idle {
        final RawWebSocket ws;
        final long created;
        final String via;
        /** С ним сейчас работает фоновая проверка, отдавать его клиенту нельзя. */
        boolean checking;

        Idle(RawWebSocket ws, String via) {
            this.ws = ws;
            this.created = System.nanoTime();
            this.via = via;
        }

        boolean suspect() {
            return System.nanoTime() - created >= SUSPECT_AGE_NANOS;
        }
    }

    private static final class Bucket {
        /** От старых к новым. */
        final List<Idle> idle = new ArrayList<>();
        boolean refilling;
        int failures;
        long refillAfter;
        long lastTake;
        boolean everTaken;
        int generation;
    }

    protected final TgWsProxy proxy;
    private final long maxAgeNanos;
    private final Map<K, Bucket> buckets = new HashMap<>();
    private volatile boolean closed;

    IdlePool(TgWsProxy proxy, long maxAgeSeconds) {
        this.proxy = proxy;
        this.maxAgeNanos = maxAgeSeconds * 1_000_000_000L;
    }

    /** Сколько соединений держать для ключа, 0 - не держать. */
    abstract int targetSize();

    /** Открывает новое соединение или возвращает null, если ни один способ не сработал. */
    abstract Idle connect(K key);

    /** Готовое соединение или null, если за короткое время его получить не удалось. */
    Idle take(K key) throws InterruptedException {
        long deadline = System.nanoTime() + MISS_WAIT_NANOS;
        while (true) {
            Idle candidate = null;
            synchronized (this) {
                Bucket bucket = bucket(key);
                bucket.lastTake = System.nanoTime();
                bucket.everTaken = true;
                for (int i = bucket.idle.size() - 1; i >= 0; i--) {
                    if (!bucket.idle.get(i).checking) {
                        candidate = bucket.idle.remove(i);
                        break;
                    }
                }
            }
            if (candidate != null) {
                if (isStale(candidate)) {
                    Idle dead = candidate;
                    proxy.executor().execute(dead.ws::close);
                    continue;
                }
                scheduleRefill(key);
                return candidate;
            }
            scheduleRefill(key);
            synchronized (this) {
                Bucket bucket = bucket(key);
                while (bucket.refilling && bucket.idle.isEmpty() && !closed) {
                    long left = deadline - System.nanoTime();
                    if (left <= 0) {
                        return null;
                    }
                    wait(left / 1_000_000L + 1);
                }
                if (bucket.idle.isEmpty() || closed) {
                    return null;
                }
            }
        }
    }

    private boolean isStale(Idle idle) {
        return System.nanoTime() - idle.created >= maxAgeNanos || idle.ws.isStale();
    }

    private Bucket bucket(K key) {
        Bucket bucket = buckets.get(key);
        if (bucket == null) {
            bucket = new Bucket();
            buckets.put(key, bucket);
        }
        return bucket;
    }

    void scheduleRefill(K key) {
        int needed;
        final Bucket bucket;
        final int generation;
        synchronized (this) {
            if (closed) {
                return;
            }
            bucket = bucket(key);
            int target = targetSize();
            needed = target - bucket.idle.size();
            if (target <= 0 || needed <= 0 || bucket.refilling || System.nanoTime() < bucket.refillAfter) {
                return;
            }
            bucket.refilling = true;
            generation = bucket.generation;
        }
        AtomicInteger left = new AtomicInteger(needed);
        AtomicInteger connected = new AtomicInteger();
        for (int i = 0; i < needed; i++) {
            proxy.executor().execute(() -> {
                Idle idle = null;
                try {
                    idle = connect(key);
                } catch (RuntimeException e) {
                    ProxyLog.d("pool connect failed: " + e);
                }
                boolean adopted = false;
                synchronized (this) {
                    // соединение, начатое до смены сети, никому не нужно
                    if (idle != null && !closed && bucket.generation == generation) {
                        bucket.idle.add(idle);
                        connected.incrementAndGet();
                        adopted = true;
                        notifyAll();
                    }
                }
                if (idle != null && !adopted) {
                    idle.ws.close();
                }
                if (left.decrementAndGet() == 0) {
                    refillFinished(bucket, connected.get(), key);
                }
            });
        }
    }

    private void refillFinished(Bucket bucket, int connected, K key) {
        synchronized (this) {
            bucket.refilling = false;
            if (connected > 0) {
                bucket.failures = 0;
                bucket.refillAfter = 0;
            } else {
                bucket.failures++;
                long delay = Math.min(BACKOFF_INITIAL_MS << Math.min(bucket.failures - 1, 12), BACKOFF_MAX_MS);
                bucket.refillAfter = System.nanoTime() + delay * 1_000_000L;
                ProxyLog.i("Пул " + key + ": не удалось подключиться, повтор через " + delay / 1000 + " с");
            }
            notifyAll();
        }
    }

    /** Раз в несколько секунд убирает устаревшие соединения и, пока клиент активен, пополняет запас. */
    void tick() {
        List<K> keys;
        synchronized (this) {
            if (closed) {
                return;
            }
            keys = new ArrayList<>(buckets.keySet());
        }
        for (K key : keys) {
            List<Idle> snapshot;
            boolean active;
            synchronized (this) {
                Bucket bucket = bucket(key);
                snapshot = new ArrayList<>(bucket.idle);
                active = bucket.everTaken && System.nanoTime() - bucket.lastTake < ACTIVE_WINDOW_NANOS;
            }
            for (Idle idle : snapshot) {
                synchronized (this) {
                    if (!bucket(key).idle.contains(idle)) {
                        continue;
                    }
                    idle.checking = true;
                }
                boolean stale = isStale(idle);
                synchronized (this) {
                    idle.checking = false;
                    if (stale) {
                        bucket(key).idle.remove(idle);
                    }
                }
                if (stale) {
                    idle.ws.close();
                }
            }
            if (active) {
                scheduleRefill(key);
            }
        }
    }

    /** Закрывает весь запас ключа: соединение из него оказалось мёртвым, значит, и остальные под подозрением. */
    void discard(K key) {
        List<Idle> dead;
        synchronized (this) {
            Bucket bucket = bucket(key);
            dead = new ArrayList<>();
            for (Idle idle : new ArrayList<>(bucket.idle)) {
                if (!idle.checking) {
                    bucket.idle.remove(idle);
                    dead.add(idle);
                }
            }
        }
        for (Idle idle : dead) {
            idle.ws.close();
        }
        scheduleRefill(key);
    }

    /** Сеть сменилась: старые соединения не работают, а прошлые неудачи ничего не значат. */
    void flush() {
        List<Idle> all = new ArrayList<>();
        synchronized (this) {
            for (Bucket bucket : buckets.values()) {
                all.addAll(bucket.idle);
                bucket.idle.clear();
                bucket.failures = 0;
                bucket.refillAfter = 0;
                bucket.generation++;
            }
            notifyAll();
        }
        for (Idle idle : all) {
            idle.ws.close();
        }
    }

    void close() {
        List<Idle> all = new ArrayList<>();
        synchronized (this) {
            closed = true;
            for (Bucket bucket : buckets.values()) {
                all.addAll(bucket.idle);
                bucket.idle.clear();
            }
            notifyAll();
        }
        for (Idle idle : all) {
            idle.ws.close();
        }
    }
}
