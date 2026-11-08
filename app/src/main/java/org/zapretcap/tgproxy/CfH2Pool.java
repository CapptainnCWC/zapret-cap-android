package org.zapretcap.tgproxy;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

/**
 * Медиа Telegram через HTTP/2 к Cloudflare: перенос proxy/cf_h2.py.
 *
 * Каждый пакет MTProto уходит отдельным POST /api, все каналы к одному домену делят одно соединение. Так не упираемся
 * в ограничение Cloudflare на число WebSocket. У такого транспорта сервер отвечает только на запрос, поэтому, пока
 * клиент молчит, канал повторяет его последний пакет: Telegram отбрасывает дубликат и заодно отдаёт накопленное.
 *
 * Состояние всех каналов линии защищено монитором линии (в оригинале его заменяет однопоточность asyncio).
 * Сеть и ожидание других потоков всегда вне монитора.
 */
final class CfH2Pool {
    static final int MAX_PACKET = 4 * 1024 * 1024;
    static final int MAX_PLAIN_PADDING = 256;
    static final int MAX_CHANNEL_REQUESTS = 8;
    static final int MAX_CHANNEL_BYTES = 8 * 1024 * 1024;
    static final int MAX_LANE_REQUESTS = 64;
    static final int MAX_LANE_BYTES = 32 * 1024 * 1024;
    static final int MAX_LANE_REPLY_BYTES = 32 * 1024 * 1024;
    static final long DOMAIN_COOLDOWN_MS = 30_000;
    static final long REQUEST_TIMEOUT_MS = 65_000;
    static final long SETUP_TIMEOUT_MS = 8_000;
    static final long REPLAY_IDLE_MS = 1_000;
    static final long REPLAY_REQUEST_MS = 3_000;
    static final long REPLAY_CHECK_MS = 250;
    static final long REPLAY_MAX_AGE_MS = 30_000;
    static final int REPLAY_HISTORY_BYTES = 64 * 1024;
    static final int REPLAY_HISTORY_PACKETS = 16;
    static final int MAX_CHANNEL_REPLAYS = 2;
    static final long REPLAY_SLOT_MS = 30_000;
    static final long REPLAY_RETRY_MS = 2_000;
    static final int REPLAY_MAX_ATTEMPTS = 3;
    static final int REPLY_QUEUE_SIZE = 16;
    private static final long NEVER = Long.MIN_VALUE;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Ошибка, о которой клиент должен узнать как об ошибке транспорта MTProto, а не просто по разрыву. */
    static final class TransportError extends IOException {
        final int code;

        TransportError(int code, String source) {
            super(code + " (" + source + ")");
            this.code = code;
        }
    }

    /** Кончилась своя память для ответов: сеть и домен здесь ни при чём. */
    static final class ReplyBufferFull extends IOException {
        ReplyBufferFull(String message) {
            super(message);
        }
    }

    /** То, что нужно линии от HTTP/2. Отделено от OkHttp, чтобы логику каналов можно было проверить без сети. */
    interface Transport {
        void preflight() throws IOException;

        byte[] post(byte[] body, Request request) throws IOException;

        void close();
    }

    static long now() {
        return System.nanoTime() / 1_000_000;
    }

    private static boolean allZero(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    // --- кадры MTProto клиента

    static final class Packet {
        final byte[] body;
        final boolean quick;

        Packet(byte[] body, boolean quick) {
            this.body = body;
            this.quick = quick;
        }
    }

    static Packet readPacket(DataInputStream in, Mtproto.AesCtr decryptor, byte[] tag) throws IOException {
        boolean quick;
        long length;
        if (Arrays.equals(tag, Mtproto.TAG_ABRIDGED)) {
            int first = readPlain(in, decryptor, 1)[0] & 0xff;
            quick = (first & 0x80) != 0;
            long words = first & 0x7f;
            if (words == 0x7f) {
                byte[] more = readPlain(in, decryptor, 3);
                words = (more[0] & 0xffL) | (more[1] & 0xffL) << 8 | (more[2] & 0xffL) << 16;
            }
            length = words * 4;
        } else {
            byte[] header = readPlain(in, decryptor, 4);
            long value = (header[0] & 0xffL) | (header[1] & 0xffL) << 8 | (header[2] & 0xffL) << 16 | (header[3] & 0xffL) << 24;
            quick = (value & 0x80000000L) != 0;
            length = value & 0x7fffffffL;
        }
        boolean secure = Arrays.equals(tag, Mtproto.TAG_SECURE);
        if (length < 24 || length > MAX_PACKET + (secure ? MAX_PLAIN_PADDING : 0)) {
            throw new IOException("native packet length outside supported range: " + length);
        }
        byte[] body = readPlain(in, decryptor, (int) length);
        if (secure) {
            boolean plaintext = allZero(Arrays.copyOf(body, 8));
            long packetLength;
            int maxPadding;
            if (plaintext) {
                packetLength = 20 + ((body[16] & 0xffL) | (body[17] & 0xffL) << 8 | (body[18] & 0xffL) << 16 | (body[19] & 0xffL) << 24);
                maxPadding = MAX_PLAIN_PADDING;
            } else {
                packetLength = 24 + ((length - 24) / 16) * 16;
                maxPadding = 15;
            }
            long padding = length - packetLength;
            if (packetLength < 24 || packetLength > length || padding > maxPadding) {
                throw new IOException("invalid padded native packet: frame=" + length + " packet=" + packetLength);
            }
            body = Arrays.copyOf(body, (int) packetLength);
        }
        if (body.length % 4 != 0 || body.length > MAX_PACKET) {
            throw new IOException("invalid native packet alignment or size");
        }
        return new Packet(body, quick);
    }

    private static byte[] readPlain(DataInputStream in, Mtproto.AesCtr decryptor, int count) throws IOException {
        byte[] data = new byte[count];
        in.readFully(data);
        return decryptor.update(data);
    }

    static byte[] encodeReply(byte[] body, byte[] tag) {
        if (body.length == 0 || body.length % 4 != 0 || body.length > MAX_PACKET) {
            throw new IllegalArgumentException("invalid HTTP MTProto response length: " + body.length);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(body.length + 8);
        if (Arrays.equals(tag, Mtproto.TAG_ABRIDGED)) {
            int words = body.length / 4;
            if (words < 0x7f) {
                out.write(words);
            } else {
                out.write(0x7f);
                out.write(words);
                out.write(words >> 8);
                out.write(words >> 16);
            }
            out.write(body, 0, body.length);
            return out.toByteArray();
        }
        byte[] padding = new byte[0];
        if (Arrays.equals(tag, Mtproto.TAG_SECURE)) {
            padding = new byte[RANDOM.nextInt(4)];
            RANDOM.nextBytes(padding);
        }
        int total = body.length + padding.length;
        out.write(total);
        out.write(total >> 8);
        out.write(total >> 16);
        out.write(total >> 24);
        out.write(body, 0, body.length);
        out.write(padding, 0, padding.length);
        return out.toByteArray();
    }

    // --- запрос

    /** Один POST. Отмена обрывает его, а завершение освобождает ёмкость канала и линии. */
    final class Request implements Runnable {
        final Channel channel;
        final byte[] body;
        final boolean replay;
        final ReplayPacket packet;
        /** Порядок создания: при равном времени отправки первым вытесняется более старый запрос. */
        final int order;
        private final CountDownLatch done = new CountDownLatch(1);
        private volatile boolean cancelled;
        private volatile Runnable canceller;

        Request(Channel channel, byte[] body, boolean replay, ReplayPacket packet) {
            this.channel = channel;
            this.body = body;
            this.replay = replay;
            this.packet = packet;
            this.order = channel.requests;
        }

        boolean isCancelled() {
            return cancelled;
        }

        boolean isDone() {
            return done.getCount() == 0;
        }

        void setCanceller(Runnable newCanceller) {
            canceller = newCanceller;
            if (cancelled) {
                newCanceller.run();
            }
        }

        void bodySent() {
            synchronized (channel.lane) {
                channel.sentSince.put(this, now());
            }
        }

        void responseStarted() {
            synchronized (channel.lane) {
                channel.receiving.add(this);
                channel.lastProgress = now();
            }
        }

        void bodyProgress() {
            synchronized (channel.lane) {
                channel.lastProgress = now();
            }
        }

        /** Вызывать вне монитора: ждёт, пока поток запроса закончится. */
        void cancelAndWait() throws InterruptedException {
            cancelled = true;
            Runnable current = canceller;
            if (current != null) {
                current.run();
            }
            done.await();
        }

        @Override
        public void run() {
            try {
                if (cancelled) {
                    return;
                }
                byte[] reply = channel.lane.post(this);
                synchronized (channel.lane) {
                    channel.lastProgress = now();
                    if (reply.length > 0 && !channel.closed) {
                        if (packet != null) {
                            byte[] replyId = Arrays.copyOf(reply, Math.min(24, reply.length));
                            if (!Arrays.equals(replyId, packet.replyId)) {
                                // новый ответ, а не дубликат: на этот пакет снова можно потратить повторы
                                packet.replyId = replyId;
                                packet.attempts = 0;
                            }
                        }
                        if (channel.queue.size() >= REPLY_QUEUE_SIZE || channel.replyBytes + reply.length > MAX_CHANNEL_BYTES) {
                            throw new IOException("H2 client response queue exceeded bound");
                        }
                        channel.replyBytes += reply.length;
                        channel.queue.addLast(reply);
                        channel.lane.notifyAll();
                    }
                }
            } catch (IOException | RuntimeException e) {
                if (!cancelled) {
                    proxy.stats().h2Errors.incrementAndGet();
                    if (e instanceof TransportError) {
                        ProxyLog.w("[" + channel.label + "] H2 " + channel.lane.host + ": ошибка транспорта " + e.getMessage());
                    } else {
                        ProxyLog.w("[" + channel.label + "] H2 запрос не удался: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                    }
                    channel.fail(e);
                }
            } finally {
                channel.finishRequest(this);
                done.countDown();
            }
        }
    }

    static final class ReplayPacket {
        final long sentAt;
        final byte[] body;
        final int sequence;
        int attempts;
        long lastAttemptAt = NEVER;
        Request pending;
        final Set<Request> originals = new HashSet<>();
        boolean retired;
        byte[] replyId;

        ReplayPacket(long sentAt, byte[] body, int sequence) {
            this.sentAt = sentAt;
            this.body = body;
            this.sequence = sequence;
        }

        boolean replayed() {
            return lastAttemptAt != NEVER || attempts > 0;
        }
    }

    // --- канал: одно соединение клиента

    final class Channel {
        final Lane lane;
        final int id;
        final String label;
        boolean closed;
        Integer transportError;
        final Map<Request, Integer> pending = new LinkedHashMap<>();
        final Map<Request, Long> pendingSince = new HashMap<>();
        final Map<Request, Long> sentSince = new HashMap<>();
        long pendingBytes;
        long replyBytes;
        final ArrayDeque<Object> queue = new ArrayDeque<>();
        boolean recoveryWakeup;
        int requests;
        int replayRequests;
        long up;
        long down;
        final Set<Request> receiving = new HashSet<>();
        Long deliveringSince;
        final Set<Request> replayPending = new HashSet<>();
        final List<ReplayPacket> replayHistory = new ArrayList<>();
        byte[] replayKey;
        int replayRotations;
        int capacityRotations;
        long lastProgress = now();
        long lastNativeSend = lastProgress;
        boolean sendLocked;
        boolean closeDone;
        boolean stopRequested;
        Long uploadWaitSince;
        String uploadWaitPhase = "-";
        int uploadWaitBytes;

        Channel(Lane lane, int id, String label) {
            this.lane = lane;
            this.id = id;
            this.label = label;
            lane.channels.add(this);
        }

        boolean nativeBackpressure() {
            return replyBytes != 0 || deliveringSince != null;
        }

        boolean hasCapacity(int length) {
            return pending.size() < MAX_CHANNEL_REQUESTS && pendingBytes + length <= MAX_CHANNEL_BYTES;
        }

        void wakeReceiver() {
            if (!closed && pending.isEmpty() && !nativeBackpressure()) {
                recoveryWakeup = true;
                lane.notifyAll();
            }
        }

        boolean overdueOriginal(ReplayPacket entry, long time) {
            if (entry.retired) {
                return true;
            }
            for (Request request : entry.originals) {
                Long sent = sentSince.get(request);
                if (sent != null && !receiving.contains(request) && time - sent >= REPLAY_REQUEST_MS) {
                    return true;
                }
            }
            return false;
        }

        int replayLimit(ReplayPacket entry) {
            boolean last = !replayHistory.isEmpty() && entry == replayHistory.get(replayHistory.size() - 1);
            return !entry.originals.isEmpty() || entry.retired || last ? REPLAY_MAX_ATTEMPTS : 0;
        }

        /** Запрос, который можно оборвать ради места: давно отправлен, ответа нет, и пакет можно будет повторить. */
        Map.Entry<Request, ReplayPacket> capacityCandidate(long time) {
            List<Map.Entry<Request, Long>> sorted = new ArrayList<>(sentSince.entrySet());
            Collections.sort(sorted, (a, b) -> {
                boolean replayA = replayPending.contains(a.getKey());
                boolean replayB = replayPending.contains(b.getKey());
                if (replayA != replayB) {
                    return replayA ? -1 : 1;
                }
                int bySent = Long.compare(a.getValue(), b.getValue());
                return bySent != 0 ? bySent : a.getKey().order - b.getKey().order;
            });
            for (Map.Entry<Request, Long> pair : sorted) {
                Request request = pair.getKey();
                if (request.isDone() || receiving.contains(request) || time - pair.getValue() < REPLAY_REQUEST_MS) {
                    continue;
                }
                if (replayPending.contains(request)) {
                    return new java.util.AbstractMap.SimpleEntry<>(request, null);
                }
                for (ReplayPacket entry : replayHistory) {
                    if (entry.originals.contains(request)) {
                        if (time - entry.sentAt <= REPLAY_MAX_AGE_MS) {
                            return new java.util.AbstractMap.SimpleEntry<>(request, entry);
                        }
                        break;
                    }
                }
            }
            return null;
        }

        /** Если отправка упёрлась в лимит, долгие опросы не должны её держать. Возвращает запрос для обрыва. */
        Request pickUploadRoom(long time) {
            if (closed || uploadWaitSince == null) {
                return null;
            }
            List<Channel> channels;
            if ("channel-capacity".equals(uploadWaitPhase)) {
                if (hasCapacity(uploadWaitBytes)) {
                    return null;
                }
                channels = Collections.singletonList(this);
            } else if ("lane-capacity".equals(uploadWaitPhase)) {
                if (lane.hasCapacity(uploadWaitBytes)) {
                    return null;
                }
                channels = new ArrayList<>(lane.channels);
                Collections.sort(channels, Comparator.comparingLong(channel -> {
                    long oldest = time;
                    for (long sent : channel.sentSince.values()) {
                        oldest = Math.min(oldest, sent);
                    }
                    return oldest;
                }));
            } else {
                return null;
            }
            for (Channel channel : channels) {
                Map.Entry<Request, ReplayPacket> candidate = channel.capacityCandidate(time);
                if (candidate == null) {
                    continue;
                }
                channel.sentSince.remove(candidate.getKey());
                if (candidate.getValue() != null) {
                    candidate.getValue().retired = true;
                }
                channel.capacityRotations++;
                lane.capacityRotations++;
                return candidate.getKey();
            }
            return null;
        }

        /** Почему пакет нельзя повторить прямо сейчас, null - можно. */
        String replayBlocker(ReplayPacket entry, long time) {
            long age = time - entry.sentAt;
            if (age < 0 || age > REPLAY_MAX_AGE_MS) {
                return "expired";
            }
            if (entry.attempts >= replayLimit(entry)) {
                return "budget-used";
            }
            if (nativeBackpressure()) {
                return "native-backpressure";
            }
            for (Request request : entry.originals) {
                if (receiving.contains(request)) {
                    return "original-body";
                }
            }
            if (entry.pending != null && receiving.contains(entry.pending)) {
                return "replay-body";
            }
            if (entry.replayed() && entry.lastAttemptAt != NEVER && time - entry.lastAttemptAt < REPLAY_RETRY_MS) {
                return "backoff-or-progress";
            }
            if (overdueOriginal(entry, time)) {
                return null;
            }
            if (entry != replayHistory.get(replayHistory.size() - 1)) {
                return "receiver-active";
            }
            for (Request request : pending.keySet()) {
                if (request != entry.pending) {
                    return "receiver-active";
                }
            }
            if (entry.replayed() && time - lastProgress < REPLAY_IDLE_MS) {
                return "backoff-or-progress";
            }
            return null;
        }

        void fail(Exception error) {
            synchronized (lane) {
                if (closed) {
                    return;
                }
                if (error instanceof TransportError) {
                    transportError = ((TransportError) error).code;
                }
                closed = true;
                recoveryWakeup = true;
                queue.clear();
                replyBytes = 0;
                queue.addLast(error);
                lane.notifyAll();
            }
        }

        private void await(BooleanSupplier condition, long timeoutMs) throws IOException, InterruptedException {
            long deadline = now() + timeoutMs;
            while (!condition.getAsBoolean()) {
                if (stopRequested) {
                    throw new IOException("H2 channel stopped");
                }
                long left = deadline - now();
                if (left <= 0) {
                    throw new IOException("H2 capacity wait timed out");
                }
                lane.wait(left);
            }
        }

        boolean send(byte[] body, boolean quick, boolean replay) throws IOException, InterruptedException {
            synchronized (lane) {
                if (replay && sendLocked) {
                    return false;
                }
                if (!replay) {
                    uploadWaitSince = now();
                    uploadWaitPhase = "send-lock";
                    uploadWaitBytes = body.length;
                }
                try {
                    await(() -> !sendLocked, REQUEST_TIMEOUT_MS);
                    sendLocked = true;
                    try {
                        return sendLocked(body, replay);
                    } finally {
                        sendLocked = false;
                        lane.notifyAll();
                    }
                } finally {
                    if (!replay) {
                        uploadWaitSince = null;
                        uploadWaitPhase = "-";
                        uploadWaitBytes = 0;
                    }
                }
            }
        }

        private boolean sendLocked(byte[] body, boolean replay) throws IOException, InterruptedException {
            int length = body.length;
            if (replay && !hasCapacity(length)) {
                return false;
            }
            if (!replay) {
                uploadWaitPhase = "channel-capacity";
                await(() -> closed || hasCapacity(length), REQUEST_TIMEOUT_MS);
            }
            if (closed) {
                throw new IOException("H2 channel closed");
            }
            if (!replay) {
                uploadWaitPhase = "lane-capacity";
                await(() -> lane.closed || lane.hasCapacity(length), REQUEST_TIMEOUT_MS);
            } else if (!lane.hasCapacity(length)) {
                return false;
            }
            if (lane.closed) {
                throw new IOException("H2 lane closed");
            }
            if (closed) {
                throw new IOException("H2 channel closed");
            }
            long time = now();
            ReplayPacket replayPacket = replay ? findPacket(body) : null;
            if (replay && (replayPacket == null || replayPacket.pending != null || replayBlocker(replayPacket, time) != null)) {
                return false;
            }
            lane.inflight++;
            lane.queuedBytes += length;
            pendingBytes += length;
            requests++;
            if (replay) {
                replayRequests++;
            }
            up += length;
            proxy.stats().bytesUp.addAndGet(length);
            if (!replay) {
                lastNativeSend = time;
            }
            ReplayPacket nativePacket = replay ? null : rememberPacket(body, time);
            Request request = new Request(this, body, replay, replayPacket != null ? replayPacket : nativePacket);
            pending.put(request, length);
            pendingSince.put(request, time);
            if (nativePacket != null) {
                nativePacket.originals.add(request);
                trimHistory(time);
            }
            if (replay) {
                replayPending.add(request);
                replayPacket.attempts++;
                replayPacket.lastAttemptAt = time;
                replayPacket.pending = request;
            }
            try {
                executor().execute(request);
            } catch (RejectedExecutionException stopping) {
                finishRequest(request);
                throw new IOException("H2 pool stopping");
            }
            return true;
        }

        ReplayPacket findPacket(byte[] body) {
            for (ReplayPacket entry : replayHistory) {
                if (Arrays.equals(entry.body, body)) {
                    return entry;
                }
            }
            return null;
        }

        /** Рукопожатие (нулевой auth_key_id) никогда не повторяется: второй раз оно начало бы новый обмен ключами. */
        ReplayPacket rememberPacket(byte[] body, long time) {
            byte[] key = Arrays.copyOf(body, 8);
            if (allZero(key)) {
                return null;
            }
            if (!Arrays.equals(replayKey, key)) {
                replayHistory.clear();
                replayKey = key;
            }
            if (body.length > REPLAY_HISTORY_BYTES) {
                return null;
            }
            ReplayPacket packet = findPacket(body);
            if (packet == null) {
                packet = new ReplayPacket(time, body, requests);
                replayHistory.add(packet);
            }
            return packet;
        }

        void trimHistory(long time) {
            long retained = 0;
            for (ReplayPacket entry : replayHistory) {
                retained += entry.body.length;
            }
            while (replayHistory.size() > REPLAY_HISTORY_PACKETS || retained > REPLAY_HISTORY_BYTES) {
                ReplayPacket victim = replayHistory.get(0);
                for (ReplayPacket entry : replayHistory) {
                    boolean protectedRetired = entry.retired && entry.attempts < REPLAY_MAX_ATTEMPTS
                            && time - entry.sentAt <= REPLAY_MAX_AGE_MS;
                    if (entry.originals.isEmpty() && !protectedRetired) {
                        victim = entry;
                        break;
                    }
                }
                replayHistory.remove(victim);
                retained -= victim.body.length;
            }
        }

        void finishRequest(Request request) {
            synchronized (lane) {
                Integer length = pending.remove(request);
                if (length == null) {
                    return;
                }
                pendingBytes -= length;
                pendingSince.remove(request);
                sentSince.remove(request);
                replayPending.remove(request);
                receiving.remove(request);
                ReplayPacket packet = request.packet;
                if (packet == null) {
                    for (ReplayPacket entry : replayHistory) {
                        if (entry.originals.contains(request) || entry.pending == request) {
                            packet = entry;
                            break;
                        }
                    }
                }
                if (packet != null) {
                    packet.originals.remove(request);
                    if (packet.pending == request) {
                        packet.pending = null;
                    }
                }
                lane.inflight--;
                lane.queuedBytes -= length;
                lane.notifyAll();
                wakeReceiver();
            }
        }

        void recover() throws InterruptedException {
            while (true) {
                Request toCancel;
                byte[] toSend = null;
                synchronized (lane) {
                    if (closed || stopRequested) {
                        return;
                    }
                    if (!recoveryWakeup) {
                        lane.wait(REPLAY_CHECK_MS);
                    }
                    recoveryWakeup = false;
                    if (closed || stopRequested) {
                        return;
                    }
                    long time = now();
                    toCancel = pickUploadRoom(time);
                }
                if (toCancel != null) {
                    toCancel.cancelAndWait();
                    continue;
                }
                synchronized (lane) {
                    if (closed || stopRequested) {
                        return;
                    }
                    if (nativeBackpressure()) {
                        continue;
                    }
                    long time = now();
                    List<ReplayPacket> candidates = new ArrayList<>(replayHistory);
                    Collections.sort(candidates, (a, b) -> {
                        boolean overdueA = overdueOriginal(a, time);
                        boolean overdueB = overdueOriginal(b, time);
                        if (overdueA != overdueB) {
                            return overdueA ? -1 : 1;
                        }
                        return overdueA ? a.sequence - b.sequence : b.sequence - a.sequence;
                    });
                    for (ReplayPacket entry : candidates) {
                        if (replayBlocker(entry, time) != null) {
                            continue;
                        }
                        Request replace = entry.pending;
                        if (replace == null && replayPending.size() >= MAX_CHANNEL_REPLAYS) {
                            for (Request request : pending.keySet()) {
                                if (replayPending.contains(request) && !receiving.contains(request)) {
                                    replace = request;
                                    break;
                                }
                            }
                            if (replace == null) {
                                continue;
                            }
                        }
                        if (replace != null) {
                            Long sent = sentSince.get(replace);
                            if (receiving.contains(replace) || sent == null || time - sent < REPLAY_SLOT_MS) {
                                continue;
                            }
                            replayRotations++;
                            toCancel = replace;
                        }
                        toSend = entry.body;
                        break;
                    }
                }
                if (toCancel != null) {
                    toCancel.cancelAndWait();
                }
                if (toSend != null) {
                    try {
                        send(toSend, false, true);
                    } catch (IOException e) {
                        return;
                    }
                }
            }
        }

        byte[] receive() throws IOException, InterruptedException {
            synchronized (lane) {
                while (queue.isEmpty()) {
                    if (stopRequested) {
                        throw new IOException("H2 channel stopped");
                    }
                    lane.wait();
                }
                Object value = queue.pollFirst();
                if (value instanceof Exception) {
                    throw value instanceof IOException ? (IOException) value : new IOException((Exception) value);
                }
                byte[] reply = (byte[]) value;
                replyBytes -= reply.length;
                wakeReceiver();
                return reply;
            }
        }

        void requestStop() {
            synchronized (lane) {
                stopRequested = true;
                lane.notifyAll();
            }
        }

        void close() throws InterruptedException {
            List<Request> requests;
            synchronized (lane) {
                if (closeDone) {
                    return;
                }
                closeDone = true;
                fail(new IOException("H2 channel closed"));
                closed = true;
                stopRequested = true;
                lane.notifyAll();
                requests = new ArrayList<>(pending.keySet());
            }
            for (Request request : requests) {
                request.cancelAndWait();
            }
            synchronized (lane) {
                replayPending.clear();
                replayHistory.clear();
                sentSince.clear();
                lane.channels.remove(this);
            }
        }
    }

    // --- линия: соединение HTTP/2 с одним доменом

    final class Lane {
        final String host;
        final int id;
        Transport transport;
        final Set<Channel> channels = new HashSet<>();
        volatile long failedUntil = NEVER;
        boolean closed;
        int inflight;
        long queuedBytes;
        long replyBufferBytes;
        int capacityRotations;

        Lane(String host, int id) {
            this.host = host;
            this.id = id;
        }

        boolean hasCapacity(int length) {
            return inflight < MAX_LANE_REQUESTS && queuedBytes + length <= MAX_LANE_BYTES;
        }

        void reserveReplyBuffer(int length) throws ReplyBufferFull {
            synchronized (this) {
                if (replyBufferBytes + length > MAX_LANE_REPLY_BYTES) {
                    throw new ReplyBufferFull("H2 lane response buffers exceeded bound");
                }
                replyBufferBytes += length;
            }
        }

        void releaseReplyBuffer(long length) {
            synchronized (this) {
                replyBufferBytes -= length;
            }
        }

        byte[] post(Request request) throws IOException {
            proxy.stats().h2Requests.incrementAndGet();
            try {
                return transport.post(request.body, request);
            } catch (TransportError | ReplyBufferFull e) {
                throw e;
            } catch (IOException | RuntimeException e) {
                if (!request.isCancelled()) {
                    // отмена не значит, что домен плох: клиент мог просто уйти
                    failedUntil = now() + DOMAIN_COOLDOWN_MS;
                }
                throw e;
            }
        }

        void close() throws InterruptedException {
            List<Channel> all;
            synchronized (this) {
                closed = true;
                notifyAll();
                all = new ArrayList<>(channels);
            }
            for (Channel channel : all) {
                channel.close();
            }
            transport.close();
        }
    }

    // --- пул

    /** Как создавать транспорт для домена. В проверках подменяется на транспорт без сети. */
    interface TransportFactory {
        Transport create(String host, Lane lane);
    }

    private final TgWsProxy proxy;
    private final TransportFactory transports;
    private final ExecutorService ownExecutor;
    private final Map<String, Lane> lanes = new ConcurrentHashMap<>();
    private final Map<String, Object> locks = new ConcurrentHashMap<>();
    private final Map<String, Long> failedUntil = new ConcurrentHashMap<>();
    private final Map<Integer, Long> setupRetryAfter = new ConcurrentHashMap<>();
    private int nextLane;
    private int nextChannel;
    private volatile boolean closed;

    CfH2Pool(TgWsProxy proxy) {
        this(proxy, (host, lane) -> new H2OkHttpTransport(host, lane), null);
    }

    CfH2Pool(TgWsProxy proxy, TransportFactory transports, ExecutorService executor) {
        this.proxy = proxy;
        this.transports = transports;
        this.ownExecutor = executor;
    }

    private ExecutorService executor() {
        return ownExecutor != null ? ownExecutor : proxy.executor();
    }

    /** Канал или null: тогда соединение пойдёт обычным WebSocket через Cloudflare. */
    Channel open(int dc, String label) throws IOException, InterruptedException {
        if (closed) {
            throw new IOException("H2 pool closed");
        }
        Long retryAfter = setupRetryAfter.get(dc);
        if (retryAfter != null && now() < retryAfter) {
            return null;
        }
        Future<Channel> future = executor().submit(() -> openBlocking(dc, label));
        try {
            return future.get(SETUP_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            setupRetryAfter.put(dc, now() + DOMAIN_COOLDOWN_MS);
            proxy.stats().h2Errors.incrementAndGet();
            ProxyLog.w("[" + label + "] H2 DC" + dc + ": настройка заняла слишком долго, на 30 с используется WebSocket");
            return null;
        } catch (ExecutionException e) {
            throw new IOException(e.getCause());
        }
    }

    private Channel openBlocking(int dc, String label) throws IOException, InterruptedException {
        if (!Mtproto.DC_DEFAULT_IPS.containsKey(dc)) {
            return null;
        }
        for (String base : proxy.cfDomains().forDc(dc)) {
            String host = "kws" + dc + "." + base;
            Object lock = locks.get(host);
            if (lock == null) {
                locks.putIfAbsent(host, new Object());
                lock = locks.get(host);
            }
            synchronized (lock) {
                if (closed) {
                    throw new IOException("H2 pool closed");
                }
                Lane lane = lanes.get(host);
                Long hostFailed = failedUntil.get(host);
                long failed = Math.max(hostFailed != null ? hostFailed : NEVER, lane != null ? lane.failedUntil : NEVER);
                if (now() < failed) {
                    continue;
                }
                if (lane == null) {
                    int laneId;
                    synchronized (this) {
                        laneId = ++nextLane;
                    }
                    lane = new Lane(host, laneId);
                    lane.transport = transports.create(host, lane);
                    try {
                        lane.transport.preflight();
                    } catch (IOException | RuntimeException e) {
                        proxy.stats().h2Errors.incrementAndGet();
                        failedUntil.put(host, now() + DOMAIN_COOLDOWN_MS);
                        ProxyLog.w("[" + label + "] H2: домен не прошёл проверку: " + e.getClass().getSimpleName());
                        ProxyLog.d("H2 preflight " + host + ": " + e);
                        lane.close();
                        continue;
                    }
                    if (closed) {
                        lane.close();
                        throw new IOException("H2 pool closed during preflight");
                    }
                    lanes.put(host, lane);
                }
                int channelId;
                synchronized (this) {
                    channelId = ++nextChannel;
                }
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException();
                }
                Channel channel;
                synchronized (lane) {
                    if (lane.closed) {
                        continue;
                    }
                    channel = new Channel(lane, channelId, label);
                }
                proxy.cfDomains().setDomainForDc(dc, base);
                ProxyLog.i("[" + label + "] DC" + dc + " media -> HTTP/2, линия " + lane.id + ", канал " + channelId);
                return channel;
            }
        }
        return null;
    }

    /** Передаёт данные клиента через канал, пока одна из сторон не закончит. */
    void bridge(Socket client, InputStream in, OutputStream out, Channel channel, Mtproto.CryptoCtx ctx, byte[] tag)
            throws InterruptedException {
        DataInputStream input = new DataInputStream(in);
        CountDownLatch first = new CountDownLatch(1);
        CountDownLatch all = new CountDownLatch(3);
        CountDownLatch downloadDone = new CountDownLatch(1);

        Runnable upload = () -> {
            try {
                while (true) {
                    Packet packet = readPacket(input, ctx.cltDec, tag);
                    channel.send(packet.body, packet.quick, false);
                }
            } catch (EOFException e) {
                ProxyLog.d("[" + channel.label + "] H2 native EOF");
            } catch (IOException | RuntimeException e) {
                synchronized (channel.lane) {
                    if (!channel.closed && !channel.stopRequested) {
                        ProxyLog.w("[" + channel.label + "] H2 передача прервана: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                first.countDown();
                all.countDown();
            }
        };
        Runnable download = () -> {
            try {
                while (true) {
                    byte[] body = channel.receive();
                    synchronized (channel.lane) {
                        if (channel.closed) {
                            return;
                        }
                        channel.deliveringSince = now();
                    }
                    try {
                        out.write(ctx.cltEnc.update(encodeReply(body, tag)));
                        out.flush();
                    } finally {
                        synchronized (channel.lane) {
                            channel.deliveringSince = null;
                        }
                    }
                    proxy.stats().bytesDown.addAndGet(body.length);
                    synchronized (channel.lane) {
                        channel.down += body.length;
                        channel.lastProgress = now();
                        channel.wakeReceiver();
                    }
                }
            } catch (IOException | RuntimeException e) {
                ProxyLog.d("[" + channel.label + "] H2 download ended: " + e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                downloadDone.countDown();
                first.countDown();
                all.countDown();
            }
        };
        Runnable recover = () -> {
            try {
                channel.recover();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                first.countDown();
                all.countDown();
            }
        };
        executor().execute(upload);
        executor().execute(download);
        executor().execute(recover);
        first.await();

        channel.requestStop();
        try {
            // чтение из сокета нельзя прервать иначе, но писать клиенту ещё может понадобиться
            client.shutdownInput();
        } catch (IOException ignored) {
            // клиент уже ушёл
        }
        if (downloadDone.await(2, TimeUnit.SECONDS)) {
            Integer error;
            synchronized (channel.lane) {
                error = channel.transportError;
            }
            if (error != null) {
                try {
                    byte[] body = {(byte) (int) error, (byte) (error >> 8), (byte) (error >> 16), (byte) (error >> 24)};
                    out.write(ctx.cltEnc.update(encodeReply(body, tag)));
                    out.flush();
                    proxy.stats().bytesDown.addAndGet(4);
                } catch (IOException ignored) {
                    // клиент уже ушёл
                }
            }
        }
        channel.close();
        Dialer.closeQuietly(client);
        all.await(5, TimeUnit.SECONDS);
    }

    /** Сеть сменилась: линии через старую сеть мертвы, а прошлые неудачи доменов ничего не значат. */
    void resetLanes() {
        List<Lane> old = new ArrayList<>(lanes.values());
        lanes.clear();
        failedUntil.clear();
        for (Lane lane : old) {
            try {
                lane.close();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    void close() {
        closed = true;
        for (Lane lane : lanes.values()) {
            try {
                lane.close();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        lanes.clear();
    }

    /** Для проверок: линия с заданным транспортом и новый канал на ней. */
    Channel channelForTest(Transport transport, String label) {
        Lane lane = new Lane("test", 1);
        lane.transport = transport;
        synchronized (lane) {
            return new Channel(lane, 1, label);
        }
    }
}
