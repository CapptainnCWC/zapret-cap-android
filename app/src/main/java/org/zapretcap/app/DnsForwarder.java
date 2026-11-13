package org.zapretcap.app;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadLocalRandom;

import javax.net.ssl.HttpsURLConnection;

/**
 * Локальный DNS режима VPN. Движок отправляет сюда все запросы приложений на порт 53, а этот класс опрашивает
 * настоящие серверы и отдаёт лучший ответ. Само приложение исключено из VPN, поэтому запросы идут по настоящей сети.
 *
 * Зачем он нужен. Обычный DNS по UDP провайдер подделывает: на www.youtube.com от имени 1.1.1.1 приходит
 * «такого домена нет». А когда оператор включает белые списки, 1.1.1.1 и 8.8.8.8 недоступны вовсе, и браузер не
 * может найти ни один сайт, даже разрешённый. Поэтому основной путь здесь зашифрованный (DoH), его не подделать,
 * а запасной идёт через DNS Яндекса и DNS самой сети, которые работают и в режиме белых списков. Победителем
 * считается ответ с адресами: пустой ответ и «домена нет» могут оказаться подделкой.
 */
final class DnsForwarder {
    private static final String TAG = "ZapretCap";
    private static final String[] DOH_URLS = {"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"};
    private static final String[] UDP_SERVERS = {"77.88.8.8", "77.88.8.1", "1.1.1.1", "8.8.8.8"};
    /** Сколько ждать ответа от предыдущих серверов, прежде чем спросить следующий. */
    private static final int STEP_MS = 250;
    private static final int TOTAL_MS = 3500;
    /** Пустой ответ может быть подделкой: даём другим серверам время ответить адресами. */
    private static final int EMPTY_GRACE_MS = 700;
    private static final int MAX_PACKET = 4096;
    private static final int CACHE_SIZE = 512;
    private static final int RCODE_NXDOMAIN = 3;
    /** На всплеск запросов при открытии страницы хватит запасных серверов: десятки рукопожатий TLS только тормозили бы. */
    private static final Semaphore DOH_SLOTS = new Semaphore(4);

    /** Откуда можно получить ответ. */
    private interface Upstream {
        byte[] ask(byte[] query, int timeoutMs) throws IOException;
    }

    private final Map<String, Cached> cache = Collections.synchronizedMap(
            new LinkedHashMap<String, Cached>(CACHE_SIZE, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Cached> eldest) {
                    return size() > CACHE_SIZE;
                }
            });
    private final ExecutorService pool = Executors.newCachedThreadPool();
    private final List<Upstream> fixedUpstreams = new ArrayList<>();
    private volatile List<Upstream> networkUpstreams = Collections.emptyList();
    /** Записи hosts: имя - адреса. Пусто, если подмена выключена. */
    private volatile Map<String, List<InetAddress>> hosts = Collections.emptyMap();
    /** Кто ответил адресами последним. С него начинаем: в белом списке иначе каждый запрос ждал бы недоступный DoH. */
    private volatile Upstream preferred;
    private volatile boolean running;
    private DatagramSocket socket;

    DnsForwarder() {
        for (String url : DOH_URLS) {
            fixedUpstreams.add((query, timeout) -> askDoh(url, query, timeout));
        }
        for (String server : UDP_SERVERS) {
            fixedUpstreams.add((query, timeout) -> askUdp(InetAddress.getByName(server), query, timeout));
        }
    }

    private static final class Cached {
        final byte[] answer;
        final long expires;

        Cached(byte[] answer, long expires) {
            this.answer = answer;
            this.expires = expires;
        }
    }

    /** Запускает на свободном порту 127.0.0.1 и возвращает порт. */
    int start() throws IOException {
        socket = new DatagramSocket(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), 0));
        running = true;
        Thread thread = new Thread(this::serve, "dns-forwarder");
        thread.setDaemon(true);
        thread.start();
        return socket.getLocalPort();
    }

    void stop() {
        running = false;
        if (socket != null) {
            socket.close();
        }
        pool.shutdownNow();
    }

    /** DNS самой сети: в режиме белых списков он почти всегда работает, поэтому служит последней надеждой. */
    /**
     * Как Update Hosts File в Windows-версии, только без записи в системный файл: на такие имена отвечаем сами.
     */
    void setHosts(Map<String, List<InetAddress>> entries) {
        hosts = entries;
    }

    void setNetworkServers(List<InetAddress> servers) {
        List<Upstream> upstreams = new ArrayList<>();
        for (InetAddress server : servers) {
            upstreams.add((query, timeout) -> askUdp(server, query, timeout));
        }
        networkUpstreams = upstreams;
    }

    /** При смене сети прежние ответы и лучший сервер могут не подходить. */
    void onNetworkChanged() {
        cache.clear();
        preferred = null;
    }

    /**
     * Первый запрос в процессе долгий: загружается TLS, выясняется, какой сервер вообще отвечает в этой сети. Если
     * делать это до поднятия туннеля, приложения сразу после включения не останутся без DNS на несколько секунд.
     */
    void warmUp() {
        try {
            lookupIpv4("www.gstatic.com");
        } catch (IOException | RuntimeException e) {
            Log.w(TAG, "dns warm up", e);
        }
    }

    /** Первый адрес IPv4 для имени: так подбор конфига находит сайты тем же путём, что и приложения через VPN. */
    InetAddress lookupIpv4(String host) throws IOException {
        byte[] reply = resolve(buildQuery(host));
        return reply == null ? null : firstIpv4(reply);
    }

    private void serve() {
        byte[] buffer = new byte[MAX_PACKET];
        while (running) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(packet);
                byte[] query = Arrays.copyOf(packet.getData(), packet.getLength());
                InetAddress clientAddress = packet.getAddress();
                int clientPort = packet.getPort();
                pool.execute(() -> answer(query, clientAddress, clientPort));
            } catch (RejectedExecutionException | SocketException stopped) {
                return;
            } catch (IOException e) {
                Log.w(TAG, "dns receive", e);
            }
        }
    }

    private void answer(byte[] query, InetAddress clientAddress, int clientPort) {
        if (query.length < 12) {
            return;
        }
        String key = questionKey(query);
        Cached cached = key == null ? null : cache.get(key);
        byte[] reply = fromHosts(query);
        if (reply != null) {
            // ответ из hosts, серверы не спрашиваем
        } else if (cached != null && cached.expires > System.currentTimeMillis()) {
            reply = withId(cached.answer, query);
        } else {
            reply = resolve(query);
            if (reply != null && key != null) {
                int ttl = minTtl(reply);
                if (ttl > 0) {
                    cache.put(key, new Cached(reply, System.currentTimeMillis() + ttl * 1000L));
                }
            } else if (reply == null && cached != null) {
                // ни один сервер не ответил: старый адрес лучше, чем отсутствие ответа
                reply = withId(cached.answer, query);
            }
        }
        if (reply == null) {
            reply = servfail(query);
        }
        PushLog.onDnsReply(reply);
        try {
            socket.send(new DatagramPacket(reply, reply.length, clientAddress, clientPort));
        } catch (IOException e) {
            if (running) {
                Log.w(TAG, "dns send", e);
            }
        }
    }

    private byte[] resolve(byte[] query) {
        List<Upstream> upstreams = new ArrayList<>(fixedUpstreams);
        upstreams.addAll(networkUpstreams);
        Upstream first = preferred;
        if (first != null && upstreams.remove(first)) {
            upstreams.add(0, first);
        }

        Race race = new Race();
        long deadline = System.currentTimeMillis() + TOTAL_MS;
        int sent = 0;
        long graceUntil = Long.MAX_VALUE;
        synchronized (race) {
            while (true) {
                long now = System.currentTimeMillis();
                if (race.haveAddresses || now >= deadline || now >= graceUntil) {
                    break;
                }
                if (sent < upstreams.size()) {
                    Upstream upstream = upstreams.get(sent++);
                    try {
                        pool.execute(() -> run(upstream, query, deadline, race));
                    } catch (RejectedExecutionException stopped) {
                        return null;
                    }
                } else if (race.finished >= sent) {
                    break;
                }
                if (race.best != null && graceUntil == Long.MAX_VALUE) {
                    graceUntil = now + EMPTY_GRACE_MS;
                }
                long wait = deadline - now;
                if (sent < upstreams.size()) {
                    wait = Math.min(wait, STEP_MS);
                }
                if (graceUntil != Long.MAX_VALUE) {
                    wait = Math.min(wait, graceUntil - now);
                }
                try {
                    race.wait(Math.max(1, wait));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
            if (race.haveAddresses) {
                preferred = race.winner;
            }
            return race.best;
        }
    }

    private static final class Race {
        byte[] best;
        boolean haveAddresses;
        Upstream winner;
        int finished;
    }

    private static void run(Upstream upstream, byte[] query, long deadline, Race race) {
        byte[] reply = null;
        try {
            int left = (int) (deadline - System.currentTimeMillis());
            if (left > 0) {
                reply = upstream.ask(query, left);
            }
        } catch (IOException | RuntimeException unreachable) {
            // сервер недоступен: ответят другие
        }
        synchronized (race) {
            race.finished++;
            if (reply != null && reply.length >= 12 && reply[0] == query[0] && reply[1] == query[1]) {
                if (hasAnswers(reply)) {
                    if (!race.haveAddresses) {
                        race.best = reply;
                        race.haveAddresses = true;
                        race.winner = upstream;
                    }
                } else if (!race.haveAddresses && (race.best == null || rcode(race.best) == RCODE_NXDOMAIN)) {
                    // «домена нет» уступает любому другому ответу: его подделывают чаще всего
                    race.best = reply;
                }
            }
            race.notifyAll();
        }
    }

    private static byte[] askUdp(InetAddress server, byte[] query, int timeoutMs) throws IOException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        try (DatagramSocket upstream = new DatagramSocket()) {
            upstream.connect(server, 53);
            upstream.send(new DatagramPacket(query, query.length));
            byte[] buffer = new byte[MAX_PACKET];
            while (true) {
                int left = (int) (deadline - System.currentTimeMillis());
                if (left <= 0) {
                    return null;
                }
                upstream.setSoTimeout(left);
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                try {
                    upstream.receive(packet);
                } catch (SocketTimeoutException timeout) {
                    return null;
                }
                // ответ с чужим номером не наш
                if (packet.getLength() >= 12 && buffer[0] == query[0] && buffer[1] == query[1]) {
                    return Arrays.copyOf(buffer, packet.getLength());
                }
            }
        }
    }

    /** DoH по адресу, а не по имени: иначе для него самого понадобился бы DNS. */
    private static byte[] askDoh(String url, byte[] query, int timeoutMs) throws IOException {
        if (!DOH_SLOTS.tryAcquire()) {
            return null;
        }
        try {
            return requestDoh(url, query, timeoutMs);
        } finally {
            DOH_SLOTS.release();
        }
    }

    private static byte[] requestDoh(String url, byte[] query, int timeoutMs) throws IOException {
        HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
        connection.setConnectTimeout(timeoutMs);
        connection.setReadTimeout(timeoutMs);
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/dns-message");
        connection.setRequestProperty("Accept", "application/dns-message");
        // В DoH номер запроса должен быть нулевым, чтобы ответы кэшировались, поэтому меняем его туда и обратно
        byte[] body = query.clone();
        body[0] = 0;
        body[1] = 0;
        connection.setFixedLengthStreamingMode(body.length);
        try (OutputStream out = connection.getOutputStream()) {
            out.write(body);
        }
        if (connection.getResponseCode() != 200) {
            connection.disconnect();
            return null;
        }
        // ответ читается до конца: тогда система оставит соединение открытым и следующий запрос будет быстрым
        ByteArrayOutputStream reply = new ByteArrayOutputStream();
        byte[] buffer = new byte[MAX_PACKET];
        try (InputStream in = connection.getInputStream()) {
            int n;
            while ((n = in.read(buffer)) >= 0) {
                reply.write(buffer, 0, n);
            }
        }
        byte[] answer = reply.toByteArray();
        if (answer.length < 12) {
            return null;
        }
        answer[0] = query[0];
        answer[1] = query[1];
        return answer;
    }

    static byte[] buildQuery(String host) throws IOException {
        ByteArrayOutputStream packet = new ByteArrayOutputStream();
        int id = ThreadLocalRandom.current().nextInt(65536);
        packet.write(id >> 8);
        packet.write(id);
        packet.write(new byte[]{1, 0, 0, 1, 0, 0, 0, 0, 0, 0});
        for (String label : host.split("\\.")) {
            packet.write(label.length());
            packet.write(label.getBytes(StandardCharsets.US_ASCII));
        }
        packet.write(new byte[]{0, 0, 1, 0, 1});
        return packet.toByteArray();
    }

    static InetAddress firstIpv4(byte[] packet) throws IOException {
        if (!hasAnswers(packet)) {
            return null;
        }
        int answers = (packet[6] & 0xff) << 8 | packet[7] & 0xff;
        int offset = skipName(packet, 12);
        if (offset < 0) {
            return null;
        }
        offset += 4;
        for (int i = 0; i < answers; i++) {
            offset = skipName(packet, offset);
            if (offset < 0 || offset + 10 > packet.length) {
                return null;
            }
            int type = (packet[offset] & 0xff) << 8 | packet[offset + 1] & 0xff;
            int size = (packet[offset + 8] & 0xff) << 8 | packet[offset + 9] & 0xff;
            offset += 10;
            if (type == 1 && size == 4 && offset + 4 <= packet.length) {
                return InetAddress.getByAddress(Arrays.copyOfRange(packet, offset, offset + 4));
            }
            offset += size;
        }
        return null;
    }

    /** Ответ из hosts на запрос A или AAAA. Если для имени есть адреса только другого вида, ответ пустой, как у системы. */
    private byte[] fromHosts(byte[] query) {
        Map<String, List<InetAddress>> entries = hosts;
        if (entries.isEmpty() || ((query[4] & 0xff) << 8 | query[5] & 0xff) != 1) {
            return null;
        }
        StringBuilder name = new StringBuilder();
        int offset = 12;
        while (offset < query.length) {
            int length = query[offset] & 0xff;
            if (length == 0 || (length & 0xC0) != 0 || offset + 1 + length > query.length) {
                break;
            }
            if (name.length() > 0) {
                name.append('.');
            }
            for (int i = 0; i < length; i++) {
                char c = (char) (query[offset + 1 + i] & 0xff);
                name.append(c >= 'A' && c <= 'Z' ? (char) (c + 32) : c);
            }
            offset += length + 1;
        }
        if (offset + 5 > query.length || query[offset] != 0) {
            return null;
        }
        List<InetAddress> addresses = entries.get(name.toString());
        if (addresses == null) {
            return null;
        }
        int type = (query[offset + 1] & 0xff) << 8 | query[offset + 2] & 0xff;
        int questionEnd = offset + 5;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(query, 0, 2);
        out.write(0x81);
        out.write(0x80);
        out.write(0);
        out.write(1);
        List<byte[]> answers = new ArrayList<>();
        for (InetAddress address : addresses) {
            byte[] raw = address.getAddress();
            if ((type == 1 && raw.length == 4) || (type == 28 && raw.length == 16)) {
                answers.add(raw);
            }
        }
        out.write(answers.size() >> 8);
        out.write(answers.size());
        out.write(new byte[4], 0, 4);
        out.write(query, 12, questionEnd - 12);
        for (byte[] raw : answers) {
            // имя - ссылка на вопрос, TTL 5 минут
            out.write(new byte[]{(byte) 0xC0, 12, 0, (byte) type, 0, 1, 0, 0, 1, 0x2C, 0, (byte) raw.length}, 0, 12);
            out.write(raw, 0, raw.length);
        }
        return out.toByteArray();
    }

    static int rcode(byte[] packet) {
        return packet[3] & 0x0f;
    }

    static boolean hasAnswers(byte[] packet) {
        return rcode(packet) == 0 && ((packet[6] & 0xff) << 8 | packet[7] & 0xff) > 0;
    }

    /** Имя, тип и класс вопроса: по ним ищем в кэше. Запрос без единственного вопроса не кэшируем. */
    static String questionKey(byte[] query) {
        if (((query[4] & 0xff) << 8 | query[5] & 0xff) != 1) {
            return null;
        }
        int end = skipName(query, 12);
        if (end < 0 || end + 4 > query.length) {
            return null;
        }
        StringBuilder key = new StringBuilder();
        for (int i = 12; i < end + 4; i++) {
            int value = query[i] & 0xff;
            // регистр в имени не важен: некоторые клиенты меняют его намеренно
            key.append((char) (value >= 'A' && value <= 'Z' ? value + 32 : value));
        }
        return key.toString();
    }

    private static int skipName(byte[] packet, int offset) {
        while (offset < packet.length) {
            int length = packet[offset] & 0xff;
            if (length == 0) {
                return offset + 1;
            }
            if ((length & 0xC0) == 0xC0) {
                return offset + 2;
            }
            offset += length + 1;
        }
        return -1;
    }

    /** Наименьший TTL записей ответа. 0 значит не кэшировать: пустые ответы и ошибки могут быть временными. */
    static int minTtl(byte[] packet) {
        if (!hasAnswers(packet)) {
            return 0;
        }
        int questions = (packet[4] & 0xff) << 8 | packet[5] & 0xff;
        int answers = (packet[6] & 0xff) << 8 | packet[7] & 0xff;
        int offset = 12;
        for (int i = 0; i < questions; i++) {
            offset = skipName(packet, offset);
            if (offset < 0) {
                return 0;
            }
            offset += 4;
        }
        long min = Long.MAX_VALUE;
        for (int i = 0; i < answers; i++) {
            offset = skipName(packet, offset);
            if (offset < 0 || offset + 10 > packet.length) {
                return 0;
            }
            long ttl = (packet[offset + 4] & 0xffL) << 24 | (packet[offset + 5] & 0xffL) << 16
                    | (packet[offset + 6] & 0xffL) << 8 | packet[offset + 7] & 0xffL;
            min = Math.min(min, ttl);
            offset += 10 + ((packet[offset + 8] & 0xff) << 8 | packet[offset + 9] & 0xff);
        }
        return min == Long.MAX_VALUE ? 0 : (int) Math.min(min, 3600);
    }

    private static byte[] withId(byte[] reply, byte[] query) {
        byte[] copy = reply.clone();
        copy[0] = query[0];
        copy[1] = query[1];
        return copy;
    }

    /** Ответ об ошибке сразу: иначе приложение ждало бы секунды и повторяло запрос. */
    static byte[] servfail(byte[] query) {
        byte[] reply = query.clone();
        reply[2] = (byte) 0x81;
        reply[3] = (byte) 0x82;
        return reply;
    }
}
