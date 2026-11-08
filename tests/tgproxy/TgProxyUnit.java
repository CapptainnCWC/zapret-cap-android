package org.zapretcap.tgproxy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Проверки без сети: повторяют ожидания из тестов tg-ws-proxy (test_bridge.py, test_cf_h2.py, test_config.py). */
public final class TgProxyUnit {
    private static int passed;
    private static int failed;

    interface Body {
        void run() throws Exception;
    }

    private static void test(String name, Body body) {
        try {
            body.run();
            passed++;
            System.out.println("  ok    " + name);
        } catch (Throwable e) {
            failed++;
            System.out.println("  FAIL  " + name + ": " + e);
        }
    }

    private static void check(boolean condition, String what) {
        if (!condition) {
            throw new AssertionError(what);
        }
    }

    private static void eq(Object expected, Object actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("expected " + expected + ", got " + actual);
        }
    }

    private static byte[] fill(char c, int n) {
        byte[] out = new byte[n];
        Arrays.fill(out, (byte) c);
        return out;
    }

    private static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    private static byte[] le32(long value) {
        return new byte[]{(byte) value, (byte) (value >> 8), (byte) (value >> 16), (byte) (value >> 24)};
    }

    private static byte[] abridged(byte[] body) {
        int words = body.length / 4;
        return words < 0x7f ? cat(new byte[]{(byte) words}, body)
                : cat(new byte[]{0x7f, (byte) words, (byte) (words >> 8), (byte) (words >> 16)}, body);
    }

    private static byte[] intermediate(byte[] body) {
        return cat(le32(body.length), body);
    }

    // для разделения поток может быть любым, важны длины: шифр здесь не нужен
    private static List<byte[]> splitAll(byte[] tag, byte[] stream, int... sizes) {
        MsgSplitter splitter = new MsgSplitter(tag);
        List<byte[]> parts = new ArrayList<>();
        int offset = 0;
        for (int size : sizes) {
            byte[] chunk = Arrays.copyOfRange(stream, offset, offset + size);
            parts.addAll(splitter.split(chunk, chunk));
            offset += size;
        }
        if (offset < stream.length) {
            byte[] chunk = Arrays.copyOfRange(stream, offset, stream.length);
            parts.addAll(splitter.split(chunk, chunk));
        }
        return parts;
    }

    private static List<Integer> lengths(List<byte[]> parts) {
        List<Integer> out = new ArrayList<>();
        for (byte[] part : parts) {
            out.add(part.length);
        }
        return out;
    }

    private static void splitterTests() {
        test("abridged: поток делится на пакеты", () -> {
            byte[] stream = cat(abridged(fill('a', 4)), abridged(fill('b', 16)), abridged(fill('c', 40)));
            eq(Arrays.asList(5, 17, 41), lengths(splitAll(Mtproto.TAG_ABRIDGED, stream)));
        });
        test("intermediate: поток делится на пакеты", () -> {
            byte[] stream = cat(intermediate(fill('a', 8)), intermediate(fill('b', 12)));
            eq(Arrays.asList(12, 16), lengths(splitAll(Mtproto.TAG_INTERMEDIATE, stream)));
        });
        test("padded intermediate разбирается как intermediate", () -> {
            byte[] stream = intermediate(fill('z', 20));
            eq(Collections.singletonList(24), lengths(splitAll(Mtproto.TAG_SECURE, stream)));
        });
        test("неполный пакет ждёт продолжения", () -> {
            byte[] packet = intermediate(fill('a', 40));
            MsgSplitter splitter = new MsgSplitter(Mtproto.TAG_INTERMEDIATE);
            byte[] first = Arrays.copyOf(packet, 10);
            byte[] second = Arrays.copyOfRange(packet, 10, packet.length);
            eq(0, splitter.split(first, first).size());
            eq(Collections.singletonList(44), lengths(splitter.split(second, second)));
        });
        test("произвольная нарезка не меняет поток", () -> {
            byte[] stream = cat(abridged(fill('a', 508 * 4)), abridged(fill('b', 4)), abridged(fill('c', 40)));
            List<byte[]> parts = splitAll(Mtproto.TAG_ABRIDGED, stream, 1, 2, 3, 700, 11);
            check(Arrays.equals(stream, cat(parts.toArray(new byte[0][]))), "поток изменился");
            eq(3, parts.size());
        });
        test("пустой кусок ничего не даёт", () -> eq(0,
                new MsgSplitter(Mtproto.TAG_INTERMEDIATE).split(new byte[0], new byte[0]).size()));
        test("нулевая длина отключает разделение", () -> {
            MsgSplitter splitter = new MsgSplitter(Mtproto.TAG_INTERMEDIATE);
            byte[] zero = cat(le32(0), fill('x', 8));
            eq(Collections.singletonList(12), lengths(splitter.split(zero, zero)));
            byte[] next = fill('y', 5);
            eq(Collections.singletonList(5), lengths(splitter.split(next, next)));
        });
        test("flush отдаёт хвост один раз", () -> {
            MsgSplitter splitter = new MsgSplitter(Mtproto.TAG_INTERMEDIATE);
            byte[] part = Arrays.copyOf(intermediate(fill('a', 40)), 7);
            splitter.split(part, part);
            eq(1, splitter.flush().size());
            eq(0, splitter.flush().size());
        });
        test("длинный заголовок и quick ack на границе кусков", () -> {
            byte[] packet = abridged(fill('a', 0x80 * 4));
            packet[0] = (byte) 0xff;
            List<byte[]> parts = splitAll(Mtproto.TAG_ABRIDGED, packet, 1, 2);
            eq(1, parts.size());
            eq(packet.length, parts.get(0).length);
            byte[] quick = cat(le32(40 | 0x80000000L), fill('b', 40));
            eq(Collections.singletonList(44), lengths(splitAll(Mtproto.TAG_INTERMEDIATE, quick, 1, 1)));
        });
    }

    /** Шифр, не меняющий данные: AES-CTR с гаммой не отключить, поэтому поток заранее шифруется тем же ключом. */
    private static CfH2Pool.Packet parse(byte[] wire, byte[] tag) throws IOException {
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        byte[] encrypted = new Mtproto.AesCtr(key, iv).update(wire);
        return CfH2Pool.readPacket(new DataInputStream(new ByteArrayInputStream(encrypted)), new Mtproto.AesCtr(key, iv), tag);
    }

    private static void framingTests() {
        test("abridged с длинным заголовком и quick ack", () -> {
            byte[] body = fill('a', 512);
            CfH2Pool.Packet packet = parse(cat(new byte[]{(byte) 0xff, (byte) 0x80, 0, 0}, body), Mtproto.TAG_ABRIDGED);
            check(Arrays.equals(body, packet.body) && packet.quick, "тело или quick");
        });
        test("intermediate: quick ack не меняет тело", () -> {
            byte[] body = fill('a', 40);
            CfH2Pool.Packet packet = parse(cat(le32(40 | 0x80000000L), body), Mtproto.TAG_INTERMEDIATE);
            check(Arrays.equals(body, packet.body) && packet.quick, "тело или quick");
        });
        test("padded plaintext: убираются все 15 длин выравнивания", () -> {
            byte[] body = cat(new byte[8], fill('m', 8), le32(20), fill('p', 20));
            for (int padding = 0; padding < 16; padding++) {
                byte[] wire = cat(body, fill('z', padding));
                CfH2Pool.Packet packet = parse(cat(le32(wire.length), wire), Mtproto.TAG_SECURE);
                check(Arrays.equals(body, packet.body) && !packet.quick, "padding " + padding);
            }
        });
        test("padded ciphertext: убираются полные блоки выравнивания", () -> {
            byte[] body = fill('k', 24 + 16);
            byte[] wire = cat(body, fill('z', 15));
            CfH2Pool.Packet packet = parse(cat(le32(wire.length), wire), Mtproto.TAG_SECURE);
            check(Arrays.equals(body, packet.body), "тело");
        });
        test("неверные длины отклоняются до чтения тела", () -> {
            for (long length : new long[]{0, 20, CfH2Pool.MAX_PACKET + 4L}) {
                try {
                    parse(le32(length), Mtproto.TAG_INTERMEDIATE);
                    throw new AssertionError("принята длина " + length);
                } catch (IOException expected) {
                    check(!(expected instanceof java.io.EOFException), "читал тело при длине " + length);
                }
            }
        });
        test("ошибка транспорта сохраняет кадр", () -> {
            byte[] error = {0x6c, (byte) 0xfe, (byte) 0xff, (byte) 0xff};
            check(Arrays.equals(cat(new byte[]{1}, error), CfH2Pool.encodeReply(error, Mtproto.TAG_ABRIDGED)), "abridged");
            check(Arrays.equals(cat(le32(4), error), CfH2Pool.encodeReply(error, Mtproto.TAG_INTERMEDIATE)), "intermediate");
        });
    }

    private static void mtprotoTests() {
        byte[] secret = ProxyConfig.fromHex("00112233445566778899aabbccddeeff");
        test("приветствие клиента: DC, media, протокол", () -> {
            SecureRandom random = new SecureRandom();
            for (int dcIdx : new int[]{2, -2, 203, -5, 10002}) {
                byte[] rnd = new byte[64];
                random.nextBytes(rnd);
                System.arraycopy(Mtproto.TAG_INTERMEDIATE, 0, rnd, 56, 4);
                rnd[60] = (byte) dcIdx;
                rnd[61] = (byte) (dcIdx >> 8);
                byte[] key = Mtproto.sha256(Arrays.copyOfRange(rnd, 8, 40), secret);
                byte[] encrypted = new Mtproto.AesCtr(key, Arrays.copyOfRange(rnd, 40, 56)).update(rnd);
                byte[] init = rnd.clone();
                System.arraycopy(encrypted, 56, init, 56, 8);
                Mtproto.Handshake handshake = Mtproto.tryHandshake(init, secret);
                check(handshake != null, "не разобрано");
                eq(Math.abs(dcIdx), handshake.dc);
                eq(dcIdx < 0, handshake.media);
                check(Arrays.equals(Mtproto.TAG_INTERMEDIATE, handshake.protoTag), "протокол");
            }
        });
        test("чужой ключ не проходит", () -> {
            int rejected = 0;
            SecureRandom random = new SecureRandom();
            for (int i = 0; i < 200; i++) {
                byte[] init = new byte[64];
                random.nextBytes(init);
                if (Mtproto.tryHandshake(init, secret) == null) {
                    rejected++;
                }
            }
            eq(200, rejected);
        });
        test("приветствие к Telegram читается сервером", () -> {
            for (int i = 0; i < 200; i++) {
                byte[] init = Mtproto.generateRelayInit(Mtproto.TAG_SECURE, -4);
                check((init[0] & 0xff) != 0xEF, "запрещённый первый байт");
                check(init[4] != 0 || init[5] != 0 || init[6] != 0 || init[7] != 0, "нули в начале");
                byte[] plain = new Mtproto.AesCtr(Arrays.copyOfRange(init, 8, 40), Arrays.copyOfRange(init, 40, 56)).update(init);
                check(Arrays.equals(Mtproto.TAG_SECURE, Arrays.copyOfRange(plain, 56, 60)), "протокол");
                eq(-4, (int) (short) ((plain[60] & 0xff) | (plain[61] << 8)));
            }
        });
        test("шифры обеих сторон согласованы, поток любыми кусками", () -> {
            byte[] rnd = new byte[64];
            new SecureRandom().nextBytes(rnd);
            byte[] prekeyIv = Arrays.copyOfRange(rnd, 8, 56);
            byte[] relay = Mtproto.generateRelayInit(Mtproto.TAG_INTERMEDIATE, 2);
            Mtproto.CryptoCtx ctx = Mtproto.buildCryptoCtx(prekeyIv, secret, relay);

            // клиент: тот же ключ, 64 байта гаммы ушли на приветствие
            Mtproto.AesCtr clientEnc = new Mtproto.AesCtr(Mtproto.sha256(Arrays.copyOf(prekeyIv, 32), secret), Arrays.copyOfRange(prekeyIv, 32, 48));
            clientEnc.update(new byte[64]);
            byte[] message = new byte[100_000];
            new SecureRandom().nextBytes(message);
            byte[] wire = clientEnc.update(message);
            ByteArrayOutputStream decoded = new ByteArrayOutputStream();
            for (int offset = 0, size = 1; offset < wire.length; offset += size, size = size * 3 % 4099 + 1) {
                int n = Math.min(size, wire.length - offset);
                decoded.write(ctx.cltDec.update(wire, offset, n));
                if (n != size) {
                    break;
                }
            }
            check(Arrays.equals(message, decoded.toByteArray()), "клиент -> прокси");

            // сервер Telegram читает то, что прокси шифрует для него, с 65-го байта своей гаммы
            Mtproto.AesCtr serverDec = new Mtproto.AesCtr(Arrays.copyOfRange(relay, 8, 40), Arrays.copyOfRange(relay, 40, 56));
            serverDec.update(new byte[64]);
            check(Arrays.equals(message, serverDec.update(ctx.tgEnc.update(message))), "прокси -> Telegram");
        });
        test("домены WebSocket как в исходнике", () -> {
            eq(Collections.singletonList("kws2.web.telegram.org"), Arrays.asList(Mtproto.wsDomains(2, false)));
            eq(Arrays.asList("kws4-1.web.telegram.org", "kws4.web.telegram.org"), Arrays.asList(Mtproto.wsDomains(4, true)));
            eq(Collections.singletonList("kws2.web.telegram.org"), Arrays.asList(Mtproto.wsDomains(203, false)));
        });
    }

    private static void configTests() {
        test("разбор DC:IP", () -> {
            eq("1.2.3.4", ProxyConfig.parseDcIpList(Collections.singletonList("4:1.2.3.4")).get(4));
            for (String bad : new String[]{"4", "x:1.2.3.4", "4:1.2.3", "4:1.2.3.256", "4:example.com"}) {
                try {
                    ProxyConfig.parseDcIpList(Collections.singletonList(bad));
                    throw new AssertionError("принято " + bad);
                } catch (IllegalArgumentException expected) {
                    eq(bad, expected.getMessage());
                }
            }
        });
        test("список доменов: разделители и повторы", () -> eq(Arrays.asList("a.dev", "b.dev", "c.dev"),
                ProxyConfig.coerceDomainList(" a.dev, b.dev;c.dev  A.DEV ")));
        test("ключ", () -> {
            check(ProxyConfig.isValidSecret(ProxyConfig.randomSecret()), "случайный ключ");
            check(!ProxyConfig.isValidSecret("abc"), "короткий");
            check(!ProxyConfig.isValidSecret(new String(fill('g', 32))), "не hex");
        });
        test("проверка домена как в _is_valid_domain", () -> {
            check(CfDomains.isValidDomain("kws.example.co.uk"), "обычный");
            for (String bad : new String[]{"", "nodot", ".a.com", "a.com.", "-a.com", "a-.com", "a..com", "a.c", "a.123", "a_b.com"}) {
                check(!CfDomains.isValidDomain(bad), bad);
            }
        });
        test("балансировка: сначала рабочий домен, без повторов", () -> {
            CfDomains domains = new CfDomains();
            domains.update(Arrays.asList("a.dev", "b.dev", "c.dev"));
            domains.setDomainForDc(4, "b.dev");
            List<String> order = domains.forDc(4);
            eq("b.dev", order.get(0));
            eq(3, new java.util.HashSet<>(order).size());
            eq(3, domains.forDc(1).size());
        });
    }

    // --- логика HTTP/2 без сети

    interface Handler {
        byte[] handle(byte[] body, CfH2Pool.Request request, int call) throws IOException, InterruptedException;
    }

    private static final class Fake implements CfH2Pool.Transport {
        final List<byte[]> calls = Collections.synchronizedList(new ArrayList<>());
        final List<Long> times = Collections.synchronizedList(new ArrayList<>());
        final Handler handler;

        Fake(Handler handler) {
            this.handler = handler;
        }

        @Override
        public void preflight() {
        }

        @Override
        public byte[] post(byte[] body, CfH2Pool.Request request) throws IOException {
            calls.add(body);
            times.add(System.nanoTime());
            request.bodySent();
            try {
                return handler.handle(body, request, calls.size());
            } catch (InterruptedException e) {
                throw new IOException(e);
            }
        }

        @Override
        public void close() {
        }

        int count(byte[] body) {
            int n = 0;
            synchronized (calls) {
                for (byte[] call : calls) {
                    if (Arrays.equals(call, body)) {
                        n++;
                    }
                }
            }
            return n;
        }
    }

    private static byte[] hang(CfH2Pool.Request request) throws IOException, InterruptedException {
        CountDownLatch cancelled = new CountDownLatch(1);
        request.setCanceller(cancelled::countDown);
        cancelled.await();
        throw new IOException("Canceled");
    }

    private static byte[] body(String prefix, int index) {
        return cat(prefix.getBytes(java.nio.charset.StandardCharsets.US_ASCII), fill((char) ('A' + index), 32));
    }

    private static boolean waitFor(java.util.function.BooleanSupplier condition, long timeoutMs) throws InterruptedException {
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            if (condition.getAsBoolean()) {
                return true;
            }
            Thread.sleep(5);
        }
        return condition.getAsBoolean();
    }

    private static void h2Tests() {
        ExecutorService pool = Executors.newCachedThreadPool(r -> {
            Thread thread = new Thread(r);
            thread.setDaemon(true);
            return thread;
        });
        ProxyConfig config = new ProxyConfig();
        config.cfproxyH2Media = false;
        TgWsProxy proxy = new TgWsProxy(config);
        CfH2Pool h2 = new CfH2Pool(proxy, (host, lane) -> {
            throw new IllegalStateException();
        }, pool);

        test("опрос: пока запрос ждёт, повторяется тот же шифротекст", () -> {
            byte[] packet = cat("opaque-key-and-message-id".getBytes(java.nio.charset.StandardCharsets.US_ASCII), fill('x', 15));
            Fake fake = new Fake((b, request, call) -> call == 1 ? hang(request) : fill('r', 40));
            CfH2Pool.Channel channel = h2.channelForTest(fake, "t");
            channel.send(packet, false, false);
            pool.execute(() -> {
                try {
                    channel.recover();
                } catch (InterruptedException ignored) {
                    // конец проверки
                }
            });
            check(Arrays.equals(fill('r', 40), channel.receive()), "ответ");
            eq(2, fake.count(packet));
            eq(1, channel.replayRequests);
            channel.close();
            check(channel.pending.isEmpty(), "незавершённые запросы");
            eq(0, channel.lane.inflight);
        });

        test("опрос: запрос завершился без ответа, пакет повторяется один раз", () -> {
            byte[] packet = fill('k', 40);
            Fake fake = new Fake((b, request, call) -> call == 1 ? new byte[0] : fill('r', 40));
            CfH2Pool.Channel channel = h2.channelForTest(fake, "t");
            channel.send(packet, false, false);
            check(waitFor(() -> {
                synchronized (channel.lane) {
                    return channel.pending.isEmpty();
                }
            }, 2000), "первый запрос не завершился");
            pool.execute(() -> {
                try {
                    channel.recover();
                } catch (InterruptedException ignored) {
                    // конец проверки
                }
            });
            check(Arrays.equals(fill('r', 40), channel.receive()), "ответ");
            Thread.sleep(500);
            eq(2, fake.calls.size());
            channel.close();
        });

        test("рукопожатие никогда не повторяется", () -> {
            byte[] handshake = cat(new byte[8], fill('h', 32));
            Fake fake = new Fake((b, request, call) -> fill('r', 40));
            CfH2Pool.Channel channel = h2.channelForTest(fake, "t");
            channel.send(handshake, false, false);
            channel.receive();
            pool.execute(() -> {
                try {
                    channel.recover();
                } catch (InterruptedException ignored) {
                    // конец проверки
                }
            });
            Thread.sleep(2500);
            eq(1, fake.calls.size());
            check(channel.replayHistory.isEmpty(), "попало в историю");
            channel.close();
        });

        test("бесполезные ответы: число повторов ограничено, опрашивается только последний", () -> {
            byte[] older = body("samekey!", 0);
            byte[] latest = body("samekey!", 1);
            Fake fake = new Fake((b, request, call) -> new byte[0]);
            CfH2Pool.Channel channel = h2.channelForTest(fake, "t");
            channel.send(older, false, false);
            channel.send(latest, false, false);
            pool.execute(() -> {
                try {
                    channel.recover();
                } catch (InterruptedException ignored) {
                    // конец проверки
                }
            });
            check(waitFor(() -> fake.calls.size() >= 5, 12000), "мало повторов: " + fake.calls.size());
            Thread.sleep(2500);
            eq(1, fake.count(older));
            eq(4, fake.count(latest));
            check(channel.replayPending.isEmpty(), "незавершённые повторы");
            eq(0, channel.lane.inflight);
            List<Long> latestTimes = new ArrayList<>();
            synchronized (fake.calls) {
                for (int i = 0; i < fake.calls.size(); i++) {
                    if (Arrays.equals(fake.calls.get(i), latest)) {
                        latestTimes.add(fake.times.get(i));
                    }
                }
            }
            for (int i = 2; i < latestTimes.size(); i++) {
                check(latestTimes.get(i) - latestTimes.get(i - 1) >= (CfH2Pool.REPLAY_RETRY_MS - 50) * 1_000_000L, "повторы слишком часто");
            }
            channel.close();
        });

        test("новый ответ возвращает право на повторы", () -> {
            byte[] packet = body("samekey!", 2);
            Fake fake = new Fake((b, request, call) -> call <= 6 ? body("reply-", call) : new byte[0]);
            CfH2Pool.Channel channel = h2.channelForTest(fake, "t");
            channel.send(packet, false, false);
            pool.execute(() -> {
                try {
                    channel.recover();
                } catch (InterruptedException ignored) {
                    // конец проверки
                }
            });
            for (int i = 1; i <= 6; i++) {
                check(Arrays.equals(body("reply-", i), channel.receive()), "ответ " + i);
            }
            channel.close();
        });

        test("долгие опросы не держат новый запрос, вытесненный пакет повторяется", () -> {
            List<byte[]> bodies = new ArrayList<>();
            for (int i = 0; i < CfH2Pool.MAX_CHANNEL_REQUESTS; i++) {
                bodies.add(body("samekey!", i));
            }
            byte[] fresh = cat("samekey!".getBytes(java.nio.charset.StandardCharsets.US_ASCII), fill('n', 32));
            final Fake[] holder = new Fake[1];
            Fake fake = new Fake((b, request, call) -> {
                if (Arrays.equals(b, fresh)) {
                    return fill('n', 40);
                }
                if (Arrays.equals(b, bodies.get(0)) && holder[0].count(bodies.get(0)) == 2) {
                    return fill('r', 40);
                }
                return hang(request);
            });
            holder[0] = fake;
            CfH2Pool.Channel channel = h2.channelForTest(fake, "t");
            for (byte[] item : bodies) {
                channel.send(item, false, false);
            }
            pool.execute(() -> {
                try {
                    channel.recover();
                } catch (InterruptedException ignored) {
                    // конец проверки
                }
            });
            channel.send(fresh, false, false);
            List<String> received = new ArrayList<>();
            received.add(new String(channel.receive()).substring(0, 1));
            received.add(new String(channel.receive()).substring(0, 1));
            Collections.sort(received);
            eq(Arrays.asList("n", "r"), received);
            eq(2, fake.count(bodies.get(0)));
            eq(1, channel.capacityRotations);
            // вытесняется самый старый по времени отправки, а потоки могут отправить пакеты не по порядку
            int retired = 0;
            for (CfH2Pool.ReplayPacket entry : channel.replayHistory) {
                retired += entry.retired ? 1 : 0;
            }
            eq(1, retired);
            check(!channel.closed, "канал закрылся");
            channel.close();
            eq(0, channel.lane.inflight);
        });

        test("ошибка транспорта доходит до клиента и не остужает домен", () -> {
            Fake fake = new Fake((b, request, call) -> {
                throw new CfH2Pool.TransportError(-404, "HTTP 404");
            });
            CfH2Pool.Channel channel = h2.channelForTest(fake, "t");
            channel.send(body("samekey!", 3), false, false);
            try {
                channel.receive();
                throw new AssertionError("нет ошибки");
            } catch (IOException expected) {
                check(expected instanceof CfH2Pool.TransportError, "тип");
            }
            eq(-404, channel.transportError);
            eq(Long.MIN_VALUE, channel.lane.failedUntil);
            channel.close();
        });

        test("сетевая ошибка закрывает канал и остужает домен, пакет не повторяется", () -> {
            byte[] packet = body("samekey!", 4);
            Fake fake = new Fake((b, request, call) -> {
                throw new IOException("boom");
            });
            CfH2Pool.Channel channel = h2.channelForTest(fake, "t");
            channel.send(packet, false, false);
            try {
                channel.receive();
                throw new AssertionError("нет ошибки");
            } catch (IOException expected) {
                eq("boom", expected.getMessage());
            }
            check(channel.closed, "канал открыт");
            check(channel.lane.failedUntil > CfH2Pool.now(), "домен не остыл");
            eq(1, fake.calls.size());
            channel.close();
        });

        test("отмена при закрытии клиента не остужает домен", () -> {
            Fake fake = new Fake((b, request, call) -> hang(request));
            CfH2Pool.Channel channel = h2.channelForTest(fake, "t");
            channel.send(body("samekey!", 5), false, false);
            check(waitFor(() -> fake.calls.size() == 1, 2000), "запрос не начался");
            channel.close();
            eq(Long.MIN_VALUE, channel.lane.failedUntil);
            eq(0, channel.lane.inflight);
            check(channel.pending.isEmpty(), "незавершённые запросы");
        });

        test("очередь ответов переполнена: закрывается только этот канал", () -> {
            Fake fake = new Fake((b, request, call) -> fill('r', 40));
            CfH2Pool.Channel channel = h2.channelForTest(fake, "t");
            for (int i = 0; i < CfH2Pool.REPLY_QUEUE_SIZE + 1; i++) {
                channel.send(body("samekey!", i), false, false);
                Thread.sleep(2);
            }
            check(waitFor(() -> {
                synchronized (channel.lane) {
                    return channel.closed;
                }
            }, 2000), "канал не закрылся");
            channel.close();
        });

        test("ёмкость канала: запросов не больше предела", () -> {
            Fake fake = new Fake((b, request, call) -> hang(request));
            CfH2Pool.Channel channel = h2.channelForTest(fake, "t");
            for (int i = 0; i < CfH2Pool.MAX_CHANNEL_REQUESTS; i++) {
                channel.send(body("samekey!", i), false, false);
            }
            CountDownLatch sent = new CountDownLatch(1);
            pool.execute(() -> {
                try {
                    channel.send(body("samekey!", 20), false, false);
                    sent.countDown();
                } catch (IOException | InterruptedException ignored) {
                    // освобождается закрытием канала
                }
            });
            check(!sent.await(300, TimeUnit.MILLISECONDS), "предел превышен");
            eq(CfH2Pool.MAX_CHANNEL_REQUESTS, channel.pending.size());
            channel.close();
        });
        pool.shutdownNow();
    }

    public static void main(String[] args) {
        System.out.println("== разделение пакетов");
        splitterTests();
        System.out.println("== кадры MTProto");
        framingTests();
        System.out.println("== приветствие и шифры");
        mtprotoTests();
        System.out.println("== настройки и домены");
        configTests();
        System.out.println("== логика HTTP/2");
        h2Tests();
        System.out.println();
        System.out.println("Пройдено: " + passed + ", ошибок: " + failed);
        for (String domain : CfDomains.defaults()) {
            if (args.length > 0 && args[0].equals("--domains")) {
                System.out.println(domain);
            }
        }
        System.exit(failed == 0 ? 0 : 1);
    }
}
