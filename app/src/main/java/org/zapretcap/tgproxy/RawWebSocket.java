package org.zapretcap.tgproxy;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.locks.ReentrantLock;

/** Минимальный клиент WebSocket: нужно самому выбирать IP, SNI и заголовок Host. */
final class RawWebSocket implements Closeable {
    private static final int OP_CONT = 0x0;
    private static final int OP_TEXT = 0x1;
    private static final int OP_BINARY = 0x2;
    private static final int OP_CLOSE = 0x8;
    private static final int OP_PING = 0x9;
    private static final int OP_PONG = 0xA;
    private static final int MAX_MESSAGE_LEN = 16 * 1024 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    static final class HandshakeError extends IOException {
        final int status;

        HandshakeError(int status, String line) {
            super("HTTP " + status + ": " + line);
            this.status = status;
        }
    }

    private final Socket plain;
    private final Socket socket;
    private final PushbackInputStream pushback;
    private final DataInputStream in;
    private final OutputStream out;
    private final ReentrantLock writeLock = new ReentrantLock();
    private final ByteArrayOutputStream fragments = new ByteArrayOutputStream();
    private volatile boolean closed;

    private RawWebSocket(Socket plain, Socket socket, PushbackInputStream pushback) throws IOException {
        this.plain = plain;
        this.socket = socket;
        this.pushback = pushback;
        this.in = new DataInputStream(pushback);
        this.out = socket.getOutputStream();
    }

    /**
     * @param host   куда подключаться: IP или имя
     * @param domain заголовок Host и, если не задан sni, имя в ClientHello
     * @param sni    маскировка: другое имя в ClientHello, имя сертификата при этом не сверяется
     */
    static RawWebSocket connect(ProxyConfig config, String host, String domain, int timeoutMs, String path,
                                String sni, boolean secure) throws IOException {
        int socks = Dialer.socksPort();
        if (socks <= 0) {
            return open(config, host, domain, timeoutMs, path, sni, secure, 0);
        }
        try {
            return open(config, host, domain, Math.min(timeoutMs, Dialer.VIA_ENGINE_TIMEOUT_MS), path, sni, secure, socks);
        } catch (IOException e) {
            // Настоящий ответ HTTP значит, что соединение в порядке, а отказал сам сервер: прямой путь его не изменит
            if (e instanceof HandshakeError && ((HandshakeError) e).status != 0) {
                throw e;
            }
            ProxyLog.d("WS " + domain + " через движок не удалось, повтор напрямую: " + e.getClass().getSimpleName());
            return open(config, host, domain, timeoutMs, path, sni, secure, 0);
        }
    }

    private static RawWebSocket open(ProxyConfig config, String host, String domain, int timeoutMs, String path,
                                     String sni, boolean secure, int socks) throws IOException {
        Socket plain = Dialer.tcp(host, secure ? 443 : 80, Math.min(timeoutMs, 10000), socks);
        Socket socket = plain;
        try {
            setSocketOptions(plain, config.bufferSize);
            if (secure) {
                socket = Dialer.tls(plain, sni != null ? sni : domain, 443, sni == null, Math.min(timeoutMs, 10000));
            }
            socket.setSoTimeout(timeoutMs);
            OutputStream output = socket.getOutputStream();
            String request = "GET " + path + " HTTP/1.1\r\n"
                    + "Host: " + domain + "\r\n"
                    + "Upgrade: websocket\r\n"
                    + "Connection: Upgrade\r\n"
                    + "Sec-WebSocket-Key: " + randomKey() + "\r\n"
                    + "Sec-WebSocket-Version: 13\r\n"
                    + "Sec-WebSocket-Protocol: binary\r\n"
                    + "\r\n";
            output.write(request.getBytes(StandardCharsets.US_ASCII));
            output.flush();

            BufferedInputStream buffered = new BufferedInputStream(socket.getInputStream(), 64 * 1024);
            String first = readLine(buffered);
            if (first == null || first.isEmpty()) {
                throw new HandshakeError(0, "empty response");
            }
            String line;
            while ((line = readLine(buffered)) != null && !line.isEmpty()) {
                // заголовки ответа не нужны, важен только статус
            }
            String[] parts = first.split(" ", 3);
            int status = 0;
            try {
                status = parts.length >= 2 ? Integer.parseInt(parts[1]) : 0;
            } catch (NumberFormatException ignored) {
                // останется 0: не ответ HTTP
            }
            if (status != 101) {
                throw new HandshakeError(status, first);
            }
            socket.setSoTimeout(0);
            return new RawWebSocket(plain, socket, new PushbackInputStream(buffered, 1));
        } catch (IOException | RuntimeException e) {
            Dialer.closeQuietly(socket);
            Dialer.closeQuietly(plain);
            throw e;
        }
    }

    static void setSocketOptions(Socket socket, int bufferSize) {
        try {
            socket.setTcpNoDelay(true);
            socket.setReceiveBufferSize(bufferSize);
            socket.setSendBufferSize(bufferSize);
        } catch (IOException ignored) {
            // это только оптимизация
        }
    }

    private static String randomKey() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        StringBuilder out = new StringBuilder(24);
        for (int i = 0; i < 15; i += 3) {
            int n = (bytes[i] & 0xff) << 16 | (bytes[i + 1] & 0xff) << 8 | (bytes[i + 2] & 0xff);
            out.append(BASE64[n >> 18 & 63]).append(BASE64[n >> 12 & 63]).append(BASE64[n >> 6 & 63]).append(BASE64[n & 63]);
        }
        int n = (bytes[15] & 0xff) << 16;
        return out.append(BASE64[n >> 18 & 63]).append(BASE64[n >> 12 & 63]).append("==").toString();
    }

    private static String readLine(BufferedInputStream input) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int b;
        while ((b = input.read()) >= 0) {
            if (b == '\n') {
                break;
            }
            if (b != '\r') {
                line.write(b);
            }
            if (line.size() > 16 * 1024) {
                throw new IOException("HTTP header line too long");
            }
        }
        if (b < 0 && line.size() == 0) {
            return null;
        }
        return line.toString("UTF-8");
    }

    boolean isClosed() {
        return closed;
    }

    void send(byte[] data) throws IOException {
        if (closed) {
            throw new IOException("WebSocket closed");
        }
        byte[] frame = buildFrame(OP_BINARY, data);
        writeLock.lock();
        try {
            out.write(frame);
            out.flush();
        } finally {
            writeLock.unlock();
        }
    }

    void sendBatch(List<byte[]> parts) throws IOException {
        if (closed) {
            throw new IOException("WebSocket closed");
        }
        ByteArrayOutputStream batch = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            batch.write(buildFrame(OP_BINARY, part));
        }
        writeLock.lock();
        try {
            out.write(batch.toByteArray());
            out.flush();
        } finally {
            writeLock.unlock();
        }
    }

    /** Следующее сообщение или null, если сервер закрыл соединение. */
    byte[] recv() throws IOException {
        while (!closed) {
            int first = in.readUnsignedByte();
            int second = in.readUnsignedByte();
            boolean fin = (first & 0x80) != 0;
            int opcode = first & 0x0F;
            long length = second & 0x7F;
            if (length == 126) {
                length = in.readUnsignedShort();
            } else if (length == 127) {
                length = in.readLong();
            }
            if (length < 0 || length > MAX_MESSAGE_LEN) {
                throw new IOException("WS frame too large: " + length);
            }
            byte[] maskKey = null;
            if ((second & 0x80) != 0) {
                maskKey = new byte[4];
                in.readFully(maskKey);
            }
            byte[] payload = new byte[(int) length];
            in.readFully(payload);
            if (maskKey != null) {
                xorMask(payload, maskKey);
            }

            if (opcode == OP_CLOSE) {
                closed = true;
                writeControlQuietly(OP_CLOSE, payload.length >= 2 ? new byte[]{payload[0], payload[1]} : new byte[0]);
                return null;
            }
            if (opcode == OP_PING) {
                writeControlQuietly(OP_PONG, payload);
                continue;
            }
            if (opcode == OP_CONT || opcode == OP_TEXT || opcode == OP_BINARY) {
                if (fin && fragments.size() == 0) {
                    return payload;
                }
                fragments.write(payload);
                if (fragments.size() > MAX_MESSAGE_LEN) {
                    throw new IOException("WS message too large: " + fragments.size());
                }
                if (!fin) {
                    continue;
                }
                byte[] message = fragments.toByteArray();
                fragments.reset();
                return message;
            }
        }
        return null;
    }

    private void writeControlQuietly(int opcode, byte[] payload) {
        // поток отправки мог упереться в полный буфер: ответ на служебный кадр не стоит ожидания
        if (writeLock.tryLock()) {
            try {
                out.write(buildFrame(opcode, payload));
                out.flush();
            } catch (IOException ignored) {
                // соединение и так разрывается
            } finally {
                writeLock.unlock();
            }
        }
    }

    /**
     * Живо ли соединение, пока оно ждёт в пуле. Заглянуть в сокет, не забирая данные, можно только коротким чтением:
     * у TLS нет способа узнать о разрыве иначе.
     */
    boolean isStale() {
        if (closed) {
            return true;
        }
        try {
            socket.setSoTimeout(1);
            int value = pushback.read();
            if (value < 0) {
                return true;
            }
            pushback.unread(value);
            return false;
        } catch (SocketTimeoutException stillOpen) {
            return false;
        } catch (IOException e) {
            return true;
        } finally {
            try {
                socket.setSoTimeout(0);
            } catch (IOException ignored) {
                // значит сокет уже закрыт, следующая проверка это увидит
            }
        }
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            writeControlQuietly(OP_CLOSE, new byte[0]);
        }
        // обычное соединение закрывается первым: закрытие TLS могло бы ждать вместе с заблокированной записью
        Dialer.closeQuietly(plain);
        Dialer.closeQuietly(socket);
    }

    private static byte[] buildFrame(int opcode, byte[] data) {
        int length = data.length;
        int header = length < 126 ? 2 : length < 65536 ? 4 : 10;
        byte[] frame = new byte[header + 4 + length];
        frame[0] = (byte) (0x80 | opcode);
        if (length < 126) {
            frame[1] = (byte) (0x80 | length);
        } else if (length < 65536) {
            frame[1] = (byte) (0x80 | 126);
            frame[2] = (byte) (length >> 8);
            frame[3] = (byte) length;
        } else {
            frame[1] = (byte) (0x80 | 127);
            for (int i = 0; i < 8; i++) {
                frame[2 + i] = (byte) ((long) length >> (56 - 8 * i));
            }
        }
        byte[] mask = new byte[4];
        RANDOM.nextBytes(mask);
        System.arraycopy(mask, 0, frame, header, 4);
        int start = header + 4;
        for (int i = 0; i < length; i++) {
            frame[start + i] = (byte) (data[i] ^ mask[i & 3]);
        }
        return frame;
    }

    private static void xorMask(byte[] data, byte[] mask) {
        for (int i = 0; i < data.length; i++) {
            data[i] ^= mask[i & 3];
        }
    }

    @Override
    public String toString() {
        return String.format(Locale.ROOT, "ws[%s]", closed ? "closed" : "open");
    }
}
