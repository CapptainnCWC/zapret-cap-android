package org.zapretcap.tgproxy;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Исходящие соединения прокси. Пока включён режим VPN, они идут через ciadpi: само приложение исключено из VPN,
 * и без этого домены Cloudflare остались бы без обхода. Это то же, что совет из tg-ws-proxy добавить их в zapret.
 */
public final class Dialer {
    /**
     * Сколько ждать соединения через движок, прежде чем повторить его напрямую. Приём обхода может сломать
     * рукопожатие: фейк с чужим именем доходит до сервера, если тот ближе его TTL, и сервер обрывает связь или молчит.
     */
    static final int VIA_ENGINE_TIMEOUT_MS = 5000;

    private static volatile int socksPort;

    private Dialer() {
    }

    /** Порт SOCKS5 движка режима VPN, 0 - соединяться напрямую. */
    public static void setSocksPort(int port) {
        socksPort = port;
    }

    public static int socksPort() {
        return socksPort;
    }

    static Socket tcp(String host, int port, int timeoutMs) throws IOException {
        return tcp(host, port, timeoutMs, socksPort);
    }

    public static Socket tcp(String host, int port, int timeoutMs, int socks) throws IOException {
        List<InetAddress> addresses = addresses(host);
        int share = addresses.size() > 1 ? timeoutMs / 2 : timeoutMs;
        IOException last = null;
        for (InetAddress address : addresses) {
            try {
                return connect(address, port, share, socks);
            } catch (IOException e) {
                last = e;
            }
        }
        throw last;
    }

    /**
     * IPv4 первым и не больше двух адресов. Android часто ставит первым IPv6, а на мобильных сетях он бывает
     * неисправен: соединение висело бы весь таймаут, и клиент успевал бы переподключиться.
     */
    private static List<InetAddress> addresses(String host) throws IOException {
        InetAddress[] all = InetAddress.getAllByName(host);
        List<InetAddress> ordered = new ArrayList<>();
        for (InetAddress address : all) {
            if (address instanceof Inet4Address) {
                ordered.add(address);
            }
        }
        for (InetAddress address : all) {
            if (!(address instanceof Inet4Address)) {
                ordered.add(address);
            }
        }
        return ordered.size() > 2 ? ordered.subList(0, 2) : ordered;
    }

    private static Socket connect(InetAddress address, int port, int timeoutMs, int socks) throws IOException {
        Socket socket = new Socket();
        try {
            if (socks > 0) {
                socket.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), socks), timeoutMs);
                socket.setSoTimeout(timeoutMs);
                socksConnect(socket, address, port);
                socket.setSoTimeout(0);
            } else {
                socket.connect(new InetSocketAddress(address, port), timeoutMs);
            }
            return socket;
        } catch (IOException | RuntimeException e) {
            closeQuietly(socket);
            throw e;
        }
    }

    private static void socksConnect(Socket socket, InetAddress address, int port) throws IOException {
        OutputStream out = socket.getOutputStream();
        DataInputStream in = new DataInputStream(socket.getInputStream());
        out.write(new byte[]{5, 1, 0});
        out.flush();
        byte[] reply = new byte[2];
        in.readFully(reply);
        if (reply[0] != 5 || reply[1] != 0) {
            throw new IOException("SOCKS5: auth refused");
        }
        byte[] ip = address.getAddress();
        ByteBuffer request = ByteBuffer.allocate(4 + ip.length + 2);
        request.put((byte) 5).put((byte) 1).put((byte) 0).put((byte) (address instanceof Inet4Address ? 1 : 4));
        request.put(ip).putShort((short) port);
        out.write(request.array());
        out.flush();
        byte[] head = new byte[4];
        in.readFully(head);
        if (head[1] != 0) {
            throw new IOException("SOCKS5: connect failed, code " + head[1]);
        }
        int skip = head[3] == 1 ? 4 : head[3] == 4 ? 16 : in.readUnsignedByte();
        in.readFully(new byte[skip + 2]);
    }

    /**
     * TLS поверх готового соединения.
     *
     * @param sni           имя в ClientHello
     * @param checkHostname сверять ли сертификат с этим именем. Цепочка доверия проверяется всегда
     */
    public static SSLSocket tls(Socket plain, String sni, int port, boolean checkHostname, int timeoutMs) throws IOException {
        SSLSocket socket = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(plain, sni, port, true);
        SSLParameters parameters = socket.getSSLParameters();
        parameters.setServerNames(Collections.singletonList(new SNIHostName(sni)));
        if (checkHostname) {
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
        }
        socket.setSSLParameters(parameters);
        socket.setSoTimeout(timeoutMs);
        socket.startHandshake();
        socket.setSoTimeout(0);
        return socket;
    }

    public static void closeQuietly(java.io.Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException | RuntimeException ignored) {
                // соединение и так заканчивается
            }
        }
    }
}
