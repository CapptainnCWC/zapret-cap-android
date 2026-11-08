package org.zapretcap.tgproxy;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.ConnectionPool;
import okhttp3.EventListener;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

/** POST /api через одно соединение HTTP/2 с доменом Cloudflare. */
final class H2OkHttpTransport implements CfH2Pool.Transport {
    private static final MediaType OCTET_STREAM = MediaType.get("application/octet-stream");

    /** Пока работает режим VPN, соединения идут через ciadpi, как и все остальные соединения прокси. */
    private final ProxySelector viaDialer = new ProxySelector() {
        @Override
        public List<Proxy> select(URI uri) {
            int port = Dialer.socksPort();
            if (port <= 0 || direct) {
                return Collections.singletonList(Proxy.NO_PROXY);
            }
            return Collections.singletonList(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", port)));
        }

        @Override
        public void connectFailed(URI uri, SocketAddress address, IOException e) {
            ProxyLog.d("H2 connect via SOCKS failed: " + e);
        }
    };

    private volatile boolean direct;
    private final String url;
    private final CfH2Pool.Lane lane;
    private final OkHttpClient client;

    H2OkHttpTransport(String host, CfH2Pool.Lane lane) {
        this.url = "https://" + host + "/api";
        this.lane = lane;
        this.client = new OkHttpClient.Builder()
                .protocols(Arrays.asList(Protocol.HTTP_2, Protocol.HTTP_1_1))
                .proxySelector(viaDialer)
                .connectTimeout(8, TimeUnit.SECONDS)
                .readTimeout(CfH2Pool.REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .writeTimeout(CfH2Pool.REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .retryOnConnectionFailure(false)
                .followRedirects(false)
                .followSslRedirects(false)
                // молча умершее соединение иначе обнаружилось бы только по таймауту запроса, больше чем через минуту
                .pingInterval(15, TimeUnit.SECONDS)
                .connectionPool(new ConnectionPool(1, 2, TimeUnit.MINUTES))
                .eventListenerFactory(call -> {
                    CfH2Pool.Request request = call.request().tag(CfH2Pool.Request.class);
                    return request == null ? EventListener.NONE : new RequestEvents(request);
                })
                .build();
    }

    private static final class RequestEvents extends EventListener {
        private final CfH2Pool.Request request;

        RequestEvents(CfH2Pool.Request request) {
            this.request = request;
        }

        @Override
        public void requestBodyEnd(Call call, long byteCount) {
            request.bodySent();
        }

        @Override
        public void responseHeadersEnd(Call call, Response response) {
            request.responseStarted();
        }
    }

    @Override
    public void preflight() throws IOException {
        if (Dialer.socksPort() > 0) {
            OkHttpClient viaEngine = client.newBuilder()
                    .connectTimeout(Dialer.VIA_ENGINE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                    .readTimeout(Dialer.VIA_ENGINE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                    .build();
            try {
                checkDomain(viaEngine);
                return;
            } catch (IOException e) {
                // повторов в OkHttp нет намеренно, иначе он отправил бы пакет дважды, поэтому переключаемся здесь
                ProxyLog.d("H2 через движок не удалось, линия пойдёт напрямую: " + e);
                direct = true;
            }
        }
        checkDomain(client);
    }

    private void checkDomain(OkHttpClient http) throws IOException {
        Request request = new Request.Builder().url(url).head().header("User-Agent", "tg-ws-proxy").build();
        try (Response response = http.newCall(request).execute()) {
            if (response.protocol() != Protocol.HTTP_2) {
                throw new IOException("CF /api preflight negotiated " + response.protocol());
            }
            int code = response.code();
            if (!(code >= 200 && code < 300) && code != 405 && code != 501) {
                throw new IOException("CF /api preflight HTTP " + code + " cf_ray=" + response.header("cf-ray", "-"));
            }
        }
    }

    @Override
    public byte[] post(byte[] body, CfH2Pool.Request request) throws IOException {
        Request http = new Request.Builder()
                .url(url)
                .post(RequestBody.create(OCTET_STREAM, body))
                .header("Accept-Encoding", "identity")
                .header("User-Agent", "tg-ws-proxy")
                .tag(CfH2Pool.Request.class, request)
                .build();
        Call call = client.newCall(http);
        request.setCanceller(call::cancel);
        long buffered = 0;
        try (Response response = call.execute()) {
            String ray = response.header("cf-ray", "-");
            if (response.protocol() != Protocol.HTTP_2) {
                throw new IOException("CF /api downgraded to " + response.protocol());
            }
            int code = response.code();
            if (code == 403 || code == 404 || code == 429 || code == 444) {
                throw new CfH2Pool.TransportError(-code, "HTTP " + code + " cf_ray=" + ray);
            }
            if (code != 200) {
                throw new IOException("CF /api HTTP " + code + " cf_ray=" + ray);
            }
            String type = response.header("content-type", "");
            if (type.toLowerCase(Locale.ROOT).contains("text/html")) {
                throw new IOException("CF /api returned HTML instead of MTProto");
            }
            String lengthHeader = response.header("content-length");
            long declared = -1;
            if (lengthHeader != null) {
                try {
                    declared = Long.parseLong(lengthHeader.trim());
                } catch (NumberFormatException e) {
                    throw new IOException("bad Content-Length");
                }
                if (declared < 0 || declared > CfH2Pool.MAX_PACKET) {
                    throw new CfH2Pool.ReplyBufferFull("H2 response Content-Length exceeds native packet bound");
                }
            }
            ResponseBody responseBody = response.body();
            byte[] content = new byte[declared >= 0 ? (int) declared : 16 * 1024];
            int received = 0;
            if (responseBody != null) {
                try (InputStream in = responseBody.byteStream()) {
                    byte[] chunk = new byte[64 * 1024];
                    int n;
                    while ((n = in.read(chunk)) >= 0) {
                        if (received + n > CfH2Pool.MAX_PACKET) {
                            throw new CfH2Pool.ReplyBufferFull("H2 response exceeds native packet bound");
                        }
                        lane.reserveReplyBuffer(n);
                        buffered += n;
                        if (received + n > content.length) {
                            content = Arrays.copyOf(content, Math.min(CfH2Pool.MAX_PACKET, Math.max(content.length * 2, received + n)));
                        }
                        System.arraycopy(chunk, 0, content, received, n);
                        received += n;
                        request.bodyProgress();
                    }
                }
            }
            if (declared >= 0 && "identity".equals(response.header("content-encoding", "identity")) && received != declared) {
                throw new IOException("incomplete H2 response body");
            }
            if (received % 4 != 0) {
                throw new IOException("CF /api response is not an aligned MTProto packet");
            }
            if (received == 4) {
                int value = (content[0] & 0xff) | (content[1] & 0xff) << 8 | (content[2] & 0xff) << 16 | content[3] << 24;
                if (value < 0) {
                    throw new CfH2Pool.TransportError(value, "HTTP 200 payload");
                }
            }
            return received == content.length ? content : Arrays.copyOf(content, received);
        } finally {
            lane.releaseReplyBuffer(buffered);
        }
    }

    @Override
    public void close() {
        client.connectionPool().evictAll();
        client.dispatcher().executorService().shutdown();
    }
}
