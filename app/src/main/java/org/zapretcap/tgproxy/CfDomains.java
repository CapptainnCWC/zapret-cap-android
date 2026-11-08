package org.zapretcap.tgproxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

/** Домены Cloudflare-прокси: встроенный список, обновление с GitHub и выбор домена для каждого DC. */
public final class CfDomains {
    private static final String LIST_HOST = "raw.githubusercontent.com";
    private static final String LIST_PATH = "/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";
    /** Если DNS подменён, файл всё равно будет доступен по этому адресу. */
    private static final String LIST_PINNED_IP = "185.199.109.133";
    private static final int MIN_VALID_DOMAINS = 3;
    private static final int[] DCS = {1, 2, 3, 4, 5, 203};

    /** Имена закодированы, как в исходном проекте. */
    private static final String[] ENCODED = {
            "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com", "twdmbzcm.com",
            "awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com", "bxaxtxmrw.com", "dmohrsgmohcrwb.com",
            "vwbmtmoi.com", "khgrre.com", "ulihssf.com", "tmhqsdqmfpmk.com", "xwuwoqbm.com",
            "orgcnunpj.com", "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com",
    };
    private static final String SUFFIX = new String(new char[]{46, 99, 111, 46, 117, 107});

    private final Random random = new Random();
    private List<String> domains = new ArrayList<>();
    private final Map<Integer, String> dcToDomain = new HashMap<>();

    static String decode(String encoded) {
        if (!encoded.endsWith(".com")) {
            return encoded;
        }
        String name = encoded.substring(0, encoded.length() - 4);
        int letters = 0;
        for (char c : name.toCharArray()) {
            if (Character.isLetter(c)) {
                letters++;
            }
        }
        StringBuilder out = new StringBuilder();
        for (char c : name.toCharArray()) {
            if (Character.isLetter(c)) {
                int base = c > '`' ? 97 : 65;
                out.append((char) (Math.floorMod(c - base - letters, 26) + base));
            } else {
                out.append(c);
            }
        }
        return out.append(SUFFIX).toString();
    }

    /** Встроенный список в раскодированном виде. */
    public static List<String> defaults() {
        List<String> result = new ArrayList<>();
        for (String encoded : ENCODED) {
            result.add(decode(encoded));
        }
        return result;
    }

    synchronized void update(List<String> newDomains) {
        if (new LinkedHashSet<>(domains).equals(new LinkedHashSet<>(newDomains)) || newDomains.isEmpty()) {
            return;
        }
        domains = new ArrayList<>(newDomains);
        for (int dc : DCS) {
            dcToDomain.put(dc, domains.get(random.nextInt(domains.size())));
        }
    }

    synchronized boolean setDomainForDc(int dc, String domain) {
        if (domain.equals(dcToDomain.get(dc))) {
            return false;
        }
        dcToDomain.put(dc, domain);
        return true;
    }

    /** Домен подключается, но Telegram через него не отвечает: следующий клиент начнёт с другого. */
    synchronized void forgetDomainForDc(int dc, String domain) {
        if (domain.equals(dcToDomain.get(dc))) {
            dcToDomain.remove(dc);
        }
    }

    /** Сначала домен, который уже работал для этого DC, затем остальные в случайном порядке. */
    synchronized List<String> forDc(int dc) {
        List<String> result = new ArrayList<>();
        String current = dcToDomain.get(dc);
        if (current != null) {
            result.add(current);
        }
        List<String> shuffled = new ArrayList<>(domains);
        Collections.shuffle(shuffled, random);
        for (String domain : shuffled) {
            if (!domain.equals(current)) {
                result.add(domain);
            }
        }
        return result;
    }

    static boolean isValidDomain(String domain) {
        if (domain == null || domain.isEmpty() || domain.length() > 253 || domain.startsWith(".") || domain.endsWith(".")) {
            return false;
        }
        String[] labels = domain.split("\\.", -1);
        if (labels.length < 2) {
            return false;
        }
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) {
                return false;
            }
            for (char c : label.toCharArray()) {
                if (!Character.isLetterOrDigit(c) && c != '-') {
                    return false;
                }
            }
        }
        String tld = labels[labels.length - 1];
        if (tld.length() < 2) {
            return false;
        }
        for (char c : tld.toCharArray()) {
            if (Character.isLetter(c)) {
                return true;
            }
        }
        return false;
    }

    /** Загрузка необязательна: при любой ошибке продолжает работать текущий список. */
    void refresh() {
        List<String> fetched = fetch();
        LinkedHashSet<String> pool = new LinkedHashSet<>();
        for (String domain : fetched) {
            String item = domain.trim().toLowerCase(Locale.ROOT);
            if (isValidDomain(item)) {
                pool.add(item);
            }
        }
        if (pool.size() >= MIN_VALID_DOMAINS) {
            update(new ArrayList<>(pool));
            ProxyLog.i("Список доменов CF-прокси обновлён: " + pool.size());
        } else {
            ProxyLog.w("Список доменов CF-прокси не обновлён, работает текущий");
        }
    }

    private static List<String> fetch() {
        for (String host : Arrays.asList(LIST_PINNED_IP, LIST_HOST)) {
            try {
                String text = download(host);
                List<String> decoded = new ArrayList<>();
                for (String line : text.split("\\r?\\n")) {
                    String item = line.trim();
                    if (!item.isEmpty() && !item.startsWith("#")) {
                        decoded.add(decode(item));
                    }
                }
                return decoded;
            } catch (IOException | RuntimeException e) {
                ProxyLog.d("CF domain list via " + host + ": " + e);
            }
        }
        return Collections.emptyList();
    }

    private static String download(String host) throws IOException {
        StringBuilder query = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < 7; i++) {
            query.append((char) ('a' + random.nextInt(26)));
        }
        Socket plain = Dialer.tcp(host, 443, 10000);
        try (Socket socket = Dialer.tls(plain, LIST_HOST, 443, true, 10000)) {
            socket.setSoTimeout(10000);
            OutputStream out = socket.getOutputStream();
            // HTTP/1.0: ответ заканчивается закрытием соединения и не бывает разбит на куски
            out.write(("GET " + LIST_PATH + "?" + query + " HTTP/1.0\r\nHost: " + LIST_HOST
                    + "\r\nUser-Agent: tg-ws-proxy\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            InputStream in = socket.getInputStream();
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) > 0 && body.size() < 1024 * 1024) {
                body.write(buffer, 0, n);
            }
            String response = body.toString("UTF-8");
            int split = response.indexOf("\r\n\r\n");
            if (split < 0 || !response.startsWith("HTTP/1.") || !response.substring(0, response.indexOf("\r\n")).contains(" 200")) {
                throw new IOException("unexpected response");
            }
            return response.substring(split + 4);
        } finally {
            Dialer.closeQuietly(plain);
        }
    }
}
