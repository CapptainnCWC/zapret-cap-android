package org.zapretcap.tgproxy;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Настройки прокси. Значения по умолчанию те же, что в tg-ws-proxy. */
public final class ProxyConfig {
    public static final String DEFAULT_DC_IP = "149.154.167.220";

    public int port = 1443;
    public String host = "127.0.0.1";
    public String secret = randomSecret();
    public Map<Integer, String> dcRedirects = defaultDcRedirects();
    public int bufferSize = 256 * 1024;
    public int poolSize = 4;
    public boolean fallbackCfproxy = true;
    public List<String> cfproxyUserDomains = new ArrayList<>();
    public List<String> cfproxyWorkerDomains = new ArrayList<>();
    public boolean cfproxyH2Media = true;
    public boolean disableSecure;
    public boolean forceTestDc;

    public boolean h2Enabled() {
        return cfproxyH2Media && fallbackCfproxy && !disableSecure && !forceTestDc;
    }

    public static Map<Integer, String> defaultDcRedirects() {
        Map<Integer, String> map = new LinkedHashMap<>();
        map.put(2, DEFAULT_DC_IP);
        map.put(4, DEFAULT_DC_IP);
        return map;
    }

    public static String randomSecret() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return toHex(bytes);
    }

    public static String toHex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        }
        return out.toString();
    }

    public static boolean isValidSecret(String secret) {
        return secret != null && secret.matches("[0-9a-fA-F]{32}");
    }

    public static byte[] fromHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** Разбирает записи вида 2:149.154.167.220. Ошибка содержит саму неверную запись. */
    public static Map<Integer, String> parseDcIpList(Collection<String> entries) {
        Map<Integer, String> map = new LinkedHashMap<>();
        for (String entry : entries) {
            int colon = entry.indexOf(':');
            if (colon < 0) {
                throw new IllegalArgumentException(entry);
            }
            int dc;
            try {
                dc = Integer.parseInt(entry.substring(0, colon).trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(entry);
            }
            String ip = entry.substring(colon + 1).trim();
            if (!isIpv4(ip)) {
                throw new IllegalArgumentException(entry);
            }
            map.put(dc, ip);
        }
        return map;
    }

    static boolean isIpv4(String ip) {
        String[] parts = ip.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (!part.matches("[0-9]{1,3}") || Integer.parseInt(part) > 255) {
                return false;
            }
        }
        return true;
    }

    /** Домены через запятую, точку с запятой или пробел, без повторов. */
    public static List<String> coerceDomainList(String value) {
        List<String> result = new ArrayList<>();
        if (value == null) {
            return result;
        }
        Set<String> seen = new LinkedHashSet<>();
        for (String item : value.replace(',', ' ').replace(';', ' ').trim().split("\\s+")) {
            if (!item.isEmpty() && seen.add(item.toLowerCase(Locale.ROOT))) {
                result.add(item);
            }
        }
        return result;
    }

    public String link() {
        return "tg://proxy?server=" + host + "&port=" + port + "&secret=dd" + secret;
    }
}
