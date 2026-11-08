package org.zapretcap.app;

import android.content.Context;
import android.content.SharedPreferences;

import org.zapretcap.tgproxy.ProxyConfig;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Настройки прокси Telegram. Значения по умолчанию как в tg-ws-proxy. */
final class TgProxySettings {
    static final String ENABLED = "tg_enabled";
    static final String PORT = "tg_port";
    static final String SECRET = "tg_secret";
    static final String DC_IPS = "tg_dc_ips";
    static final String CFPROXY = "tg_cfproxy";
    static final String CF_DOMAINS = "tg_cf_domains";
    static final String H2 = "tg_h2";
    static final String WORKER_DOMAINS = "tg_worker_domains";
    static final String NO_SECURE = "tg_no_secure";
    static final String BUF_KB = "tg_buf_kb";
    static final String POOL_SIZE = "tg_pool";
    /** Конфиг обхода только для прокси. Пусто - без обхода. */
    static final String STRATEGY = "tg_strategy";

    static final String DEFAULT_DC_IPS = "2:" + ProxyConfig.DEFAULT_DC_IP + "\n4:" + ProxyConfig.DEFAULT_DC_IP;
    static final int DEFAULT_PORT = 1443;
    static final int DEFAULT_BUF_KB = 256;
    static final int DEFAULT_POOL_SIZE = 4;

    private TgProxySettings() {
    }

    static SharedPreferences prefs(Context context) {
        return BypassVpnService.prefs(context);
    }

    /** Ключ создаётся один раз: Telegram запоминает его вместе с адресом прокси. */
    static String secret(Context context) {
        SharedPreferences prefs = prefs(context);
        String secret = prefs.getString(SECRET, null);
        if (!ProxyConfig.isValidSecret(secret)) {
            secret = ProxyConfig.randomSecret();
            prefs.edit().putString(SECRET, secret).apply();
        }
        return secret;
    }

    static String strategy(Context context) {
        return prefs(context).getString(STRATEGY, TgEngine.DIRECT);
    }

    static List<String> dcLines(String text) {
        List<String> lines = new ArrayList<>();
        for (String line : text.split("\\r?\\n")) {
            if (!line.trim().isEmpty()) {
                lines.add(line.trim());
            }
        }
        return lines;
    }

    static ProxyConfig load(Context context) {
        SharedPreferences prefs = prefs(context);
        ProxyConfig config = new ProxyConfig();
        config.port = prefs.getInt(PORT, DEFAULT_PORT);
        config.secret = secret(context);
        try {
            config.dcRedirects = ProxyConfig.parseDcIpList(dcLines(prefs.getString(DC_IPS, DEFAULT_DC_IPS)));
        } catch (IllegalArgumentException e) {
            // экран настроек не сохранит такую запись, но файл настроек мог быть восстановлен из старой версии
            config.dcRedirects = ProxyConfig.defaultDcRedirects();
        }
        config.fallbackCfproxy = prefs.getBoolean(CFPROXY, true);
        config.cfproxyUserDomains = ProxyConfig.coerceDomainList(prefs.getString(CF_DOMAINS, ""));
        config.cfproxyH2Media = prefs.getBoolean(H2, true);
        config.cfproxyWorkerDomains = ProxyConfig.coerceDomainList(prefs.getString(WORKER_DOMAINS, ""));
        config.disableSecure = prefs.getBoolean(NO_SECURE, false);
        config.bufferSize = Math.max(4, prefs.getInt(BUF_KB, DEFAULT_BUF_KB)) * 1024;
        config.poolSize = Math.max(0, prefs.getInt(POOL_SIZE, DEFAULT_POOL_SIZE));
        return config;
    }

    /** Домены, через которые прокси ходит к Cloudflare: они тоже должны попадать под обход. */
    static List<String> bypassDomains(Context context) {
        SharedPreferences prefs = prefs(context);
        List<String> domains = new ArrayList<>(Arrays.asList("workers.dev"));
        domains.addAll(org.zapretcap.tgproxy.CfDomains.defaults());
        domains.addAll(ProxyConfig.coerceDomainList(prefs.getString(CF_DOMAINS, "")));
        domains.addAll(ProxyConfig.coerceDomainList(prefs.getString(WORKER_DOMAINS, "")));
        return domains;
    }
}
