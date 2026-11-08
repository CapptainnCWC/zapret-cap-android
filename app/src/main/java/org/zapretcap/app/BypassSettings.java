package org.zapretcap.app;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Настройки обхода из service.bat Windows-версии, которые имеют смысл на телефоне: IPSet Filter, Replace active fakes,
 * Update IPSet List и Update Hosts File. Для hosts права root не нужны: адреса подставляет локальный DNS приложения.
 * Фильтр игр не перенесён: в Windows он нужен для игр через Steam.
 */
final class BypassSettings {
    /** Режимы как в service.bat: none - профили IPSet ничего не ловят, loaded - список адресов, any - любые адреса. */
    enum IpsetMode {NONE, LOADED, ANY}

    static final String DISCORD_FAKE_DEFAULT = "ACTIVE_DISCORD_UDP.bin";
    /** Адрес из документации, его нет в интернете: так Windows-версия выключает профили IPSet. */
    private static final String IPSET_PLACEHOLDER = "203.0.113.113/32";
    private static final String IPSET_ASSET = "lists/ipset-service.txt";
    private static final String HOSTS_ASSET = "lists/hosts.txt";
    private static final String IPSET_URL =
            "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/ipset-service.txt";
    private static final String HOSTS_URL =
            "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/hosts";
    private static final Pattern CIDR = Pattern.compile("[0-9a-fA-F:.]+(/\\d{1,3})?");
    private static final int TIMEOUT_MS = 15000;

    private static final String KEY_IPSET = "ipset_mode";
    private static final String KEY_DISCORD_FAKE = "discord_fake";
    private static final String KEY_HOSTS = "hosts_enabled";

    private static volatile boolean changed;

    private BypassSettings() {
    }

    private static SharedPreferences prefs(Context context) {
        return BypassVpnService.prefs(context);
    }

    static IpsetMode ipsetMode(Context context) {
        try {
            return IpsetMode.valueOf(prefs(context).getString(KEY_IPSET, IpsetMode.NONE.name()));
        } catch (IllegalArgumentException e) {
            return IpsetMode.NONE;
        }
    }

    static void setIpsetMode(Context context, IpsetMode mode) {
        prefs(context).edit().putString(KEY_IPSET, mode.name()).apply();
        changed = true;
    }

    static String discordFake(Context context) {
        return prefs(context).getString(KEY_DISCORD_FAKE, DISCORD_FAKE_DEFAULT);
    }

    static void setDiscordFake(Context context, String name) {
        prefs(context).edit().putString(KEY_DISCORD_FAKE, name).apply();
        changed = true;
    }

    static boolean hostsEnabled(Context context) {
        return prefs(context).getBoolean(KEY_HOSTS, false);
    }

    static void setHostsEnabled(Context context, boolean enabled) {
        prefs(context).edit().putBoolean(KEY_HOSTS, enabled).apply();
        changed = true;
    }

    /** Было ли изменение со времени последнего вызова: движок прочитает настройки только при перезапуске. */
    static boolean consumeChanged() {
        boolean was = changed;
        changed = false;
        return was;
    }

    /** Обновлённые списки лежат вне папки data: её содержимое заменяется при каждом обновлении приложения. */
    static File ipsetFile(Context context) {
        return new File(new File(context.getFilesDir(), "user-lists"), "ipset.txt");
    }

    static File hostsFile(Context context) {
        return new File(new File(context.getFilesDir(), "user-lists"), "hosts.txt");
    }

    private static InputStream open(Context context, File updated, String asset) throws IOException {
        return updated.exists() ? new FileInputStream(updated) : context.getAssets().open(asset);
    }

    /** Фейки, которые можно поставить вместо фейка Discord: как Replace active fakes в Windows-версии. */
    static List<String> fakeChoices(Context context) throws IOException {
        List<String> names = new ArrayList<>();
        for (String name : context.getAssets().list("fake")) {
            if (name.endsWith(".bin") && !name.startsWith("ACTIVE_GAME")) {
                names.add(name);
            }
        }
        Collections.sort(names);
        names.remove(DISCORD_FAKE_DEFAULT);
        names.add(0, DISCORD_FAKE_DEFAULT);
        return names;
    }

    /** Записывает списки адресов туда, откуда их читает движок. */
    static void apply(Context context) throws IOException {
        File lists = new File(Data.dir(context), "lists");
        // локальные сети и служебные адреса из ipset-exclude.txt: их не трогает ни один профиль
        copy(new File(lists, "ipset-exclude.txt"), new File(lists, "vpn-ipset-exclude.txt"));
        File active = new File(lists, "vpn-ipset-all.txt");
        if (ipsetMode(context) == IpsetMode.LOADED) {
            try (InputStream in = open(context, ipsetFile(context), IPSET_ASSET); OutputStream out = new FileOutputStream(active)) {
                pipe(in, out);
            }
        } else {
            write(active, IPSET_PLACEHOLDER + "\n");
        }
    }

    /**
     * Подставляет настройки в аргументы движка. В режиме any у групп IPSet пропадает -j: они ловят любой адрес.
     */
    static List<String> substitute(Context context, List<String> tokens, String lists, String fake) {
        IpsetMode mode = ipsetMode(context);
        String discordFake = discordFake(context);
        List<String> out = new ArrayList<>(tokens.size());
        for (int i = 0; i < tokens.size(); i++) {
            String token = tokens.get(i);
            if (token.equals("-j") && i + 1 < tokens.size() && tokens.get(i + 1).equals("%IPSET%")) {
                if (mode != IpsetMode.ANY) {
                    out.add(token);
                    out.add(new File(lists, "vpn-ipset-all.txt").getPath());
                }
                i++;
                continue;
            }
            if (token.equals("%FAKE%/" + DISCORD_FAKE_DEFAULT)) {
                token = "%FAKE%/" + discordFake;
            }
            out.add(token.replace("%LISTS%", lists).replace("%FAKE%", fake));
        }
        return out;
    }

    static int ipsetCount(Context context) {
        int count = 0;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                open(context, ipsetFile(context), IPSET_ASSET), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    count++;
                }
            }
        } catch (IOException e) {
            return 0;
        }
        return count;
    }

    /** Имя - адреса. Пусто, если подмена выключена. */
    static Map<String, List<InetAddress>> hosts(Context context) {
        Map<String, List<InetAddress>> map = new HashMap<>();
        if (!hostsEnabled(context)) {
            return map;
        }
        try (InputStream in = open(context, hostsFile(context), HOSTS_ASSET)) {
            parseHosts(readAll(in), map);
        } catch (IOException e) {
            return map;
        }
        return map;
    }

    static int hostsCount(Context context) {
        Map<String, List<InetAddress>> map = new HashMap<>();
        try (InputStream in = open(context, hostsFile(context), HOSTS_ASSET)) {
            parseHosts(readAll(in), map);
        } catch (IOException e) {
            return 0;
        }
        return map.size();
    }

    private static int parseHosts(String text, Map<String, List<InetAddress>> map) {
        int entries = 0;
        for (String raw : text.split("\n")) {
            String line = raw.trim();
            int comment = line.indexOf('#');
            if (comment >= 0) {
                line = line.substring(0, comment).trim();
            }
            String[] parts = line.split("\\s+");
            if (parts.length < 2 || !CIDR.matcher(parts[0]).matches() || parts[0].contains("/")) {
                continue;
            }
            InetAddress address;
            try {
                // только числовой адрес: getByName с именем ушёл бы в DNS
                address = InetAddress.getByName(parts[0]);
            } catch (IOException e) {
                continue;
            }
            if (address.isAnyLocalAddress()) {
                continue;
            }
            for (int i = 1; i < parts.length; i++) {
                map.computeIfAbsent(parts[i].toLowerCase(Locale.ROOT), k -> new ArrayList<>()).add(address);
                entries++;
            }
        }
        return entries;
    }

    /** Скачивает свежий список IPSet. Возвращает число подсетей. */
    static int updateIpset(Context context) throws IOException {
        String text = download(IPSET_URL);
        int count = 0;
        for (String raw : text.split("\n")) {
            String line = raw.trim();
            if (line.isEmpty()) {
                continue;
            }
            if (!CIDR.matcher(line).matches()) {
                throw new IOException("не похоже на список адресов: " + line);
            }
            count++;
        }
        if (count < 100) {
            throw new IOException("слишком короткий список: " + count);
        }
        save(ipsetFile(context), text);
        changed = true;
        return count;
    }

    /** Скачивает свежий список hosts. Возвращает число имён. */
    static int updateHosts(Context context) throws IOException {
        String text = download(HOSTS_URL);
        Map<String, List<InetAddress>> map = new HashMap<>();
        parseHosts(text, map);
        if (map.isEmpty()) {
            throw new IOException("в файле нет ни одной записи");
        }
        save(hostsFile(context), text);
        changed = true;
        return map.size();
    }

    /**
     * Сначала напрямую: приложение исключено из VPN. GitHub бывает недоступен без обхода, тогда через движок,
     * если обход сейчас включён.
     */
    static String download(String url) throws IOException {
        IOException direct;
        try {
            return fetch(url, Proxy.NO_PROXY);
        } catch (IOException e) {
            direct = e;
        }
        int socks = BypassVpnService.enginePort;
        if (socks > 0) {
            return fetch(url, new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", socks)));
        }
        throw direct;
    }

    private static String fetch(String url, Proxy proxy) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection(proxy);
        connection.setConnectTimeout(TIMEOUT_MS);
        connection.setReadTimeout(TIMEOUT_MS);
        try {
            int code = connection.getResponseCode();
            if (code != 200) {
                throw new IOException("GitHub ответил " + code);
            }
            try (InputStream in = connection.getInputStream()) {
                return readAll(in);
            }
        } finally {
            connection.disconnect();
        }
    }

    private static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        pipe(in, out);
        return out.toString("UTF-8").replace("\r", "");
    }

    private static void pipe(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[16384];
        int n;
        while ((n = in.read(buffer)) > 0) {
            out.write(buffer, 0, n);
        }
    }

    private static void copy(File from, File to) throws IOException {
        try (InputStream in = new FileInputStream(from); OutputStream out = new FileOutputStream(to)) {
            pipe(in, out);
        }
    }

    private static void write(File file, String text) throws IOException {
        try (OutputStream out = new FileOutputStream(file)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        }
    }

    /** Сначала во временный файл: обрыв записи не должен оставить обрезанный список. */
    private static void save(File target, String text) throws IOException {
        File dir = target.getParentFile();
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("mkdir " + dir);
        }
        File temp = new File(dir, target.getName() + ".tmp");
        write(temp, text);
        if (!temp.renameTo(target)) {
            throw new IOException("rename " + target);
        }
    }
}
