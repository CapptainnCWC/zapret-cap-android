package org.zapretcap.app;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Стратегии, списки и фейки: лежат в assets, движкам нужны как обычные файлы. */
final class Data {
    static final String EXT_VPN = ".vpn";
    private static final String[] DIRS = {"strategies", "lists", "fake"};
    /** TTL фейков в конфигах. Если подбор нашёл значение лучше, оно хранится отдельно для каждого конфига. */
    static final String FAKE_TTL = "8";
    static final String TTL_KEY_PREFIX = "ttl:";
    static final String STRATEGY_KEY_PREFIX = "strategy:";
    static final String SCORE_KEY_PREFIX = "score:";

    private Data() {
    }

    static File dir(Context context) {
        return new File(context.getFilesDir(), "data");
    }

    /** Копирует файлы один раз на каждую установленную версию. */
    static synchronized void extract(Context context) throws IOException {
        File dir = dir(context);
        File stamp = new File(dir, ".stamp");
        String version = packageStamp(context);
        if (stamp.exists() && version.equals(readFirstLine(stamp))) {
            return;
        }
        deleteRecursive(dir);
        AssetManager assets = context.getAssets();
        for (String sub : DIRS) {
            File target = new File(dir, sub);
            if (!target.mkdirs()) {
                throw new IOException("mkdir " + target);
            }
            for (String name : assets.list(sub)) {
                copy(assets, sub + "/" + name, new File(target, name));
            }
        }
        try (OutputStream out = new FileOutputStream(stamp)) {
            out.write(version.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String packageStamp(Context context) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            return info.versionName + "/" + info.lastUpdateTime;
        } catch (PackageManager.NameNotFoundException e) {
            return "";
        }
    }

    private static void copy(AssetManager assets, String from, File to) throws IOException {
        try (InputStream in = assets.open(from); OutputStream out = new FileOutputStream(to)) {
            byte[] buffer = new byte[16384];
            int n;
            while ((n = in.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
        }
    }

    private static void deleteRecursive(File file) {
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteRecursive(child);
            }
        }
        file.delete();
    }

    private static String readFirstLine(File file) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new java.io.FileInputStream(file), StandardCharsets.UTF_8))) {
            return reader.readLine();
        }
    }

    /**
     * Записывает действующие списки доменов перед запуском движка: те, что настроил человек, и домены,
     * через которые прокси Telegram ходит к Cloudflare. Их подсеть часто ограничена. В исходном проекте это
     * совет добавить их в zapret, здесь он выполняется сам. В assets этих имён нет, они зависят от настроек.
     */
    static void applyLists(Context context) throws IOException {
        List<String> telegram = TgProxySettings.bypassDomains(context);
        UserLists.apply(context, telegram);
        BypassSettings.apply(context);
        StringBuilder domains = new StringBuilder();
        for (String domain : telegram) {
            domains.append(domain).append('\n');
        }
        writeText(new File(new File(dir(context), "lists"), "list-telegram.txt"), domains.toString());
    }

    private static void writeText(File file, String text) throws IOException {
        try (OutputStream out = new FileOutputStream(file)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        }
    }

    /** Конфиг для вида сети: выбранный человеком, а если выбора ещё не было, рекомендованный для этой сети. */
    static String strategyFor(Context context, String kind) {
        String own = BypassVpnService.prefs(context).getString(STRATEGY_KEY_PREFIX + kind, null);
        return own != null ? own : recommended(kind);
    }

    /**
     * Что показало себя лучше в тестах на настоящих сетях: и на Wi-Fi, и на мобильной сети лучшим оказался один конфиг.
     * Отдельный выбор для каждой сети всё равно нужен: на другом провайдере лучшим может быть другой, его найдёт «Подобрать».
     */
    static String recommended(String kind) {
        return "vpn combo";
    }

    static void setStrategyFor(Context context, String kind, String name) {
        BypassVpnService.prefs(context).edit().putString(STRATEGY_KEY_PREFIX + kind, name).apply();
    }

    /** Имена стратегий: general первая, номера по порядку, ALT2 раньше ALT10. */
    static List<String> strategies(Context context) throws IOException {
        List<String> names = new ArrayList<>();
        for (String file : context.getAssets().list("strategies")) {
            if (file.endsWith(EXT_VPN)) {
                names.add(file.substring(0, file.length() - EXT_VPN.length()));
            }
        }
        Collections.sort(names, Data::compareNatural);
        return names;
    }

    static int compareNatural(String a, String b) {
        boolean generalA = a.equals("general");
        boolean generalB = b.equals("general");
        if (generalA != generalB) {
            return generalA ? -1 : 1;
        }
        return padNumbers(a).compareTo(padNumbers(b));
    }

    private static String padNumbers(String text) {
        StringBuilder out = new StringBuilder();
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i <= text.length(); i++) {
            char c = i < text.length() ? text.charAt(i) : 0;
            if (c >= '0' && c <= '9') {
                digits.append(c);
                continue;
            }
            if (digits.length() > 0) {
                for (int pad = digits.length(); pad < 6; pad++) {
                    out.append('0');
                }
                out.append(digits);
                digits.setLength(0);
            }
            if (c != 0) {
                out.append(c);
            }
        }
        return out.toString();
    }

    /** Process.isAlive появился только в Android 8, а приложение работает с Android 7. */
    static boolean isAlive(Process process) {
        try {
            process.exitValue();
            return false;
        } catch (IllegalThreadStateException running) {
            return true;
        }
    }

    /** TTL зависит от расстояния до оборудования провайдера, поэтому хранится отдельно для каждой сети. */
    static String ttlKey(String kind, String strategy) {
        return TTL_KEY_PREFIX + kind + ":" + strategy;
    }

    static String scoreKey(String kind, String strategy) {
        return SCORE_KEY_PREFIX + kind + ":" + strategy;
    }

    static List<String> ciadpiCommand(Context context, int port, int dnsPort, List<String> args) {
        List<String> command = new ArrayList<>();
        command.add(new File(context.getApplicationInfo().nativeLibraryDir, "libciadpi.so").getPath());
        command.add("-i");
        command.add("127.0.0.1");
        command.add("-p");
        command.add(Integer.toString(port));
        if (dnsPort > 0) {
            // настройка всего движка, поэтому раньше групп
            command.add("--dns-port");
            command.add(Integer.toString(dnsPort));
        }
        command.addAll(args);
        return command;
    }

    private static List<String> excludeFirst(List<String> lines) {
        List<String> ordered = new ArrayList<>();
        for (String line : lines) {
            if (line.contains("-exclude.txt")) {
                ordered.add(line);
            }
        }
        for (String line : lines) {
            if (!line.contains("-exclude.txt")) {
                ordered.add(line);
            }
        }
        return ordered;
    }

    /** Аргументы ciadpi с TTL, который выбрал человек, а если не выбрал - который подобрала проверка конфигов. */
    static List<String> vpnArgs(Context context, String kind, String strategy) throws IOException {
        int chosen = BypassSettings.fakeTtl(context, kind);
        if (chosen > 0) {
            return vpnArgs(context, strategy, chosen, true);
        }
        return vpnArgs(context, strategy, BypassVpnService.prefs(context).getInt(ttlKey(kind, strategy), 0), false);
    }

    static List<String> vpnArgs(Context context, String strategy, int ttl) throws IOException {
        return vpnArgs(context, strategy, ttl, false);
    }

    /**
     * Аргументы ciadpi: строка файла - группа, группы разделяет -An.
     *
     * @param ttl TTL фейков вместо записанного в конфиге, 0 - оставить как есть
     * @param everyFake заменить TTL всех фейков с малым TTL, а не только стандартный {@link #FAKE_TTL}:
     *                  так человек задаёт TTL для любого конфига, в том числе для vpn combo с его 5 и 6
     */
    static List<String> vpnArgs(Context context, String strategy, int ttl, boolean everyFake) throws IOException {
        File dir = dir(context);
        File file = new File(new File(dir, "strategies"), strategy + EXT_VPN);
        String lists = new File(dir, "lists").getPath();
        String fake = new File(dir, "fake").getPath();
        List<String> args = new ArrayList<>();
        boolean first = true;
        // Побеждает первая подходящая группа. Домен из «Не трогать» обязан идти без изменений в любом конфиге,
        // поэтому исключения проверяются раньше всех остальных групп с доменами.
        List<String> lines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new java.io.FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    lines.add(line);
                }
            }
        }
        for (String line : excludeFirst(lines)) {
            if (!first) {
                args.add("-An");
            }
            first = false;
            String previous = "";
            List<String> tokens = new ArrayList<>();
            for (String token : line.split("\\s+")) {
                // -t 64 у фейков UDP намеренно обычный, менять нужно только малый TTL
                boolean fakeTtl = ttl > 0 && previous.equals("-t")
                        && (everyFake ? isSmallTtl(token) : token.equals(FAKE_TTL));
                tokens.add(fakeTtl ? Integer.toString(ttl) : token);
                previous = token;
            }
            args.addAll(BypassSettings.substitute(context, tokens, lists, fake));
        }
        return args;
    }

    /** TTL фейка, который не должен дойти до сайта. Обычный TTL у фейков UDP (64) сюда не входит. */
    private static boolean isSmallTtl(String token) {
        try {
            int value = Integer.parseInt(token);
            return value > 0 && value < 32;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
