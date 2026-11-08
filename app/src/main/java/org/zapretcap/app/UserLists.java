package org.zapretcap.app;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Списки доменов, которые можно менять в приложении. Пока список не меняли, действует встроенный из assets.
 * Изменённый лежит вне папки data: её содержимое заменяется при каждом обновлении приложения.
 */
final class UserLists {
    enum Kind {
        GENERAL("general"), GOOGLE("google"), EXCLUDE("exclude");

        final String id;

        Kind(String id) {
            this.id = id;
        }

        String vpnFile() {
            return "vpn-list-" + id + ".txt";
        }
    }

    /** Пустой файл движки считают отсутствием фильтра, и обход применился бы ко всем сайтам. */
    private static final String PLACEHOLDER = "domain.example.abc";

    private static volatile boolean changed;

    private UserLists() {
    }

    private static File file(Context context, Kind kind) {
        return new File(new File(context.getFilesDir(), "user-lists"), kind.id + ".txt");
    }

    static boolean isCustom(Context context, Kind kind) {
        return file(context, kind).exists();
    }

    static synchronized List<String> load(Context context, Kind kind) throws IOException {
        File custom = file(context, kind);
        try (InputStream in = custom.exists() ? new FileInputStream(custom)
                : context.getAssets().open("lists/" + kind.vpnFile())) {
            return readLines(in);
        }
    }

    private static List<String> readLines(InputStream in) throws IOException {
        List<String> lines = new ArrayList<>();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String line;
        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (!line.isEmpty() && !line.startsWith("#")) {
                lines.add(line);
            }
        }
        return lines;
    }

    static synchronized void save(Context context, Kind kind, List<String> domains) throws IOException {
        File target = file(context, kind);
        File dir = target.getParentFile();
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("mkdir " + dir);
        }
        // сначала во временный файл: обрыв записи не должен оставить обрезанный список
        File temp = new File(dir, kind.id + ".tmp");
        try (OutputStream out = new FileOutputStream(temp)) {
            out.write((String.join("\n", domains) + "\n").getBytes(StandardCharsets.UTF_8));
        }
        if (!temp.renameTo(target)) {
            throw new IOException("rename " + target);
        }
        changed = true;
    }

    /**
     * Домен попадает ровно в один список: в разных конфигах группы идут в разном порядке,
     * и домен из двух списков работал бы то так, то эдак.
     */
    static synchronized void add(Context context, Kind kind, List<String> domains) throws IOException {
        for (Kind other : Kind.values()) {
            List<String> list = load(context, other);
            if (other == kind) {
                Set<String> merged = new LinkedHashSet<>(domains);
                merged.addAll(list);
                save(context, other, new ArrayList<>(merged));
            } else if (list.removeAll(domains)) {
                save(context, other, list);
            }
        }
    }

    static synchronized void reset(Context context, Kind kind) throws IOException {
        File custom = file(context, kind);
        if (custom.exists() && !custom.delete()) {
            throw new IOException("delete " + custom);
        }
        changed = true;
    }

    /** Было ли изменение со времени последнего вызова: работающий движок прочитает списки только при перезапуске. */
    static boolean consumeChanged() {
        boolean was = changed;
        changed = false;
        return was;
    }

    /**
     * Домен из того, что вставил человек: адрес сайта, домен с www, *.домен. null, если это не домен.
     * Списки движков покрывают и поддомены, поэтому www и маска не нужны.
     */
    static String normalize(String input) {
        String text = input.trim().toLowerCase(Locale.ROOT);
        int scheme = text.indexOf("://");
        if (scheme >= 0) {
            text = text.substring(scheme + 3);
        }
        int end = text.length();
        for (char stop : new char[]{'/', '?', '#', ':'}) {
            int at = text.indexOf(stop);
            if (at >= 0 && at < end) {
                end = at;
            }
        }
        text = text.substring(0, end);
        if (text.startsWith("*.")) {
            text = text.substring(2);
        } else if (text.startsWith(".")) {
            text = text.substring(1);
        }
        if (text.startsWith("www.") && text.indexOf('.', 4) > 0) {
            text = text.substring(4);
        }
        if (text.endsWith(".")) {
            text = text.substring(0, text.length() - 1);
        }
        // кириллический домен движок сравнивает только в виде xn--: он приходит из TLS именно так
        if (text.length() > 253 || !text.matches("[a-z0-9-]+(\\.[a-z0-9-]+)+")) {
            return null;
        }
        return text;
    }

    /** Несколько доменов одной строкой: через пробел, запятую или с новой строки. */
    static List<String> parse(String input, List<String> invalid) {
        Set<String> domains = new LinkedHashSet<>();
        for (String part : input.split("[\\s,;]+")) {
            if (part.isEmpty()) {
                continue;
            }
            String domain = normalize(part);
            if (domain != null) {
                domains.add(domain);
            } else {
                invalid.add(part);
            }
        }
        return new ArrayList<>(domains);
    }

    /** Домены, которые человек добавил к встроенному списку. */
    static List<String> added(Context context, Kind kind) throws IOException {
        List<String> list = load(context, kind);
        try (InputStream in = context.getAssets().open("lists/" + kind.vpnFile())) {
            list.removeAll(readLines(in));
        }
        return list;
    }

    /** Записывает действующие списки туда, откуда их читают движки. */
    static void apply(Context context, List<String> extraGeneral) throws IOException {
        File lists = new File(Data.dir(context), "lists");
        for (Kind kind : Kind.values()) {
            List<String> domains = load(context, kind);
            if (kind == Kind.GENERAL) {
                Set<String> merged = new LinkedHashSet<>(domains);
                merged.addAll(extraGeneral);
                domains = new ArrayList<>(merged);
            }
            write(new File(lists, kind.vpnFile()), domains);
        }
    }

    private static void write(File file, List<String> domains) throws IOException {
        StringBuilder text = new StringBuilder();
        for (String domain : domains) {
            text.append(domain).append('\n');
        }
        if (text.length() == 0) {
            text.append(PLACEHOLDER).append('\n');
        }
        try (OutputStream out = new FileOutputStream(file)) {
            out.write(text.toString().getBytes(StandardCharsets.UTF_8));
        }
    }
}
