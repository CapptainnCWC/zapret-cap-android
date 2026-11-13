package org.zapretcap.app;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ComponentInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.os.Build;
import android.os.Process;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Тестовая сборка: через что приходят пуш-уведомления. Пишет в files/push-log.txt:
 * - соединения приложений с пуш-сервисами (Google FCM, Xiaomi, Huawei, RuStore/VK и любые хосты с push в имени),
 *   с открытием и закрытием. Видны только при включённом обходе: соединения берутся из туннеля;
 * - каждое уведомление: приложение, время, какие пуш-SDK в нём есть, какие пуш-каналы были открыты в этот момент
 *   и с какими серверами само приложение соединялось за минуту до него. Текст уведомлений не пишется.
 */
final class PushLog {
    private static final String TAG = "ZapretCapPush";
    private static final long MAX_BYTES = 10L * 1024 * 1024;
    private static final long RECENT_MS = 60_000;
    private static final int MAX_NAMES = 8192;
    private static final ExecutorService WRITER = Executors.newSingleThreadExecutor();

    private static volatile Context app;
    /** Адрес - имя из ответов DNS: в туннеле видны только адреса. */
    private static final Map<String, String> NAMES = new ConcurrentHashMap<>();
    /** Открытые соединения туннеля: номер из hev - описание. */
    private static final Map<String, Conn> OPEN = new ConcurrentHashMap<>();
    /** Недавно открытые соединения всех приложений: для контекста уведомлений. */
    private static final ArrayDeque<Conn> RECENT = new ArrayDeque<>();
    private static final Map<String, String> SDKS = new ConcurrentHashMap<>();
    private static volatile Thread tail;

    private static final class Conn {
        final long opened = System.currentTimeMillis();
        String packages;
        int uid;
        String address;
        int port;
        String host;
        String channel;
    }

    private PushLog() {
    }

    static void init(Context context) {
        if (app == null) {
            app = context.getApplicationContext();
        }
    }

    static File file(Context context) {
        return new File(context.getFilesDir(), "push-log.txt");
    }

    static void write(String message) {
        Log.i(TAG, message);
        Context context = app;
        if (context == null) {
            return;
        }
        File target = file(context);
        String line = new SimpleDateFormat("MM-dd HH:mm:ss", Locale.ROOT).format(new Date()) + " " + message + "\n";
        WRITER.execute(() -> {
            try {
                if (target.length() > MAX_BYTES) {
                    File old = new File(target.getParentFile(), "push-log.1.txt");
                    old.delete();
                    target.renameTo(old);
                }
                try (OutputStream out = new FileOutputStream(target, true)) {
                    out.write(line.getBytes(StandardCharsets.UTF_8));
                }
            } catch (IOException e) {
                Log.w(TAG, "log write", e);
            }
        });
    }

    static void clear(Context context) {
        WRITER.execute(() -> {
            file(context).delete();
            new File(context.getFilesDir(), "push-log.1.txt").delete();
        });
    }

    /** Размер журнала в КБ: показывает, что он пишется. */
    static long sizeKb(Context context) {
        return (file(context).length() + new File(context.getFilesDir(), "push-log.1.txt").length()) / 1024;
    }

    // --- DNS

    /** Запоминает адреса из ответа DNS под именем, которое спрашивало приложение. */
    static void onDnsReply(byte[] packet) {
        if (packet == null || packet.length < 12 || (packet[3] & 0x0f) != 0) {
            return;
        }
        int questions = (packet[4] & 0xff) << 8 | packet[5] & 0xff;
        int answers = (packet[6] & 0xff) << 8 | packet[7] & 0xff;
        if (questions != 1 || answers == 0) {
            return;
        }
        StringBuilder name = new StringBuilder();
        int offset = 12;
        while (offset < packet.length) {
            int length = packet[offset] & 0xff;
            if (length == 0) {
                offset++;
                break;
            }
            if ((length & 0xC0) != 0 || offset + 1 + length > packet.length) {
                return;
            }
            if (name.length() > 0) {
                name.append('.');
            }
            name.append(new String(packet, offset + 1, length, StandardCharsets.US_ASCII).toLowerCase(Locale.ROOT));
            offset += length + 1;
        }
        offset += 4;
        String host = name.toString();
        for (int i = 0; i < answers; i++) {
            offset = skipName(packet, offset);
            if (offset < 0 || offset + 10 > packet.length) {
                return;
            }
            int type = (packet[offset] & 0xff) << 8 | packet[offset + 1] & 0xff;
            int size = (packet[offset + 8] & 0xff) << 8 | packet[offset + 9] & 0xff;
            offset += 10;
            if (offset + size > packet.length) {
                return;
            }
            if ((type == 1 && size == 4) || (type == 28 && size == 16)) {
                try {
                    byte[] raw = new byte[size];
                    System.arraycopy(packet, offset, raw, 0, size);
                    if (NAMES.size() > MAX_NAMES) {
                        NAMES.clear();
                    }
                    NAMES.put(InetAddress.getByAddress(raw).getHostAddress(), host);
                } catch (IOException ignored) {
                    // длина проверена
                }
            }
            offset += size;
        }
    }

    private static int skipName(byte[] packet, int offset) {
        while (offset < packet.length) {
            int length = packet[offset] & 0xff;
            if (length == 0) {
                return offset + 1;
            }
            if ((length & 0xC0) == 0xC0) {
                return offset + 2;
            }
            offset += length + 1;
        }
        return -1;
    }

    // --- соединения из туннеля

    /** Читает журнал соединений hev, пока работает туннель. Файл только обрезается: hev держит его открытым. */
    static synchronized void startTail(Context context, File sessions) {
        init(context);
        stopTail();
        try {
            new RandomAccessFile(sessions, "rw").setLength(0);
        } catch (IOException e) {
            write("session log unavailable: " + e);
            return;
        }
        OPEN.clear();
        Thread thread = new Thread(() -> tailLoop(context, sessions), "push-tail");
        thread.setDaemon(true);
        tail = thread;
        thread.start();
        write("== обход включён, соединения пишутся");
    }

    static synchronized void stopTail() {
        Thread thread = tail;
        tail = null;
        if (thread != null) {
            thread.interrupt();
            write("== обход выключен, соединения не видны (уведомления пишутся дальше)");
        }
    }

    private static void tailLoop(Context context, File sessions) {
        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        long position = 0;
        StringBuilder partial = new StringBuilder();
        byte[] buffer = new byte[16384];
        while (!Thread.currentThread().isInterrupted()) {
            try (RandomAccessFile in = new RandomAccessFile(sessions, "rw")) {
                long length = in.length();
                if (length < position) {
                    position = 0;
                }
                if (length > position) {
                    in.seek(position);
                    int n;
                    while ((n = in.read(buffer)) > 0) {
                        position += n;
                        partial.append(new String(buffer, 0, n, StandardCharsets.US_ASCII));
                        int end;
                        while ((end = partial.indexOf("\n")) >= 0) {
                            handle(context, manager, partial.substring(0, end));
                            partial.delete(0, end + 1);
                        }
                    }
                    if (position > 2 * 1024 * 1024) {
                        // всё прочитано: обрезаем, hev пишет с O_APPEND и продолжит с начала
                        in.setLength(0);
                        position = 0;
                    }
                }
            } catch (IOException e) {
                Log.w(TAG, "tail", e);
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    private static void handle(Context context, ConnectivityManager manager, String line) {
        String[] parts = line.trim().split(" ");
        if (parts.length >= 6 && parts[0].equals("O")) {
            Conn conn = new Conn();
            try {
                conn.address = InetAddress.getByName(parts[4]).getHostAddress();
                conn.port = Integer.parseInt(parts[5]);
                int sourcePort = Integer.parseInt(parts[3]);
                conn.uid = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                        ? manager.getConnectionOwnerUid(6, // IPPROTO_TCP
                        new InetSocketAddress(InetAddress.getByName(parts[2]), sourcePort),
                        new InetSocketAddress(InetAddress.getByName(conn.address), conn.port))
                        : Process.INVALID_UID;
            } catch (IOException | RuntimeException e) {
                return;
            }
            conn.packages = packages(context, conn.uid);
            conn.host = NAMES.get(conn.address);
            conn.channel = channel(conn.host, conn.port, conn.packages);
            OPEN.put(parts[1], conn);
            synchronized (RECENT) {
                RECENT.addLast(conn);
                long border = System.currentTimeMillis() - RECENT_MS;
                while (!RECENT.isEmpty() && RECENT.peekFirst().opened < border) {
                    RECENT.removeFirst();
                }
            }
            if (conn.channel != null) {
                write("CONN open  " + conn.channel + " | " + conn.packages + " -> " + describe(conn));
            }
        } else if (parts.length >= 2 && parts[0].equals("C")) {
            Conn conn = OPEN.remove(parts[1]);
            if (conn != null && conn.channel != null) {
                long seconds = (System.currentTimeMillis() - conn.opened) / 1000;
                write("CONN close " + conn.channel + " | " + conn.packages + " -> " + describe(conn)
                        + " after " + seconds + " s");
            }
        }
    }

    private static String describe(Conn conn) {
        return (conn.host != null ? conn.host + " " : "") + conn.address + ":" + conn.port;
    }

    /** Чей это пуш-канал, или null, если соединение на пуш не похоже. */
    static String channel(String host, int port, String packages) {
        String h = host == null ? "" : host;
        if ((port >= 5228 && port <= 5230) || h.endsWith("mtalk.google.com")) {
            return "Google FCM";
        }
        if (h.contains("xmpush") || h.contains("mipush") || packages.contains("com.xiaomi.xmsf")) {
            return "Xiaomi MiPush";
        }
        if (h.endsWith("push.hicloud.com") || h.endsWith("push.dbankcloud.com") || packages.contains("com.huawei.hwid")) {
            return "Huawei HMS Push";
        }
        if (h.contains("vkpns") || (h.contains("rustore") && h.contains("push"))) {
            return "RuStore/VK Push";
        }
        if (h.contains("push") || h.contains("notif") || port == 5222 || port == 5223) {
            return "push (" + (h.isEmpty() ? "порт " + port : h) + ")";
        }
        return null;
    }

    private static String packages(Context context, int uid) {
        if (uid < 0) {
            return "?";
        }
        String[] names = context.getPackageManager().getPackagesForUid(uid);
        if (names == null || names.length == 0) {
            return "uid" + uid;
        }
        return String.join(",", names);
    }

    // --- уведомления

    static void onNotification(Context context, String pkg, String channelId, String category) {
        init(context);
        StringBuilder text = new StringBuilder("NOTIF ").append(pkg);
        if (channelId != null) {
            text.append(" channel=").append(channelId);
        }
        if (category != null) {
            text.append(" category=").append(category);
        }
        text.append("\n      встроено: ").append(sdks(context, pkg));
        text.append("\n      открытые пуш-каналы: ").append(openChannels());
        text.append("\n      соединения приложения за минуту: ").append(recentOf(pkg));
        write(text.toString());
    }

    private static String openChannels() {
        if (tail == null) {
            return "не видно, обход выключен";
        }
        Map<String, Set<String>> byChannel = new LinkedHashMap<>();
        for (Conn conn : OPEN.values()) {
            if (conn.channel != null) {
                byChannel.computeIfAbsent(conn.channel, k -> new LinkedHashSet<>()).add(conn.packages);
            }
        }
        if (byChannel.isEmpty()) {
            return "нет";
        }
        List<String> items = new ArrayList<>();
        for (Map.Entry<String, Set<String>> entry : byChannel.entrySet()) {
            items.add(entry.getKey() + " (" + String.join(", ", entry.getValue()) + ")");
        }
        return String.join("; ", items);
    }

    private static String recentOf(String pkg) {
        if (tail == null) {
            return "не видно, обход выключен";
        }
        Set<String> hosts = new LinkedHashSet<>();
        synchronized (RECENT) {
            Iterator<Conn> it = RECENT.descendingIterator();
            long border = System.currentTimeMillis() - RECENT_MS;
            while (it.hasNext()) {
                Conn conn = it.next();
                if (conn.opened < border) {
                    break;
                }
                if (conn.packages.contains(pkg)) {
                    hosts.add(describe(conn));
                }
            }
        }
        return hosts.isEmpty() ? "нет" : String.join(", ", hosts);
    }

    /** Какие пуш-SDK встроены в приложение: по его службам и приёмникам. */
    static String sdks(Context context, String pkg) {
        String cached = SDKS.get(pkg);
        if (cached != null) {
            return cached;
        }
        PackageManager pm = context.getPackageManager();
        Set<String> found = new LinkedHashSet<>();
        if (!pm.queryIntentServices(new Intent("com.google.firebase.MESSAGING_EVENT").setPackage(pkg), 0).isEmpty()) {
            found.add("Google FCM");
        }
        if (!pm.queryIntentServices(new Intent("com.huawei.push.action.MESSAGING_EVENT").setPackage(pkg), 0).isEmpty()) {
            found.add("Huawei HMS");
        }
        try {
            PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SERVICES | PackageManager.GET_RECEIVERS);
            List<ComponentInfo> components = new ArrayList<>();
            if (info.services != null) {
                java.util.Collections.addAll(components, info.services);
            }
            if (info.receivers != null) {
                java.util.Collections.addAll(components, info.receivers);
            }
            for (ComponentInfo component : components) {
                String name = component.name;
                if (name.startsWith("ru.rustore.sdk.pushclient")) {
                    found.add("RuStore Push");
                } else if (name.startsWith("com.vk.push")) {
                    found.add("VK Push");
                } else if (name.startsWith("com.xiaomi.mipush") || name.startsWith("com.xiaomi.push")) {
                    found.add("Xiaomi MiPush");
                } else if (name.startsWith("com.huawei.hms.push")) {
                    found.add("Huawei HMS");
                } else if (name.startsWith("com.onesignal")) {
                    found.add("OneSignal (поверх FCM)");
                } else if (name.startsWith("com.pushwoosh")) {
                    found.add("Pushwoosh (поверх FCM)");
                } else if (name.startsWith("com.google.firebase.messaging")) {
                    found.add("Google FCM");
                }
            }
        } catch (PackageManager.NameNotFoundException e) {
            return "?";
        }
        String result = found.isEmpty() ? "пуш-SDK не найдено, своё соединение или ничего" : String.join(", ", found);
        SDKS.put(pkg, result);
        return result;
    }
}
