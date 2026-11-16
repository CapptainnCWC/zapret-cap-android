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
import java.util.Collections;
import java.util.List;

/**
 * Режим root: настоящий nfqws2 из zapret2 и те же стратегии, что в Linux-версии, без перевода в приёмы ByeDPI.
 * Движок получает пакеты из очереди NFQUEUE и сам отправляет обманки с неверными номерами TCP и меткой времени,
 * поэтому малый TTL не нужен. Правила iptables повторяют lib/engine.sh Linux-версии.
 *
 * nfqws2 работает отдельным процессом root и переживает остановку приложения: обход не засыпает вместе с ним.
 */
final class RootEngine {
    static final String EXT = ".conf";
    private static final String QNUM = "310";
    private static final String FWMARK = "0x40000000";
    private static final String CHAIN_POST = "zapret_cap_post";
    private static final String CHAIN_PRE = "zapret_cap_pre";
    /** Сколько первых пакетов соединения отдавать движку: стратегии работают с началом соединения. */
    private static final int PKT_OUT_TCP = 20;
    private static final int PKT_IN_TCP = 10;
    private static final int PKT_OUT_UDP = 12;
    private static final int PKT_IN_UDP = 3;
    /** Игровой фильтр выключен: как в Linux-версии, вместо диапазона портов стоит заведомо пустой порт. */
    private static final String GAME_FILTER_OFF = "12";
    private static final String[] LUA = {"zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua", "zapret-cap.lua"};
    private static final long TIMEOUT_MS = 30_000;

    private RootEngine() {
    }

    /** Имена стратегий root-режима в том же порядке, что и обычные. */
    static List<String> strategies(Context context) throws IOException {
        List<String> names = new ArrayList<>();
        String[] files = context.getAssets().list("root/strategies");
        if (files != null) {
            for (String file : files) {
                if (file.endsWith(EXT)) {
                    names.add(file.substring(0, file.length() - EXT.length()));
                }
            }
        }
        Collections.sort(names, Data::compareNatural);
        return names;
    }

    private static File runDir(Context context) {
        File dir = new File(context.getFilesDir(), "root-run");
        dir.mkdirs();
        return dir;
    }

    private static String binary(Context context) {
        return new File(context.getApplicationInfo().nativeLibraryDir, "libnfqws2.so").getPath();
    }

    /**
     * Запускает стратегию. Перед запуском останавливает прежний движок и убирает его правила.
     *
     * @param anyIpset группы IPSet ловят любой адрес: для проверки фризов на адресах хостингов
     */
    static void start(Context context, String strategy, boolean anyIpset) throws IOException {
        Data.extract(context);
        Data.applyLists(context);
        prepareLists(context, anyIpset);
        Conf conf = Conf.read(context, strategy);
        String run = runDir(context).getPath();
        String nfq = quote(binary(context));
        StringBuilder args = new StringBuilder();
        args.append(" --qnum=").append(QNUM).append(" --fwmark=").append(FWMARK);
        // После запуска nfqws2 сбрасывает права root, оставляя себе только сетевые привилегии. По умолчанию он
        // становится «никем» и не может прочитать списки в папке приложения, поэтому работает от имени приложения.
        // 3003 - группа inet: без неё Android не даёт открывать сетевые сокеты
        int uid = android.os.Process.myUid();
        args.append(" --uid=").append(uid).append(':').append(uid).append(",3003");
        File lua = new File(Data.dir(context), "root/lua");
        for (String name : LUA) {
            args.append(' ').append(quote("--lua-init=@" + new File(lua, name).getPath()));
        }
        for (String arg : conf.args) {
            args.append(' ').append(quote(arg));
        }
        String log = quote(run + "/nfqws2.log");
        String pid = quote(run + "/nfqws2.pid");
        StringBuilder script = new StringBuilder();
        script.append(stopScript(run));
        // стратегии с меткой времени TCP не работают, если она выключена
        script.append("[ \"$(cat /proc/sys/net/ipv4/tcp_timestamps 2>/dev/null)\" = 0 ] && echo 1 > /proc/sys/net/ipv4/tcp_timestamps\n");
        script.append(nfq).append(" --dry-run").append(args).append(" >").append(log)
                .append(" 2>&1 || { echo 'ZC: стратегия не прошла проверку параметров'; tail -n 5 ").append(log).append("; exit 21; }\n");
        script.append(firewallScript(conf));
        script.append("if [ $? -ne 0 ]; then echo 'ZC: не удалось применить правила iptables'; zc_down; exit 22; fi\n");
        // без этого conntrack считает ответы на пакеты с перекрытием номеров недействительными
        script.append("L=/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal\n")
                .append("if [ -w $L ]; then [ -f ").append(quote(run + "/liberal")).append(" ] || cat $L > ")
                .append(quote(run + "/liberal")).append("; echo 1 > $L; fi\n");
        script.append(nfq).append(" --daemon --pidfile=").append(pid).append(args).append(" >").append(log)
                .append(" 2>&1 || { echo 'ZC: nfqws2 не запустился'; tail -n 5 ").append(log).append("; zc_down; exit 23; }\n");
        script.append("i=0; while [ ! -s ").append(pid).append(" ] && [ $i -lt 20 ]; do sleep 0.1; i=$((i+1)); done\n");
        script.append("sleep 0.3\n");
        script.append("P=$(cat ").append(pid).append(" 2>/dev/null)\n");
        script.append("if [ -z \"$P\" ] || [ ! -d /proc/$P ]; then echo 'ZC: nfqws2 завершился сразу после запуска'; tail -n 5 ")
                .append(log).append("; zc_down; exit 24; fi\n");
        script.append("chmod 644 ").append(pid).append(' ').append(log).append(" 2>/dev/null\nexit 0\n");
        RootShell.Result result = RootShell.exec(context, script.toString(), TIMEOUT_MS);
        if (!result.ok()) {
            throw new IOException(message(result));
        }
    }

    static void stop(Context context) throws IOException {
        RootShell.Result result = RootShell.exec(context, stopScript(runDir(context).getPath()) + "exit 0\n", TIMEOUT_MS);
        if (!result.ok()) {
            throw new IOException(message(result));
        }
    }

    /** Работает ли движок и на месте ли его правила: их мог сбросить системный сервис сети. */
    static boolean running(Context context) {
        String pid = quote(runDir(context).getPath() + "/nfqws2.pid");
        String script = "P=$(cat " + pid + " 2>/dev/null)\n"
                + "[ -n \"$P\" ] && [ -d /proc/$P ] && grep -q nfqws2 /proc/$P/cmdline 2>/dev/null"
                + " && iptables -w 5 -t mangle -S " + CHAIN_POST + " >/dev/null 2>&1\n";
        try {
            return RootShell.exec(context, script, TIMEOUT_MS).ok();
        } catch (IOException e) {
            return false;
        }
    }

    private static String message(RootShell.Result result) {
        StringBuilder text = new StringBuilder();
        for (String line : result.output.split("\n")) {
            line = line.trim();
            if (!line.isEmpty()) {
                text.append(text.length() > 0 ? " " : "").append(line.startsWith("ZC: ") ? line.substring(4) : line);
            }
        }
        return text.length() > 0 ? text.toString() : "команда root завершилась с кодом " + result.code;
    }

    /** Функция zc_down и её вызов: останавливает движок, убирает цепочки и возвращает настройку conntrack. */
    private static String stopScript(String run) {
        String pid = quote(run + "/nfqws2.pid");
        String liberal = quote(run + "/liberal");
        return "zc_down() {\n"
                + "P=$(cat " + pid + " 2>/dev/null)\n"
                + "if [ -n \"$P\" ] && [ -d /proc/$P ] && grep -q nfqws2 /proc/$P/cmdline 2>/dev/null; then\n"
                + " kill $P 2>/dev/null; i=0; while [ -d /proc/$P ] && [ $i -lt 15 ]; do sleep 0.1; i=$((i+1)); done\n"
                + " [ -d /proc/$P ] && kill -9 $P 2>/dev/null\n"
                + "fi\n"
                // движок от прошлой установки приложения: файла с его номером уже нет
                + "pkill -x libnfqws2.so 2>/dev/null\n"
                + "rm -f " + pid + "\n"
                + "for t in iptables ip6tables; do\n"
                + " while $t -w 5 -t mangle -D POSTROUTING -j " + CHAIN_POST + " 2>/dev/null; do :; done\n"
                + " while $t -w 5 -t mangle -D PREROUTING -j " + CHAIN_PRE + " 2>/dev/null; do :; done\n"
                + " while $t -w 5 -t raw -D OUTPUT -j " + CHAIN_POST + " 2>/dev/null; do :; done\n"
                + " for table in mangle raw; do for chain in " + CHAIN_POST + " " + CHAIN_PRE + "; do\n"
                + "  $t -w 5 -t $table -F $chain 2>/dev/null; $t -w 5 -t $table -X $chain 2>/dev/null\n"
                + " done; done\n"
                + "done\n"
                + "if [ -f " + liberal + " ]; then cat " + liberal
                + " > /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal 2>/dev/null; rm -f " + liberal + "; fi\n"
                + "return 0\n"
                + "}\n"
                + "zc_down\n";
    }

    /**
     * Правила как в ipt_up Linux-версии: в очередь идут первые пакеты соединений на портах стратегии и пакеты
     * с флагами начала и конца. Если в ядре нет счётчика пакетов соединения (connbytes), исходящие пакеты идут
     * в очередь все, а входящие только с флагами: движок сам отбирает нужное, но нагрузка на процессор выше.
     */
    private static String firewallScript(Conf conf) {
        String tcp = conf.portsTcp.replace('-', ':');
        String udp = conf.portsUdp.replace('-', ':');
        String jump = "-j NFQUEUE --queue-num " + QNUM + " --queue-bypass";
        String nomark = "-m mark ! --mark " + FWMARK + "/" + FWMARK;
        String orig = "-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes";
        String reply = "-m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes";
        String post = CHAIN_POST;
        String pre = CHAIN_PRE;
        return "zc_up() {\n"
                + "for t in iptables ip6tables; do\n"
                + " I=\"$t -w 5\"\n"
                + " $I -t mangle -N " + post + " 2>/dev/null; $I -t mangle -N " + pre + " 2>/dev/null\n"
                + " $I -t mangle -A POSTROUTING -j " + post + " || { [ $t = ip6tables ] && continue; return 1; }\n"
                + " $I -t mangle -A PREROUTING -j " + pre + " || return 1\n"
                + " $I -t mangle -A " + post + " -o lo -j RETURN\n"
                + " if $I -t mangle -A " + post + " " + nomark + " -p tcp -m multiport --dports " + tcp + " " + orig + " 1:" + PKT_OUT_TCP + " " + jump + " 2>/dev/null; then\n"
                + "  $I -t mangle -A " + post + " " + nomark + " -p udp -m multiport --dports " + udp + " " + orig + " 1:" + PKT_OUT_UDP + " " + jump + " || return 1\n"
                + "  $I -t mangle -A " + pre + " -p tcp -m multiport --sports " + tcp + " " + reply + " 1:" + PKT_IN_TCP + " " + jump + "\n"
                + "  $I -t mangle -A " + pre + " -p udp -m multiport --sports " + udp + " " + reply + " 1:" + PKT_IN_UDP + " " + jump + "\n"
                + " else\n"
                + "  echo 'ZC: в ядре нет connbytes, в очередь идут все исходящие пакеты'\n"
                + "  $I -t mangle -A " + post + " " + nomark + " -p tcp -m multiport --dports " + tcp + " " + jump + " || return 1\n"
                + "  $I -t mangle -A " + post + " " + nomark + " -p udp -m multiport --dports " + udp + " " + jump + " || return 1\n"
                + " fi\n"
                + " $I -t mangle -A " + post + " " + nomark + " -p tcp -m multiport --dports " + tcp + " --tcp-flags FIN FIN " + jump + "\n"
                + " $I -t mangle -A " + post + " " + nomark + " -p tcp -m multiport --dports " + tcp + " --tcp-flags RST RST " + jump + "\n"
                + " $I -t mangle -I " + pre + " 1 -i lo -j RETURN\n"
                + " $I -t mangle -A " + pre + " -p tcp -m multiport --sports " + tcp + " --tcp-flags SYN,ACK SYN,ACK " + jump + "\n"
                + " $I -t mangle -A " + pre + " -p tcp -m multiport --sports " + tcp + " --tcp-flags FIN FIN " + jump + "\n"
                + " $I -t mangle -A " + pre + " -p tcp -m multiport --sports " + tcp + " --tcp-flags RST RST " + jump + "\n"
                // пакеты самого движка не должны попадать в conntrack, кроме SYN: его заменяет syndata,
                // и без записи о соединении счётчик пакетов дальше ничего бы не отдал движку
                + " $I -t raw -N " + post + " 2>/dev/null\n"
                + " if $I -t raw -A OUTPUT -j " + post + " 2>/dev/null; then\n"
                + "  $I -t raw -A " + post + " -m mark --mark " + FWMARK + "/" + FWMARK + " -p tcp --tcp-flags SYN SYN -j RETURN\n"
                + "  $I -t raw -A " + post + " -m mark --mark " + FWMARK + "/" + FWMARK + " -j CT --notrack 2>/dev/null\n"
                + " fi\n"
                + "done\n"
                + "return 0\n"
                + "}\n"
                + "zc_up\n";
    }

    /** Списки под именами, которых ждут стратегии nfqws2: действующие списки приложения уже лежат рядом. */
    private static void prepareLists(Context context, boolean anyIpset) throws IOException {
        File lists = new File(Data.dir(context), "lists");
        for (String id : new String[]{"general", "google", "exclude"}) {
            copy(new File(lists, "vpn-list-" + id + ".txt"), new File(lists, "list-" + id + ".txt"));
        }
        // пустой список nfqws2 считает отсутствием фильтра, поэтому в дополнительных файлах стоит заглушка
        write(new File(lists, "list-general-user.txt"), "domain.example.abc\n");
        write(new File(lists, "list-exclude-user.txt"), "domain.example.abc\n");
        write(new File(lists, "ipset-exclude-user.txt"), "203.0.113.113/32\n");
        File ipset = new File(lists, "ipset-all.txt");
        if (anyIpset || BypassSettings.ipsetMode(context) == BypassSettings.IpsetMode.ANY) {
            // пустой файл: группа IPSet применяется к любому адресу
            write(ipset, "");
        } else {
            // заглушка в режиме «выключен» или загруженный список: их уже подготовил BypassSettings.apply
            copy(new File(lists, "vpn-ipset-all.txt"), ipset);
        }
    }

    private static void copy(File from, File to) throws IOException {
        try (InputStream in = new FileInputStream(from); OutputStream out = new FileOutputStream(to)) {
            byte[] buffer = new byte[16384];
            int n;
            while ((n = in.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
        }
    }

    private static void write(File file, String text) throws IOException {
        try (OutputStream out = new FileOutputStream(file)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        }
    }

    /** Аргумент в одинарных кавычках: в путях и значениях стратегий встречаются скобки, пробелы и знаки < >. */
    static String quote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    /** Разобранная стратегия: порты для правил iptables и аргументы nfqws2 с подставленными путями. */
    static final class Conf {
        String portsTcp = "";
        String portsUdp = "";
        final List<String> args = new ArrayList<>();

        static Conf read(Context context, String strategy) throws IOException {
            File dir = Data.dir(context);
            File file = new File(new File(dir, "root/strategies"), strategy + EXT);
            String lists = new File(dir, "lists").getPath();
            String fake = new File(dir, "fake").getPath();
            Conf conf = new Conf();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new FileInputStream(file), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) {
                        continue;
                    }
                    if (line.startsWith("PORTS_TCP=")) {
                        conf.portsTcp = subst(line.substring(10), lists, fake);
                    } else if (line.startsWith("PORTS_UDP=")) {
                        conf.portsUdp = subst(line.substring(10), lists, fake);
                    } else {
                        for (String token : line.split("\\s+")) {
                            conf.args.add(subst(token, lists, fake));
                        }
                    }
                }
            }
            if (conf.portsTcp.isEmpty() || conf.portsUdp.isEmpty() || conf.args.isEmpty()) {
                throw new IOException("стратегия " + strategy + " повреждена");
            }
            return conf;
        }

        private static String subst(String value, String lists, String fake) {
            return value.replace("%LISTS%", lists).replace("%FAKE%", fake)
                    .replace("%GameFilterTCP%", GAME_FILTER_OFF).replace("%GameFilterUDP%", GAME_FILTER_OFF);
        }
    }
}
