package org.zapretcap.app;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Команды от имени root для режима с nfqws2. Один сеанс su на всё время работы: каждая новая команда через
 * отдельный su вызывала бы у Magisk новый запрос и всплывающее уведомление.
 */
final class RootShell {
    private static final String TAG = "ZapretCapRoot";
    private static final String MARKER = "__ZC_DONE__";
    private static final AtomicInteger COUNTER = new AtomicInteger();

    private static Process session;
    private static OutputStream stdin;
    private static BufferedReader stdout;

    static final class Result {
        final int code;
        final String output;

        Result(int code, String output) {
            this.code = code;
            this.output = output;
        }

        boolean ok() {
            return code == 0;
        }
    }

    private RootShell() {
    }

    /** Есть ли root. Первый вызов показывает запрос прав, поэтому ждём ответа человека до полуминуты. */
    static boolean available(Context context) {
        try {
            Result result = exec(context, "id -u", 30_000);
            return result.ok() && result.output.trim().equals("0");
        } catch (IOException e) {
            return false;
        }
    }

    /** Выполняет скрипт от root и возвращает его код и вывод. */
    static synchronized Result exec(Context context, String script, long timeoutMs) throws IOException {
        File bridge = bridgeDir(context);
        if (bridge != null) {
            return execBridge(bridge, script, timeoutMs);
        }
        try {
            return execSession(script, timeoutMs);
        } catch (IOException broken) {
            // сеанс мог умереть вместе с su: одна попытка с новым
            closeSession();
            return execSession(script, timeoutMs);
        }
    }

    private static Result execSession(String script, long timeoutMs) throws IOException {
        if (session == null || !Data.isAlive(session)) {
            closeSession();
            session = new ProcessBuilder("su").redirectErrorStream(true).start();
            stdin = session.getOutputStream();
            stdout = new BufferedReader(new InputStreamReader(session.getInputStream(), StandardCharsets.UTF_8));
        }
        String marker = MARKER + COUNTER.incrementAndGet() + "_";
        // скрипт в скобках: его exit не должен завершить весь сеанс
        String command = "( " + script + "\n) 2>&1 </dev/null\necho \"" + marker + "$?\"\n";
        stdin.write(command.getBytes(StandardCharsets.UTF_8));
        stdin.flush();
        StringBuilder output = new StringBuilder();
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (true) {
            while (!stdout.ready()) {
                if (System.currentTimeMillis() > deadline) {
                    closeSession();
                    throw new IOException("root не ответил за " + timeoutMs / 1000 + " с");
                }
                if (!Data.isAlive(session)) {
                    closeSession();
                    throw new IOException("нет прав root: su завершился. " + output.toString().trim());
                }
                try {
                    Thread.sleep(20);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted");
                }
            }
            String line = stdout.readLine();
            if (line == null) {
                closeSession();
                throw new IOException("нет прав root. " + output.toString().trim());
            }
            int at = line.indexOf(marker);
            if (at >= 0) {
                output.append(line, 0, at);
                int code;
                try {
                    code = Integer.parseInt(line.substring(at + marker.length()).trim());
                } catch (NumberFormatException e) {
                    code = -1;
                }
                return new Result(code, output.toString());
            }
            output.append(line).append('\n');
        }
    }

    private static String read(File file) throws IOException {
        StringBuilder text = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new java.io.FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                text.append(line).append('\n');
            }
        }
        return text.toString();
    }

    private static void closeSession() {
        if (session != null) {
            session.destroy();
        }
        session = null;
        stdin = null;
        stdout = null;
    }

    /**
     * Только в отладочной сборке, для проверки в эмуляторе: там su пускает лишь оболочку adb. Скрипты кладутся
     * в files/root-bridge, а их выполняет цикл, запущенный из adb root (tests/root-bridge.sh).
     */
    private static File bridgeDir(Context context) {
        if ((context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            return null;
        }
        File dir = new File(context.getFilesDir(), "root-bridge");
        return dir.isDirectory() ? dir : null;
    }

    private static Result execBridge(File dir, String script, long timeoutMs) throws IOException {
        String id = System.currentTimeMillis() + "-" + COUNTER.incrementAndGet();
        File temp = new File(dir, id + ".tmp");
        File request = new File(dir, id + ".sh");
        File code = new File(dir, id + ".rc");
        File output = new File(dir, id + ".out");
        try (OutputStream out = new FileOutputStream(temp)) {
            out.write(script.getBytes(StandardCharsets.UTF_8));
        }
        if (!temp.renameTo(request)) {
            throw new IOException("root-bridge: не удалось передать скрипт");
        }
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (!code.exists()) {
            if (System.currentTimeMillis() > deadline) {
                throw new IOException("root-bridge не ответил");
            }
            try {
                TimeUnit.MILLISECONDS.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted");
            }
        }
        try {
            String text = output.exists() ? read(output) : "";
            String rc = read(code).trim();
            return new Result(rc.isEmpty() ? -1 : Integer.parseInt(rc), text);
        } catch (NumberFormatException e) {
            return new Result(-1, "");
        } finally {
            request.delete();
            code.delete();
            output.delete();
            Log.d(TAG, "bridge exec " + id);
        }
    }
}
