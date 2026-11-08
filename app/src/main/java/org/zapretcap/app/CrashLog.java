package org.zapretcap.app;

import android.content.Context;

import org.zapretcap.tgproxy.ProxyLog;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Запоминает причину аварийного завершения. Иначе журнал пропал бы вместе с процессом, а у человека
 * остался бы только прокси, который сам перезапустился и оборвал все соединения.
 */
final class CrashLog {
    private static final String FILE = "last-crash.txt";
    private static final int LOG_LINES = 40;
    private static boolean installed;

    private CrashLog() {
    }

    static synchronized void install(Context context) {
        if (installed) {
            return;
        }
        installed = true;
        File file = new File(context.getApplicationContext().getFilesDir(), FILE);
        Thread.UncaughtExceptionHandler previous = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> {
            try (FileOutputStream out = new FileOutputStream(file)) {
                out.write(report(thread, error).getBytes(StandardCharsets.UTF_8));
            } catch (IOException | RuntimeException ignored) {
                // процесс и так завершается
            }
            if (previous != null) {
                previous.uncaughtException(thread, error);
            }
        });
    }

    private static String report(Thread thread, Throwable error) {
        StringWriter text = new StringWriter();
        PrintWriter writer = new PrintWriter(text);
        writer.println(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT).format(new Date()) + ", поток " + thread.getName());
        error.printStackTrace(writer);
        List<String> lines = ProxyLog.recent();
        for (String line : lines.subList(Math.max(0, lines.size() - LOG_LINES), lines.size())) {
            writer.println(line);
        }
        writer.flush();
        return text.toString();
    }

    /** Отчёт о последнем сбое или null, если сбоев не было. */
    static String read(Context context) {
        File file = new File(context.getFilesDir(), FILE);
        if (!file.exists()) {
            return null;
        }
        try (FileInputStream in = new FileInputStream(file)) {
            ByteArrayOutputStream text = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) >= 0) {
                text.write(buffer, 0, n);
            }
            return text.toString("UTF-8");
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }
}
