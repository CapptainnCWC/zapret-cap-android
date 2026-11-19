package org.zapretcap.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import com.yausername.youtubedl_android.YoutubeDL;
import com.yausername.youtubedl_android.YoutubeDLRequest;
import com.yausername.youtubedl_android.YoutubeDLResponse;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Тест загрузки видео через yt-dlp, как в Linux-версии (ytdldownloadtest.md). Музыкальные боты и загрузчики качают
 * YouTube с googlevideo одним длинным HTTPS-потоком, и цензор режет именно такие потоки: замедляет или
 * останавливает посреди передачи. Тест сайтов и тест фризов этого не видят. Здесь качается настоящий ролик
 * (10,3 МБ, «Big Buck Bunny» с канала Blender) тем же способом, что и боты.
 *
 * yt-dlp и Python идут в APK только для arm64. На других архитектурах {@link #init} вернёт false, и подбор
 * пропустит видео.
 */
final class VideoTest {
    private static final String TAG = "ZapretCapVideo";
    static final String URL = "https://www.youtube.com/watch?v=aqz-KE-bpKQ";
    private static final String FORMAT = "140/251/ba";
    /** Общий предел: если к этому моменту данные ещё идут, загрузка медленная. */
    private static final int TIMEOUT_S = 20;
    /** Столько секунд без единого байта yt-dlp сам считает обрывом: это зависание. */
    private static final int STALL_S = 5;
    /** Ссылки на поток в info.json живут около 6 часов и привязаны к адресу: берём с запасом. */
    private static final long INFO_LIFETIME_MS = 4 * 60 * 60 * 1000L;
    private static final long UPDATE_EVERY_MS = 24 * 60 * 60 * 1000L;
    private static final String KEY_UPDATED = "ytdlp_updated_at";
    private static final String PROGRESS = "download:@video %(progress.status)s %(progress.downloaded_bytes)s "
            + "%(progress.total_bytes)s %(progress.elapsed)s";
    private static final AtomicInteger IDS = new AtomicInteger();
    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "video-watchdog");
        thread.setDaemon(true);
        return thread;
    });

    /** Итог одной стратегии: скачалось, медленно, зависло или не скачалось. */
    static final class Score {
        static final int OK = 0;
        static final int SLOW = 1;
        static final int STALL = 2;
        static final int FAIL = 3;

        final boolean ok;
        final boolean stall;
        final long bytes;
        final long millis;
        final long total;

        Score(boolean ok, boolean stall, long bytes, long millis, long total) {
            this.ok = ok;
            this.stall = stall;
            this.bytes = bytes;
            this.millis = millis;
            this.total = total;
        }

        int klass() {
            if (ok) {
                return OK;
            }
            if (bytes <= 0) {
                return FAIL;
            }
            return stall ? STALL : SLOW;
        }

        /** КБ/с, десятичные: байт за миллисекунду. */
        double speed() {
            return millis > 0 ? (double) bytes / millis : 0;
        }

        /**
         * Место в сортировке, как в Linux-версии: класс, а внутри него скорость по логарифму. Шум скорости
         * (3 и 3,5 МБ/с) порядок не меняет: учитывается только разница в два раза и больше.
         */
        int rank() {
            double kbps = Math.max(speed(), 1);
            return klass() * 100 + 60 - (int) Math.floor(Math.log(kbps) / Math.log(2));
        }

        String text(Context context) {
            switch (klass()) {
                case OK:
                    return context.getString(R.string.video_ok, speedText(speed()));
                case SLOW:
                    return context.getString(R.string.video_slow, speedText(speed()));
                case STALL:
                    return context.getString(R.string.video_stall, sizeText(bytes));
                default:
                    return context.getString(R.string.video_fail);
            }
        }

        String encode() {
            return (ok ? 1 : 0) + "," + (stall ? 1 : 0) + "," + bytes + "," + millis + "," + total;
        }

        static Score decode(String value) {
            if (value == null) {
                return null;
            }
            String[] parts = value.split(",");
            if (parts.length != 5) {
                return null;
            }
            try {
                return new Score("1".equals(parts[0]), "1".equals(parts[1]), Long.parseLong(parts[2]),
                        Long.parseLong(parts[3]), Long.parseLong(parts[4]));
            } catch (NumberFormatException e) {
                return null;
            }
        }

        private static String speedText(double kbps) {
            if (kbps >= 1000) {
                return String.format(Locale.ROOT, "%.1f МБ/с", kbps / 1000).replace('.', ',');
            }
            return Math.round(kbps) + " КБ/с";
        }

        private static String sizeText(long bytes) {
            if (bytes >= 1_000_000) {
                return String.format(Locale.ROOT, "%.1f МБ", bytes / 1e6).replace('.', ',');
            }
            return Math.max(1, Math.round(bytes / 1000.0)) + " КБ";
        }
    }

    /** Ранг для стратегии без итога видео: такие идут после проверенных. */
    static final int UNTESTED_RANK = 9999;

    private final Context context;
    private final File dir;
    private final File info;

    VideoTest(Context context) {
        this.context = context.getApplicationContext();
        dir = new File(this.context.getCacheDir(), "ytdl-test");
        info = new File(dir, "info.json");
    }

    /** Распаковывает Python и yt-dlp. False - на этой архитектуре теста нет или он не запустился. */
    boolean init() {
        try {
            YoutubeDL.getInstance().init(context);
            return true;
        } catch (Throwable e) {
            Log.w(TAG, "yt-dlp unavailable", e);
            return false;
        }
    }

    /**
     * Свежий yt-dlp раз в сутки: YouTube меняется каждые несколько недель, и старый перестаёт получать ссылки.
     * Без связи с GitHub годится тот, что уже есть.
     */
    void updateIfDue() {
        SharedPreferences prefs = BypassVpnService.prefs(context);
        if (System.currentTimeMillis() - prefs.getLong(KEY_UPDATED, 0) < UPDATE_EVERY_MS) {
            return;
        }
        try {
            YoutubeDL.getInstance().updateYoutubeDL(context, YoutubeDL.UpdateChannel._STABLE);
            prefs.edit().putLong(KEY_UPDATED, System.currentTimeMillis()).apply();
        } catch (Throwable e) {
            Log.w(TAG, "yt-dlp update failed", e);
        }
    }

    boolean prepared() {
        return info.isFile() && System.currentTimeMillis() - info.lastModified() < INFO_LIFETIME_MS;
    }

    /**
     * Разбирает ролик один раз: частые запросы к YouTube с одного адреса приводят к проверке «вы не бот».
     *
     * @param socksPort движок, через который идёт запрос, 0 - напрямую
     */
    boolean prepare(int socksPort) {
        if (prepared()) {
            return true;
        }
        dir.mkdirs();
        YoutubeDLRequest request = new YoutubeDLRequest(URL)
                .addOption("-J")
                .addOption("--ignore-config")
                .addOption("--no-playlist")
                .addOption("--socket-timeout", Integer.toString(STALL_S))
                // разбор пробуется при каждой стратегии, пока YouTube не ответит: без повторов каждая попытка
                // занимает секунды, а не 16 с
                .addOption("--extractor-retries", "0");
        proxy(request, socksPort);
        String id = "ytdl-info-" + IDS.incrementAndGet();
        ScheduledFuture<?> watchdog = WATCHDOG.schedule(() -> YoutubeDL.getInstance().destroyProcessById(id),
                45, TimeUnit.SECONDS);
        try {
            YoutubeDLResponse response = YoutubeDL.getInstance().execute(request, id);
            String json = response.getOut();
            if (json == null || !json.trim().startsWith("{")) {
                return false;
            }
            File temp = new File(dir, "info.json.tmp");
            try (OutputStream out = new FileOutputStream(temp)) {
                out.write(json.getBytes(StandardCharsets.UTF_8));
            }
            return temp.renameTo(info);
        } catch (Throwable e) {
            Log.w(TAG, "video info failed", e);
            return false;
        } finally {
            watchdog.cancel(false);
        }
    }

    /**
     * Качает ролик через стратегию и сразу его удаляет.
     *
     * @param socksPort движок стратегии (режим VPN: само приложение исключено из туннеля), 0 - напрямую
     */
    Score download(int socksPort) {
        dir.mkdirs();
        deleteMedia();
        YoutubeDLRequest request = new YoutubeDLRequest(Collections.emptyList())
                .addOption("--ignore-config")
                .addOption("--no-playlist")
                .addOption("--load-info-json", info.getAbsolutePath())
                .addOption("-f", FORMAT)
                // в stdout библиотека копит всё в памяти: 10 МБ ролика туда нельзя, поэтому файл и удаление
                .addOption("-o", new File(dir, "media.%(ext)s").getAbsolutePath())
                .addOption("--no-part")
                .addOption("--force-overwrites")
                .addOption("--socket-timeout", Integer.toString(STALL_S))
                // без повторов: иначе yt-dlp переподключился бы, и зависание не было бы видно
                .addOption("--retries", "0")
                .addOption("--fragment-retries", "0")
                .addOption("--extractor-retries", "0")
                .addOption("--newline")
                .addOption("--progress-template", PROGRESS);
        proxy(request, socksPort);
        String id = "ytdl-test-" + IDS.incrementAndGet();
        String[] last = new String[1];
        boolean[] killed = new boolean[1];
        ScheduledFuture<?> watchdog = WATCHDOG.schedule(() -> {
            killed[0] = true;
            YoutubeDL.getInstance().destroyProcessById(id);
        }, TIMEOUT_S, TimeUnit.SECONDS);
        boolean failed = false;
        try {
            YoutubeDL.getInstance().execute(request, id, (progress, eta, line) -> {
                if (line != null && line.startsWith("@video ")) {
                    last[0] = line;
                }
                return kotlin.Unit.INSTANCE;
            });
        } catch (YoutubeDL.CanceledException e) {
            killed[0] = true;
        } catch (Throwable e) {
            failed = true;
            Log.i(TAG, "video download ended with error: " + e.getMessage());
        } finally {
            watchdog.cancel(false);
            deleteMedia();
        }
        return score(last[0], killed[0], failed);
    }

    /** Строка «@video статус байт размер секунд» и то, как закончился yt-dlp. */
    private static Score score(String line, boolean killed, boolean failed) {
        long bytes = 0;
        long total = 0;
        long millis = 0;
        boolean finished = false;
        if (line != null) {
            String[] parts = line.trim().split("\\s+");
            if (parts.length >= 5) {
                finished = "finished".equals(parts[1]);
                bytes = number(parts[2]);
                total = number(parts[3]);
                try {
                    millis = Math.round(Double.parseDouble(parts[4]) * 1000);
                } catch (NumberFormatException ignored) {
                    millis = 0;
                }
            }
        }
        if (finished && total > 0) {
            bytes = total;
        }
        boolean ok = finished && !killed;
        // убит сторожем, а данные шли - медленно; вышел сам с ошибкой после данных - зависло
        boolean stall = !ok && !killed && (failed || !finished) && bytes > 0;
        return new Score(ok, stall, bytes, Math.max(millis, 1), total);
    }

    private static long number(String value) {
        try {
            return (long) Double.parseDouble(value);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static void proxy(YoutubeDLRequest request, int socksPort) {
        if (socksPort > 0) {
            // socks5h: имя сайта уходит движку, а он берёт адрес у DNS приложения, а не у подменённого DNS сети
            request.addOption("--proxy", "socks5h://127.0.0.1:" + socksPort);
        }
    }

    private void deleteMedia() {
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.getName().startsWith("media.")) {
                    file.delete();
                }
            }
        }
    }
}
