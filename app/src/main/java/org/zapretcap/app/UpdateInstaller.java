package org.zapretcap.app;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Log;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.util.Arrays;

/**
 * Скачивает APK из релиза и передаёт его системному установщику. Установку подтверждает человек в окне Android,
 * а система ставит только APK, подписанный тем же ключом, что и установленное приложение.
 */
final class UpdateInstaller {
    private static final String TAG = "ZapretUpdate";
    private static final String ACTION_STATUS = "org.zapretcap.app.UPDATE_STATUS";
    private static final int TIMEOUT_MS = 20000;
    private static final long MAX_SIZE = 64L * 1024 * 1024;

    interface Progress {
        void onProgress(long done, long total);
    }

    private UpdateInstaller() {
    }

    /** Без этого разрешения Android не покажет окно установки. Выдаётся в настройках, отдельно для приложения. */
    static boolean canInstall(Context context) {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.O || context.getPackageManager().canRequestPackageInstalls();
    }

    static File apkFile(Context context) {
        return new File(new File(context.getCacheDir(), "update"), "zapret-cap.apk");
    }

    /** Сетевой запрос: вызывать не из главного потока. */
    static File download(Context context, String url, Progress progress) throws IOException {
        File target = apkFile(context);
        File dir = target.getParentFile();
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("mkdir " + dir);
        }
        File temp = new File(dir, "zapret-cap.apk.part");
        IOException direct;
        try {
            fetch(url, Proxy.NO_PROXY, temp, progress);
            direct = null;
        } catch (IOException e) {
            direct = e;
        }
        // приложение исключено из VPN; если GitHub напрямую недоступен, пробуем через работающий движок обхода
        int socks = BypassVpnService.enginePort;
        if (direct != null && socks > 0) {
            fetch(url, new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", socks)), temp, progress);
        } else if (direct != null) {
            throw direct;
        }
        verify(context, temp);
        if (target.exists() && !target.delete() || !temp.renameTo(target)) {
            throw new IOException("rename " + target);
        }
        return target;
    }

    private static void fetch(String url, Proxy proxy, File out, Progress progress) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection(proxy);
        connection.setConnectTimeout(TIMEOUT_MS);
        connection.setReadTimeout(TIMEOUT_MS);
        // GitHub отдаёт файл переадресацией на свой CDN, тоже по https
        connection.setInstanceFollowRedirects(true);
        try {
            int code = connection.getResponseCode();
            if (code != 200) {
                throw new IOException("GitHub ответил " + code);
            }
            long total = connection.getContentLengthLong();
            if (total > MAX_SIZE) {
                throw new IOException("файл слишком большой: " + total);
            }
            try (InputStream in = connection.getInputStream(); OutputStream os = new FileOutputStream(out)) {
                byte[] buffer = new byte[65536];
                long done = 0;
                int n;
                while ((n = in.read(buffer)) > 0) {
                    os.write(buffer, 0, n);
                    done += n;
                    if (done > MAX_SIZE) {
                        throw new IOException("файл слишком большой");
                    }
                    progress.onProgress(done, total);
                }
            }
        } finally {
            connection.disconnect();
        }
    }

    /** Заранее, чтобы показать понятную причину, а не общую ошибку установщика. */
    @SuppressWarnings("deprecation")
    private static void verify(Context context, File apk) throws IOException {
        PackageManager pm = context.getPackageManager();
        int flags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES;
        PackageInfo archive = pm.getPackageArchiveInfo(apk.getPath(), flags);
        if (archive == null) {
            throw new IOException("скачанный файл повреждён");
        }
        if (!context.getPackageName().equals(archive.packageName)) {
            throw new IOException("в релизе чужое приложение: " + archive.packageName);
        }
        try {
            PackageInfo installed = pm.getPackageInfo(context.getPackageName(), flags);
            if (!Arrays.equals(signatures(installed), signatures(archive))) {
                throw new IOException("APK подписан другим ключом, обновить поверх нельзя");
            }
        } catch (PackageManager.NameNotFoundException e) {
            throw new IOException(e);
        }
    }

    @SuppressWarnings("deprecation")
    private static Signature[] signatures(PackageInfo info) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && info.signingInfo != null) {
            return info.signingInfo.getApkContentsSigners();
        }
        return info.signatures;
    }

    /** Передаёт APK установщику Android. Дальше система сама покажет окно с кнопкой «Обновить». */
    static void install(Context context, File apk) throws IOException {
        PackageInstaller installer = context.getPackageManager().getPackageInstaller();
        PackageInstaller.SessionParams params =
                new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        params.setAppPackageName(context.getPackageName());
        params.setSize(apk.length());
        int id = installer.createSession(params);
        try (PackageInstaller.Session session = installer.openSession(id)) {
            try (InputStream in = new FileInputStream(apk);
                 OutputStream out = session.openWrite("zapret-cap.apk", 0, apk.length())) {
                byte[] buffer = new byte[65536];
                int n;
                while ((n = in.read(buffer)) > 0) {
                    out.write(buffer, 0, n);
                }
                session.fsync(out);
            }
            int flags = PendingIntent.FLAG_UPDATE_CURRENT
                    | (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ? PendingIntent.FLAG_MUTABLE : 0);
            Intent status = new Intent(context, StatusReceiver.class).setAction(ACTION_STATUS);
            PendingIntent pending = PendingIntent.getBroadcast(context, id, status, flags);
            session.commit(pending.getIntentSender());
        } catch (IOException | RuntimeException e) {
            installer.abandonSession(id);
            throw e;
        }
    }

    /** Ответы установщика: просьба подтвердить, успех или причина отказа. */
    public static final class StatusReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
            if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
                Intent confirm = intent.getParcelableExtra(Intent.EXTRA_INTENT);
                if (confirm != null) {
                    confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    context.startActivity(confirm);
                }
                return;
            }
            if (status == PackageInstaller.STATUS_SUCCESS) {
                return;
            }
            String message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);
            Log.w(TAG, "install failed: " + status + " " + message);
            if (status != PackageInstaller.STATUS_FAILURE_ABORTED) {
                Toast.makeText(context, context.getString(R.string.update_install_failed,
                        message != null ? message : String.valueOf(status)), Toast.LENGTH_LONG).show();
            }
        }
    }
}
