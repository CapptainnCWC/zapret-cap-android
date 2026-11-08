package org.zapretcap.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

/**
 * Проверка новой версии по последнему релизу на GitHub. Скачивает и ставит её UpdateInstaller.
 */
final class UpdateChecker {
    static final String RELEASES_URL = "https://github.com/CapptainnCWC/zapret-cap-android/releases/latest";
    private static final String API_URL =
            "https://api.github.com/repos/CapptainnCWC/zapret-cap-android/releases/latest";
    private static final String KEY_LATEST = "update_latest";
    private static final String KEY_CHECKED = "update_checked_at";
    private static final long DAY_MS = 24L * 60 * 60 * 1000;

    static final class Release {
        final String version;
        final String notes;
        final String pageUrl;
        /** Ссылка на zapret-cap.apk в релизе. */
        final String apkUrl;

        Release(String version, String notes, String pageUrl, String apkUrl) {
            this.version = version;
            this.notes = notes;
            this.pageUrl = pageUrl;
            this.apkUrl = apkUrl;
        }
    }

    private UpdateChecker() {
    }

    static String installedVersion(Context context) {
        try {
            String name = context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName;
            return name != null ? name : "0";
        } catch (PackageManager.NameNotFoundException e) {
            return "0";
        }
    }

    /** Сетевой запрос: вызывать не из главного потока. */
    static Release fetch(Context context) throws IOException {
        try {
            JSONObject json = new JSONObject(BypassSettings.download(API_URL));
            String version = json.getString("tag_name").replaceFirst("^[vV]", "");
            String page = json.optString("html_url", RELEASES_URL);
            JSONArray assets = json.optJSONArray("assets");
            String apk = null;
            for (int i = 0; assets != null && i < assets.length(); i++) {
                JSONObject asset = assets.getJSONObject(i);
                if (asset.optString("name").endsWith(".apk")) {
                    apk = asset.getString("browser_download_url");
                    break;
                }
            }
            if (apk == null || !apk.startsWith("https://github.com/")) {
                throw new IOException("в релизе " + version + " нет APK");
            }
            prefs(context).edit()
                    .putString(KEY_LATEST, version)
                    .putLong(KEY_CHECKED, System.currentTimeMillis())
                    .apply();
            return new Release(version, json.optString("body", ""), page, apk);
        } catch (JSONException e) {
            throw new IOException("GitHub прислал непонятный ответ", e);
        }
    }

    /** Версия с GitHub из прошлой проверки, если она новее установленной. */
    static String knownUpdate(Context context) {
        String latest = prefs(context).getString(KEY_LATEST, null);
        return latest != null && isNewer(latest, installedVersion(context)) ? latest : null;
    }

    /** Сама проверка раз в сутки: человек увидит новую версию, даже не нажимая кнопку. */
    static boolean due(Context context) {
        return System.currentTimeMillis() - prefs(context).getLong(KEY_CHECKED, 0) > DAY_MS;
    }

    /** 1.4.10 новее 1.4.9: сравниваем числа, а не строки. */
    static boolean isNewer(String candidate, String installed) {
        String[] a = candidate.split("[.\\-]");
        String[] b = installed.split("[.\\-]");
        for (int i = 0; i < Math.max(a.length, b.length); i++) {
            int x = i < a.length ? number(a[i]) : 0;
            int y = i < b.length ? number(b[i]) : 0;
            if (x != y) {
                return x > y;
            }
        }
        return false;
    }

    private static int number(String part) {
        String digits = part.replaceAll("\\D.*", "");
        try {
            return digits.isEmpty() ? 0 : Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static SharedPreferences prefs(Context context) {
        return BypassVpnService.prefs(context);
    }
}
