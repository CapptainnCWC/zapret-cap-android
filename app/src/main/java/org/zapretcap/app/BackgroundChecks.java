package org.zapretcap.app;

import android.app.ActivityManager;
import android.app.AppOpsManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.PowerManager;
import android.os.Process;
import android.provider.Settings;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Настройки, без которых система останавливает обход с выключенным экраном. Туннель работает внутри процесса
 * приложения: если его заморозить, через VPN не проходит ни один пакет, пуш-соединения умирают, и уведомления
 * приходят только после включения экрана или выключения обхода.
 */
final class BackgroundChecks {
    private static final String CHANNEL = "background";
    private static final int NOTIFICATION_ID = 3;
    private static final String KEY_OEM_CONFIRMED = "oem_background_confirmed";
    /** Скрытая операция MIUI «Автозапуск»: 0 - разрешено. */
    private static final int MIUI_AUTOSTART_OP = 10008;

    static final class Issue {
        final String id;
        final String title;
        final String text;
        final String button;
        final Intent action;
        /** Состояние нельзя проверить: человек сам подтверждает, что настроил. */
        final boolean unverifiable;

        Issue(String id, String title, String text, String button, Intent action, boolean unverifiable) {
            this.id = id;
            this.title = title;
            this.text = text;
            this.button = button;
            this.action = action;
            this.unverifiable = unverifiable;
        }
    }

    private BackgroundChecks() {
    }

    private static SharedPreferences prefs(Context context) {
        return BypassVpnService.prefs(context);
    }

    static List<Issue> issues(Context context) {
        List<Issue> issues = new ArrayList<>();
        String pkg = context.getPackageName();
        PowerManager power = context.getSystemService(PowerManager.class);
        if (!power.isIgnoringBatteryOptimizations(pkg)) {
            issues.add(new Issue("battery", context.getString(R.string.bg_battery_title),
                    context.getString(R.string.bg_battery_text), context.getString(R.string.bg_battery_button),
                    new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + pkg)),
                    false));
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                && context.getSystemService(ActivityManager.class).isBackgroundRestricted()) {
            issues.add(new Issue("restricted", context.getString(R.string.bg_restricted_title),
                    context.getString(R.string.bg_restricted_text), context.getString(R.string.bg_open_app_settings),
                    appDetails(context), false));
        }
        Issue oem = oemIssue(context);
        if (oem != null) {
            issues.add(oem);
        }
        return issues;
    }

    /** Строка для журнала пушей: в каком состоянии настройки на момент включения обхода. */
    static String summary(Context context) {
        PowerManager power = context.getSystemService(PowerManager.class);
        StringBuilder text = new StringBuilder("фоновая работа: оптимизация батареи ")
                .append(power.isIgnoringBatteryOptimizations(context.getPackageName()) ? "выключена" : "ВКЛЮЧЕНА");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            text.append(", ограничение фона ").append(
                    context.getSystemService(ActivityManager.class).isBackgroundRestricted() ? "ВКЛЮЧЕНО" : "нет");
        }
        Boolean autostart = miuiAutostart(context);
        if (autostart != null) {
            text.append(", автозапуск MIUI ").append(autostart ? "разрешён" : "ЗАПРЕЩЁН");
        }
        text.append(", телефон ").append(Build.MANUFACTURER).append(' ').append(Build.MODEL);
        if (oemAutostartIntent(context) != null && autostart == null) {
            text.append(", автозапуск у производителя ")
                    .append(prefs(context).getBoolean(KEY_OEM_CONFIRMED, false) ? "настроен по словам человека" : "не подтверждён");
        }
        return text.toString();
    }

    static void confirmOem(Context context) {
        prefs(context).edit().putBoolean(KEY_OEM_CONFIRMED, true).apply();
        refreshNotification(context);
    }

    /** Показывает или убирает уведомление о настройках. Вызывается при включении обхода и при открытии приложения. */
    static void refreshNotification(Context context) {
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        List<Issue> issues = issues(context);
        if (issues.isEmpty()) {
            manager.cancel(NOTIFICATION_ID);
            return;
        }
        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(new NotificationChannel(CHANNEL,
                    context.getString(R.string.bg_channel), NotificationManager.IMPORTANCE_DEFAULT));
            builder = new Notification.Builder(context, CHANNEL);
        } else {
            builder = new Notification.Builder(context);
        }
        StringBuilder text = new StringBuilder();
        for (Issue issue : issues) {
            if (text.length() > 0) {
                text.append('\n');
            }
            text.append("• ").append(issue.title);
        }
        PendingIntent open = PendingIntent.getActivity(context, 10,
                new Intent(context, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        builder.setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.bg_notification_title))
                .setContentText(issues.get(0).title)
                .setStyle(new Notification.BigTextStyle().bigText(
                        context.getString(R.string.bg_notification_text) + "\n" + text))
                .setContentIntent(open)
                .setOnlyAlertOnce(true);
        // в уведомлении помещается три кнопки, обычно проблем меньше
        for (int i = 0; i < issues.size() && i < 3; i++) {
            Issue issue = issues.get(i);
            PendingIntent action = PendingIntent.getActivity(context, 11 + i,
                    issue.action.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE);
            builder.addAction(new Notification.Action.Builder(null, issue.button, action).build());
        }
        manager.notify(NOTIFICATION_ID, builder.build());
    }

    private static Intent appDetails(Context context) {
        return new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + context.getPackageName()));
    }

    /** Автозапуск и фоновая работа у производителей, которые останавливают приложения сверх Android. */
    private static Issue oemIssue(Context context) {
        Intent intent = oemAutostartIntent(context);
        if (intent == null) {
            return null;
        }
        Boolean miui = miuiAutostart(context);
        if (miui != null) {
            if (miui) {
                return null;
            }
            return new Issue("oem", context.getString(R.string.bg_miui_title), context.getString(R.string.bg_miui_text),
                    context.getString(R.string.bg_autostart_button), intent, false);
        }
        if (prefs(context).getBoolean(KEY_OEM_CONFIRMED, false)) {
            return null;
        }
        return new Issue("oem", context.getString(R.string.bg_oem_title, Build.MANUFACTURER),
                context.getString(oemText()), context.getString(R.string.bg_autostart_button), intent, true);
    }

    private static int oemText() {
        String maker = Build.MANUFACTURER.toLowerCase(Locale.ROOT);
        if (maker.contains("huawei") || maker.contains("honor")) {
            return R.string.bg_huawei_text;
        }
        if (maker.contains("samsung")) {
            return R.string.bg_samsung_text;
        }
        return R.string.bg_oem_text;
    }

    /** Экран автозапуска производителя или null, если у этого телефона такого нет. */
    static Intent oemAutostartIntent(Context context) {
        String maker = Build.MANUFACTURER.toLowerCase(Locale.ROOT);
        String[][] candidates;
        if (maker.contains("xiaomi") || maker.contains("redmi") || maker.contains("poco")) {
            candidates = new String[][]{
                    {"com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity"}};
        } else if (maker.contains("huawei")) {
            candidates = new String[][]{
                    {"com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity"},
                    {"com.huawei.systemmanager", "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity"},
                    {"com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity"}};
        } else if (maker.contains("honor")) {
            candidates = new String[][]{
                    {"com.hihonor.systemmanager", "com.hihonor.systemmanager.startupmgr.ui.StartupNormalAppListActivity"},
                    {"com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity"}};
        } else if (maker.contains("oppo") || maker.contains("realme") || maker.contains("oneplus")) {
            candidates = new String[][]{
                    {"com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity"},
                    {"com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity"},
                    {"com.oppo.safe", "com.oppo.safe.permission.startup.StartupAppListActivity"},
                    {"com.oneplus.security", "com.oneplus.security.chainlaunch.view.ChainLaunchAppListActivity"}};
        } else if (maker.contains("vivo") || maker.contains("iqoo")) {
            candidates = new String[][]{
                    {"com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity"},
                    {"com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.BgStartUpManager"}};
        } else if (maker.contains("samsung")) {
            candidates = new String[][]{
                    {"com.samsung.android.lool", "com.samsung.android.sm.battery.ui.BatteryActivity"},
                    {"com.samsung.android.sm", "com.samsung.android.sm.battery.ui.BatteryActivity"}};
        } else if (maker.contains("asus")) {
            candidates = new String[][]{
                    {"com.asus.mobilemanager", "com.asus.mobilemanager.powersaver.PowerSaverSettings"}};
        } else {
            return null;
        }
        PackageManager pm = context.getPackageManager();
        for (String[] candidate : candidates) {
            Intent intent = new Intent().setComponent(new ComponentName(candidate[0], candidate[1]));
            if (pm.resolveActivity(intent, 0) != null) {
                return intent;
            }
        }
        // свой экран не нашёлся: хотя бы настройки приложения, где у таких прошивок есть раздел батареи
        return appDetails(context);
    }

    /** Разрешён ли автозапуск в MIUI. Null - не MIUI или узнать нельзя. */
    static Boolean miuiAutostart(Context context) {
        String maker = Build.MANUFACTURER.toLowerCase(Locale.ROOT);
        if (!(maker.contains("xiaomi") || maker.contains("redmi") || maker.contains("poco"))) {
            return null;
        }
        try {
            AppOpsManager ops = context.getSystemService(AppOpsManager.class);
            Method check = AppOpsManager.class.getMethod("checkOpNoThrow", int.class, int.class, String.class);
            int mode = (Integer) check.invoke(ops, MIUI_AUTOSTART_OP, Process.myUid(), context.getPackageName());
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }
}
