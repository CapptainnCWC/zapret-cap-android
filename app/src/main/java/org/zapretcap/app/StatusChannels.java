package org.zapretcap.app;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;

/**
 * Каналы постоянных уведомлений обхода и прокси. Раньше у них была низкая важность, а HyperOS 2 такие уведомления
 * в шторке не показывает. Поднять важность существующего канала приложение не может, поэтому каналы новые:
 * обычная важность, но без звука и вибрации. Старые каналы удаляются, когда их уведомления уже заменены.
 */
final class StatusChannels {
    static final String BYPASS = "bypass_status";
    static final String TELEGRAM = "telegram_proxy_status";
    private static final String OLD_BYPASS = "bypass";
    private static final String OLD_TELEGRAM = "telegram_proxy";

    private StatusChannels() {
    }

    /** Создаёт канал. Вызывать перед каждым уведомлением: если канал уже есть, система его не меняет. */
    static void ensure(Context context, String id, int name) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(id, context.getString(name),
                NotificationManager.IMPORTANCE_DEFAULT);
        channel.setSound(null, null);
        channel.enableVibration(false);
        channel.setShowBadge(false);
        context.getSystemService(NotificationManager.class).createNotificationChannel(channel);
    }

    /** Удаляет старый канал. Пока на нём висит уведомление службы, система не даст это сделать: попробуем позже. */
    static void dropOld(Context context, String newId) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        String old = BYPASS.equals(newId) ? OLD_BYPASS : OLD_TELEGRAM;
        try {
            context.getSystemService(NotificationManager.class).deleteNotificationChannel(old);
        } catch (RuntimeException stillInUse) {
            // уведомление службы ещё на старом канале
        }
    }
}
