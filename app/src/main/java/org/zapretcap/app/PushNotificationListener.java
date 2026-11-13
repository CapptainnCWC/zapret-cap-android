package org.zapretcap.app;

import android.app.Notification;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

/** Тестовая сборка: видит каждое уведомление, чтобы записать, от какого приложения и когда оно пришло. */
public class PushNotificationListener extends NotificationListenerService {
    @Override
    public void onListenerConnected() {
        PushLog.init(this);
        PushLog.write("== доступ к уведомлениям есть, уведомления пишутся");
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        Notification notification = sbn.getNotification();
        // постоянные уведомления служб (музыка, VPN, загрузки) обновляются часто и к пушам отношения не имеют
        if ((notification.flags & (Notification.FLAG_ONGOING_EVENT | Notification.FLAG_FOREGROUND_SERVICE)) != 0
                || (notification.flags & Notification.FLAG_GROUP_SUMMARY) != 0
                || getPackageName().equals(sbn.getPackageName())) {
            return;
        }
        PushLog.onNotification(this, sbn.getPackageName(), notification.getChannelId(), notification.category);
    }
}
