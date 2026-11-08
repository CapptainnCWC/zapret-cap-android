package org.zapretcap.app;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * После перезагрузки запускает прокси Telegram, если он был включён.
 * Telegram запоминает адрес прокси, и без работающего прокси он не подключится.
 */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())
                && TgProxySettings.prefs(context).getBoolean(TgProxySettings.ENABLED, false)) {
            TelegramProxyService.start(context);
        }
    }
}
