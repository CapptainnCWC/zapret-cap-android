package org.zapretcap.app;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * После перезагрузки запускает прокси Telegram, если он был включён: Telegram запоминает адрес прокси, и без
 * работающего прокси он не подключится. В режиме root так же возвращает обход.
 */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            return;
        }
        if (TgProxySettings.prefs(context).getBoolean(TgProxySettings.ENABLED, false)) {
            TelegramProxyService.start(context);
        }
        // режим VPN после перезагрузки поднимает сама система, а nfqws2 и его правила iptables пропадают
        if (BypassSettings.rootMode(context)
                && BypassVpnService.prefs(context).getBoolean(BypassVpnService.KEY_ROOT_ON, false)) {
            Intent start = new Intent(context, BypassVpnService.class).setAction(BypassVpnService.ACTION_START);
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                context.startForegroundService(start);
            } else {
                context.startService(start);
            }
        }
    }
}
