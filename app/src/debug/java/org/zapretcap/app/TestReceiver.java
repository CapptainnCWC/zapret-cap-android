package org.zapretcap.app;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.util.Log;

/**
 * Управление из adb, только в отладочной сборке:
 *   am broadcast -n org.zapretcap.app/.TestReceiver --es cmd start --es strategy "vpn split"
 *   am broadcast -n org.zapretcap.app/.TestReceiver --es cmd stop
 */
public class TestReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String cmd = intent.getStringExtra("cmd");
        Log.i("ZapretCapTest", "cmd=" + cmd + " phase=" + AppState.phase + " strategy=" + AppState.strategy);
        if ("start".equals(cmd)) {
            String strategy = intent.getStringExtra("strategy");
            BypassVpnService.prefs(context).edit()
                    .putString("strategy", strategy)
                    .putString("strategy:wifi", strategy)
                    .putString("strategy:cell", strategy)
                    .commit();
            if (VpnService.prepare(context) != null) {
                Log.e("ZapretCapTest", "no vpn consent");
                return;
            }
            Intent start = new Intent(context, BypassVpnService.class)
                    .setAction(BypassVpnService.ACTION_START);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(start);
            } else {
                context.startService(start);
            }
        } else if ("stop".equals(cmd)) {
            context.startService(new Intent(context, BypassVpnService.class).setAction(BypassVpnService.ACTION_STOP));
        }
    }
}
