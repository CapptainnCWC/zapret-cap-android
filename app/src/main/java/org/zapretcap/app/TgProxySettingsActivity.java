package org.zapretcap.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.zapretcap.tgproxy.ConnectivityTest;
import org.zapretcap.tgproxy.ProxyConfig;
import org.zapretcap.tgproxy.ProxyLog;

import java.util.List;

/** Настройки прокси Telegram: те же поля, что в настройках tg-ws-proxy. */
public class TgProxySettingsActivity extends Activity {
    private EditText port;
    private EditText secret;
    private EditText dcIps;
    private CheckBox cfProxy;
    private EditText cfDomains;
    private CheckBox h2;
    private EditText workerDomains;
    private CheckBox noSecure;
    private EditText bufKb;
    private EditText poolSize;
    private android.widget.Spinner strategy;
    private final java.util.List<String> strategies = new java.util.ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_tg_settings);
        port = findViewById(R.id.tg_port);
        secret = findViewById(R.id.tg_secret);
        dcIps = findViewById(R.id.tg_dc_ips);
        cfProxy = findViewById(R.id.tg_cfproxy);
        cfDomains = findViewById(R.id.tg_cf_domains);
        h2 = findViewById(R.id.tg_h2);
        workerDomains = findViewById(R.id.tg_worker_domains);
        noSecure = findViewById(R.id.tg_no_secure);
        bufKb = findViewById(R.id.tg_buf_kb);
        poolSize = findViewById(R.id.tg_pool);
        strategy = findViewById(R.id.tg_strategy);
        setupStrategies();

        SharedPreferences prefs = TgProxySettings.prefs(this);
        port.setText(String.valueOf(prefs.getInt(TgProxySettings.PORT, TgProxySettings.DEFAULT_PORT)));
        secret.setText(TgProxySettings.secret(this));
        dcIps.setText(prefs.getString(TgProxySettings.DC_IPS, TgProxySettings.DEFAULT_DC_IPS));
        cfProxy.setChecked(prefs.getBoolean(TgProxySettings.CFPROXY, true));
        cfDomains.setText(prefs.getString(TgProxySettings.CF_DOMAINS, ""));
        h2.setChecked(prefs.getBoolean(TgProxySettings.H2, true));
        workerDomains.setText(prefs.getString(TgProxySettings.WORKER_DOMAINS, ""));
        noSecure.setChecked(prefs.getBoolean(TgProxySettings.NO_SECURE, false));
        bufKb.setText(String.valueOf(prefs.getInt(TgProxySettings.BUF_KB, TgProxySettings.DEFAULT_BUF_KB)));
        poolSize.setText(String.valueOf(prefs.getInt(TgProxySettings.POOL_SIZE, TgProxySettings.DEFAULT_POOL_SIZE)));

        findViewById(R.id.tg_save).setOnClickListener(v -> {
            if (save()) {
                finish();
            }
        });
        findViewById(R.id.tg_copy).setOnClickListener(v -> {
            if (save()) {
                copyToClipboard(TgProxySettings.load(this).link());
                Toast.makeText(this, R.string.tg_link_copied, Toast.LENGTH_SHORT).show();
            }
        });
        findViewById(R.id.tg_test).setOnClickListener(v -> {
            if (save()) {
                runTest();
            }
        });
        findViewById(R.id.tg_log).setOnClickListener(v -> showLog());
    }

    private static Integer parseInt(EditText field, int min, int max) {
        try {
            int value = Integer.parseInt(field.getText().toString().trim());
            return value >= min && value <= max ? value : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Сохраняет только целиком верные настройки и перезапускает работающий прокси. */
    private boolean save() {
        Integer portValue = parseInt(port, 1, 65535);
        if (portValue == null) {
            return reject(port, getString(R.string.tg_bad_port));
        }
        String secretValue = secret.getText().toString().trim();
        if (secretValue.length() != 32) {
            return reject(secret, getString(R.string.tg_bad_secret_len));
        }
        if (!ProxyConfig.isValidSecret(secretValue)) {
            return reject(secret, getString(R.string.tg_bad_secret_hex));
        }
        String dcText = dcIps.getText().toString();
        try {
            ProxyConfig.parseDcIpList(TgProxySettings.dcLines(dcText));
        } catch (IllegalArgumentException e) {
            return reject(dcIps, getString(R.string.tg_bad_dc, e.getMessage()));
        }
        Integer bufValue = parseInt(bufKb, 4, 16384);
        if (bufValue == null) {
            return reject(bufKb, getString(R.string.tg_bad_number));
        }
        Integer poolValue = parseInt(poolSize, 0, 32);
        if (poolValue == null) {
            return reject(poolSize, getString(R.string.tg_bad_number));
        }

        SharedPreferences prefs = TgProxySettings.prefs(this);
        boolean changed = prefs.getInt(TgProxySettings.PORT, TgProxySettings.DEFAULT_PORT) != portValue
                || !TgProxySettings.secret(this).equals(secretValue)
                || !prefs.getString(TgProxySettings.DC_IPS, TgProxySettings.DEFAULT_DC_IPS).equals(dcText)
                || prefs.getBoolean(TgProxySettings.CFPROXY, true) != cfProxy.isChecked()
                || !prefs.getString(TgProxySettings.CF_DOMAINS, "").equals(cfDomains.getText().toString())
                || prefs.getBoolean(TgProxySettings.H2, true) != h2.isChecked()
                || !prefs.getString(TgProxySettings.WORKER_DOMAINS, "").equals(workerDomains.getText().toString())
                || prefs.getBoolean(TgProxySettings.NO_SECURE, false) != noSecure.isChecked()
                || prefs.getInt(TgProxySettings.BUF_KB, TgProxySettings.DEFAULT_BUF_KB) != bufValue
                || prefs.getInt(TgProxySettings.POOL_SIZE, TgProxySettings.DEFAULT_POOL_SIZE) != poolValue
                || !TgProxySettings.strategy(this).equals(selectedStrategy());
        prefs.edit()
                .putInt(TgProxySettings.PORT, portValue)
                .putString(TgProxySettings.SECRET, secretValue)
                .putString(TgProxySettings.DC_IPS, dcText)
                .putBoolean(TgProxySettings.CFPROXY, cfProxy.isChecked())
                .putString(TgProxySettings.CF_DOMAINS, cfDomains.getText().toString())
                .putBoolean(TgProxySettings.H2, h2.isChecked())
                .putString(TgProxySettings.WORKER_DOMAINS, workerDomains.getText().toString())
                .putBoolean(TgProxySettings.NO_SECURE, noSecure.isChecked())
                .putInt(TgProxySettings.BUF_KB, bufValue)
                .putInt(TgProxySettings.POOL_SIZE, poolValue)
                .putString(TgProxySettings.STRATEGY, selectedStrategy())
                .apply();
        if (changed && prefs.getBoolean(TgProxySettings.ENABLED, false)) {
            TelegramProxyService.restart(this);
        }
        return true;
    }

    private void setupStrategies() {
        strategies.clear();
        strategies.addAll(TgProxySettings.strategyChoices(this));
        java.util.List<String> labels = new java.util.ArrayList<>();
        for (String name : strategies) {
            labels.add(TgProxySettings.strategyLabel(this, name));
        }
        android.widget.ArrayAdapter<String> adapter = new android.widget.ArrayAdapter<>(
                this, android.R.layout.simple_spinner_item, labels);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        strategy.setAdapter(adapter);
        strategy.setSelection(Math.max(strategies.indexOf(TgProxySettings.strategy(this)), 0), false);
    }

    private String selectedStrategy() {
        int position = strategy.getSelectedItemPosition();
        return position >= 0 && position < strategies.size() ? strategies.get(position) : TgEngine.DIRECT;
    }

    /** Кнопки внизу экрана, а поле с ошибкой может быть за его краем: показываем его, иначе кнопка будто не работает. */
    private boolean reject(EditText field, String message) {
        field.setError(message);
        field.requestFocus();
        ScrollView scroll = findViewById(R.id.tg_scroll);
        int margin = (int) (64 * getResources().getDisplayMetrics().density);
        scroll.post(() -> scroll.smoothScrollTo(0, Math.max(0, field.getTop() - margin)));
        return false;
    }

    private void runTest() {
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.tg_test)
                .setMessage(R.string.tg_test_running)
                .setPositiveButton(android.R.string.ok, null)
                .show();
        ProxyConfig config = TgProxySettings.load(this);
        new Thread(() -> {
            String text;
            try {
                text = ConnectivityTest.run(config);
            } catch (InterruptedException e) {
                return;
            }
            String result = text.isEmpty() ? getString(R.string.tg_test_nothing) : text;
            runOnUiThread(() -> {
                if (dialog.isShowing()) {
                    dialog.setMessage(result);
                }
            });
        }, "tg-connectivity-test").start();
    }

    private void showLog() {
        List<String> lines = ProxyLog.recent();
        String text = lines.isEmpty() ? getString(R.string.tg_log_empty) : String.join("\n", lines);
        String crash = CrashLog.read(this);
        if (crash != null) {
            text = text + "\n\n" + getString(R.string.tg_log_crash) + "\n" + crash;
        }
        String shown = text;
        TextView view = new TextView(this);
        view.setText(shown);
        view.setTextIsSelectable(true);
        view.setTextSize(11);
        int padding = (int) (16 * getResources().getDisplayMetrics().density);
        view.setPadding(padding, padding, padding, padding);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(view);
        scroll.post(() -> scroll.fullScroll(ScrollView.FOCUS_DOWN));
        new AlertDialog.Builder(this)
                .setTitle(R.string.tg_log)
                .setView(scroll)
                .setPositiveButton(android.R.string.ok, null)
                .setNeutralButton(R.string.tg_copy, (d, w) -> copyToClipboard(shown))
                .show();
    }

    private void copyToClipboard(String text) {
        getSystemService(ClipboardManager.class).setPrimaryClip(ClipData.newPlainText("zapret-cap", text));
    }
}
