package org.zapretcap.app;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import org.zapretcap.tgproxy.Stats;
import org.zapretcap.tgproxy.TgWsProxy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** Главный экран: включить, выключить и выбрать конфиг отдельно для Wi-Fi и мобильной сети. */
public class MainActivity extends Activity implements AppState.Listener {
    private static final int REQUEST_VPN = 1;

    private final List<String> names = new ArrayList<>();

    private SharedPreferences prefs;
    private TextView status;
    private TextView error;
    private TextView hint;
    private Button toggle;
    private ListView list;
    private ConfigAdapter adapter;
    private View hero;
    private ImageView heroIcon;
    private TextView statusDetail;
    private TextView tabWifi;
    private TextView tabCell;
    /** Для какой сети сейчас открыт выбор конфига. */
    private String editingKind;
    private String lastKind;
    private TextView tgStatus;
    private TextView tgStrategy;
    private TextView updateButton;
    private boolean updateChecking;
    private Switch tgSwitch;
    private View testButton;
    private AlertDialog testDialog;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable testTick = this::updateTest;
    private final Runnable statsTick = new Runnable() {
        @Override
        public void run() {
            updateTelegram();
            handler.postDelayed(this, 2000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        CrashLog.install(this);
        setContentView(R.layout.activity_main);
        prefs = BypassVpnService.prefs(this);

        list = findViewById(R.id.list);
        LayoutInflater inflater = getLayoutInflater();
        View header = inflater.inflate(R.layout.main_header, list, false);
        View footer = inflater.inflate(R.layout.main_footer, list, false);
        list.addHeaderView(header, null, false);
        list.addFooterView(footer, null, false);

        status = header.findViewById(R.id.status);
        statusDetail = header.findViewById(R.id.status_detail);
        error = header.findViewById(R.id.error);
        hint = header.findViewById(R.id.hint);
        hero = header.findViewById(R.id.hero);
        heroIcon = header.findViewById(R.id.hero_icon);
        toggle = header.findViewById(R.id.toggle);
        footer.findViewById(R.id.open_bypass_settings).setOnClickListener(
                v -> startActivity(new Intent(this, BypassSettingsActivity.class)));
        updateButton = footer.findViewById(R.id.check_update);
        updateButton.setOnClickListener(v -> checkUpdate(true));
        showUpdateState();
        tabWifi = header.findViewById(R.id.tab_wifi);
        tabCell = header.findViewById(R.id.tab_cell);
        tabWifi.setOnClickListener(v -> showKind(NetKind.WIFI));
        tabCell.setOnClickListener(v -> showKind(NetKind.CELL));

        adapter = new ConfigAdapter();
        list.setAdapter(adapter);
        list.setOnItemClickListener((parent, view, position, id) -> {
            int index = position - list.getHeaderViewsCount();
            if (index >= 0 && index < names.size()) {
                onStrategyPicked(names.get(index));
            }
        });

        toggle.setOnClickListener(v -> onToggle());
        testButton = header.findViewById(R.id.test_configs);
        testButton.setOnClickListener(v -> {
            ConfigTester.start(this);
            updateTest();
        });
        header.findViewById(R.id.open_domains).setOnClickListener(
                v -> startActivity(new Intent(this, DomainListActivity.class)));

        editingKind = NetKind.current(this);

        tgStatus = header.findViewById(R.id.tg_status);
        tgSwitch = header.findViewById(R.id.tg_switch);
        tgSwitch.setOnClickListener(v -> {
            if (tgSwitch.isChecked()) {
                TelegramProxyService.start(this);
                askBatteryExemption();
            } else {
                TelegramProxyService.stop(this);
            }
        });
        header.findViewById(R.id.tg_connect).setOnClickListener(v -> connectTelegram());
        tgStrategy = header.findViewById(R.id.tg_strategy_pick);
        tgStrategy.setOnClickListener(v -> pickTgStrategy());
        header.findViewById(R.id.tg_open_settings).setOnClickListener(
                v -> startActivity(new Intent(this, TgProxySettingsActivity.class)));

        loadStrategies();
        requestNotifications();
    }

    @Override
    protected void onStart() {
        super.onStart();
        AppState.setListener(this);
        if (UpdateChecker.due(this)) {
            checkUpdate(false);
        } else {
            showUpdateState();
        }
        // за время, пока экрана не было, телефон мог сменить сеть
        String kind = NetKind.current(this);
        if (!kind.equals(lastKind)) {
            lastKind = kind;
            showKind(kind);
        }
        // работающий движок читает списки и настройки только при запуске
        boolean listsChanged = UserLists.consumeChanged();
        boolean settingsChanged = BypassSettings.consumeChanged();
        if ((listsChanged || settingsChanged) && AppState.phase == AppState.Phase.ON) {
            start();
            Toast.makeText(this, R.string.domains_applied, Toast.LENGTH_SHORT).show();
        }
        onStateChanged();
        statsTick.run();
        updateTest();
        // служба могла быть остановлена системой, пока приложения не было на экране
        if (TgProxySettings.prefs(this).getBoolean(TgProxySettings.ENABLED, false)) {
            if (AppState.tgPhase == AppState.Phase.OFF) {
                TelegramProxyService.start(this);
            }
            askBatteryExemption();
        }
    }

    @Override
    protected void onStop() {
        handler.removeCallbacks(statsTick);
        handler.removeCallbacks(testTick);
        closeTestDialog();
        AppState.setListener(null);
        super.onStop();
    }

    private String selected() {
        return Data.strategyFor(this, editingKind);
    }

    /** Показать выбор конфига для сети. Сеть, в которой телефон сейчас, отмечена в названии вкладки. */
    private void showKind(String kind) {
        editingKind = kind;
        sortConfigs();
        String current = NetKind.current(this);
        tabWifi.setSelected(NetKind.WIFI.equals(kind));
        tabCell.setSelected(NetKind.CELL.equals(kind));
        tabWifi.setText(NetKind.WIFI.equals(current)
                ? getString(R.string.net_current_suffix, getString(R.string.net_wifi)) : getString(R.string.net_wifi));
        tabCell.setText(NetKind.CELL.equals(current)
                ? getString(R.string.net_current_suffix, getString(R.string.net_cell)) : getString(R.string.net_cell));
        adapter.notifyDataSetChanged();
    }

    /** Список длинный: то, что нужно чаще всего, всегда наверху. Порядок не меняется, пока человек выбирает конфиг. */
    private void sortConfigs() {
        String chosen = selected();
        String recommended = Data.recommended(editingKind);
        java.util.Collections.sort(names, (a, b) -> {
            int rankA = a.equals(chosen) ? 0 : a.equals(recommended) ? 1 : 2;
            int rankB = b.equals(chosen) ? 0 : b.equals(recommended) ? 1 : 2;
            return rankA != rankB ? rankA - rankB : Data.compareNatural(a, b);
        });
    }

    private void loadStrategies() {
        names.clear();
        try {
            names.addAll(Data.strategies(this));
        } catch (IOException e) {
            AppState.set(AppState.Phase.OFF, null, e.getMessage());
        }
        if (!names.contains(selected()) && !names.isEmpty()) {
            // такого конфига больше нет, например после обновления приложения
            Data.setStrategyFor(this, editingKind, names.get(0));
        }
        sortConfigs();
        adapter.notifyDataSetChanged();
        hint.setText(R.string.hint_vpn);
    }

    @Override
    public void onStateChanged() {
        AppState.Phase phase = AppState.phase;
        boolean on = phase == AppState.Phase.ON;
        if (on) {
            status.setText(R.string.status_on_short);
            statusDetail.setText(getString(R.string.status_detail_on, AppState.strategy, getString(
                    NetKind.CELL.equals(NetKind.current(this)) ? R.string.net_cell : R.string.net_wifi)));
            toggle.setText(R.string.turn_off);
        } else if (phase == AppState.Phase.STARTING) {
            status.setText(R.string.status_starting);
            statusDetail.setText(AppState.strategy);
            toggle.setText(R.string.turn_off);
        } else {
            status.setText(R.string.status_off_short);
            statusDetail.setText(R.string.status_detail_off);
            toggle.setText(R.string.turn_on);
        }
        hero.setBackgroundResource(on ? R.drawable.bg_card_on : R.drawable.bg_card);
        int accent = getColor(R.color.accent);
        int muted = getColor(R.color.muted);
        heroIcon.setImageTintList(android.content.res.ColorStateList.valueOf(on ? getColor(R.color.on_accent) : muted));
        heroIcon.setBackgroundTintList(android.content.res.ColorStateList.valueOf(on ? accent : getColor(R.color.surface_alt)));
        // основное действие выделено, когда обход выключен: выключение не должно быть самым заметным на экране
        toggle.setBackgroundTintList(android.content.res.ColorStateList.valueOf(on ? getColor(R.color.surface) : accent));
        toggle.setTextColor(on ? getColor(R.color.on_surface) : getColor(R.color.on_accent));
        String message = AppState.error;
        error.setText(message);
        error.setVisibility(message == null || message.isEmpty() ? View.GONE : View.VISIBLE);
        updateTelegram();
    }

    private void showUpdateState() {
        if (updateChecking) {
            updateButton.setText(R.string.update_checking);
            return;
        }
        String update = UpdateChecker.knownUpdate(this);
        updateButton.setText(update != null
                ? getString(R.string.update_available_button, update)
                : getString(R.string.update_check, UpdateChecker.installedVersion(this)));
        updateButton.setTextColor(getColor(update != null ? R.color.accent : R.color.on_surface));
    }

    /** По кнопке показываем результат; сама проверка раз в сутки только меняет надпись на кнопке. */
    private void checkUpdate(boolean manual) {
        if (updateChecking) {
            return;
        }
        updateChecking = true;
        showUpdateState();
        new Thread(() -> {
            UpdateChecker.Release release = null;
            String failure = null;
            try {
                release = UpdateChecker.fetch(this);
            } catch (IOException e) {
                failure = String.valueOf(e.getMessage());
            }
            UpdateChecker.Release result = release;
            String error = failure;
            runOnUiThread(() -> {
                updateChecking = false;
                if (isFinishing() || isDestroyed()) {
                    return;
                }
                showUpdateState();
                if (manual) {
                    showUpdateResult(result, error);
                }
            });
        }, "update-check").start();
    }

    private void showUpdateResult(UpdateChecker.Release release, String error) {
        String installed = UpdateChecker.installedVersion(this);
        if (release == null) {
            Toast.makeText(this, getString(R.string.update_failed, error), Toast.LENGTH_LONG).show();
            return;
        }
        if (!UpdateChecker.isNewer(release.version, installed)) {
            Toast.makeText(this, getString(R.string.update_latest, installed), Toast.LENGTH_SHORT).show();
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle(getString(R.string.update_available_title, release.version))
                .setMessage(getString(R.string.update_available_message, installed, release.notes.trim()))
                .setPositiveButton(R.string.update_install, (d, w) -> installUpdate(release))
                .setNeutralButton(R.string.update_open, (d, w) -> openUrl(release.pageUrl))
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void installUpdate(UpdateChecker.Release release) {
        if (!UpdateInstaller.canInstall(this)) {
            Toast.makeText(this, R.string.update_need_permission, Toast.LENGTH_LONG).show();
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        Uri.parse("package:" + getPackageName())));
            } catch (ActivityNotFoundException e) {
                openUrl(release.pageUrl);
            }
            return;
        }
        android.widget.ProgressBar bar = new android.widget.ProgressBar(
                this, null, android.R.attr.progressBarStyleHorizontal);
        bar.setIndeterminate(true);
        int pad = (int) (24 * getResources().getDisplayMetrics().density);
        bar.setPadding(pad, pad / 2, pad, 0);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(getString(R.string.update_downloading, release.version))
                // строка сообщения нужна сразу: появиться позже она не сможет
                .setMessage("")
                .setView(bar)
                .setCancelable(false)
                .show();
        new Thread(() -> {
            String failure = null;
            java.io.File apk = null;
            try {
                apk = UpdateInstaller.download(this, release.apkUrl, (done, total) -> runOnUiThread(() -> {
                    if (total > 0) {
                        bar.setIndeterminate(false);
                        bar.setMax((int) (total / 1024));
                        bar.setProgress((int) (done / 1024));
                        dialog.setMessage(getString(R.string.update_progress,
                                Stats.humanBytes(done), Stats.humanBytes(total)));
                    }
                }));
                UpdateInstaller.install(this, apk);
            } catch (IOException | RuntimeException e) {
                failure = String.valueOf(e.getMessage());
            }
            String error = failure;
            runOnUiThread(() -> {
                if (!isDestroyed()) {
                    dialog.dismiss();
                }
                if (error != null) {
                    Toast.makeText(this, getString(R.string.update_download_failed, error), Toast.LENGTH_LONG).show();
                }
            });
        }, "update-download").start();
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (ActivityNotFoundException e) {
            ClipboardManager clipboard = getSystemService(ClipboardManager.class);
            clipboard.setPrimaryClip(ClipData.newPlainText(url, url));
            Toast.makeText(this, url, Toast.LENGTH_LONG).show();
        }
    }

    /** Конфиг прокси выбирается отдельно от основного обхода: с некоторыми конфигами YouTube работает, а Telegram нет. */
    private void pickTgStrategy() {
        java.util.List<String> names = TgProxySettings.strategyChoices(this);
        String[] labels = new String[names.size()];
        for (int i = 0; i < labels.length; i++) {
            labels[i] = TgProxySettings.strategyLabel(this, names.get(i));
        }
        new AlertDialog.Builder(this)
                .setTitle(R.string.tg_section_strategy)
                .setSingleChoiceItems(labels, Math.max(names.indexOf(TgProxySettings.strategy(this)), 0), (dialog, which) -> {
                    TgProxySettings.setStrategy(this, names.get(which));
                    dialog.dismiss();
                    updateTelegram();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void updateTelegram() {
        tgStrategy.setText(getString(R.string.tg_strategy_pick,
                TgProxySettings.strategyLabel(this, TgProxySettings.strategy(this))));
        AppState.Phase phase = AppState.tgPhase;
        TgWsProxy proxy = AppState.tgProxy;
        tgSwitch.setChecked(phase != AppState.Phase.OFF);
        if (phase == AppState.Phase.ON && proxy != null && proxy.stats().recentBadKey()) {
            tgStatus.setText(R.string.tg_status_bad_key);
        } else if (phase == AppState.Phase.ON && proxy != null) {
            Stats stats = proxy.stats();
            tgStatus.setText(getString(R.string.tg_status_on, (int) stats.active(),
                    Stats.humanBytes(stats.bytesDown()), Stats.humanBytes(stats.bytesUp())));
        } else if (phase == AppState.Phase.STARTING) {
            tgStatus.setText(R.string.tg_status_starting);
        } else {
            String message = AppState.tgError;
            tgStatus.setText(message != null ? message : getString(R.string.tg_status_off));
        }
    }

    /**
     * Экономия батареи на многих телефонах усыпляет приложение даже со службой, и прокси перестаёт отвечать,
     * а Telegram переподключается по кругу. Спрашиваем один раз: решение за человеком, и система покажет свой запрос.
     */
    private void askBatteryExemption() {
        if (prefs.getBoolean("battery_asked", false)) {
            return;
        }
        prefs.edit().putBoolean("battery_asked", true).apply();
        if (getSystemService(PowerManager.class).isIgnoringBatteryOptimizations(getPackageName())) {
            return;
        }
        try {
            startActivity(new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Uri.parse("package:" + getPackageName())));
        } catch (ActivityNotFoundException e) {
            // у производителя нет такого экрана: остаётся настройка вручную, она описана в README
        }
    }

    /** Telegram сам спросит, добавить ли прокси: нужна только ссылка, а прокси к этому моменту должен работать. */
    private void connectTelegram() {
        if (AppState.tgPhase == AppState.Phase.OFF) {
            TelegramProxyService.start(this);
        }
        String link = TgProxySettings.load(this).link();
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(link)));
        } catch (ActivityNotFoundException e) {
            getSystemService(ClipboardManager.class).setPrimaryClip(ClipData.newPlainText("tg proxy", link));
            Toast.makeText(this, R.string.tg_no_telegram, Toast.LENGTH_LONG).show();
        }
    }

    private void updateTest() {
        ConfigTester test = ConfigTester.pending();
        if (test == null) {
            closeTestDialog();
            return;
        }
        if (test.finished()) {
            closeTestDialog();
            test.markShown();
            showTestResults(test);
            return;
        }
        if (testDialog == null) {
            testDialog = new AlertDialog.Builder(this)
                    .setTitle(R.string.test_title)
                    .setMessage(test.progress())
                    .setCancelable(false)
                    .setNegativeButton(android.R.string.cancel, (dialog, which) -> test.cancel())
                    .show();
            // проверка идёт несколько минут, а уснувший телефон исказил бы результат
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        } else {
            testDialog.setMessage(test.progress());
        }
        handler.removeCallbacks(testTick);
        handler.postDelayed(testTick, 500);
    }

    private void closeTestDialog() {
        if (testDialog != null) {
            testDialog.dismiss();
            testDialog = null;
        }
        getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
    }

    private void showTestResults(ConfigTester test) {
        if (test.cancelled()) {
            return;
        }
        if (test.error() != null || test.results().isEmpty()) {
            AppState.set(AppState.phase, AppState.strategy, getString(R.string.test_failed, String.valueOf(test.error())));
            return;
        }
        List<ConfigTester.Result> results = test.results();
        ConfigTester.Result best = results.get(0);
        int total = test.total();
        int direct = test.baseline().ok;
        boolean helps = best.ok > direct;
        // конфиг запоминается для той сети, в которой шла проверка
        showKind(test.kind());
        if (helps) {
            selectStrategy(best.name);
        }
        List<String> rows = new ArrayList<>();
        for (ConfigTester.Result result : results) {
            rows.add(result.ttl > 0
                    ? getString(R.string.test_row_ttl, result.ok, total, result.name, result.ttl)
                    : getString(R.string.test_row, result.ok, total, result.name));
        }
        TextView header = new TextView(this);
        int padding = (int) (20 * getResources().getDisplayMetrics().density);
        header.setPadding(padding, padding / 2, padding, padding / 2);
        header.setText(helps
                ? getString(R.string.test_chosen, best.name, best.ok, total, direct)
                : getString(R.string.test_none, direct, total));
        ListView rowsView = new ListView(this);
        rowsView.addHeaderView(header, null, false);
        rowsView.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, rows));
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.test_title)
                .setView(rowsView)
                .setPositiveButton(android.R.string.ok, null)
                .show();
        rowsView.setOnItemClickListener((parent, view, position, id) -> {
            // первая строка списка - заголовок
            selectStrategy(results.get(position - rowsView.getHeaderViewsCount()).name);
            dialog.dismiss();
        });
    }

    private void selectStrategy(String name) {
        onStrategyPicked(name);
    }

    private void onToggle() {
        if (AppState.phase == AppState.Phase.OFF) {
            start();
        } else {
            startService(new Intent(this, BypassVpnService.class).setAction(BypassVpnService.ACTION_STOP));
        }
    }

    private void onStrategyPicked(String name) {
        Data.setStrategyFor(this, editingKind, name);
        adapter.notifyDataSetChanged();
        // конфиг применяется сразу: смена при перебоях должна быть в одно касание. Выбор для другой сети подождёт её
        if (AppState.phase != AppState.Phase.OFF && editingKind.equals(NetKind.current(this))) {
            start();
        }
    }

    private void start() {
        Intent consent = VpnService.prepare(this);
        if (consent != null) {
            startActivityForResult(consent, REQUEST_VPN);
        } else {
            startVpn();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) {
                startVpn();
            } else {
                AppState.set(AppState.Phase.OFF, null, getString(R.string.error_vpn_denied));
            }
        }
    }

    private void startVpn() {
        // без этого система и прошивка усыпляют обход: на Xiaomi и похожих телефонах особенно часто
        askBatteryExemption();
        // служба сама берёт конфиг той сети, в которой телефон сейчас
        Intent intent = new Intent(this, BypassVpnService.class).setAction(BypassVpnService.ACTION_START);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
    }

    private final class ConfigAdapter extends android.widget.BaseAdapter {
        @Override
        public int getCount() {
            return names.size();
        }

        @Override
        public String getItem(int position) {
            return names.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View row = convertView != null ? convertView
                    : LayoutInflater.from(parent.getContext()).inflate(R.layout.item_config, parent, false);
            String name = getItem(position);
            boolean chosen = name.equals(selected());
            ((TextView) row.findViewById(R.id.config_name)).setText(name);
            row.findViewById(R.id.config_check).setVisibility(chosen ? View.VISIBLE : View.INVISIBLE);
            row.setBackgroundResource(chosen ? R.drawable.bg_row_selected : R.drawable.bg_row);
            TextView detail = row.findViewById(R.id.config_detail);
            String score = prefs.getString(Data.scoreKey(editingKind, name), null);
            boolean recommended = name.equals(Data.recommended(editingKind));
            if (score != null) {
                detail.setText(getString(recommended ? R.string.config_score_recommended : R.string.config_score, score));
            } else if (recommended) {
                detail.setText(R.string.config_recommended);
            }
            detail.setVisibility(score != null || recommended ? View.VISIBLE : View.GONE);
            return row;
        }
    }

    private void requestNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 2);
        }
    }
}
