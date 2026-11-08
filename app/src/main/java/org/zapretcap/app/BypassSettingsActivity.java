package org.zapretcap.app;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Настройки обхода из service.bat Windows-версии, которые работают без root. */
public class BypassSettingsActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private TextView[] ipsetTabs;
    private TextView ipsetInfo;
    private TextView hostsInfo;
    private View ipsetUpdate;
    private View hostsUpdate;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_bypass_settings);
        findViewById(R.id.back).setOnClickListener(v -> finish());

        ipsetTabs = new TextView[]{findViewById(R.id.ipset_none), findViewById(R.id.ipset_loaded), findViewById(R.id.ipset_any)};
        BypassSettings.IpsetMode[] modes = {BypassSettings.IpsetMode.NONE, BypassSettings.IpsetMode.LOADED, BypassSettings.IpsetMode.ANY};
        for (int i = 0; i < ipsetTabs.length; i++) {
            BypassSettings.IpsetMode mode = modes[i];
            ipsetTabs[i].setOnClickListener(v -> {
                BypassSettings.setIpsetMode(this, mode);
                showIpset();
            });
        }
        ipsetInfo = findViewById(R.id.ipset_info);
        ipsetUpdate = findViewById(R.id.ipset_update);
        ipsetUpdate.setOnClickListener(v -> update(true));

        Switch hosts = findViewById(R.id.hosts_enabled);
        hosts.setChecked(BypassSettings.hostsEnabled(this));
        hosts.setOnCheckedChangeListener((button, checked) -> BypassSettings.setHostsEnabled(this, checked));
        hostsInfo = findViewById(R.id.hosts_info);
        hostsUpdate = findViewById(R.id.hosts_update);
        hostsUpdate.setOnClickListener(v -> update(false));

        setupFakes();
        showIpset();
        showHosts();
    }

    @Override
    protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }

    private void setupFakes() {
        Spinner spinner = findViewById(R.id.discord_fake);
        List<String> files;
        try {
            files = BypassSettings.fakeChoices(this);
        } catch (IOException e) {
            files = new ArrayList<>();
            files.add(BypassSettings.DISCORD_FAKE_DEFAULT);
        }
        List<String> labels = new ArrayList<>();
        for (String file : files) {
            labels.add(file.equals(BypassSettings.DISCORD_FAKE_DEFAULT)
                    ? getString(R.string.fake_default) : file.substring(0, file.length() - ".bin".length()));
        }
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, labels);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        int current = files.indexOf(BypassSettings.discordFake(this));
        spinner.setSelection(Math.max(current, 0), false);
        List<String> choices = files;
        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (!choices.get(position).equals(BypassSettings.discordFake(BypassSettingsActivity.this))) {
                    BypassSettings.setDiscordFake(BypassSettingsActivity.this, choices.get(position));
                }
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });
    }

    private void showIpset() {
        BypassSettings.IpsetMode mode = BypassSettings.ipsetMode(this);
        for (int i = 0; i < ipsetTabs.length; i++) {
            ipsetTabs[i].setSelected(BypassSettings.IpsetMode.values()[i] == mode);
        }
        int hint = mode == BypassSettings.IpsetMode.NONE ? R.string.ipset_none_hint
                : mode == BypassSettings.IpsetMode.LOADED ? R.string.ipset_loaded_hint : R.string.ipset_any_hint;
        ((TextView) findViewById(R.id.ipset_hint)).setText(hint);
        worker.execute(() -> {
            int count = BypassSettings.ipsetCount(this);
            String when = when(BypassSettings.ipsetFile(this).lastModified());
            main.post(() -> ipsetInfo.setText(getString(R.string.ipset_info, count, when)));
        });
    }

    private void showHosts() {
        worker.execute(() -> {
            int count = BypassSettings.hostsCount(this);
            String when = when(BypassSettings.hostsFile(this).lastModified());
            main.post(() -> hostsInfo.setText(getString(R.string.hosts_info, count, when)));
        });
    }

    private String when(long modified) {
        return modified > 0 ? DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date(modified))
                : getString(R.string.list_builtin);
    }

    private void update(boolean ipset) {
        View button = ipset ? ipsetUpdate : hostsUpdate;
        button.setEnabled(false);
        Toast.makeText(this, R.string.list_updating, Toast.LENGTH_SHORT).show();
        worker.execute(() -> {
            String message;
            try {
                int count = ipset ? BypassSettings.updateIpset(this) : BypassSettings.updateHosts(this);
                message = getString(R.string.list_updated, count);
            } catch (IOException | RuntimeException e) {
                message = getString(R.string.list_update_failed, String.valueOf(e.getMessage()));
            }
            String text = message;
            main.post(() -> {
                if (isDestroyed()) {
                    return;
                }
                button.setEnabled(true);
                Toast.makeText(this, text, Toast.LENGTH_LONG).show();
                if (ipset) {
                    showIpset();
                } else {
                    showHosts();
                }
            });
        });
    }
}
