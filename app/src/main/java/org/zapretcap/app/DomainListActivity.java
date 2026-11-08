package org.zapretcap.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Какие домены обрабатывает обход. Поле ввода одновременно ищет по списку и добавляет новый домен. */
public class DomainListActivity extends Activity {
    private final List<String> all = new ArrayList<>();
    private final List<String> shown = new ArrayList<>();
    private UserLists.Kind kind = UserLists.Kind.GENERAL;
    private EditText input;
    private TextView description;
    private TextView count;
    private TextView reset;
    private View add;
    private TextView[] tabs;
    private BaseAdapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_domains);
        input = findViewById(R.id.domain_input);
        description = findViewById(R.id.domain_description);
        count = findViewById(R.id.domain_count);
        reset = findViewById(R.id.domain_reset);
        add = findViewById(R.id.domain_add);
        findViewById(R.id.back).setOnClickListener(v -> finish());

        tabs = new TextView[]{findViewById(R.id.tab_general), findViewById(R.id.tab_google), findViewById(R.id.tab_exclude)};
        UserLists.Kind[] kinds = {UserLists.Kind.GENERAL, UserLists.Kind.GOOGLE, UserLists.Kind.EXCLUDE};
        for (int i = 0; i < tabs.length; i++) {
            UserLists.Kind target = kinds[i];
            tabs[i].setOnClickListener(v -> show(target));
        }

        ListView list = findViewById(R.id.domain_list);
        list.setEmptyView(findViewById(R.id.domain_empty));
        adapter = new DomainAdapter();
        list.setAdapter(adapter);

        add.setOnClickListener(v -> addFromInput());
        input.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                addFromInput();
                return true;
            }
            return false;
        });
        input.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                filter();
            }
        });
        reset.setOnClickListener(v -> confirmReset());
        show(kind);
    }

    private void show(UserLists.Kind next) {
        kind = next;
        for (int i = 0; i < tabs.length; i++) {
            tabs[i].setSelected(UserLists.Kind.values()[i] == next);
        }
        description.setText(kind == UserLists.Kind.GENERAL ? R.string.domains_general_hint
                : kind == UserLists.Kind.GOOGLE ? R.string.domains_google_hint : R.string.domains_exclude_hint);
        reload();
    }

    private void reload() {
        all.clear();
        try {
            all.addAll(UserLists.load(this, kind));
        } catch (IOException e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
        }
        filter();
    }

    private void filter() {
        String query = input.getText().toString().trim().toLowerCase(Locale.ROOT);
        shown.clear();
        for (String domain : all) {
            if (query.isEmpty() || domain.contains(query)) {
                shown.add(domain);
            }
        }
        adapter.notifyDataSetChanged();
        count.setText(getResources().getQuantityString(R.plurals.domains_count, all.size(), all.size()));
        reset.setVisibility(UserLists.isCustom(this, kind) ? View.VISIBLE : View.GONE);
    }

    private void addFromInput() {
        List<String> invalid = new ArrayList<>();
        List<String> domains = UserLists.parse(input.getText().toString(), invalid);
        if (!invalid.isEmpty()) {
            input.setError(getString(R.string.domains_invalid, invalid.get(0)));
            return;
        }
        if (domains.isEmpty()) {
            return;
        }
        try {
            UserLists.add(this, kind, domains);
        } catch (IOException e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
            return;
        }
        input.setText("");
        reload();
    }

    private void remove(String domain) {
        all.remove(domain);
        try {
            UserLists.save(this, kind, all);
        } catch (IOException e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
        }
        filter();
    }

    private void confirmReset() {
        new AlertDialog.Builder(this)
                .setMessage(R.string.domains_reset_confirm)
                .setPositiveButton(R.string.domains_reset, (dialog, which) -> {
                    try {
                        UserLists.reset(this, kind);
                    } catch (IOException e) {
                        Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
                    }
                    reload();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private final class DomainAdapter extends BaseAdapter {
        @Override
        public int getCount() {
            return shown.size();
        }

        @Override
        public String getItem(int position) {
            return shown.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View row = convertView != null ? convertView
                    : LayoutInflater.from(parent.getContext()).inflate(R.layout.item_domain, parent, false);
            String domain = getItem(position);
            ((TextView) row.findViewById(R.id.domain_name)).setText(domain);
            View delete = row.findViewById(R.id.domain_delete);
            delete.setContentDescription(getString(R.string.domains_delete, domain));
            delete.setOnClickListener(v -> remove(domain));
            return row;
        }
    }
}
