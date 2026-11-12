package io.umbral;

import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import io.umbral.data.AppEntry;
import io.umbral.data.AppRepository;
import io.umbral.um.UmTemplates;
import io.umbral.util.Ui;

/**
 * UM 模块仓库。
 *
 * ══════════════════════════════════════════════════════
 *  两个状态，同一个界面
 * ══════════════════════════════════════════════════════
 *
 *   ① 仓库列表   显示官方目录里的模板（将来可接远程网址）
 *                  点一条 → 进入 ②
 *
 *   ② 选应用     可搜索、可多选、显示 App 图标 / 名称 / uid
 *                  底部按钮 → 把该模板的规则下发给所有选中的应用
 *
 *  为什么做成两个状态而不是两个界面：
 *     用户的心智是「我要这个模板，用在哪些 App 上」——
 *     一个界面里走完更顺，返回键也能自然回到列表。
 */
public class UmRepoActivity extends BaseActivity {

    private TextView tvTitle;
    private TextView tvHint;
    private TextView tvEmpty;
    private TextView btnAction;
    private EditText etSearch;
    private ListView lv;

    /** 当前状态：true = 选应用，false = 仓库列表 */
    private boolean pickingApps;

    /** 仓库列表数据 */
    private final List<UmTemplates.Tpl> tpls = new ArrayList<>();
    /** 选应用时的数据（全部 + 过滤后） */
    private final List<AppEntry> allApps = new ArrayList<>();
    private final List<AppEntry> shownApps = new ArrayList<>();
    /** 已选中的 uid */
    private final Set<Integer> selected = new HashSet<>();

    /** 当前选中的模板 */
    private UmTemplates.Tpl current;

    private Adapter adapter;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_umrepo);

        tvTitle = findViewById(R.id.tv_repo_title);
        tvHint = findViewById(R.id.tv_repo_hint);
        tvEmpty = findViewById(R.id.tv_repo_empty);
        btnAction = findViewById(R.id.btn_repo_action);
        etSearch = findViewById(R.id.et_repo_search);
        lv = findViewById(R.id.lv_repo);

        findViewById(R.id.btn_repo_back).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (pickingApps) {
                    backToTemplates();
                } else {
                    finish();
                }
            }
        });

        adapter = new Adapter();
        lv.setAdapter(adapter);

        lv.setOnItemClickListener(new android.widget.AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(android.widget.AdapterView<?> p, View v, int pos, long id) {
                if (pickingApps) {
                    toggle(pos);
                } else {
                    if (pos >= 0 && pos < tpls.size()) {
                        enterAppPick(tpls.get(pos));
                    }
                }
            }
        });

        btnAction.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                applyToSelected();
            }
        });

        etSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {
            }

            @Override
            public void onTextChanged(CharSequence s, int a, int b, int c) {
                filter(s == null ? "" : s.toString());
            }

            @Override
            public void afterTextChanged(Editable s) {
            }
        });

        loadTemplates();
        enterEditModeIfNeeded();
    }

    @Override
    public void onBackPressed() {
        if (pickingApps) {
            backToTemplates();
            return;
        }
        super.onBackPressed();
    }

    // ══════════════════ 状态 ①：仓库列表 ══════════════════

    /** 编辑模式：extra 里带 edit_name（模板名）和 edit_item（旧模块 id） */
    private String editName;
    private String editItem;
    private java.util.List<Integer> editPreselect = new java.util.ArrayList<>();

    private void enterEditModeIfNeeded() {
        android.content.Intent in = getIntent();
        if (in == null) {
            return;
        }
        editName = in.getStringExtra("edit_name");
        editItem = in.getStringExtra("edit_item");
        if (editName == null) {
            return;
        }
        /* 找出模板 */
        UmTemplates.Tpl hit = null;
        for (UmTemplates.Tpl t : UmTemplates.all()) {
            if (t.name.equals(editName)) {
                hit = t;
                break;
            }
        }
        if (hit == null) {
            return;
        }
        /* 读出旧模块的 uid 列表 */
        try {
            for (io.umbral.um.UmRepository.Item it : io.umbral.um.UmRepository.listAll(this)) {
                if (it.id.equals(editItem)) {
                    for (int u : io.umbral.um.UmRepository.appsOf(it)) {
                        editPreselect.add(u);
                    }
                    break;
                }
            }
        } catch (Throwable ignored) {
        }
        enterAppPick(hit);
        /* 预选 */
        try {
            selected.clear();
            for (int u : editPreselect) {
                selected.add(u);
            }
            adapter.notifyDataSetChanged();
            updateActionText();
        } catch (Throwable ignored) {
        }
    }

    private void loadTemplates() {
        pickingApps = false;
        current = null;
        selected.clear();
        tpls.clear();

        /* 目前只有官方内置仓库；将来从 repos() 里加远程源即可 */
        for (UmTemplates.Repo r : UmTemplates.repos()) {
            tpls.addAll(r.items);
        }

        tvTitle.setText(R.string.um_repo_title);
        tvHint.setText(R.string.um_repo_hint);
        etSearch.setVisibility(View.GONE);
        btnAction.setVisibility(View.GONE);
        tvEmpty.setText(R.string.um_repo_empty);
        tvEmpty.setVisibility(tpls.isEmpty() ? View.VISIBLE : View.GONE);
        lv.setVisibility(tpls.isEmpty() ? View.GONE : View.VISIBLE);
        adapter.notifyDataSetChanged();
    }

    // ══════════════════ 状态 ②：选应用 ══════════════════

    private void enterAppPick(UmTemplates.Tpl t) {
        current = t;
        pickingApps = true;
        selected.clear();

        tvTitle.setText(t.name);
        tvHint.setText(t.desc + "\n" + t.note);
        etSearch.setVisibility(View.VISIBLE);
        etSearch.setText("");
        btnAction.setVisibility(View.VISIBLE);
        updateActionText();

        if (!allApps.isEmpty()) {
            filter("");
            return;
        }
        tvEmpty.setText("正在读取已安装应用…");
        tvEmpty.setVisibility(View.VISIBLE);
        lv.setVisibility(View.GONE);

        new Thread(new Runnable() {
            @Override
            public void run() {
                final List<AppEntry> got = AppRepository.listAll(UmRepoActivity.this);
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        allApps.clear();
                        allApps.addAll(got);
                        filter("");
                    }
                });
            }
        }).start();
    }

    private void backToTemplates() {
        loadTemplates();
    }

    private void filter(String kw) {
        shownApps.clear();
        String k = kw.trim().toLowerCase();
        for (AppEntry e : allApps) {
            if (k.isEmpty()
                    || (e.label != null && e.label.toLowerCase().contains(k))
                    || (e.packageName != null && e.packageName.toLowerCase().contains(k))
                    || String.valueOf(e.uid).equals(k)) {
                shownApps.add(e);
            }
        }
        boolean empty = shownApps.isEmpty();
        tvEmpty.setText(k.isEmpty() ? R.string.um_empty : R.string.um_repo_no_match);
        tvEmpty.setVisibility(empty ? View.VISIBLE : View.GONE);
        lv.setVisibility(empty ? View.GONE : View.VISIBLE);
        adapter.notifyDataSetChanged();
    }

    private void toggle(int pos) {
        if (pos < 0 || pos >= shownApps.size()) {
            return;
        }
        int uid = shownApps.get(pos).uid;
        if (selected.contains(uid)) {
            selected.remove(uid);
        } else {
            selected.add(uid);
        }
        updateActionText();
        adapter.notifyDataSetChanged();
    }

    private void updateActionText() {
        btnAction.setText(getString(R.string.um_repo_apply, selected.size()));
        btnAction.setEnabled(!selected.isEmpty());
        btnAction.setAlpha(selected.isEmpty() ? 0.5f : 1f);
    }

    /** 对选中应用逐个下发模板规则 */
    private void applyToSelected() {
        if (current == null || selected.isEmpty()) {
            return;
        }
        btnAction.setEnabled(false);
        btnAction.setText(R.string.um_repo_applying);

        final int[] uids = new int[selected.size()];
        int i = 0;
        for (int u : selected) {
            uids[i++] = u;
        }
        final UmTemplates.Tpl t = current;

        new Thread(new Runnable() {
            @Override
            public void run() {
                /* ① 生成规则文本（每个选中 uid 一套） */
                StringBuilder sb = new StringBuilder();
                sb.append("# 模板：").append(t.name).append("\n");
                /*
                 * ★ 记录这批规则对哪些应用生效 ★
                 *
                 * 写进 .umb 头部，UM 列表读这个就能显示「已对 N 个应用生效」，
                 * 「修改生效应用」时也从这里读出原来的 uid 列表再重下发。
                 * 格式： # 应用： 10563,10564,10599
                 */
                sb.append("# 应用： ");
                for (int k = 0; k < uids.length; k++) {
                    if (k > 0) sb.append(',');
                    sb.append(uids[k]);
                }
                sb.append("\n");
                int lines = 0;
                for (int uid : uids) {
                    for (String line : UmTemplates.buildRules(uid, t)) {
                        sb.append(line).append('\n');
                        lines++;
                    }
                }

                String err = null;
                String moduleId = null;
                if (lines == 0) {
                    err = getString(R.string.um_tpl_none);
                } else {
                    /* ② 存成一个真正的 UM 模块（能在 UM 列表里看到、能卸载） */
                    /*
                     * ★ 模块名用中文模板名，不再用英文 id ★
                     * id 是 hide_root_env 这种内部标识，用户看不懂。
                     * 文件名允许中文（ext4 没问题），同名靠时间戳区分。
                     */
                    /*
                     * 模块名里直接带上「对几个应用生效」——
                     * 这样 UM 列表不用改任何界面就能看到：
                     *     一键隐藏环境（3 个应用）_1794382341945
                     */
                    /* 名字保持干净（带上数量会被列表截断），数量由列表副标题显示 */
                    moduleId = t.name + "_" + System.currentTimeMillis();
                    try {
                        io.umbral.um.UmRepository.saveNewModule(
                                UmRepoActivity.this, moduleId, sb.toString());
                    } catch (Throwable ex) {
                        err = "保存模块失败：" + ex.getMessage();
                    }
                    /* ③ 同时立即生效 */
                    if (err == null) {
                        for (int uid : uids) {
                            for (String line : UmTemplates.buildRules(uid, t)) {
                                io.umbral.sk.Shell.writeProc("/proc/umbral/um",
                                        io.umbral.um.UmTemplates.toBare(line));
                            }
                        }
                    }
                }

                final String ferr = err;
                final int fn = lines;
                final String fname = t.name;
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        btnAction.setEnabled(true);
                        updateActionText();
                        if (ferr == null) {
                            /* ① 通知 UM 列表重载：下次进列表会看到新模块 */
                            io.umbral.um.UmRepository.markDirty();
                        /* 编辑模式：删掉旧模块文件，避免出现两份 */
                        if (editItem != null && editName != null) {
                            try {
                                for (io.umbral.um.UmRepository.Item old :
                                        io.umbral.um.UmRepository.listAll(UmRepoActivity.this)) {
                                    if (old.id.equals(editItem)) {
                                        io.umbral.um.UmRepository.deleteFilesOf(old);
                                        break;
                                    }
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                        }
                        if (ferr != null) {
                            Toast.makeText(UmRepoActivity.this, ferr, Toast.LENGTH_LONG).show();
                            return;
                        }
                        new UmbralDialog(UmRepoActivity.this)
                                .title(getString(R.string.um_repo_saved))
                                .body("已在 UM 模块里生成《" + fname + "》，共 " + fn + " 条规则。\n\n"
                                        + "回到 UM 页就能看到它，点一下可重新应用，长按可删除。")
                                .negative(getString(R.string.cancel), null)
                                .positive(getString(R.string.um_repo_go_um), new Runnable() {
                                    @Override
                                    public void run() {
                                        finish();
                                    }
                                })
                                .show();
                    }
                });
            }
        }).start();
    }

    // ══════════════════ 适配器 ══════════════════

    private class Adapter extends BaseAdapter {
        @Override
        public int getCount() {
            return pickingApps ? shownApps.size() : tpls.size();
        }

        @Override
        public Object getItem(int i) {
            return pickingApps ? shownApps.get(i) : tpls.get(i);
        }

        @Override
        public long getItemId(int i) {
            return i;
        }

        @Override
        public View getView(int pos, View convert, ViewGroup parent) {
            View v = convert;
            if (v == null) {
                v = getLayoutInflater().inflate(R.layout.item_umrepo, parent, false);
            }
            ImageView icon = v.findViewById(R.id.iv_row_icon);
            TextView title = v.findViewById(R.id.tv_row_title);
            TextView sub = v.findViewById(R.id.tv_row_sub);
            TextView check = v.findViewById(R.id.tv_row_check);

            if (pickingApps) {
                AppEntry e = shownApps.get(pos);
                icon.setVisibility(View.VISIBLE);
                if (e.icon != null) {
                    icon.setImageDrawable(e.icon);
                } else {
                    icon.setImageResource(R.drawable.ic_apps);
                }
                title.setText(e.label);
                sub.setText(e.packageName + "   ·   uid " + e.uid);
                boolean on = selected.contains(e.uid);
                check.setVisibility(on ? View.VISIBLE : View.GONE);
                v.setAlpha(1f);
            } else {
                UmTemplates.Tpl t = tpls.get(pos);
                icon.setVisibility(View.VISIBLE);
                icon.setImageResource(R.drawable.ic_um);
                title.setText(t.name);
                sub.setText(t.desc);
                check.setVisibility(View.GONE);
                v.setAlpha(1f);
            }
            return v;
        }
    }
}
