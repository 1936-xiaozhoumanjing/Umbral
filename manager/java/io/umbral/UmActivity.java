package io.umbral;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import io.umbral.um.UmModule;
import io.umbral.um.UmRepository;
import io.umbral.util.Ui;

/**
 * UM 模块页。
 *
 * 能做的事：
 *   ① 导入 —— 支持 .umb（已加密）和纯规则文本（自动加密后保存）
 *   ② 列表 —— 显示每个模块的载荷类型 / 规则条数 / 用的是第几把钥匙
 *   ③ 应用 —— 把规则下发到 /proc/umbral/um
 *   ④ 长按删除
 *
 * 不依赖内核模块也能打开（只是「应用」会失败并说明原因）。
 */
public class UmActivity extends BaseActivity {

    private static final int REQ_PICK = 0x51;

    private ListView lv;
    private TextView tvEmpty;
    private final List<UmRepository.Item> items = new ArrayList<>();
    private Adapter adapter;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_um);

        lv = findViewById(R.id.lv_um);
        tvEmpty = findViewById(R.id.tv_um_empty);

        findViewById(R.id.btn_um_back).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });

        findViewById(R.id.btn_um_import).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                pick();
            }
        });

        /* 介绍卡片：默认收起，点一下展开完整说明 */
        final TextView introBody = findViewById(R.id.tv_intro_body);
        final TextView introMore = findViewById(R.id.btn_intro_more);
        introMore.setOnClickListener(new View.OnClickListener() {
            private boolean expanded;

            @Override
            public void onClick(View v) {
                expanded = !expanded;
                introBody.setText(expanded ? R.string.um_intro_full : R.string.um_intro_body);
                introMore.setText(expanded ? R.string.um_intro_collapse : R.string.um_intro_more);
            }
        });

        adapter = new Adapter();
        lv.setAdapter(adapter);
        lv.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> p, View v, int pos, long id) {
                apply(pos);
            }
        });
        lv.setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() {
            @Override
            public boolean onItemLongClick(AdapterView<?> p, View v, int pos, long id) {
                confirmDelete(pos);
                return true;
            }
        });

        reload();
    }

    // ══════════════════ 导入 ══════════════════

    private void pick() {
        Intent i = new Intent(Intent.ACTION_GET_CONTENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        try {
            startActivityForResult(Intent.createChooser(i, getString(R.string.um_import)),
                    REQ_PICK);
        } catch (Exception e) {
            Toast.makeText(this, String.valueOf(e.getMessage()), Toast.LENGTH_LONG).show();
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req != REQ_PICK || res != RESULT_OK || data == null || data.getData() == null) {
            return;
        }
        Uri uri = data.getData();
        String name = displayName(uri);
        InputStream in = null;
        try {
            in = getContentResolver().openInputStream(uri);
            byte[] raw = UmRepository.readAll(in);
            String id = UmRepository.importBytes(this, raw, name);
            Toast.makeText(this, getString(R.string.um_import_ok, id), Toast.LENGTH_SHORT).show();
            reload();
        } catch (UmModule.UmException e) {
            Toast.makeText(this, getString(R.string.um_import_fail, e.getMessage()),
                    Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.um_import_fail, String.valueOf(e.getMessage())),
                    Toast.LENGTH_LONG).show();
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private String displayName(Uri uri) {
        android.database.Cursor c = null;
        try {
            c = getContentResolver().query(uri,
                    new String[]{android.provider.OpenableColumns.DISPLAY_NAME}, null, null, null);
            if (c != null && c.moveToFirst()) {
                return c.getString(0);
            }
        } catch (Exception ignored) {
        } finally {
            if (c != null) {
                c.close();
            }
        }
        return uri.getLastPathSegment();
    }

    // ══════════════════ 列表 ══════════════════

    private void reload() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                final List<UmRepository.Item> got = UmRepository.listAll(UmActivity.this);
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        items.clear();
                        items.addAll(got);
                        adapter.notifyDataSetChanged();
                        boolean empty = items.isEmpty();
                        tvEmpty.setVisibility(empty ? View.VISIBLE : View.GONE);
                        lv.setVisibility(empty ? View.GONE : View.VISIBLE);
                    }
                });
            }
        }).start();
    }

    private void apply(int pos) {
        if (pos < 0 || pos >= items.size()) {
            return;
        }
        final UmRepository.Item it = items.get(pos);
        String err = UmRepository.apply(it);
        if (err == null) {
            Toast.makeText(this, getString(R.string.um_apply_ok, it.id), Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, getString(R.string.um_apply_fail, err), Toast.LENGTH_LONG).show();
        }
    }

    private void confirmDelete(int pos) {
        if (pos < 0 || pos >= items.size()) {
            return;
        }
        final UmRepository.Item it = items.get(pos);
        new UmbralDialog(this)
                .title(getString(R.string.um_delete_title, it.id))
                .body(getString(R.string.um_delete_msg))
                .negative(getString(R.string.cancel), null)
                .positive(getString(R.string.um_delete), new Runnable() {
                    @Override
                    public void run() {
                        java.io.File f = new java.io.File(it.path);
                        if (f.delete()) {
                            reload();
                        } else {
                            Toast.makeText(UmActivity.this, R.string.um_delete_fail,
                                    Toast.LENGTH_SHORT).show();
                        }
                    }
                })
                .show();
    }

    // ══════════════════ 列表适配器 ══════════════════

    private class Adapter extends BaseAdapter {
        @Override
        public int getCount() {
            return items.size();
        }

        @Override
        public Object getItem(int i) {
            return items.get(i);
        }

        @Override
        public long getItemId(int i) {
            return i;
        }

        @Override
        public View getView(int pos, View convert, ViewGroup parent) {
            View v = convert;
            if (v == null) {
                v = getLayoutInflater().inflate(R.layout.item_um, parent, false);
            }
            UmRepository.Item it = items.get(pos);

            TextView name = v.findViewById(R.id.tv_um_name);
            TextView meta = v.findViewById(R.id.tv_um_meta);
            TextView err = v.findViewById(R.id.tv_um_err);

            name.setText(it.id);
            meta.setText(it.meta());

            if (it.error == null) {
                err.setVisibility(View.GONE);
            } else {
                err.setVisibility(View.VISIBLE);
                err.setText(it.error);
                err.setTextColor(Ui.tc(UmActivity.this, R.attr.sk_error));
            }
            return v;
        }
    }
}
