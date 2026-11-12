package io.umbral;

import android.content.DialogInterface;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;

import io.umbral.launcher.LauncherStore;
import io.umbral.launcher.ScriptGuard;
import io.umbral.util.Ui;

/**
 * 脚本编辑器。
 *
 * 独立页面而不是对话框 —— 脚本长起来对话框根本没法改。
 *
 * 三个要点：
 *   ① 保存前跑一遍 ScriptGuard，把新引入的危险命令提示出来
 *   ② 有未保存修改时返回要确认，不能默默丢掉
 *   ③ 底部显示行数，长脚本至少知道自己改到哪了
 */
public class LauncherEditorActivity extends BaseActivity {

    public static final String EXTRA_PATH = "edit_path";

    private static final int MAX_BYTES = 512 * 1024;

    private EditText body;
    private TextView title;
    private TextView state;
    private TextView lines;

    private File file;
    private String original = "";
    private boolean dirty;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_launcher_editor);

        body = findViewById(R.id.et_edit_body);
        title = findViewById(R.id.tv_edit_title);
        state = findViewById(R.id.tv_edit_state);
        lines = findViewById(R.id.tv_edit_lines);

        ImageView back = findViewById(R.id.btn_edit_back);
        if (back != null) {
            back.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    confirmLeave();
                }
            });
        }

        View save = findViewById(R.id.btn_edit_save);
        if (save != null) {
            save.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    save();
                }
            });
        }

        View tab = findViewById(R.id.btn_edit_tab);
        if (tab != null) {
            tab.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    insert("\t");
                }
            });
        }

        View comment = findViewById(R.id.btn_edit_comment);
        if (comment != null) {
            comment.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    insert("# ");
                }
            });
        }

        if (body != null) {
            body.addTextChangedListener(new TextWatcher() {
                @Override
                public void beforeTextChanged(CharSequence s, int a, int b, int c) {
                }

                @Override
                public void onTextChanged(CharSequence s, int a, int b, int c) {
                }

                @Override
                public void afterTextChanged(Editable s) {
                    dirty = !s.toString().equals(original);
                    updateState();
                }
            });
        }

        String path = getIntent() == null ? null : getIntent().getStringExtra(EXTRA_PATH);
        if (path == null) {
            finish();
            return;
        }
        file = new File(path);
        if (title != null) {
            title.setText(file.getName());
        }

        String text = LauncherStore.readText(file, MAX_BYTES);
        if (text == null) {
            Toast.makeText(this, R.string.launcher_view_binary, Toast.LENGTH_LONG).show();
            finish();
            return;
        }
        original = text;
        if (body != null) {
            body.setText(text);
            body.setSelection(0);
        }
        dirty = false;
        updateState();
    }

    private void insert(String s) {
        if (body == null) {
            return;
        }
        int start = Math.max(0, body.getSelectionStart());
        body.getText().insert(start, s);
    }

    private void updateState() {
        if (state != null) {
            state.setText(dirty ? getString(R.string.editor_unsaved)
                                : getString(R.string.editor_saved));
            state.setTextColor(Ui.tc(this, dirty ? R.attr.sk_error : R.attr.sk_success));
        }
        if (lines != null && body != null) {
            String t = body.getText() == null ? "" : body.getText().toString();
            int n = 1;
            for (int i = 0; i < t.length(); i++) {
                if (t.charAt(i) == '\n') {
                    n++;
                }
            }
            lines.setText(getString(R.string.editor_lines, n));
        }
    }

    /**
     * 保存。
     *
     * 写盘前先跑安全扫描：如果用户刚加了一条危险命令，
     * 这里就应该拦一下 —— 否则等到执行时才拦，编辑过的内容已经落盘了。
     */
    private void save() {
        if (file == null || body == null) {
            return;
        }
        final String text = body.getText() == null ? "" : body.getText().toString();

        // 先写临时文件做扫描，避免先污染原文件再检查
        File tmp = new File(file.getParentFile(), ".guard_" + System.currentTimeMillis());
        FileOutputStream fo = null;
        try {
            fo = new FileOutputStream(tmp);
            fo.write(text.getBytes("UTF-8"));
            fo.flush();
        } catch (Exception e) {
            Toast.makeText(this, R.string.editor_save_fail, Toast.LENGTH_SHORT).show();
            return;
        } finally {
            if (fo != null) {
                try {
                    fo.close();
                } catch (Exception ignored) {
                }
            }
        }

        final ScriptGuard.Report rep = ScriptGuard.scan(tmp);
        try {
            tmp.delete();
        } catch (Exception ignored) {
        }

        if (rep.hasFatal()) {
            new android.app.AlertDialog.Builder(this)
                    .setTitle(R.string.guard_warn_title)
                    .setMessage(getString(R.string.guard_save_confirm,
                            ScriptGuard.summarize(rep)))
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(R.string.guard_run_anyway,
                            new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface d, int w) {
                                    doSave(text);
                                }
                            })
                    .show();
            return;
        }
        doSave(text);
    }

    private void doSave(String text) {
        FileOutputStream fo = null;
        try {
            fo = new FileOutputStream(file);
            fo.write(text.getBytes("UTF-8"));
            fo.flush();
            original = text;
            dirty = false;
            updateState();
            Toast.makeText(this, R.string.editor_save_ok, Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, R.string.editor_save_fail, Toast.LENGTH_SHORT).show();
        } finally {
            if (fo != null) {
                try {
                    fo.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private void confirmLeave() {
        if (!dirty) {
            finish();
            return;
        }
        new android.app.AlertDialog.Builder(this)
                .setTitle(R.string.editor_unsaved)
                .setMessage(R.string.editor_leave_confirm)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.editor_discard,
                        new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface d, int w) {
                                finish();
                            }
                        })
                .show();
    }

    @Override
    public void onBackPressed() {
        confirmLeave();
    }
}
