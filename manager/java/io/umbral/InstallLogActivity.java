package io.umbral;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 安装 / 刷入进度页。
 *
 * ══════════════════════════════════════════════════════
 *  为什么必须有这一页
 * ══════════════════════════════════════════════════════
 *
 *  在此之前，安装失败只弹一个 Toast / 对话框：
 *      · 长文本被截断，用户根本看不到后半段
 *      · 消失就没了，没法复制、没法截图完整
 *
 *  这一页做的事很简单，但解决根本问题：
 *      · 每一条日志一行，全部保留，可滚动到底
 *      · 失败的异常原文完整显示（不截断）
 *      · 提供「复制全部」，一键把整段日志复制到剪贴板
 *      · 提供「保存到文件」，落到 App 外部目录，adb 能直接拉
 *
 *  调用方（模块页 / UM 页）只需要：
 *      InstallLogActivity.start(context, "安装 xxx.zip");
 *      InstallLogActivity.log("解压中…");
 *      InstallLogActivity.fail("读压缩包失败：" + e);
 */
public class InstallLogActivity extends BaseActivity {

    public static final String EXTRA_TITLE = "title";

    private static final Handler UI = new Handler(Looper.getMainLooper());
    private static final StringBuilder BUFFER = new StringBuilder();
    private static InstallLogActivity CURRENT;

    private TextView tv;
    private ScrollView sv;

    /** 打开这一页并清空日志 */
    public static void start(android.content.Context ctx, String title) {
        synchronized (BUFFER) {
            BUFFER.setLength(0);
        }
        android.content.Intent i = new android.content.Intent(ctx, InstallLogActivity.class);
        i.putExtra(EXTRA_TITLE, title);
        i.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
        ctx.startActivity(i);
    }

    /** 追加一条日志（任何线程都可调用） */
    public static void log(String line) {
        String ts = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        synchronized (BUFFER) {
            BUFFER.append(ts).append("  ").append(line).append('\n');
        }
        UI.post(new Runnable() {
            @Override
            public void run() {
                InstallLogActivity a = CURRENT;
                if (a != null) {
                    a.refresh();
                }
            }
        });
    }

    /** 追加一条错误（原文完整保留） */
    public static void fail(String err) {
        log("✗ 失败：" + err);
    }

    /** 追加一条成功 */
    public static void ok(String msg) {
        log("✓ " + msg);
    }

    public static String dump() {
        synchronized (BUFFER) {
            return BUFFER.toString();
        }
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_install_log);

        CURRENT = this;
        tv = findViewById(R.id.tv_install_log);
        sv = findViewById(R.id.sv_install_log);

        String title = getIntent().getStringExtra(EXTRA_TITLE);
        if (title != null) {
            setTitle(title);
        }
        TextView head = findViewById(R.id.tv_install_title);
        if (head != null && title != null) {
            head.setText(title);
        }

        Button copy = findViewById(R.id.btn_install_copy);
        if (copy != null) {
            copy.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    android.content.ClipboardManager cm =
                            (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("umbral", dump()));
                        android.widget.Toast.makeText(InstallLogActivity.this,
                                "已复制全部日志", android.widget.Toast.LENGTH_SHORT).show();
                    }
                }
            });
        }

        Button save = findViewById(R.id.btn_install_save);
        if (save != null) {
            save.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    try {
                        java.io.File dir = getExternalFilesDir(null);
                        java.io.File f = new java.io.File(dir, "install_" + System.currentTimeMillis() + ".txt");
                        java.io.FileOutputStream fo = new java.io.FileOutputStream(f);
                        fo.write(dump().getBytes("UTF-8"));
                        fo.flush();
                        fo.getFD().sync();
                        fo.close();
                        android.widget.Toast.makeText(InstallLogActivity.this,
                                "已保存：" + f.getAbsolutePath(),
                                android.widget.Toast.LENGTH_LONG).show();
                    } catch (Throwable t) {
                        android.widget.Toast.makeText(InstallLogActivity.this,
                                "保存失败：" + t, android.widget.Toast.LENGTH_LONG).show();
                    }
                }
            });
        }

        refresh();
    }

    @Override
    protected void onDestroy() {
        if (CURRENT == this) {
            CURRENT = null;
        }
        super.onDestroy();
    }

    private void refresh() {
        if (tv == null) {
            return;
        }
        tv.setText(dump());
        if (sv != null) {
            sv.post(new Runnable() {
                @Override
                public void run() {
                    sv.fullScroll(View.FOCUS_DOWN);
                }
            });
        }
    }
}
