package io.umbral;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;

import io.umbral.launcher.LauncherSession;
import io.umbral.util.Ui;

/**
 * 内置终端 —— 执行 .sh 并在界面里实时交互。
 *
 * 设计取向：**把脚本当成一个对话对象**，而不是「点一下跑完给结果」。
 *
 *   脚本 print("按音量下键继续")  → 输出区实时出现
 *   用户按「2」快捷键            → 写进脚本 stdin
 *   脚本继续往下跑              → 输出继续追加
 *
 * 三块东西配合：
 *   LauncherSession  持有 Process，负责读输出、写 stdin
 *   本 Activity      负责渲染 + 收集输入
 *   快捷按键条        把常见回答（1/2/3/y/n/回车）做成一排按钮
 *
 * 关于音量键：靠 getevent 读音量键的脚本在这里收不到按键 —— 那需要读
 * /dev/input，普通应用没有权限。能读 stdin 的脚本（大多数真机辅助脚本
 * 都提供 stdin 模式）正常可用。这一点在页面上如实说明，不做假的「能用」。
 */
public class LauncherTerminalActivity extends BaseActivity {

    public static final String EXTRA_PATH = "script_path";
    public static final String EXTRA_USE_ROOT = "use_root";

    private TextView tvOut;
    private TextView tvState;
    private TextView tvTitle;
    private ScrollView svOut;
    private EditText etIn;

    private LauncherSession session;
    private final StringBuilder buffer = new StringBuilder();
    private boolean exited;
    private boolean autoScroll = true;
    /** 用户主动点了停止 —— 这种情况下不该报「代码 N」，而该说「已停止」 */
    private boolean stoppedByUser;
    /** 本次是否以 root 身份执行 */
    private boolean asRoot;
    /** 输出里出现权限拒绝的次数，用来在结束时给一句人话解释 */
    private int permDenials;
    private int notFounds;

    private static final int MAX_CHARS = 200 * 1024;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_launcher_terminal);

        // 脚本可能在等用户操作，息屏会让提示看不见 —— 终端页期间不让它灭
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        tvOut = findViewById(R.id.tv_term_out);
        tvState = findViewById(R.id.tv_term_state);
        tvTitle = findViewById(R.id.tv_term_title);
        svOut = findViewById(R.id.sv_term_out);
        etIn = findViewById(R.id.et_term_in);

        ImageView back = findViewById(R.id.btn_term_back);
        if (back != null) {
            back.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    confirmExit();
                }
            });
        }

        View stop = findViewById(R.id.btn_term_stop);
        if (stop != null) {
            stop.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    stopSession(true);
                }
            });
        }

        View paste = findViewById(R.id.btn_term_paste);
        if (paste != null) {
            paste.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    pasteFromClipboard();
                }
            });
        }

        View send = findViewById(R.id.btn_term_send);
        if (send != null) {
            send.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    sendInput();
                }
            });
        }

        if (etIn != null) {
            etIn.setImeOptions(EditorInfo.IME_ACTION_SEND);
            etIn.setOnEditorActionListener(new TextView.OnEditorActionListener() {
                @Override
                public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                    if (actionId == EditorInfo.IME_ACTION_SEND) {
                        sendInput();
                        return true;
                    }
                    return false;
                }
            });
        }

        // 长按输出区：复制全部 / 清空 / 保存日志
        if (tvOut != null) {
            tvOut.setOnLongClickListener(new View.OnLongClickListener() {
                @Override
                public boolean onLongClick(View v) {
                    showOutputMenu();
                    return true;
                }
            });
        }

        buildQuickKeys();

        // 用户手动往上翻的时候不要再自动滚到底，否则看不清历史输出
        if (svOut != null) {
            svOut.setOnScrollChangeListener(new View.OnScrollChangeListener() {
                @Override
                public void onScrollChange(View v, int x, int y, int ox, int oy) {
                    autoScroll = !svOut.canScrollVertically(1);
                }
            });
        }

        asRoot = getIntent() != null && getIntent().getBooleanExtra(EXTRA_USE_ROOT, false);

        String path = getIntent() == null ? null : getIntent().getStringExtra(EXTRA_PATH);
        if (path == null) {
            Toast.makeText(this, R.string.launcher_run_fail, Toast.LENGTH_SHORT).show();
            finish();
            return;
        }
        File script = new File(path);
        if (tvTitle != null) {
            tvTitle.setText(script.getName());
        }

        // 进来之前就该拦掉的两件事，先说清楚再跑
        String lower = script.getName().toLowerCase();
        if (!lower.endsWith(".sh") && !lower.endsWith(".ko")) {
            append(getString(R.string.terminal_err_not_shko) + "\n");
            setState(getString(R.string.launcher_run_fail), true);
            exited = true;
            return;
        }
        if (lower.endsWith(".ko")) {
            // 加载模块需要 root，这一版没有 root 通道，如实告知
            append(getString(R.string.terminal_err_no_root) + "\n");
            setState(getString(R.string.launcher_run_fail), true);
            exited = true;
            return;
        }
        if (!script.exists()) {
            append(getString(R.string.terminal_err_no_file) + "\n");
            setState(getString(R.string.launcher_run_fail), true);
            exited = true;
            return;
        }

        // 执行前先过安全闸
        guard(script);
    }

    // ── 安全闸 ──

    /**
     * 执行前的静态检查。
     *
     * 致命命中 → 直接不跑，把证据摆给用户看（用户说的「自动终止」在这里
     *            等价于「根本不让它起来」，因为进程还没创建）。
     * 警告命中 → 列出来，用户点「仍要执行」才继续。
     *
     * 为什么不在运行中杀：没有 root 就拿不到文件操作事件，
     * 无法在 syscall 层拦截。等内核模块就位后可以在 do_unlinkat 上补。
     */
    private void guard(final File script) {
        final io.umbral.launcher.ScriptGuard.Report rep =
                io.umbral.launcher.ScriptGuard.scan(script);
        if (rep.clean()) {
            startSession(script);
            return;
        }

        String detail = io.umbral.launcher.ScriptGuard.summarize(rep)
                + "\n\n" + getString(R.string.guard_note);

        if (rep.hasFatal()) {
            exited = true;
            append(getString(R.string.guard_blocked_title) + "\n\n" + detail + "\n");
            setState(getString(R.string.guard_blocked_title), true);
            new android.app.AlertDialog.Builder(this)
                    .setTitle(R.string.guard_blocked_title)
                    .setMessage(getString(R.string.guard_blocked_body, detail))
                    .setPositiveButton(android.R.string.ok, null)
                    .setCancelable(false)
                    .show();
            return;
        }

        // 警告级：让用户自己判断
        new android.app.AlertDialog.Builder(this)
                .setTitle(R.string.guard_warn_title)
                .setMessage(getString(R.string.guard_warn_body, detail))
                .setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        exited = true;
                        append(getString(R.string.guard_blocked_title) + "\n");
                        setState(getString(R.string.guard_blocked_title), true);
                    }
                })
                .setPositiveButton(R.string.guard_run_anyway, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int w) {
                        startSession(script);
                    }
                })
                .setCancelable(false)
                .show();
    }

    // ── 会话 ──

    private void startSession(File script) {
        setState(getString(R.string.terminal_running)
                + "  ·  " + getString(asRoot ? R.string.run_mode_root_short
                                            : R.string.run_mode_normal_short), false);
        append(getString(R.string.terminal_started, script.getName()) + "\n");
        append(getString(R.string.terminal_as_user,
                getString(asRoot ? R.string.run_mode_root_short
                                 : R.string.run_mode_normal_short)) + "\n\n");
        try {
            session = LauncherSession.start(script, script.getParentFile(), asRoot,
                    new LauncherSession.Listener() {
                        @Override
                        public void onOutput(final String chunk) {
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    append(chunk);
                                }
                            });
                        }

                        @Override
                        public void onExit(final int code) {
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    exited = true;

                                    // 先把「为什么结束」说清楚，再补诊断
                                    String reason;
                                    boolean bad;
                                    if (stoppedByUser) {
                                        reason = getString(R.string.terminal_stopped);
                                        bad = false;
                                    } else if (code == 0) {
                                        reason = getString(R.string.terminal_exit_ok);
                                        bad = false;
                                    } else if (code > 128) {
                                        // Unix 惯例：进程被信号终止时退出值是 128+信号号
                                        reason = getString(R.string.terminal_exit_signal, code - 128);
                                        bad = true;
                                    } else {
                                        reason = getString(R.string.terminal_exited, code);
                                        bad = true;
                                    }
                                    append("\n" + reason + "\n");

                                    // 输出里有权限拒绝 / 命令找不到，就给人话解释，
                                    // 而不是让用户对着 "代码 0" 发愣
                                    String hint = diagnose();
                                    if (hint != null) {
                                        append("\n" + getString(R.string.terminal_hint_title) + "\n"
                                                + hint + "\n");
                                        bad = true;
                                    }

                                    setState(reason + "  ·  " + getString(asRoot
                                            ? R.string.run_mode_root_short
                                            : R.string.run_mode_normal_short), bad);
                                }
                            });
                        }
                    });
        } catch (Exception e) {
            exited = true;
            String msg = e.getMessage() == null ? "" : e.getMessage();
            append("\n" + getString(R.string.terminal_err_start_failed, msg) + "\n");
            setState(getString(R.string.launcher_run_fail), true);
        }
    }

    private void stopSession(boolean ask) {
        if (exited || session == null) {
            if (!ask) {
                finish();
            }
            return;
        }
        if (!ask) {
            session.stop();
            return;
        }
        new android.app.AlertDialog.Builder(this)
                .setTitle(R.string.terminal_stop)
                .setMessage(R.string.terminal_kill_confirm)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.terminal_stop,
                        new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface d, int w) {
                                stoppedByUser = true;
                                if (session != null) {
                                    session.stop();
                                }
                                append("\n" + getString(R.string.terminal_stopped) + "\n");
                                setState(getString(R.string.terminal_stopped), false);
                            }
                        })
                .show();
    }

    private void confirmExit() {
        if (!exited && session != null && session.isAlive()) {
            new android.app.AlertDialog.Builder(this)
                    .setTitle(R.string.terminal_stop)
                    .setMessage(R.string.terminal_kill_confirm)
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(R.string.terminal_stop,
                            new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface d, int w) {
                                    if (session != null) {
                                        session.stop();
                                    }
                                    finish();
                                }
                            })
                    .show();
        } else {
            finish();
        }
    }

    /**
     * 把输入框里的内容 + 换行送到脚本。
     *
     * 发完必须把焦点还回输入框并重新拉起键盘 —— 否则用户每发一次都要
     * 再点一下输入框，交互是断的。
     */
    private void sendInput() {
        if (etIn == null) {
            return;
        }
        String text = etIn.getText() == null ? "" : etIn.getText().toString();
        sendRaw(text + "\n");
        etIn.setText("");
        append(text + "\n");   // 回显，让用户看到自己送了什么
        keepInputFocused();
    }

    /** 焦点回到输入框，并确保软键盘是展开的 */
    private void keepInputFocused() {
        if (etIn == null) {
            return;
        }
        etIn.requestFocus();
        etIn.post(new Runnable() {
            @Override
            public void run() {
                InputMethodManager imm = (InputMethodManager)
                        getSystemService(Context.INPUT_METHOD_SERVICE);
                if (imm != null) {
                    imm.showSoftInput(etIn, InputMethodManager.SHOW_IMPLICIT);
                }
            }
        });
    }

    /** 送一段原始文本（快捷键用，不加换行由调用方决定） */
    private void sendRaw(String s) {
        if (session == null || !session.isAlive()) {
            Toast.makeText(this, R.string.terminal_not_running, Toast.LENGTH_SHORT).show();
            return;
        }
        session.send(s);
    }

    private void pasteFromClipboard() {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm == null || cm.getPrimaryClip() == null
                || cm.getPrimaryClip().getItemCount() == 0) {
            Toast.makeText(this, R.string.terminal_clip_empty, Toast.LENGTH_SHORT).show();
            return;
        }
        ClipData.Item item = cm.getPrimaryClip().getItemAt(0);
        CharSequence cs = item.coerceToText(this);
        if (cs == null) {
            return;
        }
        if (etIn != null) {
            // 粘到输入框，让用户可以改完再发 —— 直接发出去太容易误触
            int start = Math.max(0, etIn.getSelectionStart());
            etIn.getText().insert(start, cs);
        }
    }

    // ── 渲染 ──

    private void append(String s) {
        if (s == null || s.isEmpty()) {
            return;
        }
        countSignals(s);
        buffer.append(s);
        // 太长就砍掉前半段，防止长时间运行把内存吃光
        if (buffer.length() > MAX_CHARS) {
            buffer.delete(0, buffer.length() - MAX_CHARS);
        }
        if (tvOut != null) {
            tvOut.setText(buffer.toString());
            if (autoScroll && svOut != null) {
                svOut.post(new Runnable() {
                    @Override
                    public void run() {
                        if (svOut != null) {
                            svOut.fullScroll(View.FOCUS_DOWN);
                        }
                    }
                });
            }
        }
    }

    /** 长按输出区的菜单 */
    private void showOutputMenu() {
        new android.app.AlertDialog.Builder(this)
                .setTitle(R.string.terminal_menu_title)
                .setItems(new CharSequence[]{
                        getString(R.string.terminal_menu_copy),
                        getString(R.string.terminal_menu_clear),
                        getString(R.string.terminal_menu_save)
                }, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int which) {
                        if (which == 0) {
                            copyAll();
                        } else if (which == 1) {
                            buffer.setLength(0);
                            if (tvOut != null) {
                                tvOut.setText("");
                            }
                            Toast.makeText(LauncherTerminalActivity.this,
                                    R.string.terminal_cleared, Toast.LENGTH_SHORT).show();
                        } else {
                            saveLog();
                        }
                    }
                })
                .show();
    }

    private void copyAll() {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm == null) {
            return;
        }
        cm.setPrimaryClip(ClipData.newPlainText("umbral_log", buffer.toString()));
        Toast.makeText(this, R.string.terminal_copied, Toast.LENGTH_SHORT).show();
    }

    /**
     * 把输出存到应用私有目录，供事后排查。
     * 存私有目录而不是 /sdcard：不申请额外权限，路径由菜单提示给出。
     */
    private void saveLog() {
        try {
            java.io.File dir = new java.io.File(getFilesDir(), "logs");
            if (!dir.exists() && !dir.mkdirs()) {
                throw new java.io.IOException("mkdirs failed");
            }
            String stamp = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss",
                    java.util.Locale.US).format(new java.util.Date());
            java.io.File f = new java.io.File(dir, "term_" + stamp + ".log");
            java.io.FileOutputStream fo = new java.io.FileOutputStream(f);
            try {
                fo.write(buffer.toString().getBytes("UTF-8"));
                fo.flush();
            } finally {
                fo.close();
            }
            Toast.makeText(this,
                    getString(R.string.terminal_saved, f.getName()),
                    Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, R.string.terminal_save_fail, Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * 扫输出里的错误特征。
     *
     * 为什么需要：脚本常常是「这条命令失败了，但后面还有 echo」，
     * 于是退出码是 0，用户完全不知道中间出过错。
     * 这里把特征记下来，结束时给一句人话解释。
     */
    private void countSignals(String s) {
        permDenials += countOf(s, "Permission denied")
                + countOf(s, "Operation not permitted")
                + countOf(s, "EACCES")
                + countOf(s, "EPERM");
        notFounds += countOf(s, "No such file or directory")
                + countOf(s, "command not found")
                + countOf(s, "not found");
    }

    private int countOf(String haystack, String needle) {
        if (haystack == null || needle == null) {
            return 0;
        }
        int n = 0;
        int i = 0;
        while ((i = haystack.indexOf(needle, i)) >= 0) {
            n++;
            i += needle.length();
        }
        return n;
    }

    /** @return 诊断文字，无需诊断时返回 null */
    private String diagnose() {
        StringBuilder sb = new StringBuilder();
        if (permDenials > 0) {
            sb.append("· ").append(getString(R.string.terminal_hint_perm))
              .append(' ').append(getString(R.string.terminal_hint_count, permDenials))
              .append('\n');
        }
        if (notFounds > 0) {
            sb.append("· ").append(getString(R.string.terminal_hint_notfound))
              .append(' ').append(getString(R.string.terminal_hint_count, notFounds))
              .append('\n');
        }
        String out = sb.toString().trim();
        return out.isEmpty() ? null : out;
    }

    private void setState(String text, boolean dead) {
        if (tvState == null) {
            return;
        }
        tvState.setText(text);
        tvState.setTextColor(Ui.tc(this, dead ? R.attr.sk_error : R.attr.sk_success));
    }

    /**
     * 快捷按键条。
     *
     * 选这几个是因为脚本提示基本就是这几类：
     *   「按 1 / 按 2 选择」     → 1 2 3
     *   「是否继续 (y/n)」        → y n
     *   「按回车确认」            → ⏎
     *   「输入完成后回车」        → Esc / Ctrl+C 退出
     */
    private void buildQuickKeys() {
        LinearLayout row = findViewById(R.id.row_term_keys);
        if (row == null) {
            return;
        }
        addKey(row, "\u23ce", "\n", true);      // 回车
        addKey(row, "1", "1", false);
        addKey(row, "2", "2", false);
        addKey(row, "3", "3", false);
        addKey(row, "y", "y\n", false);
        addKey(row, "n", "n\n", false);
        addKey(row, "Esc", "\u001b", false);
        addKey(row, "Ctrl+C", "\u0003", false);
    }

    private void addKey(LinearLayout row, String label, final String payload, boolean bold) {
        TextView b = new TextView(this);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMarginEnd(dp(6));
        b.setLayoutParams(lp);
        b.setText(label);
        b.setTextSize(13);
        b.setTypeface(null, bold ? android.graphics.Typeface.BOLD
                                 : android.graphics.Typeface.NORMAL);
        b.setTextColor(Ui.tc(this, R.attr.sk_on_surface));
        b.setBackgroundResource(R.drawable.bg_chip);
        b.setPadding(dp(14), dp(8), dp(14), dp(8));
        b.setClickable(true);
        // 关键：不抢焦点。否则点一下快捷键，输入框就失焦，
        // 用户要再点回来才能继续打字 —— 正是「发一次要点一次」的根源。
        b.setFocusable(false);
        b.setFocusableInTouchMode(false);
        b.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                sendRaw(payload);
                append(label.equals("\u23ce") ? "\n" : label + "\n");
                keepInputFocused();
            }
        });
        row.addView(b);
    }

    private int dp(int v) {
        return Math.round(getResources().getDisplayMetrics().density * v);
    }

    @Override
    protected void onResume() {
        super.onResume();
        // 回到前台就把光标放回输入框，省一次点击
        keepInputFocused();
    }

    @Override
    public void onBackPressed() {
        confirmExit();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        // 界面没了就别留着脚本空转
        if (session != null && !exited) {
            session.stop();
        }
    }
}
