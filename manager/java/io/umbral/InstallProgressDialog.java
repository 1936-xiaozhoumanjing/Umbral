package io.umbral;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 刷入进度：全屏覆盖 + 进度条 + 实时滚动的日志。
 *
 * ══════════════════════════════════════════════════════
 *  为什么要有这一屏（而不是弹个对话框）
 * ══════════════════════════════════════════════════════
 *
 *  安装模块可能要做十几步（读包、解压 104 个文件、写模块目录、
 *  建 disable 标记……），其中任何一步都可能失败。
 *
 *  用户要看的是：
 *     · 现在做到第几步（进度条 + 百分比）
 *     · 每一步做了什么（滚动的日志行）
 *     · 失败时停在哪一步、原始异常是什么（不截断）
 *
 *  所以这一屏是全屏的、有进度条、日志实时滚动、可复制可保存。
 *
 *  ★ 线程模型：step()/log() 可以在任意线程调，内部 post 到主线程。
 */
public class InstallProgressDialog {

    /** 字符画标题（仿 KSU 刷入界面） */
    private static final String ART =
            " ██╗   ██╗███╗   ███╗██████╗ ██████╗  █████╗ ██╗\n"
            + " ██║   ██║████╗ ████║██╔══██╗██╔══██╗██╔══██╗██║\n"
            + " ██║   ██║██╔████╔██║██████╔╝██████╔╝███████║██║\n"
            + " ██║   ██║██║╚██╔╝██║██╔══██╗██╔══██╗██╔══██║██║\n"
            + " ╚██████╔╝██║ ╚═╝ ██║██████╔╝██║  ██║██║  ██║███████╗\n"
            + "  ╚═════╝ ╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝";

    private final Dialog dialog;
    private final ProgressBar bar;
    private final TextView tvLog;
    private final TextView tvStep;
    private final ScrollView sv;
    private final Button btnCopy;
    private final Button btnClose;
    private final StringBuilder buf = new StringBuilder();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final int totalSteps;
    private int done;

    public InstallProgressDialog(Context ctx, String title, int totalSteps) {
        this.totalSteps = Math.max(1, totalSteps);

        LinearLayout root = new LinearLayout(ctx);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#F7F7F8"));
        int pad = (int) (ctx.getResources().getDisplayMetrics().density * 16);
        root.setPadding(pad, pad, pad, pad);

        /*
         * ★ 仿 KSU 的字符画标题 ★
         * KSU 刷入界面顶部是用字符拼的 KSU 字样，我们放 UMBRAL。
         * 用等宽小字号，避免在不同屏幕上换行错位。
         */
        TextView tvArt = new TextView(ctx);
        tvArt.setText(ART);
        tvArt.setTextSize(6.5f);
        tvArt.setTextColor(Color.parseColor("#1A1A1A"));
        tvArt.setTypeface(android.graphics.Typeface.MONOSPACE);
        tvArt.setIncludeFontPadding(false);
        tvArt.setLineSpacing(0f, 0.95f);
        root.addView(tvArt, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView tvTitle = new TextView(ctx);
        tvTitle.setText(title);
        tvTitle.setTextSize(17);
        tvTitle.setTextColor(Color.parseColor("#1A1A1A"));
        root.addView(tvTitle, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        tvStep = new TextView(ctx);
        tvStep.setText("准备中…");
        tvStep.setTextSize(13);
        tvStep.setTextColor(Color.parseColor("#666666"));
        LinearLayout.LayoutParams lpStep = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lpStep.topMargin = pad / 2;
        root.addView(tvStep, lpStep);

        bar = new ProgressBar(ctx, null, android.R.attr.progressBarStyleHorizontal);
        bar.setMax(this.totalSteps);
        bar.setProgress(0);
        LinearLayout.LayoutParams lpBar = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, (int) (6 * ctx.getResources().getDisplayMetrics().density));
        lpBar.topMargin = pad / 2;
        root.addView(bar, lpBar);

        sv = new ScrollView(ctx);
        LinearLayout.LayoutParams lpSv = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        lpSv.topMargin = pad / 2;
        tvLog = new TextView(ctx);
        tvLog.setTextSize(11);
        tvLog.setTextColor(Color.parseColor("#333333"));
        tvLog.setTypeface(android.graphics.Typeface.MONOSPACE);
        tvLog.setTextIsSelectable(true);
        sv.addView(tvLog);
        root.addView(sv, lpSv);

        LinearLayout barRow = new LinearLayout(ctx);
        barRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams lpRow = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lpRow.topMargin = pad / 2;

        btnCopy = new Button(ctx);
        btnCopy.setText("复制日志");
        btnCopy.setEnabled(false);
        barRow.addView(btnCopy, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        btnClose = new Button(ctx);
        btnClose.setText("关闭");
        btnClose.setEnabled(false);
        barRow.addView(btnClose, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        root.addView(barRow, lpRow);

        dialog = new Dialog(ctx);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setContentView(root);
        dialog.setCancelable(false);
        Window w = dialog.getWindow();
        if (w != null) {
            w.setBackgroundDrawable(new ColorDrawable(Color.WHITE));
            w.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
            w.setLayout(WindowManager.LayoutParams.MATCH_PARENT,
                    WindowManager.LayoutParams.MATCH_PARENT);
        }

        btnCopy.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    android.content.ClipboardManager cm =
                            (android.content.ClipboardManager)
                                    dialog.getContext().getSystemService(Context.CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("umbral", buf.toString()));
                        btnCopy.setText("已复制");
                    }
                } catch (Throwable ignored) {
                }
            }
        });
        btnClose.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    dialog.dismiss();
                } catch (Throwable ignored) {
                }
            }
        });
    }

    public void show() {
        try {
            dialog.show();
        } catch (Throwable ignored) {
        }
    }

    /** 推进到第 n 步（1..totalSteps），并写一行日志 */
    public void step(final int n, final String line) {
        log(line);
        ui.post(new Runnable() {
            @Override
            public void run() {
                done = Math.max(done, n);
                bar.setProgress(Math.min(done, totalSteps));
                tvStep.setText("第 " + Math.min(done, totalSteps) + " / " + totalSteps + " 步");
            }
        });
    }

    /** 只写日志 */
    public void log(final String line) {
        final String ts = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        synchronized (buf) {
            buf.append(ts).append("  ").append(line).append('\n');
        }
        ui.post(new Runnable() {
            @Override
            public void run() {
                tvLog.setText(buf.toString());
                sv.post(new Runnable() {
                    @Override
                    public void run() {
                        sv.fullScroll(View.FOCUS_DOWN);
                    }
                });
            }
        });
    }

    /** 完成：ok=true 绿色收尾，false 停在错误行 */
    public void finish(final boolean ok, final String summary) {
        log(ok ? ("✓ " + summary) : ("✗ " + summary));
        ui.post(new Runnable() {
            @Override
            public void run() {
                if (ok) {
                    bar.setProgress(totalSteps);
                    tvStep.setText("完成");
                } else {
                    tvStep.setText("失败 —— 完整日志见下方");
                }
                btnCopy.setEnabled(true);
                btnClose.setEnabled(true);
                dialog.setCancelable(true);
            }
        });
    }

    public String dump() {
        synchronized (buf) {
            return buf.toString();
        }
    }
}
