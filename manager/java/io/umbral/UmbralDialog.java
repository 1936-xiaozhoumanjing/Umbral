package io.umbral;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import io.umbral.util.Ui;

/**
 * 自绘对话框。
 *
 * ══════════════════════════════════════════════════════
 *  为什么不用 AlertDialog
 * ══════════════════════════════════════════════════════
 *
 *  AlertDialog 的外框（直角、标题区、按钮分隔线）由系统画，
 *  长相完全跟随 ROM。红魔上出来是一块发闷的黑方块，
 *  和 App 自己的圆角卡片风格撞得很厉害。
 *
 *  这里整块自己画：
 *    圆角 22dp + 1dp 描边
 *    标题 17sp 粗体
 *    正文可滚动，行距放宽
 *    按钮区分主（填充）/次（描边），间距统一
 *
 * ══════════════════════════════════════════════════════
 *  用法
 * ══════════════════════════════════════════════════════
 *
 *  new UmbralDialog(ctx)
 *      .title("删除")
 *      .body("确定删掉这个脚本吗？")
 *      .positive("删除", listener)
 *      .negative("取消", null)
 *      .show();
 */
public class UmbralDialog {

    private final Context ctx;
    private final Dialog dialog;
    private final View root;

    private TextView title;
    private TextView body;
    private ScrollView bodyScroll;
    private FrameLayout content;
    private TextView btnPos;
    private TextView btnNeu;
    private TextView btnNeg;

    public UmbralDialog(Context ctx) {
        this.ctx = ctx;
        this.dialog = new Dialog(ctx);
        this.root = LayoutInflater.from(ctx).inflate(R.layout.dialog_umbral, null);

        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setContentView(root);
        dialog.setCanceledOnTouchOutside(true);

        // 去掉系统窗口背景，否则圆角外面会出现一圈直角黑底
        Window w = dialog.getWindow();
        if (w != null) {
            w.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            w.setLayout(ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT);
            // 左右留边，别顶到屏幕边缘
            WindowManager.LayoutParams lp = w.getAttributes();
            lp.width = WindowManager.LayoutParams.MATCH_PARENT;
            lp.gravity = Gravity.CENTER;
            w.setAttributes(lp);
        }

        title = root.findViewById(R.id.dlg_title);
        body = root.findViewById(R.id.dlg_body);
        bodyScroll = root.findViewById(R.id.dlg_body_scroll);
        content = root.findViewById(R.id.dlg_content);
        btnPos = root.findViewById(R.id.dlg_btn_positive);
        btnNeu = root.findViewById(R.id.dlg_btn_neutral);
        btnNeg = root.findViewById(R.id.dlg_btn_negative);

        // 给根布局留左右边距，圆角才不会贴边
        int m = dp(20);
        root.setPadding(root.getPaddingLeft(), root.getPaddingTop(),
                root.getPaddingRight(), root.getPaddingBottom());
        if (w != null) {
            w.getDecorView().setPadding(m, 0, m, 0);
        }
    }

    public UmbralDialog title(CharSequence t) {
        if (title != null && t != null && t.length() > 0) {
            title.setText(t);
            title.setVisibility(View.VISIBLE);
        }
        return this;
    }

    public UmbralDialog body(CharSequence t) {
        if (body != null && bodyScroll != null && t != null && t.length() > 0) {
            body.setText(t);
            bodyScroll.setVisibility(View.VISIBLE);
            // 正文超过一定高度就内部滚动，避免长文本把按钮顶出屏幕
            bodyScroll.post(new Runnable() {
                @Override
                public void run() {
                    int max = dp(380);
                    if (bodyScroll.getHeight() > max) {
                        ViewGroup.LayoutParams lp = bodyScroll.getLayoutParams();
                        lp.height = max;
                        bodyScroll.setLayoutParams(lp);
                    }
                }
            });
        }
        return this;
    }

    /** 塞自定义内容（单选组、权限九宫格之类） */
    public UmbralDialog content(View v) {
        if (content != null && v != null) {
            content.removeAllViews();
            content.addView(v);
            content.setVisibility(View.VISIBLE);
        }
        return this;
    }

    public UmbralDialog positive(CharSequence text, final Runnable onClick) {
        if (btnPos == null || text == null || text.length() == 0) {
            return this;
        }
        btnPos.setText(text);
        btnPos.setVisibility(View.VISIBLE);
        btnPos.setTextColor(Ui.tc(ctx, R.attr.sk_on_primary));
        btnPos.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // 先关再跑回调：回调里可能又要弹一个对话框
                dismiss();
                if (onClick != null) {
                    onClick.run();
                }
            }
        });
        return this;
    }

    public UmbralDialog neutral(CharSequence text, final Runnable onClick) {
        if (btnNeu == null || text == null || text.length() == 0) {
            return this;
        }
        btnNeu.setText(text);
        btnNeu.setVisibility(View.VISIBLE);
        btnNeu.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dismiss();
                if (onClick != null) {
                    onClick.run();
                }
            }
        });
        return this;
    }

    public UmbralDialog negative(CharSequence text, final Runnable onClick) {
        if (btnNeg == null || text == null || text.length() == 0) {
            return this;
        }
        btnNeg.setText(text);
        btnNeg.setVisibility(View.VISIBLE);
        btnNeg.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dismiss();
                if (onClick != null) {
                    onClick.run();
                }
            }
        });
        return this;
    }

    /** 返回键 / 点外面关闭时的回调（可选） */
    public UmbralDialog onCancel(final Runnable r) {
        dialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface d) {
                if (r != null) {
                    r.run();
                }
            }
        });
        return this;
    }

    /** 不允许点外面关闭 */
    public UmbralDialog blocking() {
        dialog.setCanceledOnTouchOutside(false);
        dialog.setCancelable(false);
        return this;
    }

    public UmbralDialog show() {
        try {
            dialog.show();
        } catch (Exception e) {
            // 宿主 Activity 已经销毁时 show 会抛，静默忽略，别让 App 崩
            return this;
        }
        return this;
    }

    public void dismiss() {
        try {
            if (dialog.isShowing()) {
                dialog.dismiss();
            }
        } catch (Exception ignored) {
        }
    }

    public boolean isShowing() {
        try {
            return dialog.isShowing();
        } catch (Exception e) {
            return false;
        }
    }

    private int dp(int v) {
        return Math.round(ctx.getResources().getDisplayMetrics().density * v);
    }

    // ══════════════════════════════════════════════════════
    //  便捷入口
    // ══════════════════════════════════════════════════════

    /** 一行文字 + 一个确定按钮 */
    public static void message(Context ctx, CharSequence title, CharSequence body,
                               CharSequence ok) {
        new UmbralDialog(ctx)
                .title(title)
                .body(body)
                .positive(ok, null)
                .show();
    }

    /** 确认框 */
    public static void confirm(Context ctx, CharSequence title, CharSequence body,
                               CharSequence ok, Runnable onOk) {
        new UmbralDialog(ctx)
                .title(title)
                .body(body)
                .negative(ctx.getString(android.R.string.cancel), null)
                .positive(ok, onOk)
                .show();
    }

    /** 只用一个 Activity 当宿主时的辅助，避免误用已销毁的 Context */
    public static UmbralDialog of(Activity a) {
        return new UmbralDialog(a);
    }
}
