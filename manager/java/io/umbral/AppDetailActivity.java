package io.umbral;

import io.umbral.util.Ui;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.Toast;

import io.umbral.data.AppEntry;
import io.umbral.data.AppRepository;
import io.umbral.sk.ModuleControl;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 应用详情页 —— 两步授权的第二步。
 *
 * 在列表里点一下只是「进来看看」，必须在这一页再点一次授权按钮，
 * 并经过确认对话框，才会真正写进授权名单。
 */
public class AppDetailActivity extends BaseActivity {

    public static final String EXTRA_PKG = "pkg";

    private String pkg;
    private AppEntry entry;

    private TextView btnAuthorize;
    private TextView tvStatus;
    private View statusDot;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app_detail);

        pkg = getIntent() == null ? null : getIntent().getStringExtra(EXTRA_PKG);
        if (pkg == null) {
            finish();
            return;
        }
        entry = AppRepository.find(this, pkg);
        if (entry == null) {
            finish();
            return;
        }

        findViewById(R.id.btn_back).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });

        bindStatic();
        btnAuthorize = findViewById(R.id.btn_authorize);
        btnAuthorize.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onAuthorizeClicked();
            }
        });

        render();
    }

    private void bindStatic() {
        ImageView icon = findViewById(R.id.iv_detail_icon);
        if (entry.icon != null) {
            icon.setImageDrawable(entry.icon);
        } else {
            icon.setImageResource(R.drawable.ic_apps);
        }

        ((TextView) findViewById(R.id.tv_detail_name)).setText(entry.label);
        ((TextView) findViewById(R.id.tv_detail_pkg)).setText(entry.packageName);
        ((TextView) findViewById(R.id.tv_detail_uid)).setText(String.valueOf(entry.uid));

        String ver = entry.versionName;
        if (ver == null || ver.isEmpty()) {
            ver = "-";
        }
        if (entry.versionCode > 0) {
            ver = ver + "  (" + entry.versionCode + ")";
        }
        ((TextView) findViewById(R.id.tv_detail_version)).setText(ver);

        ((TextView) findViewById(R.id.tv_detail_installed)).setText(fmt(entry.firstInstallTime));
        ((TextView) findViewById(R.id.tv_detail_updated)).setText(fmt(entry.lastUpdateTime));
        ((TextView) findViewById(R.id.tv_detail_sdk)).setText("API " + entry.targetSdk);

        tvStatus = findViewById(R.id.tv_detail_status);
        statusDot = findViewById(R.id.v_status_dot);
    }

    private void render() {
        if (entry.granted) {
            tvStatus.setText(R.string.granted);
            tvStatus.setTextColor(Ui.tc(this, R.attr.sk_success));
            statusDot.setBackgroundResource(R.drawable.dot_on);

            btnAuthorize.setText(R.string.revoke_root);
            btnAuthorize.setBackgroundResource(R.drawable.bg_btn_danger);
            btnAuthorize.setTextColor(Ui.tc(this, R.attr.sk_on_primary));
        } else {
            tvStatus.setText(R.string.not_granted);
            tvStatus.setTextColor(Ui.tc(this, R.attr.sk_on_surface_variant));
            statusDot.setBackgroundResource(R.drawable.dot_off);

            btnAuthorize.setText(R.string.authorize_root);
            btnAuthorize.setBackgroundResource(R.drawable.bg_btn_primary);
            btnAuthorize.setTextColor(Ui.tc(this, R.attr.sk_on_primary));
        }
    }

    /**
     * 授权按钮。
     *
     * 已授权 → 撤销确认
     * 未授权 → **先选模式**：
     *      影子用户   只拉 caps，uid 不变，看不出有 root
     *      超级用户   caps + uid→0，是真 root，但一眼能查出
     *
     * 为什么必须让用户选：这两种模式的能力互斥 ——
     *   检查 getuid 的程序（MT 管理器 root 模式、Termux）只认超级用户；
     *   要躲检测的程序只认影子。选错了就是「授权了却不管用」。
     */
    private void onAuthorizeClicked() {
        if (entry.granted) {
            new UmbralDialog(this)
                    .title(getString(R.string.revoke_root))
                    .body(getString(R.string.app_detail_revoke_confirm, entry.label))
                    .negative(getString(R.string.cancel), null)
                    .positive(getString(R.string.revoke), new Runnable() {
                        @Override
                        public void run() {
                            boolean ok = AppRepository.revoke(AppDetailActivity.this, pkg);
                            Toast.makeText(AppDetailActivity.this,
                                    getString(ok ? R.string.toast_revoked : R.string.revoke_failed,
                                            entry.label),
                                    Toast.LENGTH_SHORT).show();
                            entry.granted = false;
                            entry.grantMode = ModuleControl.MODE_NONE;
                            render();
                        }
                    })
                    .show();
            return;
        }

        // 模式选择
        /*
         * ★ 必须是 RadioGroup，不能是 LinearLayout ★
         *
         * RadioButton 放在普通 LinearLayout 里互相不排斥 ——
         * 勾了「超级用户」，影子用户那个不会自动取消，
         * 看起来就是"两个权限同时在"。
         * RadioGroup 才会强制单选。实测就是这个 bug。
         */
        final android.widget.RadioGroup box = new android.widget.RadioGroup(this);
        box.setOrientation(LinearLayout.VERTICAL);

        final RadioButton rbShadow = modeRow(box, R.string.grant_mode_shadow,
                R.string.grant_mode_shadow_desc, true);
        final RadioButton rbSuper = modeRow(box, R.string.grant_mode_super,
                R.string.grant_mode_super_desc, false);

        /* 完全影子：只有设置里打开了这个功能才出现 */
        final boolean fullShadowOn = getSharedPreferences("sk_settings", MODE_PRIVATE)
                .getBoolean("full_shadow_enabled", false);
        final RadioButton rbFull;
        if (fullShadowOn) {
            rbFull = modeRow(box, R.string.grant_mode_full,
                    R.string.grant_mode_full_desc, false);
        } else {
            rbFull = null;
        }

        new UmbralDialog(this)
                .title(getString(R.string.grant_mode_title, entry.label))
                .content(box)
                .negative(getString(R.string.cancel), null)
                .positive(getString(R.string.confirm_grant), new Runnable() {
                    @Override
                    public void run() {
                        int mode;
                        if (rbFull != null && rbFull.isChecked()) {
                            mode = ModuleControl.MODE_FULL;
                        } else if (rbSuper.isChecked()) {
                            mode = ModuleControl.MODE_SUPER;
                        } else {
                            mode = ModuleControl.MODE_SHADOW;
                        }
                        boolean ok = AppRepository.grant(AppDetailActivity.this, pkg, mode);
                        Toast.makeText(AppDetailActivity.this,
                                getString(ok ? R.string.toast_granted : R.string.grant_failed,
                                        entry.label),
                                Toast.LENGTH_SHORT).show();
                        entry.granted = ok;
                        entry.grantMode = ok ? mode : ModuleControl.MODE_NONE;
                        render();
                    }
                })
                .show();
    }

    /** 往容器里加一行「单选 + 说明」 */
    private RadioButton modeRow(LinearLayout parent, int titleRes, int descRes, boolean checked) {
        RadioButton rb = new RadioButton(this);
        /*
         * ★ 必须给唯一 ID ★
         *   RadioGroup 靠子 View 的 id 区分彼此；
         *   两个 RadioButton 都是 NO_ID(-1) 时它无法判断谁跟谁互斥，
         *   结果就是「勾一个另一个不取消」—— 实测就是这个坑。
         */
        rb.setId(android.view.View.generateViewId());
        rb.setText(titleRes);
        rb.setTextSize(15);
        rb.setTextColor(Ui.tc(this, R.attr.sk_on_surface));
        int pad = Math.round(getResources().getDisplayMetrics().density * 6);
        rb.setPadding(0, pad, 0, 0);
        parent.addView(rb);
        /* 加入之后才设选中 —— RadioGroup 看到子项存在才能互斥 */
        rb.setChecked(checked);

        TextView tv = new TextView(this);
        tv.setText(descRes);
        tv.setTextSize(11);
        tv.setTextColor(Ui.tc(this, R.attr.sk_on_surface_variant));
        int s4 = Math.round(getResources().getDisplayMetrics().density * 4);
        int s34 = Math.round(getResources().getDisplayMetrics().density * 34);
        tv.setPadding(s34, 0, 0, s4);
        parent.addView(tv);

        return rb;
    }


    private String fmt(long ms) {
        if (ms <= 0) {
            return "-";
        }
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault());
        return sdf.format(new Date(ms));
    }
}
