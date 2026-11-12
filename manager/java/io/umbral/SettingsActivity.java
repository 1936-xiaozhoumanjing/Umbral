package io.umbral;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.CompoundButton;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import io.umbral.data.AppRepository;
import io.umbral.sk.SkBridge;

public class SettingsActivity extends BaseActivity {

    public static final String PREFS = "sk_settings";

    public static final String KEY_DEFAULT_MODE = "default_mode";
    public static final String KEY_NOTIFY = "notify";
    public static final String KEY_HIDE = "hide";
    public static final String KEY_VERBOSE = "verbose";

    public static final int MODE_ASK = 0;
    public static final int MODE_DENY_SILENT = 1;
    public static final int MODE_GRANT_TEMP = 2;

    private String[] modeLabels() {
        return new String[]{
                getString(R.string.grant_ask),
                getString(R.string.grant_deny),
                getString(R.string.grant_once)};
    }
    private static final String[] MODE_DESC = {
            "新应用请求 root 时弹窗询问",
            "不发通知，直接拒绝",
            "授予一次操作，用完即失效"
    };

    private SharedPreferences prefs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.page_settings);

        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);

        findViewById(R.id.btn_back).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });

        setupLanguage();
        setupTheme();
        setupDefaultMode();
        setupSwitches();
        setupRevokeAll();
    }

    /**
     * 语言切换。
     * 注意：这里只改「应用内」的界面语言。
     * 桌面图标名由 values/ 里的 app_name 决定，永远是 Umbral，不受此处影响。
     */
    private void setupLanguage() {
        final TextView value = findViewById(R.id.tv_language_value);
        value.setText(LocaleHelper.label(this, LocaleHelper.index(this)));

        findViewById(R.id.row_privacy).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new android.app.AlertDialog.Builder(SettingsActivity.this)
                        .setTitle(R.string.privacy_title)
                        .setMessage(R.string.privacy_body)
                        .setPositiveButton(android.R.string.ok, null)
                        .show();
            }
        });

        findViewById(R.id.row_language).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(SettingsActivity.this)
                        .setTitle(R.string.settings_language)
                        .setSingleChoiceItems(
                                LocaleHelper.allLabels(SettingsActivity.this),
                                LocaleHelper.index(SettingsActivity.this),
                                new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface d, int which) {
                                        LocaleHelper.setIndex(SettingsActivity.this, which);
                                        d.dismiss();
                                        // recreate 后 attachBaseContext 会按新语言重新解析资源
                                        recreate();
                                    }
                                })
                        .show();
            }
        });
    }

    private void setupTheme() {
        final TextView value = findViewById(R.id.tv_theme_value);
        value.setText(ThemeManager.name(this));

        findViewById(R.id.row_theme).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(SettingsActivity.this)
                        .setTitle(R.string.theme_picker_title)
                        .setSingleChoiceItems(ThemeManager.names(SettingsActivity.this), ThemeManager.get(SettingsActivity.this),
                                new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface d, int which) {
                                        ThemeManager.set(SettingsActivity.this, which);
                                        d.dismiss();
                                        recreate();
                                    }
                                })
                        .show();
            }
        });
    }

    private void setupDefaultMode() {
        final TextView desc = findViewById(R.id.tv_default_mode_desc);
        final TextView btn = findViewById(R.id.btn_default_mode);

        int mode = prefs.getInt(KEY_DEFAULT_MODE, MODE_ASK);
        btn.setText(modeLabels()[mode]);
        desc.setText(MODE_DESC[mode]);

        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(SettingsActivity.this)
                        .setTitle(R.string.mode_picker_title)
                        .setSingleChoiceItems(modeLabels(), prefs.getInt(KEY_DEFAULT_MODE, MODE_ASK),
                                new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface d, int which) {
                                        prefs.edit().putInt(KEY_DEFAULT_MODE, which).apply();
                                        btn.setText(modeLabels()[which]);
                                        desc.setText(MODE_DESC[which]);
                                        d.dismiss();
                                    }
                                })
                        .show();
            }
        });
    }

    private void setupSwitches() {
        bindSwitch(R.id.sw_notify, KEY_NOTIFY, true);
        bindSwitch(R.id.sw_hide, KEY_HIDE, true);

        /*
         * 启动器开关。
         *
         * 它存在 "umbral" 偏好里（和 MainActivity 的 launcherEnabled() 同一份），
         * 不放在本页的 "sk_settings" —— 否则从设置页打开、从首次弹窗打开
         * 会写成两个值，导航栏表现不一致。
         *
         * 这里只负责写值；导航栏是 MainActivity 的事，返回时它会重新读。
         */
        final android.content.SharedPreferences app =
                getSharedPreferences("umbral", MODE_PRIVATE);
        Switch swLauncher = findViewById(R.id.sw_launcher);
        if (swLauncher != null) {
            swLauncher.setChecked(app.getBoolean("launcher_enabled", false));
            swLauncher.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton b, boolean checked) {
                    app.edit().putBoolean("launcher_enabled", checked).apply();
                    Toast.makeText(SettingsActivity.this,
                            checked ? R.string.launcher_prompt_yes : R.string.launcher_prompt_no,
                            Toast.LENGTH_SHORT).show();
                }
            });
        }
    }

    private void bindSwitch(int viewId, final String key, boolean defValue) {
        Switch sw = findViewById(viewId);
        sw.setChecked(prefs.getBoolean(key, defValue));
        sw.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton b, boolean checked) {
                prefs.edit().putBoolean(key, checked).apply();
            }
        });
    }

    private void setupRevokeAll() {
        findViewById(R.id.row_revoke_all).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(SettingsActivity.this)
                        .setTitle(R.string.settings_revoke_all)
                        .setMessage(R.string.revoke_all_msg)
                        .setNegativeButton("取消", null)
                        .setPositiveButton("撤销", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface d, int which) {
                                AppRepository.revokeAll(SettingsActivity.this);
                                Toast.makeText(SettingsActivity.this,
                                        getString(R.string.toast_revoked_all), Toast.LENGTH_SHORT).show();
                            }
                        })
                        .show();
            }
        });
    }
}
