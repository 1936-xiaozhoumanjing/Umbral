package io.umbral;

import android.os.Bundle;
import android.os.Process;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import io.umbral.sk.SkBridge;
import io.umbral.util.Ui;

/**
 * 影子权限页。
 *
 * 这一页把内核模块通过 /proc/umbral 暴露的东西完整摆出来：
 *
 *   version      模块版本
 *   backend      实际使用的 syscall hook（不同内核能用的通道不一样）
 *   stats        六项计数：seen / elevated / reverted / denied / lsm_seen / lsm_bypass
 *   selftest     struct 偏移、hook 位图、root cred 指针
 *   token        当前 uid 对应的 32 字节令牌（64 个 hex 字符）
 *
 * 判读要点（也是这一页唯一真正重要的判断）：
 *
 *   elevated 与 reverted 不要求配平：
 *     本设计提权后**不撤销**（避免 revert 打坏 cred 引用计数），
 *     所以 reverted 恒为 0 是正常状态，不是泄漏。
 *        这是影子权限最危险的故障模式：进程在提权窗口内被杀、
 *        或者 kretprobe 的 return handler 没装上，都会导致它。
 */
public class ShadowActivity extends BaseActivity {

    private TextView tvState;
    private TextView tvStats;
    private TextView tvHealth;
    private TextView tvUid;
    private TextView tvToken;
    private View btnCopy;

    private String mToken;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_shadow);

        tvState  = findViewById(R.id.tv_shadow_state);
        tvStats  = findViewById(R.id.tv_shadow_stats);
        tvHealth = findViewById(R.id.tv_shadow_health);
        tvUid    = findViewById(R.id.tv_shadow_uid);
        tvToken  = findViewById(R.id.tv_shadow_token);
        btnCopy  = findViewById(R.id.btn_copy_token);

        ImageView back = findViewById(R.id.btn_back);
        if (back != null) {
            back.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    finish();
                }
            });
        }

        ImageView refresh = findViewById(R.id.btn_refresh);
        if (refresh != null) {
            refresh.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    // 清掉缓存，强制重新探测
                    SkBridge.invalidate();
                    render();
                }
            });
        }

        if (btnCopy != null) {
            btnCopy.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    copyToken();
                }
            });
        }

        render();
    }

    private void render() {
        boolean connected = SkBridge.isConnected();

        // ── 模块状态 ──
        if (!connected) {
            tvState.setText(getString(R.string.shadow_not_connected));
            tvState.setTextColor(Ui.tc(this, R.attr.sk_error));
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append("version   ").append(SkBridge.version()).append('\n');
            sb.append("backend   ").append(SkBridge.backend()).append('\n');

            String hooks = SkBridge.selftestField("hooks");
            if (hooks != null) {
                sb.append("hooks     ").append(hooks).append("  ")
                  .append(hooksText(hooks)).append('\n');
            }
            String exit = SkBridge.selftestField("offsetof_exit");
            if (exit != null) {
                // 这一行是从内核里读回来的 —— 布局对了它才会是 1464
                sb.append("exit 偏移  ").append(exit)
                  .append(" (1448 = 布局错，1464 = 正确)").append('\n');
            }
            String sens = SkBridge.selftestField("sensitive_count");
            if (sens != null) {
                sb.append("敏感调用  ").append(sens).append(" 项");
            }
            tvState.setText(sb.toString().trim());
            tvState.setTextColor(Ui.tc(this, R.attr.sk_on_surface_variant));
        }

        // ── 运行统计 ──
        if (!connected) {
            tvStats.setText("-");
            tvHealth.setText("");
        } else {
            long seen     = SkBridge.stat("seen");
            long elevated = SkBridge.stat("elevated");
            long reverted = SkBridge.stat("reverted");
            long denied   = SkBridge.stat("denied");
            long lsmSeen  = SkBridge.stat("lsm_seen");
            long lsmBy    = SkBridge.stat("lsm_bypass");

            StringBuilder sb = new StringBuilder();
            sb.append(row("seen", seen, "\u7ecf\u8fc7 hook \u7684 syscall"));
            sb.append('\n').append(row("elevated", elevated, "\u5b9e\u9645\u63d0\u6743\u6b21\u6570"));
            sb.append('\n').append(row("reverted", reverted, "\u8fd8\u539f\u6b21\u6570"));
            sb.append('\n').append(row("denied", denied, "\u56e0\u65e0\u4ee4\u724c\u800c\u62d2\u7edd"));
            sb.append('\n').append(row("lsm_seen", lsmSeen, "\u7a97\u53e3\u5185 SELinux \u68c0\u67e5"));
            sb.append('\n').append(row("lsm_bypass", lsmBy, "\u88ab\u653e\u884c\u7684 SELinux \u62d2\u7edd"));
            tvStats.setText(sb.toString());

            // 健康判据
            if (elevated >= 0 && reverted >= 0) {
                if (elevated == reverted) {
                    tvHealth.setText(getString(R.string.shadow_health_ok));
                    tvHealth.setTextColor(Ui.tc(this, R.attr.sk_success));
                } else {
                    tvHealth.setText(getString(R.string.shadow_health_leak));
                    tvHealth.setTextColor(Ui.tc(this, R.attr.sk_error));
                }
            } else {
                tvHealth.setText("");
            }
        }

        // ── 令牌 ──
        int uid = Process.myUid();
        tvUid.setText(getString(R.string.shadow_uid_fmt, uid));

        mToken = null;
        if (connected) {
            mToken = SkBridge.selfToken();
        }
        if (mToken == null) {
            tvToken.setText(getString(R.string.shadow_need_root));
            tvToken.setTextColor(Ui.tc(this, R.attr.sk_on_surface_variant));
            btnCopy.setVisibility(View.GONE);
        } else {
            // 64 个 hex 字符，每 32 个换一行，方便看也方便核对长度
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < mToken.length(); i += 32) {
                if (i > 0) {
                    sb.append('\n');
                }
                sb.append(mToken, i, Math.min(mToken.length(), i + 32));
            }
            tvToken.setText(sb.toString());
            tvToken.setTextColor(Ui.tc(this, R.attr.sk_on_surface));
            btnCopy.setVisibility(View.VISIBLE);
        }
    }

    private String row(String name, long v, String desc) {
        String val = (v < 0) ? "-" : String.valueOf(v);
        return String.format("%-11s %-10s %s", name, val, desc);
    }

    private String hooksText(String hex) {
        try {
            int bits = Integer.parseInt(hex.replace("0x", ""), 16);
            StringBuilder sb = new StringBuilder("(");
            if ((bits & 1) != 0)  sb.append("syscall ");
            if ((bits & 2) != 0)  sb.append("trace ");
            if ((bits & 4) != 0)  sb.append("inode ");
            if ((bits & 8) != 0)  sb.append("file ");
            if ((bits & 16) != 0) sb.append("open ");
            if ((bits & 32) != 0) sb.append("avc ");
            if ((bits & 64) != 0) sb.append("avc_na ");
            if ((bits & 128) != 0) sb.append("capable ");
            return sb.append(")").toString().replace("( )", "(none)");
        } catch (Exception e) {
            return "";
        }
    }

    private void copyToken() {
        if (mToken == null) {
            return;
        }
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm == null) {
            return;
        }
        cm.setPrimaryClip(ClipData.newPlainText("umbral_token", mToken));
        Toast.makeText(this, getString(R.string.shadow_copied), Toast.LENGTH_SHORT).show();
    }
}
