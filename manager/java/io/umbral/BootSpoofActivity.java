package io.umbral;

import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

import io.umbral.sk.BootSpoof;

/**
 * 「启动状态伪装」页。
 *
 * 只做三件事：
 *   ① 显示 p1/p2/p3 三项判据（属性值 / cmdline 值 / 模块是否加载）
 *   ② 一个开关：开 = 热加载 propfix，关 = 卸载
 *   ③ 操作后立刻回读校验，把真实结果贴出来（不信任 rc）
 *
 * 为什么必须显示 p1 与 p2：属性区由 cmdline 生成，
 * 只伪装一边会出现 green/orange 不一致 —— 那比 orange 本身更可疑。
 */
public class BootSpoofActivity extends BaseActivity {

    private TextView tvP1, tvP2, tvP3, tvHint;
    private Switch sw;
    private boolean suppress;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setTitle("启动状态伪装");

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        tvP1 = row(root, "p1 属性 ro.boot.verifiedbootstate");
        tvP2 = row(root, "p1 属性 ro.boot.flash.locked");
        tvP3 = row(root, "p2 cmdline androidboot.verifiedbootstate");
        tvHint = row(root, "p3 模块 /sys/module/propfix");

        sw = new Switch(this);
        sw.setText("伪装为 green / flash.locked=1");
        sw.setPadding(0, pad, 0, pad);
        root.addView(sw);
        sw.setOnCheckedChangeListener(new android.widget.CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(android.widget.CompoundButton v, boolean checked) {
                if (suppress) return;
                apply(checked);
            }
        });

        Button refresh = new Button(this);
        refresh.setText("刷新状态");
        refresh.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) { refresh(); }
        });
        root.addView(refresh);

        TextView note = new TextView(this);
        note.setText("说明：\n"
                + "· 只伪装内核可见的两处（属性区 + cmdline），两者必须一致\n"
                + "· 模块改完可卸载，值保留到重启\n"
                + "· TEE Key Attestation 里的 verifiedBootState 无法伪装（硬件签名）");
        note.setTextSize(12);
        note.setPadding(0, pad, 0, 0);
        root.addView(note);

        ScrollView sv = new ScrollView(this);
        sv.addView(root);
        setContentView(sv);

        refresh();
    }

    private TextView row(LinearLayout parent, String label) {
        TextView t = new TextView(this);
        t.setText(label + "：…");
        t.setTextSize(14);
        t.setGravity(Gravity.START);
        parent.addView(t);
        return t;
    }

    private void refresh() {
        BootSpoof.State s = BootSpoof.probe();
        tvP1.setText("p1 属性 ro.boot.verifiedbootstate：" + s.propVbs);
        tvP2.setText("p1 属性 ro.boot.flash.locked：" + s.flashLocked);
        tvP3.setText("p2 cmdline androidboot.verifiedbootstate：" + s.cmdVbs);
        tvHint.setText("p3 模块已加载：" + (s.loaded ? "是" : "否") + "\n" + s.hint);

        suppress = true;
        sw.setChecked(s.spoofed || s.loaded);
        suppress = false;
    }

    private void apply(boolean on) {
        sw.setEnabled(false);
        String r = on ? BootSpoof.enable(this) : BootSpoof.disable(this);
        // 不看返回码，直接回读真实状态
        BootSpoof.State s = BootSpoof.probe();
        tvHint.setText("操作结果：" + (r == null || r.isEmpty() ? "(无输出)" : r)
                + "\n回读：属性=" + s.propVbs + " cmdline=" + s.cmdVbs
                + " 模块=" + (s.loaded ? "已加载" : "未加载")
                + "\n" + s.hint);
        sw.setEnabled(true);
        suppress = true;
        sw.setChecked(s.spoofed || s.loaded);
        suppress = false;
    }
}
