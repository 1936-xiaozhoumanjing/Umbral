package io.umbral.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.CompoundButton;
import android.widget.Switch;
import android.widget.TextView;

import io.umbral.R;
import io.umbral.data.ModuleEntry;

import java.util.List;

public class ModuleAdapter extends BaseAdapter {

    /** 长按/点击删除键 → 卸载模块 */
    public interface OnRemoveListener {
        void onRemove(ModuleEntry entry);
    }

    public interface OnToggleListener {
        void onToggle(ModuleEntry entry, boolean enabled);
    }

    private final Context ctx;
    private final List<ModuleEntry> data;
    private final OnToggleListener listener;
    private final OnRemoveListener removeListener;

    public ModuleAdapter(Context ctx, List<ModuleEntry> data, OnToggleListener l) {
        this(ctx, data, l, null);
    }

    public ModuleAdapter(Context ctx, List<ModuleEntry> data,
                         OnToggleListener l, OnRemoveListener r) {
        this.ctx = ctx;
        this.data = data;
        this.listener = l;
        this.removeListener = r;
    }

    @Override
    public int getCount() {
        return data.size();
    }

    @Override
    public ModuleEntry getItem(int position) {
        return data.get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder h;
        if (convertView == null) {
            convertView = LayoutInflater.from(ctx).inflate(R.layout.item_module, parent, false);
            h = new ViewHolder();
            h.name = convertView.findViewById(R.id.tv_module_name);
            h.meta = convertView.findViewById(R.id.tv_module_meta);
            h.desc = convertView.findViewById(R.id.tv_module_desc);
            h.sw = convertView.findViewById(R.id.sw_module);
            h.remove = convertView.findViewById(R.id.btn_module_remove);
            convertView.setTag(h);
        } else {
            h = (ViewHolder) convertView.getTag();
        }

        final ModuleEntry e = data.get(position);
        h.name.setText(e.name);

        /*
         * ★ 状态判定（对齐 Magisk / KernelSU）★
         *
         *   .pending_reboot 存在 → 刚装上、还没重启 → 显示「待重启」并整行变灰
         *   action.sh 存在        → 该模块可执行 → meta 里标注「可执行」
         *
         * 这两个都是纯文件判断，不需要 root。
         */
        /*
         * 五个状态标志 —— 照抄 KSU module.rs:1092-1104
         *   enabled : 没有 disable 标记
         *   update  : 有 update 标记
         *   remove  : 有 remove 标记
         *   web     : 有 webroot 目录
         *   action  : 有 action.sh
         */
        boolean pending = false;      /* 待重启 */
        boolean hasAction = false;    /* 可执行 */
        boolean hasWeb = false;       /* 有界面 */
        boolean hasUpdate = false;    /* 待更新 */
        boolean hasRemove = false;    /* 待卸载 */
        try {
            java.io.File dir = new java.io.File("/data/adb/modules", e.id);
            pending = new java.io.File(dir, ".pending_reboot").exists();
            hasUpdate = new java.io.File(dir, "update").exists();
            hasRemove = new java.io.File(dir, "remove").exists();
            hasAction = new java.io.File(dir, "action.sh").exists();
            hasWeb = new java.io.File(dir, "webroot").isDirectory();
        } catch (Throwable ignored) {
        }

        /* 执行按钮：只有带 action.sh 的模块才出现 */
        if (h.btnAction == null && convertView != null) {
            h.btnAction = convertView.findViewById(R.id.btn_module_action);
        }
        if (h.btnAction != null) {
            if (hasAction) {
                h.btnAction.setVisibility(View.VISIBLE);
                final String idForAction = e.id;
                h.btnAction.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        runActionScript(idForAction);
                    }
                });
            } else {
                h.btnAction.setVisibility(View.GONE);
            }
        }

        String metaText = e.meta();
        /* 作者单独标出来，一眼能看出是谁做的（KSU 的卡片也是这个信息密度） */
        if (e.author != null && !e.author.isEmpty()
                && !metaText.contains(e.author)) {
            metaText = metaText + "  ·  作者：" + e.author;
        }
        if (pending) {
            metaText = metaText + "  ·  待重启";
        }
        if (hasUpdate) {
            metaText = metaText + "  ·  待更新";
        }
        if (hasRemove) {
            metaText = metaText + "  ·  待卸载";
        }
        if (hasAction) {
            metaText = metaText + "  ·  可执行";
        }
        if (hasWeb) {
            metaText = metaText + "  ·  有界面";
        }
        h.meta.setText(metaText);

        /* 待重启 → 整行半透明（Magisk 也是这个视觉） */
        convertView.setAlpha(pending ? 0.45f : 1.0f);
        if (h.sw != null) {
            h.sw.setEnabled(!pending);
        }

        if (e.description == null || e.description.isEmpty()) {
            h.desc.setVisibility(View.GONE);
        } else {
            h.desc.setVisibility(View.VISIBLE);
            h.desc.setText(e.description);
        }

        h.sw.setOnCheckedChangeListener(null);
        h.sw.setChecked(e.enabled);
        h.sw.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton b, boolean checked) {
                if (listener != null) {
                    listener.onToggle(e, checked);
                }
            }
        });

        if (h.remove != null) {
            h.remove.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (removeListener != null) {
                        removeListener.onRemove(e);
                    }
                }
            });
        }

        return convertView;
    }

    private static class ViewHolder {
        TextView name;
        TextView meta;
        TextView desc;
        Switch sw;
        android.widget.Button btnAction;
        android.widget.ImageView remove;
    }

    /**
     * 跑模块的 action.sh（有些模块用它做配置界面）。
     *
     * 走 su 子进程（真 uid 0），输出用全屏进度页显示，
     * 失败时原始输出完整保留。
     */
    private void runActionScript(final String moduleId) {
        final android.app.Activity act = (ctx instanceof android.app.Activity)
                ? (android.app.Activity) ctx : null;
        final io.umbral.InstallProgressDialog[] ref = new io.umbral.InstallProgressDialog[1];
        if (act != null) {
            act.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    try {
                        ref[0] = new io.umbral.InstallProgressDialog(act, "执行 " + moduleId, 2);
                        ref[0].show();
                    } catch (Throwable ignored) {
                    }
                }
            });
            try {
                Thread.sleep(250);
            } catch (InterruptedException ignored) {
            }
        }
        new Thread(new Runnable() {
            @Override
            public void run() {
                final io.umbral.InstallProgressDialog pg = ref[0];
                String out;
                boolean ok = false;
                try {
                    if (pg != null) {
                        pg.step(1, "执行 /data/adb/modules/" + moduleId + "/action.sh");
                    }
                    /*
                     * ★ 对齐 KernelSU / Magisk 的 action 执行方式 ★
                     *
                     * 它们跑 action.sh 时会带一组环境变量，很多模块靠这些
                     * 变量找自己的目录、找 su、找 WebUI：
                     *     MODPATH / MODID / KSU / MAGISK_VER_CODE …
                     *
                     * 而且不吞掉脚本输出 —— 模块自己会 am start 拉起 WebUI，
                     * 我们只管把 shell 的环境给对、把脚本跑起来。
                     */
                    String modDir = "/data/adb/modules/" + moduleId;
                    /* 照抄 KSU module.rs:898 run_action —— 同一套环境变量 */
                    String cmd = "cd " + modDir + " && "
                            + io.umbral.module.ModuleRunner.scriptEnv(moduleId, modDir)
                            + " && /system/bin/sh " + modDir + "/action.sh 2>&1";
                    /*
                     * 乙3：照抄 KSU module.rs:898 —— ScriptWait::Forever
                     * 模块的 action.sh 可能常驻（等用户操作完才退出），
                     * 所以给一个"实际等于不超时"的上限，而不是 20 秒。
                     */
                    io.umbral.sk.Shell.R r = io.umbral.sk.Shell.root(cmd);
                    out = (r.out == null || r.out.isEmpty()) ? "（无输出）" : r.out;
                    ok = r.ok();
                } catch (Throwable t) {
                    out = t.getClass().getName() + ": " + t.getMessage();
                }
                if (out == null || out.trim().isEmpty()) {
                    out = "（脚本没有输出）";
                }
                try {
                    java.io.File af = new java.io.File(ctx.getExternalFilesDir(null),
                            "action_last.txt");
                    java.io.FileOutputStream afo = new java.io.FileOutputStream(af);
                    afo.write(("模块: " + moduleId + "\nok=" + ok + "\n\n" + out)
                            .getBytes("UTF-8"));
                    afo.flush();
                    afo.getFD().sync();
                    afo.close();
                } catch (Throwable ignored) {
                }

                /* M3：脚本跑完后，如果模块自带 webroot 界面就打开它 */
                try {
                    java.io.File idx = io.umbral.ModuleWebUiActivity.indexOf(moduleId);
                    if (idx != null && ctx instanceof android.app.Activity) {
                        final android.app.Activity act = (android.app.Activity) ctx;
                        act.runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                io.umbral.ModuleWebUiActivity.start(act, moduleId);
                            }
                        });
                    }
                } catch (Throwable ignored) {
                }

                if (pg != null) {
                    pg.step(2, out);
                    pg.finish(ok, ok ? "脚本执行完成" : "脚本执行失败");
                }
            }
        }).start();
    }
}
