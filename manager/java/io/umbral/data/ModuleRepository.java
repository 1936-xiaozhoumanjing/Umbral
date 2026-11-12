package io.umbral.data;

import android.content.Context;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * 第三方模块仓库。
 *
 * ══════════════════════════════════════════════════════
 *  这里管的是「别人做的、ZIP 压缩包格式的模块」
 * ══════════════════════════════════════════════════════
 *
 *  不是我们自己的 sk_root.ko（那个在 /data/adb/umbral/，由 ModuleControl 管）。
 *  这里管的是 Magisk / KernelSU 生态的模块：
 *      ZIP 里带 module.prop + system/ + post-fs-data.sh ...
 *      装完展开成 /data/adb/modules/<id>/
 *
 *  几个关键事实（实测确认）：
 *    · 模块目录     /data/adb/modules/<id>/
 *    · 元数据       <id>/module.prop   （key=value）
 *    · 禁用标记     <id>/disable       （存在即禁用）
 *    · 待卸载标记   <id>/remove        （存在即下次开机卸载）
 *    · 动作脚本     <id>/action.sh     （手动触发的「操作」按钮）
 *
 *  所有动作都交给 ksud 做，不自己实现安装/卸载逻辑 ——
 *  KSU 的安装流程涉及解压校验、modules_update 暂存、开机替换，
 *  自己重写只会和它的状态机打架。
 */
public final class ModuleRepository {

    /** 模块根目录（Magisk / KernelSU / 影核 共用） */
    public static final String DIR_MODULES = "/data/adb/modules";

    /** KernelSU / Magisk 标准模块目录 */
    public static final String KSU_DIR = "/data/adb/modules";
    /** 待生效的更新（下次开机替换） */
    public static final String KSU_UPDATE_DIR = "/data/adb/modules_update";

    /** 上次扫描到的模块数，首页统计卡用（避免首页再扫一遍） */
    private static int sLastCount = 0;

    public static int lastCount() {
        return sLastCount;
    }

    public static void setLastCount(int n) {
        sLastCount = n;
    }

    private ModuleRepository() {
    }

    // ══════════════════════════════════════════════════════
    //  读取
    // ══════════════════════════════════════════════════════

    /**
     * 列出全部模块。会阻塞（要 su），必须在后台线程调用。
     */
    public static List<ModuleEntry> listAll(Context ctx) {
        List<ModuleEntry> out = new ArrayList<ModuleEntry>();

        String dump = shell(buildScanScript());
        if (dump == null || dump.trim().isEmpty()) {
            return out;
        }

        ModuleEntry cur = null;
        boolean disabled = false;
        boolean removing = false;

        for (String raw : dump.split("\n")) {
            String line = raw.trim();
            if (line.isEmpty()) {
                continue;
            }

            if (line.startsWith("@@MOD ")) {
                cur = new ModuleEntry();
                cur.id = line.substring(6).trim();
                cur.name = cur.id;
                cur.enabled = true;
                cur.type = ModuleEntry.TYPE_MODULE;
                cur.path = KSU_DIR + "/" + cur.id;
                disabled = false;
                removing = false;
                continue;
            }
            if (cur == null) {
                continue;
            }
            if (line.equals("@@DIS")) {
                disabled = true;
                continue;
            }
            if (line.equals("@@RM")) {
                removing = true;
                continue;
            }
            if (line.equals("@@EOF")) {
                cur.enabled = !disabled && !removing;
                if (removing) {
                    cur.description = appendNote(cur.description, "待开机卸载");
                }
                if (disabled) {
                    cur.description = appendNote(cur.description, "已禁用");
                }
                out.add(cur);
                cur = null;
                continue;
            }
            if (line.startsWith("@@P ")) {
                applyProp(cur, line.substring(4));
            }
        }

        sort(out);
        return out;
    }

    /** 冒号后追加备注，不覆盖原有描述 */
    private static String appendNote(String desc, String note) {
        if (desc == null || desc.isEmpty()) {
            return "[" + note + "]";
        }
        return desc + "  [" + note + "]";
    }

    private static void applyProp(ModuleEntry e, String line) {
        int eq = line.indexOf('=');
        if (eq <= 0) {
            return;
        }
        String k = line.substring(0, eq).trim();
        String v = line.substring(eq + 1).trim();

        if (k.equals("id")) {
            if (v.length() > 0) {
                e.id = v;
            }
        } else if (k.equals("name")) {
            if (v.length() > 0) {
                e.name = v;
            }
        } else if (k.equals("version")) {
            e.version = v;
        } else if (k.equals("author")) {
            e.author = v;
        } else if (k.equals("description")) {
            e.description = v;
        }
    }

    private static void sort(List<ModuleEntry> out) {
        Collections.sort(out, new Comparator<ModuleEntry>() {
            @Override
            public int compare(ModuleEntry a, ModuleEntry b) {
                // 启用的排前面，然后按名字
                if (a.enabled != b.enabled) {
                    return a.enabled ? -1 : 1;
                }
                return String.valueOf(a.name).compareToIgnoreCase(String.valueOf(b.name));
            }
        });
    }

    /**
     * 一次 su 往返把所有模块的元数据 dump 出来。
     *
     * 为什么不用逐模块读：每个模块一次 su 往返，9 个模块就是 9 次
     * 进程创建，界面会明显卡。
     */
    private static String buildScanScript() {
        return "for d in " + KSU_DIR + "/*; do "
                + "[ -d \"$d\" ] || continue; "
                + "echo \"@@MOD $(basename $d)\"; "
                + "[ -f \"$d/disable\" ] && echo '@@DIS'; "
                + "[ -f \"$d/remove\" ] && echo '@@RM'; "
                + "[ -f \"$d/module.prop\" ] && sed 's/^/@@P /' \"$d/module.prop\"; "
                + "echo '@@EOF'; "
                + "done";
    }

    // ══════════════════════════════════════════════════════
    //  动作 —— 全部交给 ksud
    // ══════════════════════════════════════════════════════

    /** ksud 在不在 */
    public static boolean hasKsud() {
        String r = shell("command -v ksud || ls /data/adb/ksu/bin/ksud 2>/dev/null");
        return r != null && r.contains("ksud");
    }

    private static String ksud() {
        String p = shell("ls /data/adb/ksu/bin/ksud 2>/dev/null");
        if (p != null && p.contains("/data/adb/ksu/bin/ksud")) {
            return "/data/adb/ksu/bin/ksud";
        }
        return "ksud";
    }

    /**
     * 启用 / 禁用模块。
     *
     * @return null = 成功，否则是错误描述
     */
    public static String setEnabled(ModuleEntry e, boolean enabled) {
        if (e == null || e.id == null) {
            return "模块 id 为空";
        }
        /*
         * ★ 不走 ksud，也不再起 shell ★
         *
         * 原来的写法是 exec("ksud module enable/disable")：
         *   设备上没有 ksud（我们是自己的 root）→ shell 返回 null
         *   → 报「没有 root，无法操作」
         *   而实际上 App 进程自己有权限读写 /data/adb
         *
         * 开关模块的本质只是一件事：
         *   禁用 = 在模块目录里建一个空的 disable 文件
         *   启用 = 删掉它
         * 用 Java File API 直接做，一次 shell 都不用起。
         */
        if (!validId(e.id)) {
            return "模块 id 不合法";
        }
        java.io.File dir = new java.io.File(DIR_MODULES, e.id);
        if (!dir.exists()) {
            return "模块目录不存在：" + dir.getAbsolutePath();
        }

        /*
         * ★ 必须走真 root（su 二进制），不能只用 App 自己的权限 ★
         *
         * 实测症状：界面点了「启用」看起来成功，重启后又变回禁用。
         * 原因：/data/adb/modules/<id>/disable 是 root 属主目录里的文件，
         * App 自己的身份删不掉它 —— 但 delete() 在某些情况下返回 true
         * （目录可写、文件不可删时不会报错），于是界面乐观地显示了「已启用」。
         *
         * 现在：
         *   启用 = su -c "rm -f <dir>/disable"     并回读确认文件真的没了
         *   禁用 = su -c "touch <dir>/disable"     并回读确认文件真的在
         * 同时维护 .pending_reboot（对应「重启后生效」的提示）
         */
        String flag = dir.getAbsolutePath() + "/disable";
        String pend = dir.getAbsolutePath() + "/.pending_reboot";
        String cmd = enabled
                ? ("rm -f '" + flag + "' && touch '" + pend + "' && "
                   + "([ -f '" + flag + "' ] && echo FAIL || echo OK)")
                : ("touch '" + flag + "' && rm -f '" + pend + "' && "
                   + "([ -f '" + flag + "' ] && echo OK || echo FAIL)");

        String out = null;
        try {
            io.umbral.sk.SuBridge.R r = io.umbral.sk.SuBridge.root(cmd);
            out = r.out == null ? "" : r.out.trim();
        } catch (Throwable t) {
            return "执行失败：" + t.getMessage();
        }

        if (out != null && out.contains("OK")) {
            /* 再独立回读一次，确认落盘状态和界面一致 */
            boolean nowDisabled = new java.io.File(flag).exists();
            if (nowDisabled == !enabled) {
                return null;      /* 成功 */
            }
            return "写入后状态不一致（disable=" + nowDisabled + "）";
        }
        return "操作未生效：su 返回 " + out;
    }

    /** 模块 id 合法性（和 ModuleRunner.validModuleId 同规则） */
    private static boolean validId(String id) {
        if (id == null || id.isEmpty() || id.length() > 64) {
            return false;
        }
        if (id.contains("..") || id.contains("/") || id.contains("\\")) {
            return false;
        }
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    /**
     * 从 ZIP 安装模块。
     *
     * @return null = 成功，否则是错误描述
     */
    /**
     * 安装 ZIP 模块。
     *
     * ★ 优先用我们自己的安装器 ★
     *   影核内核模块能提供真 root（超级用户模式），管理器 spawn 的 sh
     *   就是 uid 0，完全可以自己解压 ZIP 写 /data/adb/modules。
     *   ksud 只在「用 KernelSU 当 root」时才存在 —— 不再作为主路径，
     *   只在我们的安装器失败时兜底尝试一次。
     */
    public static String install(android.content.Context ctx, String zipPath) {
        if (zipPath == null || zipPath.isEmpty()) {
            return "没有选择文件";
        }

        /* ① 我们自己的安装器 */
        io.umbral.module.ModuleInstaller.Result r =
                io.umbral.module.ModuleInstaller.install(ctx, zipPath);
        if (r.ok) {
            return null;
        }

        /* ② 兜底：如果设备上还有 ksud，再试一次 */
        if (hasKsud()) {
            String tmp = "/data/local/tmp/umbral_module.zip";
            String out = shell("cp '" + zipPath + "' " + tmp
                    + " && " + ksud() + " module install " + tmp
                    + " && rm -f " + tmp);
            if (out != null) {
                String low = out.toLowerCase();
                if (!low.contains("error") && !low.contains("fail")
                        && !low.contains("invalid")) {
                    return null;
                }
            }
        }

        /* 两条路都失败：把我们的错误说清楚 */
        return r.error;
    }

    public static String uninstall(ModuleEntry e) {
        if (e == null || e.id == null) {
            return "模块 id 为空";
        }
        /*
         * 卸载 = 建一个空的 remove 标记文件（Magisk / KernelSU 的通用约定），
         * 重启后由开机脚本真正删除目录。
         *
         * 这样做的原因：直接递归删目录有风险（模块可能正被使用），
         * 而 remove 标记是生态里公认的做法，模块自己也会配合处理。
         */
        java.io.File dir = new java.io.File(DIR_MODULES, e.id);
        if (!dir.exists()) {
            return "模块目录不存在：" + dir.getAbsolutePath();
        }
        java.io.File mark = new java.io.File(dir, "remove");
        try {
            if (!mark.exists() && !mark.createNewFile()) {
                return "创建 remove 标记失败（权限不足）";
            }
            return null;
        } catch (Throwable t) {
            return "操作失败：" + t.getMessage();
        }
    }

    /** 撤销卸载标记 */
    public static String undoUninstall(ModuleEntry e) {
        if (e == null || e.id == null) {
            return "模块 id 为空";
        }
        java.io.File mark = new java.io.File(new java.io.File(DIR_MODULES, e.id), "remove");
        try {
            if (mark.exists() && !mark.delete()) {
                return "撤销失败（权限不足）";
            }
            return null;
        } catch (Throwable t) {
            return "操作失败：" + t.getMessage();
        }
    }

    /** 跑模块的 action.sh（有些模块用它做配置） */
    public static String runAction(ModuleEntry e) {
        if (e == null || e.id == null) {
            return "模块 id 为空";
        }
        String r = shell(ksud() + " module action " + quote(e.id));
        return (r == null) ? "没有 root" : null;
    }

    // ══════════════════════════════════════════════════════

    private static String quote(String s) {
        if (s == null) {
            return "''";
        }
        return "'" + s.replace("'", "'\\''") + "'";
    }

    /**
     * 跑一条命令（包在 su 里），返回 stdout+stderr。
     * 返回 null 表示 su 本身不可用。
     */
    private static String shell(String cmd) {
        /*
         * 先直接跑 —— 管理器被我们自己的模块授权之后，
         * caps 是满的、SELinux 拒绝被钩子放行，所以不需要 su 就能
         * 读 /data/adb/modules、能 exec ksud。
         *
         * 拿不到结果再退回 su —— 没被授权的设备走这条。
         */
        String direct = run(new String[]{"/system/bin/sh", "-c", cmd});
        if (direct != null && !direct.trim().isEmpty()) {
            return direct;
        }
        return run(new String[]{"su", "-c", cmd});
    }

    private static String run(String[] argv) {
        Process p = null;
        BufferedReader r = null;
        try {
            p = Runtime.getRuntime().exec(argv);
            r = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
                if (sb.length() > 256 * 1024) {
                    break;
                }
            }
            p.waitFor();
            return sb.toString();
        } catch (Exception e) {
            return null;
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (Exception ignored) {
                }
            }
            if (p != null) {
                p.destroy();
            }
        }
    }
}
