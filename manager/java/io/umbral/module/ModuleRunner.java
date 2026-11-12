package io.umbral.module;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import io.umbral.sk.SuBridge;

/**
 * 模块引擎 —— 让模块真的被执行。
 *
 * ══════════════════════════════════════════════════════
 *  对齐 Magisk / KernelSU 的执行顺序
 * ══════════════════════════════════════════════════════
 *
 *  Magisk 的开机阶段：
 *      ① post-fs-data     极早，/data 刚挂好
 *          执行 /data/adb/post-fs-data.d/*.sh
 *          执行各模块 <id>/post-fs-data.sh
 *      ② late_start service  开机后期
 *          执行 /data/adb/service.d/*.sh
 *          执行各模块 <id>/service.sh
 *
 *  我们做不到「极早」（没有 init 钩子），所以：
 *      · App 一启动就跑 post-fs-data 阶段（补做）
 *      · 之后立刻跑 service 阶段
 *      · 用 boot_id 保证每个开机周期只跑一次
 *
 *  这不是完美的 Magisk 时序，但足以让「只跑脚本」的模块生效，
 *  包括 Zygisk Next 这种自己带 zygisk 实现的模块 —— 它的
 *  post-fs-data.sh 会起守护进程，service.sh 会注入 zygote。
 *
 * ══════════════════════════════════════════════════════
 *  环境变量（模块脚本依赖它们）
 * ══════════════════════════════════════════════════════
 *
 *  MODPATH   模块目录
 *  MODID     模块 id
 *  KSU       true（让依赖 KSU 的脚本走 KSU 分支）
 *  MAGISK_VER / MAGISK_VER_CODE
 *  PATH      加上 /data/adb/umbral（我们的 su 所在）
 */
public final class ModuleRunner {

    private static final String MODULES = "/data/adb/modules";
    private static final String POST_FS_D = "/data/adb/post-fs-data.d";
    private static final String SERVICE_D = "/data/adb/service.d";
    private static final String LOG_DIR = "/data/adb/umbral/logs";
    

    /** 每个开机周期只跑一次 */
    private static volatile boolean ranThisBoot;
    private static Context CTX;

    private ModuleRunner() {
    }

    /** 开机 id（用来判断是否已经跑过） */
    private static String bootId() {
        java.io.BufferedReader r = null;
        try {
            r = new java.io.BufferedReader(new java.io.FileReader(
                    "/proc/sys/kernel/random/boot_id"));
            String s = r.readLine();
            return s == null ? "" : s.trim();
        } catch (Throwable t) {
            return "";
        } finally {
            try { if (r != null) r.close(); } catch (Exception ignored) { }
        }
    }

    /** 开机标记文件：放在 App 私有目录，App 自己可控（/data/adb 下的是 root 属主，删不掉） */
    private static File markFile() {
        File d = CTX == null ? null : CTX.getFilesDir();
        return d == null ? new File("/data/local/tmp/umbral/.last_boot")
                : new File(d, ".last_boot");
    }

    private static boolean alreadyRan() {
        try {
            File f = markFile();
            if (!f.exists()) {
                return false;
            }
            String want = bootId();
            if (want.isEmpty()) {
                return false;
            }
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.FileReader(f));
            String got = r.readLine();
            r.close();
            return want.equals(got == null ? "" : got.trim());
        } catch (Throwable t) {
            return false;
        }
    }

    private static void markRan() {
        try {
            File f = markFile();
            File d = f.getParentFile();
            if (d != null) {
                //noinspection ResultOfMethodCallIgnored
                d.mkdirs();
            }
            FileOutputStream fo = new FileOutputStream(f, false);
            fo.write(bootId().getBytes("UTF-8"));
            fo.flush();
            fo.getFD().sync();
            fo.close();
        } catch (Throwable ignored) {
        }
    }

    /**
     * 脚本环境变量 —— 完全照抄 KSU userspace/ksud/src/module.rs:63
     * get_common_script_envs()
     *
     * 少一个都会让模块走错分支（很多 customize.sh 判 KSU_VER_CODE）。
     */
    public static String scriptEnv(String modId, String modPath) {
        StringBuilder sb = new StringBuilder();
        sb.append("export ASH_STANDALONE=1").append(" && ");
        sb.append("export KSU=true").append(" && ");
        sb.append("export KSU_KERNEL_VER_CODE=").append(kernelVerCode()).append(" && ");
        sb.append("export KSU_VER_CODE=").append(KSU_VER_CODE).append(" && ");
        sb.append("export KSU_VER=").append(KSU_VER).append(" && ");
        sb.append("export KSU_UAPI_VER=1").append(" && ");
        sb.append("export KSU_RUNTIME_MODE=lkm").append(" && ");
        sb.append("export PATH=/data/local/tmp/umbral/bin:/data/local/tmp/umbral:")
          .append("/data/adb/umbral:$PATH").append(" && ");
        /* Magisk 兼容 */
        sb.append("export MAGISK_VER=").append(MAGISK_VER).append(" && ");
        sb.append("export MAGISK_VER_CODE=").append(MAGISK_VER_CODE).append(" && ");
        if (modId != null && validModuleId(modId)) {
            sb.append("export KSU_MODULE=").append(modId).append(" && ");
        }
        if (modPath != null) {
            sb.append("export MODPATH=").append(modPath).append(" && ");
            sb.append("export MODID=").append(modId == null ? "-" : modId).append(" && ");
        }
        sb.append("true");
        return sb.toString();
    }

    public static final String KSU_VER = "1.0.0-umbral";
    public static final int KSU_VER_CODE = 30000;
    public static final String MAGISK_VER = "27.0";
    public static final int MAGISK_VER_CODE = 27000;

    /** 内核版本码：取 /proc/umbral/version 里的数字，取不到用 0 */
    private static int kernelVerCode() {
        java.io.BufferedReader r = null;
        try {
            r = new java.io.BufferedReader(new java.io.FileReader("/proc/umbral/version"));
            String v = r.readLine();
            if (v == null) {
                return 0;
            }
            /* 形如 1.18.0-escnode → 取 1 18 0 拼成 11800 */
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("(\\d+)\\.(\\d+)\\.(\\d+)").matcher(v);
            if (m.find()) {
                return Integer.parseInt(m.group(1)) * 10000
                        + Integer.parseInt(m.group(2)) * 100
                        + Integer.parseInt(m.group(3));
            }
        } catch (Throwable ignored) {
        } finally {
            try { if (r != null) r.close(); } catch (Exception ignored) { }
        }
        return 0;
    }

    /**
     * 模块 id 白名单校验 —— 照抄 KSU module.rs:51 validate_module_id()
     * 目的：防 ../ 路径穿越
     */
    public static boolean validModuleId(String id) {
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

    /** 入口：App 启动时调一次（后台线程） */
    public static void runOnce(Context ctx) {
        CTX = ctx;
        if (ranThisBoot || alreadyRan()) {
            return;
        }
        ranThisBoot = true;

        StringBuilder log = new StringBuilder();
        log.append("=== 模块引擎启动 ").append(now()).append(" ===\n");

        /* ⓪ b 合并 modules_update → modules（KSU 两段式安装的第二步） */
        mergeModuleUpdates(log);

        /* ⓪ 清「待重启」标记 —— 已经重启过了，标记必须失效 */
        clearPendingReboot(log);

        /* 零1：生成 system 覆盖映射表（内核开机读它） */
        buildSystemMap(log);

        /* 零2：合并各模块 sepolicy.rule（内核解析成 bypass 表） */
        buildSepolicyTable(log);

        /* ① remove 标记：删掉用户点过「卸载」的模块（Magisk 行为） */
        handleRemoves(log);

        /* ② post-fs-data 阶段 */
        log.append("\n[post-fs-data 阶段]\n");
        runDir(POST_FS_D, log);
        forEachModule("post-fs-data.sh", log);
        log.append("[post-fs-data 阶段结束]\n");
        if (CTX != null) {
            flushLog(CTX, log.toString());
        }
        log.append("[进入 system.prop 处理]\n");
        try {
            collectSystemProp(log);
        } catch (Throwable t) {
            log.append("system.prop 异常：").append(t).append('\n');
        }
        log.append("[system.prop 处理结束]\n");
        if (CTX != null) {
            flushLog(CTX, log.toString());
        }

        /* ③ service 阶段 */
        log.append("\n[service 阶段]\n");
        runDir(SERVICE_D, log);
        forEachModule("service.sh", log);

        log.append("\n=== 结束 ").append(now()).append(" ===\n");
        writeLog(log.toString());
        /* 同时写一份到外部目录，adb 能直接读（App 私有目录读不到） */
        try {
            io.umbral.Dbg.write(ctx, "modulerun.txt", log.toString());
            File f = new File(ctx.getFilesDir(), "modulerun.txt");
            FileOutputStream fo = new FileOutputStream(f, false);
            fo.write(log.toString().getBytes("UTF-8"));
            fo.flush();
            fo.getFD().sync();
            fo.close();
        } catch (Throwable ignored) {
        }
        markRan();
    }

    /** 删掉带 remove 标记的模块目录 */
    private static void handleRemoves(StringBuilder log) {
        File dir = new File(MODULES);
        File[] mods = dir.listFiles();
        if (mods == null) {
            return;
        }
        for (File m : mods) {
            if (!m.isDirectory()) {
                continue;
            }
            if (new File(m, "remove").exists()) {
                log.append("删除模块（remove 标记）：").append(m.getName()).append('\n');
                deleteRec(m);
            }
        }
    }

    /** 跑一个目录下的 *.sh（按名字排序） */
    private static void runDir(String dirPath, StringBuilder log) {
        File dir = new File(dirPath);
        File[] fs = dir.listFiles();
        if (fs == null) {
            return;
        }
        List<File> scripts = new ArrayList<>();
        for (File f : fs) {
            if (f.isFile() && f.getName().endsWith(".sh")) {
                scripts.add(f);
            }
        }
        java.util.Collections.sort(scripts, new java.util.Comparator<File>() {
            @Override
            public int compare(File a, File b) {
                return a.getName().compareTo(b.getName());
            }
        });
        for (File f : scripts) {
            execScript(f, null, log);
        }
    }

    /** 遍历模块跑某个阶段的脚本 */
    private static void forEachModule(String scriptName, StringBuilder log) {
        File dir = new File(MODULES);
        File[] mods = dir.listFiles();
        if (mods == null) {
            return;
        }
        List<File> sorted = new ArrayList<>(Arrays.asList(mods));
        java.util.Collections.sort(sorted, new java.util.Comparator<File>() {
            @Override
            public int compare(File a, File b) {
                return a.getName().compareTo(b.getName());
            }
        });
        for (File m : sorted) {
            if (!m.isDirectory()) {
                continue;
            }
            /* 禁用的模块跳过 */
            if (new File(m, "disable").exists()) {
                log.append("跳过（已禁用）：").append(m.getName()).append('\n');
                continue;
            }
            File s = new File(m, scriptName);
            if (!s.exists()) {
                continue;
            }
            execScript(s, m, log);
        }
    }

    /** 真正执行一个脚本 */
    private static void execScript(File script, File modDir, StringBuilder log) {
        String modId = modDir == null ? "-" : modDir.getName();
        String modPath = modDir == null ? MODULES : modDir.getAbsolutePath();

        /* 照抄 KSU 的完整环境变量 */
        String cmd = "cd " + modPath + " && " + scriptEnv(modId, modPath)
                + " && /system/bin/sh " + script.getAbsolutePath() + " 2>&1";

        log.append("→ ").append(script.getAbsolutePath()).append('\n');
        try {
            SuBridge.R r = SuBridge.root(cmd);
            log.append("   exit=").append(r.code)
               .append(" 提权=").append(r.promoted).append('\n');
            if (r.out != null && !r.out.isEmpty()) {
                for (String line : r.out.split("\n")) {
                    log.append("   | ").append(line).append('\n');
                }
            }
            if (CTX != null) {
                flushLog(CTX, log.toString());
            }
        } catch (Throwable t) {
            log.append("   异常：").append(t).append('\n');
        }
    }

    /** 增量落盘：每跑完一步就写一次，跑到一半也能看到内容 */
    private static void flushLog(android.content.Context ctx, String text) {
        try {
            File f = new File(ctx.getFilesDir(), "modulerun.txt");
            FileOutputStream fo = new FileOutputStream(f, false);
            fo.write(text.getBytes("UTF-8"));
            fo.flush();
            fo.getFD().sync();
            fo.close();
        } catch (Throwable ignored) {
        }
    }

    private static void writeLog(String text) {
        try {
            File dir = new File(LOG_DIR);
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
            String name = "run-" + new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)
                    .format(new Date()) + ".log";
            File f = new File(dir, name);
            FileOutputStream fo = new FileOutputStream(f, false);
            fo.write(text.getBytes("UTF-8"));
            fo.flush();
            fo.getFD().sync();
            fo.close();
        } catch (Throwable ignored) {
        }
    }

    private static void deleteRec(File f) {
        if (f == null || !f.exists()) {
            return;
        }
        File[] cs = f.listFiles();
        if (cs != null) {
            for (File c : cs) {
                deleteRec(c);
            }
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }

    private static String now() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
    }

    /**
     * system.prop：把各模块的 key=value 汇总到一处。
     *
     * Magisk 会真的把属性塞进系统属性区；内核态改属性要走
     * security_inode 之外的路径，我们暂时做不到，
     * 所以先做「汇总 + 让 resetprop 能读到」，并在日志里写清楚这是降级实现。
     */
    private static void collectSystemProp(StringBuilder log) {
        File dir = new File(MODULES);
        File[] mods = dir.listFiles();
        if (mods == null) {
            return;
        }
        StringBuilder all = new StringBuilder();
        int n = 0;
        for (File m : mods) {
            if (!m.isDirectory() || new File(m, "disable").exists()) {
                continue;
            }
            File sp = new File(m, "system.prop");
            if (!sp.exists()) {
                continue;
            }
            all.append("# ").append(m.getName()).append('\n');
            java.io.BufferedReader r = null;
            try {
                r = new java.io.BufferedReader(new java.io.FileReader(sp));
                String line;
                while ((line = r.readLine()) != null) {
                    String t = line.trim();
                    if (t.isEmpty() || t.startsWith("#")) {
                        continue;
                    }
                    all.append(t).append('\n');
                    n++;
                }
            } catch (Throwable ignored) {
            } finally {
                try { if (r != null) r.close(); } catch (Exception ignored) { }
            }
        }
        log.append("system.prop：汇总 ").append(n).append(" 条（降级实现，resetprop 可读）\n");
        try {
            File f = new File("/data/local/tmp/umbral/props.txt");
            File d = f.getParentFile();
            if (d != null) {
                //noinspection ResultOfMethodCallIgnored
                d.mkdirs();
            }
            FileOutputStream fo = new FileOutputStream(f, false);
            fo.write(all.toString().getBytes("UTF-8"));
            fo.flush();
            fo.getFD().sync();
            fo.close();
        } catch (Throwable ignored) {
        }
    }

    /**
     * 清掉所有模块目录下的 .pending_reboot。
     *
     * 为什么需要：Magisk/KSU 用这个标记表示「装好了但要重启才生效」，
     * 重启后由它们的 daemon 清掉。我们没 daemon，所以放在每次开机跑模块引擎时清。
     * 不清的后果就是实测到的：LSPosed 重启过十次仍然显示「待重启」。
     */
    private static void clearPendingReboot(StringBuilder log) {
        File dir = new File(MODULES);
        File[] mods = dir.listFiles();
        if (mods == null) {
            return;
        }
        int n = 0;
        for (File m : mods) {
            if (!m.isDirectory()) {
                continue;
            }
            File p = new File(m, ".pending_reboot");
            if (p.exists() && p.delete()) {
                n++;
            }
        }
        if (n > 0) {
            log.append("清除待重启标记：").append(n).append(" 个模块\n");
        }
    }

    public static final String MODULES_DIR_PLAIN = "/data/adb/modules";
    public static final String MODULES_UPDATE_DIR = "/data/adb/modules_update";

    /**
     * 合并 modules_update → modules —— 照抄 KSU handle_updated_modules（module.rs:651）
     *
     * KSU 装模块分两段：
     *   ① 安装时解压到 /data/adb/modules_update/<id>
     *   ② 下次开机才合并进 /data/adb/modules/<id>
     * 这样做的好处是「安装过程中出错不会破坏正在生效的旧版本」。
     *
     * 合并规则：
     *   · update 里的文件覆盖 modules 里的同名文件
     *   · 保留 modules 里的 disable / remove 标记（用户状态不能被安装覆盖）
     *   · 合并完删掉 update 目录
     */
    private static void mergeModuleUpdates(StringBuilder log) {
        File upd = new File(MODULES_UPDATE_DIR);
        File[] ids = upd.listFiles();
        if (ids == null || ids.length == 0) {
            return;
        }
        for (File src : ids) {
            if (!src.isDirectory()) {
                continue;
            }
            String id = src.getName();
            if (!validModuleId(id)) {
                log.append("跳过非法模块 id：").append(id).append('\n');
                continue;
            }
            File dst = new File(MODULES_DIR_PLAIN, id);
            try {
                boolean hadDisable = new File(dst, "disable").exists();
                boolean hadRemove = new File(dst, "remove").exists();
                if (!dst.exists()) {
                    //noinspection ResultOfMethodCallIgnored
                    dst.mkdirs();
                }
                copyMerge(src, dst);
                /* 用户状态保留 */
                if (hadDisable) {
                    //noinspection ResultOfMethodCallIgnored
                    new File(dst, "disable").createNewFile();
                }
                if (hadRemove) {
                    //noinspection ResultOfMethodCallIgnored
                    new File(dst, "remove").createNewFile();
                }
                deleteRec(src);
                log.append("合并模块更新：").append(id)
                   .append(hadDisable ? "（保持禁用）" : "")
                   .append(hadRemove ? "（保持待卸载）" : "")
                   .append('\n');
            } catch (Throwable t) {
                log.append("合并失败 ").append(id).append("：").append(t).append('\n');
            }
        }
    }

    /** 递归复制并覆盖 */
    private static void copyMerge(File src, File dst) throws java.io.IOException {
        File[] cs = src.listFiles();
        if (cs == null) {
            return;
        }
        for (File c : cs) {
            File t = new File(dst, c.getName());
            if (c.isDirectory()) {
                if (!t.exists()) {
                    //noinspection ResultOfMethodCallIgnored
                    t.mkdirs();
                }
                copyMerge(c, t);
            } else {
                java.io.FileInputStream in = new java.io.FileInputStream(c);
                java.io.FileOutputStream out = new java.io.FileOutputStream(t, false);
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
                out.flush();
                out.getFD().sync();
                out.close();
                in.close();
                /* 脚本类保持可执行 */
                String nm = c.getName();
                if (nm.endsWith(".sh")) {
                    //noinspection ResultOfMethodCallIgnored
                    t.setExecutable(true, false);
                }
            }
        }
    }

    public static final String SYSMAP_FILE = "/data/local/tmp/umbral/systemmap.txt";

    /**
     * 扫各模块的 system/ 目录，生成「目标路径 → 真实路径」映射表。
     *
     * 内核端（sk_map_load）只负责读这张表，然后在 do_filp_open 里改路径。
     * 放 App 侧扫的原因：内核遍历目录要自己写 iterate_dir 回调，容易出错；
     * App 有目录 API，扫一遍几行代码，还能把结果写进日志方便排查。
     *
     * 优先级：按模块目录名排序，后扫到的覆盖先扫到的（后装的赢）。
     */
    private static void buildSystemMap(StringBuilder log) {
        File dir = new File(MODULES);
        File[] mods = dir.listFiles();
        if (mods == null) {
            return;
        }
        java.util.List<File> sorted = new java.util.ArrayList<>(java.util.Arrays.asList(mods));
        java.util.Collections.sort(sorted, new java.util.Comparator<File>() {
            @Override
            public int compare(File a, File b) {
                return a.getName().compareTo(b.getName());
            }
        });

        StringBuilder out = new StringBuilder();
        int n = 0;
        for (File m : sorted) {
            if (!m.isDirectory() || new File(m, "disable").exists()) {
                continue;
            }
            File sys = new File(m, "system");
            if (!sys.isDirectory()) {
                continue;
            }
            n += walkSystem(sys, "/system", out);
        }

        log.append("system 覆盖映射：").append(n).append(" 条\n");
        try {
            File f = new File(SYSMAP_FILE);
            File d = f.getParentFile();
            if (d != null && !d.exists()) {
                //noinspection ResultOfMethodCallIgnored
                d.mkdirs();
            }
            java.io.FileOutputStream fo = new java.io.FileOutputStream(f, false);
            fo.write(out.toString().getBytes("UTF-8"));
            fo.flush();
            fo.getFD().sync();
            fo.close();
        } catch (Throwable t) {
            log.append("写映射表失败：").append(t).append('\n');
        }
    }

    /** 递归收集一个模块 system/ 下的所有文件 */
    private static int walkSystem(File f, String targetPath, StringBuilder out) {
        File[] cs = f.listFiles();
        if (cs == null) {
            return 0;
        }
        int n = 0;
        for (File c : cs) {
            String t = targetPath + "/" + c.getName();
            if (c.isDirectory()) {
                n += walkSystem(c, t, out);
            } else {
                out.append(t).append(' ').append(c.getAbsolutePath()).append('\n');
                n++;
            }
        }
        return n;
    }

    public static final String SEPOLICY_FILE = "/data/local/tmp/umbral/sepolicy.txt";

    /**
     * 零2：把各模块的 sepolicy.rule 合并成一份给内核解析。
     *
     * 只保留 allow 行，并去掉行首的 "allow " 关键字 ——
     * 内核侧只需要 "scontext tcontext tclass perms" 四段。
     * 注释（# 开头）与空行跳过。
     */
    private static void buildSepolicyTable(StringBuilder log) {
        File dir = new File(MODULES);
        File[] mods = dir.listFiles();
        if (mods == null) {
            return;
        }
        StringBuilder out = new StringBuilder();
        int n = 0;
        for (File m : mods) {
            if (!m.isDirectory() || new File(m, "disable").exists()) {
                continue;
            }
            File sp = new File(m, "sepolicy.rule");
            if (!sp.exists()) {
                continue;
            }
            java.io.BufferedReader r = null;
            try {
                r = new java.io.BufferedReader(new java.io.FileReader(sp));
                String line;
                while ((line = r.readLine()) != null) {
                    String t = line.trim();
                    if (t.isEmpty() || t.startsWith("#")) {
                        continue;
                    }
                    if (t.startsWith("allow ")) {
                        out.append(t.substring(6).trim()).append('\n');
                        n++;
                    }
                }
            } catch (Throwable ignored) {
            } finally {
                try { if (r != null) r.close(); } catch (Exception ignored) { }
            }
        }
        log.append("sepolicy 规则：合并 ").append(n).append(" 条\n");
        try {
            File f = new File(SEPOLICY_FILE);
            File d = f.getParentFile();
            if (d != null && !d.exists()) {
                //noinspection ResultOfMethodCallIgnored
                d.mkdirs();
            }
            java.io.FileOutputStream fo = new java.io.FileOutputStream(f, false);
            fo.write(out.toString().getBytes("UTF-8"));
            fo.flush();
            fo.getFD().sync();
            fo.close();
        } catch (Throwable t) {
            log.append("写 sepolicy 表失败：").append(t).append('\n');
        }
    }
}
