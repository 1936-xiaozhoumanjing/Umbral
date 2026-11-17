package io.umbral.sk;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * 内核模块管理 + 授权控制。
 *
 * ══════════════════════════════════════════════════════
 *  为什么所有操作都走 su
 * ══════════════════════════════════════════════════════
 *
 *  /proc/umbral/grant 的 SELinux 标签是 u:object_r:proc:s0，
 *  普通 App（untrusted_app 域）没有写权限，连 open 都会 EACCES。
 *  所以在 ramdisk 里带一条 sepolicy 规则之前，只能借 su 代写。
 *
 *  这不是设计缺陷，是「谁有资格发 root」这个信任根问题 ——
 *  详见技能 shadow-system-kernel 第七节。
 */
public final class ModuleControl {

    /** 影子模式：只拉 caps，uid 不变（隐身） */
    public static final int MODE_SHADOW = 0;
    /** 超级用户模式：caps + uid→0（真 root，看得出） */
    public static final int MODE_SUPER = 1;
    public static final int MODE_FULL = 2;
    /** 没有授权 */
    public static final int MODE_NONE = -1;

    /** 模块固定存放位置 —— 重启后还能从这里重新加载 */
    public static final String DIR = "/data/adb/umbral";
    public static final String PATH = DIR + "/sk_root.ko";

    private ModuleControl() {
    }

    // ── 状态 ──

    /** 模块是否已加载：看 /proc/modules 里有没有 sk_root */
    /** /proc/umbral 节点在不在（区分"没加载"和"加载了但没权限"） */
    public static boolean nodeExists() {
        return new java.io.File("/proc/umbral").exists();
    }

    /**
     * 硬探测：能不能读 /data/adb 与 /data/data 的目录内容。
     *
     * 普通应用永远列不出这两个目录；能列出来只有一种解释 ——
     * 内核里的判定点/LSM 放行对这个进程生效了，也就是模块在跑且授权成功。
     * 这条比 /proc/umbral/version 更硬：即使节点被我们自己隐藏，也照样成立。
     */
    public static boolean hardProbe() {
        /*
         * 模块装上了就会留下 /data/adb/umbral 这个目录（模块自己的数据目录）。
         * 普通 App 看不到它；能 stat 到就说明影子权限或子进程通路成立。
         */
        try {
            java.io.File d = new java.io.File("/data/adb/umbral");
            if (d.exists()) {
                return true;
            }
        } catch (Throwable ignored) {
        }

        try {
            String[] a = new java.io.File("/data/adb").list();
            if (a != null && a.length > 0) {
                return true;
            }
        } catch (Throwable ignored) {
        }
        try {
            String[] b = new java.io.File("/data/data").list();
            if (b != null && b.length > 3) {   /* 至少能看到几个子目录才算真读到了 */
                return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    public static boolean isLoaded() {
        /*
         * 先直接读 /proc/umbral/version —— 这是最便宜的判据：
         *   · 模块没加载 → 文件不存在
         *   · 模块加载了但 SELinux 挡着 → 读失败，再退到 su
         * 两种失败要分开处理，不能都当「没加载」。
         */
        /*
         * 管理器现在故意不给自己的进程任何内核特权（1.49 起），
         * 所以直接读 /proc/umbral 一定失败。判定必须走特权子进程。
         * 顺序：su 子进程读版本 → 直接读 → /data/adb 硬探测。
         */
        String sv0 = SkBridge.suRead("/proc/umbral/version");
        if (sv0 != null && !sv0.trim().isEmpty()) {
            return true;
        }

        String v = readDirect("/proc/umbral/version");
        if (v != null && !v.trim().isEmpty()) {
            return true;
        }
        File f = new File("/proc/umbral");
        if (f.exists()) {
            // 目录在但读不到 → SELinux 挡着，用 su 确认
            String sv = SkBridge.suRead("/proc/umbral/version");
            if (sv != null && !sv.trim().isEmpty()) {
                return true;
            }
            // su 也不行时，用「能不能读 /data/adb」做硬判据
            return hardProbe();
        }
        return hardProbe();
    }

    /** 模块版本，未加载返回 null */
    public static String version() {
        String v = readDirect("/proc/umbral/version");
        return (v != null) ? v : SkBridge.suRead("/proc/umbral/version");
    }

    /** 模块后端（kretprobe:invoke_syscall 等） */
    public static String backend() {
        String v = readDirect("/proc/umbral/backend");
        return (v != null) ? v : SkBridge.suRead("/proc/umbral/backend");
    }

    /** 模块文件在不在固定位置 */
    public static boolean fileInstalled() {
        try {
            return new File(PATH).exists();
        } catch (Exception e) {
            return false;
        }
    }

    // ── 授权 ──

    /**
     * 查某个 uid 的授权模式。
     * 解析 /proc/umbral/grants 里的 "uid <uid> shadow|super" 行。
     */
    public static int uidGrantMode(int uid) {
        String raw = grantsRaw();
        if (raw == null) {
            return MODE_NONE;
        }
        String want = "uid " + uid + " ";
        for (String line : raw.split("\n")) {
            String t = line.trim();
            if (t.startsWith(want)) {
                if (t.contains("full")) {
            return MODE_FULL;
        }
        return t.contains("super") ? MODE_SUPER : MODE_SHADOW;
            }
        }
        return MODE_NONE;
    }

    /** 按 uid 授权（持久，跟 App 绑定） */
    public static boolean grantUid(int uid, int mode) {
        if (uid <= 0) {
            return false;
        }
        /*
         * 统一写成文字形式：super / shadow
         * 内核解析：数字只有 "1" 算超级用户，写 "2" 会被当成影子 ——
         * 这就是「界面选了超级用户、内核却是影子」的另一个来源。
         */
        String m = (mode == MODE_FULL || mode == MODE_SUPER) ? "super" : "shadow";
        /*
         * 先 off 再写新值 —— 保证一个 uid 只有一条授权记录。
         * 之前直接覆盖写，内核里可能留下两条（影子 + 超级），
         * 模式冲突会让目标应用卡死。
         */
        writeGrant("uid:" + uid + " off");
        if (!writeGrant("uid:" + uid + " " + m)) {
            return false;
        }
        /*
         * ★ 写入后必须回读确认 ★
         *
         * 内核的 grant 写入对格式敏感（"uid 123" 与 "uid:123" 走不同分支），
         * 写错时它静默忽略 —— 界面却显示"已授权"。
         * 这里回读 /proc/umbral/grants，确认这一行真的存在，才返回成功。
         */
        try {
            String g = readDirect("/proc/umbral/grants");
            if (g == null || g.isEmpty()) {
                g = SkBridge.suRead("/proc/umbral/grants");
            }
            if (g != null) {
                boolean found = false;
                for (String line : g.split("\n")) {
                    String t = line.trim();
                    if (t.startsWith("uid " + uid + " ")) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    return false;
                }
            }
        } catch (Throwable ignored) {
        }
        return true;
    }

    /** 撤销某个 uid 的授权 */
    public static boolean revokeUid(int uid) {
        if (uid <= 0) {
            return false;
        }
        return writeGrant("uid:" + uid + " off");
    }

    /** 按 pid 授权（临时，进程退出即失效，测试用） */
    public static boolean grantPid(int pid, int mode) {
        if (pid <= 0) {
            return false;
        }
        String m = (mode == MODE_SUPER) ? "1" : "0";
        String pm = (mode == MODE_FULL || mode == MODE_SUPER) ? "super" : "shadow";
        return writeGrant(pid + " " + pm);
    }

    /** 给自己授权 —— pid 用自己 */
    public static boolean grantSelf(int mode) {
        return grantPid(android.os.Process.myPid(), mode);
    }

    /** 清空全部授权 */
    public static boolean clearAll() {
        return writeGrant("clear");
    }

    /**
     * 写 /proc/umbral/grant。
     *
     * 顺序：
     *   ① 直接写 —— 需要 ramdisk / KSU 那边带一条 sepolicy
     *      （allow untrusted_app proc file write）。有这条就完全不碰 su。
     *   ② 退回 su —— 没有 sepolicy 时的兼容路径。
     *
     * 这样同一份代码在「有策略」和「没策略」的设备上都能工作，
     * 只是前者不需要 root，后者需要。
     */

    /**
     * 我们自己的 su 壳路径。
     *
     * 1.52 起管理器主进程只有影子身份，所有需要 root 的操作都必须走特权子进程。
     * 系统里没有 /system/bin/su（我们把 KSU 替换掉了），只有 /data/local/tmp/umbral/su，
     * 所以不能再写死 "su" —— 之前模块开关失败就是这个原因。
     */
    private static String suBin() {
        String[] cand = {
                "/data/local/tmp/umbral/su",
                "/data/adb/umbral/su",
                "/system/bin/su"
        };
        for (String c : cand) {
            try {
                if (new File(c).exists()) {
                    return c;
                }
            } catch (Throwable ignored) {
            }
        }
        return "su";
    }

    private static boolean writeGrant(String content) {
        if (writeDirect("/proc/umbral/grant", content)) {
            return true;
        }
        /*
         * 用 >> 而不是 >：procfs 节点不接受 O_TRUNC（open 会失败），
         * grant 只是逐行解析，追加语义就够了。
         * 这条是「模块开关失败」的直接原因之一。
         */
        String cmd = "echo '" + content + "' >> /proc/umbral/grant && echo UMBRAL_OK";
        String r = exec(new String[]{suBin(), "-c", cmd});
        return r != null && r.contains("UMBRAL_OK");
    }

    /**
     * 直接写文件（不经 su）。
     *
     * ★ 不能用 FileOutputStream ★
     *   Java 的 FileOutputStream 打开时用 O_WRONLY|O_CREAT|O_TRUNC，
     *   proc 文件不接受 O_TRUNC，open 直接返回 EINVAL ——
     *   现象是「写入静默失败」。这个坑踩过一次。
     *
     *   ParcelFileDescriptor.open(MODE_WRITE_ONLY) 只带 O_WRONLY，proc 文件能开。
     */

    /* ===== /proc/umbral 已隐藏：改走内核劫持通道 ===== */
    private static String skChanPath;

    private static final String[] SK_CHAN_CANDS = {
            "/proc/sys/vm/watermark_boost_factor",
            "/proc/sys/vm/percpu_pagelist_high_fraction",
            "/proc/sys/kernel/hung_task_check_count",
            "/proc/sys/kernel/sched_deadline_period_min_us",
            "/proc/sys/kernel/soft_watchdog",
            "/proc/sys/kernel/msg_next_id",
            "/proc/sys/kernel/sem_next_id",
            "/proc/sys/kernel/shm_next_id",
    };

    private static String skChanCmd(String path) {
        int i = path == null ? -1 : path.lastIndexOf("/umbral/");
        return i < 0 ? null : path.substring(i + 8);
    }

    private static boolean skChanAbsent;

    private static String skChanFind() {
        if (skChanPath != null) return skChanPath;
        if (skChanAbsent) return null;
        /* /proc/umbral 还在 ⇒ 模块没有通道实现（旧版 ko），不要探测也不要改道 */
        if (new java.io.File("/proc/umbral/version").exists()) {
            skChanAbsent = true;
            return null;
        }
        /* 扫描式探测：内核随机挑一个 /proc/sys/{vm,kernel} 下的冷门条目劫持，
         * 我们不知道是哪个，就逐个试（写 magic+ver，能读回带点号的内容即命中）。
         * 黑名单里的绝不试，避免误改系统关键项。 */
        String[] dirs = { "/proc/sys/vm", "/proc/sys/kernel" };
        for (String d : dirs) {
            java.io.File dir = new java.io.File(d);
            String[] names = dir.list();
            if (names == null) continue;
            java.util.Arrays.sort(names);
            for (String n : names) {
                if (skChanBlocked(n)) continue;
                String p = d + "/" + n;
                try {
                    java.io.File f = new java.io.File(p);
                    if (!f.isFile() || !f.canRead()) continue;
                    if (!writeDirect(p, "\u00ef\u00be" + "ver")) continue;
                    String r = readDirect(p);
                    if (r != null && r.contains(".")) { skChanPath = p; return p; }
                } catch (Throwable ignored) { }
            }
        }
        skChanAbsent = true;
        return null;
    }

    private static boolean skChanBlocked(String n) {
        String[] bad = { "stat", "meminfo", "cpuinfo", "vmstat", "loadavg", "uptime",
                "version", "modules", "filesystems", "ns_last_pid", "tainted",
                "randomize_va_space", "panic", "printk", "tainted", "core_pattern",
                "modprobe", "hostname", "domainname", "osrelease", "ostype",
                "sched_", "watchdog", "hung_task", "perf_", "tracepoint", "ftrace",
                "drop_caches", "swappiness", "overcommit", "max_map_count",
                "min_free_kbytes", "dirty_", "vfs_cache_pressure", "mmap_" };
        for (String b : bad) if (n.startsWith(b) || n.equals(b)) return true;
        return false;
    }

    private static boolean writeDirect(String path, String content) {
        if (path != null && path.contains("/umbral/") && !content.startsWith("\u00ef\u00be")) {
            String sub = skChanCmd(path);
            String p = skChanFind();
            /* 通道能用就走通道；不能用必须回落到直接写 /proc/umbral/xxx，
             * 否则模块没有通道实现时（例如旧版 ko）授权会全部失败。 */
            if (sub != null && p != null
                    && writeDirect(p, "\u00ef\u00be" + sub + " " + content.trim())) {
                return true;
            }
        }
        android.os.ParcelFileDescriptor pfd = null;
        java.io.FileOutputStream fo = null;
        try {
            pfd = android.os.ParcelFileDescriptor.open(
                    new File(path), android.os.ParcelFileDescriptor.MODE_WRITE_ONLY);
            fo = new java.io.FileOutputStream(pfd.getFileDescriptor());
            fo.write(content.getBytes("UTF-8"));
            fo.flush();
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            closeQuietly(fo);
            closeQuietly(pfd);
        }
    }

    /** 直接读文件（不经 su） */
    public static String readDirect(String path) {
        if (path != null && path.contains("/umbral/")) {
            String sub = skChanCmd(path);
            String p = skChanFind();
            if (sub != null && p != null && writeDirect(p, "\u00ef\u00be" + sub)) {
                String r = readDirect(p);
                if (r != null) return r;
            }
        }
        java.io.FileInputStream in = null;
        try {
            in = new java.io.FileInputStream(path);
            byte[] buf = new byte[64 * 1024];
            StringBuilder sb = new StringBuilder();
            int n;
            while ((n = in.read(buf)) > 0) {
                sb.append(new String(buf, 0, n, "UTF-8"));
                if (sb.length() > 128 * 1024) {
                    break;
                }
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        } finally {
            closeQuietly(in);
        }
    }

    // ── 模块安装 / 加载 / 卸载 ──

    /**
     * 把 APK 里的模块释放到 /data/adb/umbral/sk_root.ko。
     *
     * 为什么要固定到 /data/adb/umbral：
     *   ① 重启后模块不在内核里了，得有个地方能重新 load
     *   ② App 私有目录会被卸载/清数据影响
     *   ③ /data/adb 是所有 root 方案约定的持久目录
     */
    public static boolean installFromAssets(Context ctx) {
        File tmp = new File(ctx.getCacheDir(), "sk_root.ko");
        if (!extractAsset(ctx, tmp)) {
            return false;
        }
        /*
         * 同时写 manager.uid —— 这是 Boot 自举的关键：
         *   刷进 ramdisk 的模块由 init 加载，那时不知道管理器的 uid
         *   （重装会变），所以模块读这个文件来自我授权。
         *   文件必须由管理器自己写，因为只有它知道自己的 uid。
         */
        String cmd = "mkdir -p " + DIR
                + " && cp " + tmp.getAbsolutePath() + " " + PATH
                + " && chmod 644 " + PATH
                + " && echo " + android.os.Process.myUid() + " > " + DIR + "/manager.uid"
                + " && chmod 644 " + DIR + "/manager.uid"
                + " && echo UMBRAL_OK";
        String r = exec(new String[]{suBin(), "-c", cmd});
        // 清掉临时副本
        try {
            tmp.delete();
        } catch (Exception ignored) {
        }
        return r != null && r.contains("UMBRAL_OK");
    }

    /**
     * 加载模块。
     *
     * allowUid 是模块的 sk_allow_uid 参数 —— 让这个 uid 能直接写
     * /proc/umbral/grant（在 ramdisk 带 sepolicy 之后才真正有用）。
     */
    public static String load(Context ctx, int allowUid) {
        if (!fileInstalled()) {
            if (!installFromAssets(ctx)) {
                return "模块文件释放失败";
            }
        }
        if (isLoaded()) {
            return null;    // 已加载
        }
        String r = exec(new String[]{suBin(), "-c",
                "insmod " + PATH + " sk_allow_uid=" + allowUid + " && echo UMBRAL_OK"});
        if (r != null && r.contains("UMBRAL_OK")) {
            return null;
        }
        return r == null ? "insmod 无输出（可能没有 root）" : r.trim();
    }

    public static String unload() {
        String r = exec(new String[]{suBin(), "-c", "rmmod sk_root && echo UMBRAL_OK"});
        if (r != null && r.contains("UMBRAL_OK")) {
            return null;
        }
        return r == null ? "rmmod 无输出（可能没有 root）" : r.trim();
    }

    /** 读原始 grants 文本，调试用 */
    public static String grantsRaw() {
        String v = readDirect("/proc/umbral/grants");
        return (v != null) ? v : SkBridge.suRead("/proc/umbral/grants");
    }

    // ── 内部 ──

    private static boolean extractAsset(Context ctx, File dst) {
        InputStream in = null;
        OutputStream out = null;
        try {
            AssetManager am = ctx.getAssets();
            in = am.open(assetPath());
            out = new FileOutputStream(dst);
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            out.flush();
            closeQuietly(out);
            out = null;
            /*
             * vermagic 适配：PC 上编出来的 .ko，其 vermagic 与厂商内核的 uname -r
             * 永远不一致，insmod 会直接拒绝加载。这里在打包前把它改成目标机的值。
             * 失败不阻断流程 —— 只是这一台可能仍会 insmod 失败，日志里能看到原因。
             */
            try {
                String vm = Vermagic.patchFile(dst.getAbsolutePath());
                android.util.Log.i("umbral", "vermagic: " + vm);
            } catch (Throwable t) {
                android.util.Log.w("umbral", "vermagic: 异常 " + t);
            }
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            closeQuietly(in);
            closeQuietly(out);
        }
    }

    /**
     * 模块在 assets 里的路径 —— 按 KMI 分目录。
     * 管理器里可以打包多份，运行时按内核版本选。
     */
    private static String assetPath() {
        String k = SkBridge.kernelVersion();     // 如 6.6.30-android15-8-g...
        String androidMaj = "android15";
        if (k != null) {
            if (k.contains("android12")) {
                androidMaj = "android12";
            } else if (k.contains("android13")) {
                androidMaj = "android13";
            } else if (k.contains("android14")) {
                androidMaj = "android14";
            } else if (k.contains("android15")) {
                androidMaj = "android15";
            }
        }
        String kmi = "6.6";
        if (k != null) {
            if (k.startsWith("5.10")) {
                kmi = "5.10";
            } else if (k.startsWith("5.15")) {
                kmi = "5.15";
            } else if (k.startsWith("6.1")) {
                kmi = "6.1";
            } else if (k.startsWith("6.6")) {
                kmi = "6.6";
            }
        }
        return "arm64-v8a/" + androidMaj + "-" + kmi + "/umbral.ko";
    }

    private static String exec(String[] cmd) {
        Process p = null;
        InputStream in = null;
        try {
            p = Runtime.getRuntime().exec(cmd);
            in = p.getInputStream();
            StringBuilder sb = new StringBuilder();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) {
                sb.append(new String(buf, 0, n, "UTF-8"));
                if (sb.length() > 64 * 1024) {
                    break;
                }
            }
            p.waitFor();
            return sb.toString();
        } catch (Exception e) {
            return null;
        } finally {
            closeQuietly(in);
            if (p != null) {
                p.destroy();
            }
        }
    }

    /**
     * 确保 /data/adb/umbral/manager.uid 存在且是本 App 的 uid。
     *
     * 为什么每次启动都要校验：
     *   模块开机加载时靠这个文件知道该给谁授权。App 重装后 uid 会变，
     *   如果文件还写着旧 uid，开机自举就会授权给一个不存在的身份。
     *   所以只要模块活着、我们有权限，就把它校正一次。
     *
     * 失败是正常的（没 root 时写不了 /data/adb），不报错。
     */
    public static void ensureUidFile() {
        try {
            int me = android.os.Process.myUid();
            String cur = readDirect(DIR + "/manager.uid");
            if (cur != null && cur.trim().equals(String.valueOf(me))) {
                return;         /* 已经对了，不做无用写入 */
            }
            String cmd = "mkdir -p " + DIR
                    + " && echo " + me + " > " + DIR + "/manager.uid"
                    + " && chmod 644 " + DIR + "/manager.uid";
            exec(new String[]{suBin(), "-c", cmd});
        } catch (Throwable ignored) {
        }
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignored) {
            }
        }
    }
}
