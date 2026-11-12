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

    public static boolean isLoaded() {
        /*
         * 先直接读 /proc/umbral/version —— 这是最便宜的判据：
         *   · 模块没加载 → 文件不存在
         *   · 模块加载了但 SELinux 挡着 → 读失败，再退到 su
         * 两种失败要分开处理，不能都当「没加载」。
         */
        String v = readDirect("/proc/umbral/version");
        if (v != null && !v.trim().isEmpty()) {
            return true;
        }
        File f = new File("/proc/umbral");
        if (f.exists()) {
            // 目录在但读不到 → SELinux 挡着，用 su 确认
            String sv = SkBridge.suRead("/proc/umbral/version");
            return sv != null && !sv.trim().isEmpty();
        }
        return false;
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
        String m = (mode == MODE_FULL) ? "2" : (mode == MODE_SUPER ? "1" : "0");
        /*
         * 先 off 再写新值 —— 保证一个 uid 只有一条授权记录。
         * 之前直接覆盖写，内核里可能留下两条（影子 + 超级），
         * 模式冲突会让目标应用卡死。
         */
        writeGrant("uid:" + uid + " off");
        return writeGrant("uid:" + uid + " " + m);
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
        return writeGrant(pid + " " + m);
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
    private static boolean writeGrant(String content) {
        if (writeDirect("/proc/umbral/grant", content)) {
            return true;
        }
        String cmd = "echo '" + content + "' > /proc/umbral/grant && echo UMBRAL_OK";
        String r = exec(new String[]{"su", "-c", cmd});
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
    private static boolean writeDirect(String path, String content) {
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
        String r = exec(new String[]{"su", "-c", cmd});
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
        String r = exec(new String[]{"su", "-c",
                "insmod " + PATH + " sk_allow_uid=" + allowUid + " && echo UMBRAL_OK"});
        if (r != null && r.contains("UMBRAL_OK")) {
            return null;
        }
        return r == null ? "insmod 无输出（可能没有 root）" : r.trim();
    }

    public static String unload() {
        String r = exec(new String[]{"su", "-c", "rmmod sk_root && echo UMBRAL_OK"});
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
            exec(new String[]{"su", "-c", cmd});
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
