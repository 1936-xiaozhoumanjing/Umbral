package io.umbral.sk;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;

/**
 * 授权表持久化 —— 把内核里的授权表镜像到 /data/adb/umbral/grants.conf。
 *
 * ══════════════════════════════════════════════════════
 *  为什么需要 App 侧再做一次
 * ══════════════════════════════════════════════════════
 *
 *  内核里本来有 sk_save_grants()，用 filp_open + kernel_write 写这个文件。
 *  但实测：文件根本不存在 ——
 *      ls /data/adb/umbral/grants.conf → No such file or directory
 *  原因是内核身份写 root 属主目录这条路被我们自己的 DAC 规则挡着
 *  （属主 ≤1000 的文件保持只读那条，救 ART 用的），失败又是静默的。
 *
 *  所以改成 App 侧兜底：
 *      读 /proc/umbral/grants（内核是唯一权威）
 *      → 原样写 /data/adb/umbral/grants.conf
 *  这样重启后内核能从这个文件恢复授权，用户的授权决定才真的活过重启。
 *
 *  调用点：每次授权/取消授权之后，以及 App 启动时各同步一次。
 */
public final class GrantsPersist {

    public static final String FILE = "/data/adb/umbral/grants.conf";

    private GrantsPersist() {
    }

    /**
     * 把当前内核授权表同步到磁盘。
     *
     * @return 写入的条目数；失败返回 -1
     */
    public static int sync() {
        String content = readKernelTable();
        if (content == null) {
            return -1;
        }
        /* 只保留 "uid N shadow|super" 行，去掉统计行 */
        StringBuilder out = new StringBuilder();
        int n = 0;
        for (String line : content.split("\n")) {
            String t = line.trim();
            if (t.startsWith("uid ")) {
                out.append(t).append('\n');
                n++;
            }
        }
        if (write(out.toString())) {
            return n;
        }
        return -1;
    }

    /** 读内核授权表（两种路径都试，兼容改名前后） */
    private static String readKernelTable() {
        for (String p : new String[]{"/proc/umbral/grants", "/proc/sk/grants"}) {
            try {
                java.io.BufferedReader r = new java.io.BufferedReader(
                        new java.io.FileReader(p));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                r.close();
                if (sb.length() > 0) {
                    return sb.toString();
                }
            } catch (Throwable ignored) {
            }
        }
        /* 直接读不到就走 su 读（有真 root 时这条能成） */
        try {
            SuBridge.R r = SuBridge.root("cat /proc/umbral/grants 2>/dev/null");
            if (r.out != null && !r.out.trim().isEmpty()) {
                return r.out;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static boolean write(String text) {
        /* ① App 直接写（影子权限下 /data/adb 可写） */
        try {
            File f = new File(FILE);
            FileOutputStream fo = new FileOutputStream(f, false);
            fo.write(text.getBytes("UTF-8"));
            fo.flush();
            fo.getFD().sync();
            fo.close();
            //noinspection ResultOfMethodCallIgnored
            f.setReadable(true, false);
            return f.exists() && f.length() > 0;
        } catch (Throwable ignored) {
        }
        /* ② 走 su 写 */
        try {
            SuBridge.R r = SuBridge.root("printf '%s' '" + text.replace("'", "'\\''")
                    + "' > " + FILE + " && [ -s " + FILE + " ] && echo OK");
            return r.out != null && r.out.contains("OK");
        } catch (Throwable ignored) {
        }
        return false;
    }
}
