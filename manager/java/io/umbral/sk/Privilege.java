package io.umbral.sk;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;

/**
 * 权限自检 —— 判断管理器当前到底拿到了什么。
 *
 * ══════════════════════════════════════════════════════
 *  为什么不能靠 uid / capabilities 判断
 * ══════════════════════════════════════════════════════
 *
 *  影子权限的设计目标就是「不留可检测痕迹」：
 *      uid        保持不变（10563）
 *      CapEff     仍是 0000000000000000
 *      SELinux 域 仍是 untrusted_app
 *
 *  所以任何读这些值的检测都会得出「没有 root」的结论 —— 包括我们自己。
 *
 * ══════════════════════════════════════════════════════
 *  唯一可靠的判据：实际做一次
 * ══════════════════════════════════════════════════════
 *
 *  挑一个「普通 App 必然读不到」的资源去读：
 *
 *    /proc/umbral/version    模块自建的节点，SELinux 默认挡住 untrusted_app
 *                        读成功 = 影子钩子放行了 = 有影子权限
 *
 *    /data/adb/modules   属主 root(0)、0700
 *                        能列出来 = 真的写权限级 root
 *
 *    geteuid() == 0      只有超级用户模式（commit_creds）才会成立
 *
 *  三者组合就能分清：无权限 / 影子 / 超级用户。
 */
public final class Privilege {

    /** 权限等级 */
    public static final int NONE = 0;     /** 没有任何权限 */
    public static final int SHADOW = 1;   /** 影子权限：uid 不变但判定放行 */
    public static final int SUPER = 2;    /** 超级用户：真 uid 0 */

    public int level = NONE;
    public String reason = "";

    /** 模块是否在跑（/proc/umbral 存在） */
    public boolean moduleRunning;
    /** 能否读模块节点（影子钩子生效的直接证据） */
    public boolean canReadProc;
    /** 能否列出 /data/adb/modules（root 目录） */
    public boolean canReadAdb;
    /** geteuid 是否为 0 */
    public boolean euidZero;

    public String label() {
        switch (level) {
            case SUPER:
                return "超级用户";
            case SHADOW:
                return "影子权限";
            default:
                return "无权限";
        }
    }

    // ══════════════════ 检测 ══════════════════

    public static Privilege detect(Context ctx) {
        Privilege p = new Privilege();

        p.moduleRunning = new File("/proc/umbral").exists();
        p.euidZero = android.os.Process.myUid() == 0;

        /* ① 能不能读模块节点 —— 影子权限的直接证据 */
        p.canReadProc = readAll("/proc/umbral/version") != null;

        /* ② 能不能列 root 属主目录 —— 真 root 级写权限的证据 */
        try {
            File[] fs = new File("/data/adb/modules").listFiles();
            p.canReadAdb = fs != null;
        } catch (Throwable t) {
            p.canReadAdb = false;
        }

        /* ③ 得出结论 */
        if (p.euidZero) {
            p.level = SUPER;
            p.reason = "geteuid() == 0，已经是真 root 身份";
        } else if (p.canReadProc) {
            p.level = SHADOW;
            p.reason = "uid 仍是 " + android.os.Process.myUid()
                    + "，但能读 /proc/umbral/version —— 影子钩子在放行";
        } else if (p.moduleRunning) {
            p.level = NONE;
            p.reason = "模块在运行（/proc/umbral 存在），但没有授权给本管理器";
        } else {
            p.level = NONE;
            p.reason = "模块未加载（/proc/umbral 不存在）";
        }
        return p;
    }

    /** 一行摘要，给状态卡用 */
    public String summary() {
        StringBuilder sb = new StringBuilder();
        sb.append("权限：").append(label());
        sb.append("（uid ").append(android.os.Process.myUid()).append("）");
        if (level != NONE) {
            sb.append("\n").append(reason);
        } else {
            sb.append("\n").append(reason);
        }
        return sb.toString();
    }

    /**
     * 主动向内核认领权限。
     *
     * 内核会读本进程的 /proc/self/cmdline，确认是 io.umbral 才授予影子权限。
     * 这条路径不依赖开机时机 —— App 什么时候起来都能认领。
     */
    public static boolean claim() {
        /*
         * ★ 必须用 ParcelFileDescriptor，不能用 FileOutputStream ★
         *
         * FileOutputStream 打开时带 O_WRONLY|O_CREAT|O_TRUNC。
         * proc 文件不接受 O_CREAT/O_TRUNC：
         *   · 轻则 open 直接 EACCES（表现为"认领失败"，什么都看不到）
         *   · 重则走到内核 handler 的异常路径 —— 实测这台设备上
         *     写 /proc/umbral/claim 会让内核 panic、整个系统重启
         *
         * 所以统一走 Shell.writeProc（只带 O_WRONLY）。
         */
        return io.umbral.sk.Shell.writeProc("/proc/umbral/claim", "claim");
    }

    /**
     * 确保有权限：没有就认领一次，然后再检测。
     *
     * 调用点：App 启动、回到前台、每次刷新状态前。
     * 幂等 —— 已有权限时认领会被内核拒绝（-EEXIST），无害。
     */
    public static Privilege ensure(Context ctx) {
        Privilege p = detect(ctx);
        if (p.level != NONE) {
            return p;
        }
        if (!p.moduleRunning) {
            return p;          /* 模块都没加载，认领也没用 */
        }
        claim();
        return detect(ctx);
    }

    private static String readAll(String path) {
        BufferedReader r = null;
        try {
            File f = new File(path);
            if (!f.exists()) {
                return null;
            }
            r = new BufferedReader(new InputStreamReader(new FileInputStream(f), "UTF-8"));
            String line = r.readLine();
            return line == null ? "" : line;
        } catch (Throwable t) {
            return null;
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (Exception ignored) {
                }
            }
        }
    }
}
