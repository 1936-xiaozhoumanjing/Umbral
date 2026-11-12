package io.umbral.sk;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.BufferedReader;
import java.io.FileReader;

/**
 * Vivo / iQOO 反 root 对抗。
 *
 * ══════════════════════════════════════════════════════
 *  它们怎么反 root
 * ══════════════════════════════════════════════════════
 *
 *  Vivo / iQOO 的系统里有一批「系统管家 / 安全中心」类应用，
 *  它们会主动扫这些东西（比通用检测更狠）：
 *
 *    · /system/bin/su、/system/xbin/su 等 su 二进制
 *    · /data/adb 下的 magisk / ksu / 模块目录
 *    · /proc/mounts 里的 overlay / magisk 挂载
 *    · 系统属性 ro.debuggable / ro.secure / service.adb.root
 *    · 已安装包名（com.topjohnwu.magisk、me.weishu.kernelsu…）
 *    · 我们的 /proc/umbral 和 /data/adb/umbral
 *
 *  一旦命中，常见后果：
 *    · 弹「检测到 root，部分功能受限」
 *    · 支付/银行类应用被降级
 *    · 部分机型会记录并上报
 *
 * ══════════════════════════════════════════════════════
 *  我们怎么对抗
 * ══════════════════════════════════════════════════════
 *
 *  不跟它们比谁更狠，而是让「它们看不见」：
 *
 *    ① 检测到 Vivo/iQOO、且用户打开了「反 root 对抗」
 *    ② 找出这些安全应用的 uid
 *    ③ 对它们单独下发 UM 隐藏规则（hide 所有 root 痕迹路径）
 *    ④ 规则只作用于这几个 uid —— 其它应用不受影响
 *
 *  这样安全中心自己扫的时候，su / magisk / ksu / umbral / proc/sk
 *  全部「不存在」，而我们自己的应用照常能用。
 */
public final class VivoGuard {

    /** 已知的 Vivo / iQOO 安全与管家类包名 */
    private static final String[] SECURITY_PKGS = {
            "com.vivo.abe",              /* i管家 / 安全中心核心 */
            "com.iqoo.secure",           /* iQOO 安全中心 */
            "com.vivo.secime",           /* 安全输入法 */
            "com.vivo.gamewatch",        /* 游戏监控 */
            "com.vivo.appfilter",
            "com.bbk.iqoo.pay",          /* iQOO 钱包（会做完整性检查） */
            "com.vivo.wallet",
            "com.vivo.finance",
            "com.bbk.iqoo.fund",
            "com.vivo.assistant",
    };

    /** 要隐藏的路径（比通用模板更针对 vivo 的做法） */
    private static final String[] HIDE_PATHS = {
            "/system/bin/su", "/system/xbin/su", "/su/bin/su",
            "/data/local/su", "/data/local/xbin/su",
            "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ksud",
            "/data/adb/modules", "/data/adb/modules_update",
            "/data/adb/umbral", "/data/adb/umbral/su",
            "/proc/umbral", "/sys/module/sk_root",
            "/proc/modules", "/proc/kallsyms",
            "/init.magisk.rc", "/cache/magisk.log",
    };

    private VivoGuard() {
    }

    /** 读系统属性（不需要 root，普通文件读） */
    public static String prop(String key) {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/system/build.prop"));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith(key + "=")) {
                    return line.substring(key.length() + 1).trim();
                }
            }
        } catch (Throwable ignored) {
        } finally {
            try { if (r != null) r.close(); } catch (Exception ignored) { }
        }
        return "";
    }

    /** 是否 Vivo / iQOO 系（区分 vivo / iqoo 两个品牌，都算） */
    public static boolean isVivoFamily() {
        String brand = prop("ro.product.brand").toLowerCase();
        String manu = prop("ro.product.manufacturer").toLowerCase();
        String os = prop("ro.vivo.os.version");
        String abe = prop("ro.vivo.abe");

        if (brand.contains("vivo") || brand.contains("iqoo")) {
            return true;
        }
        if (manu.contains("vivo") || manu.contains("bbk")) {
            return true;
        }
        if (!os.isEmpty() || !abe.isEmpty()) {
            return true;
        }
        return false;
    }

    /** 具体是哪一家（给界面显示用） */
    public static String familyName() {
        String brand = prop("ro.product.brand").toLowerCase();
        if (brand.contains("iqoo")) {
            return "iQOO";
        }
        if (brand.contains("vivo")) {
            return "vivo";
        }
        return isVivoFamily() ? "vivo 系" : "";
    }

    /** 用户是否打开了「反 root 对抗」 */
    public static boolean enabled(Context ctx) {
        SharedPreferences sp = ctx.getSharedPreferences("sk_settings", Context.MODE_PRIVATE);
        return sp.getBoolean("vivo_guard", false);
    }

    public static void setEnabled(Context ctx, boolean on) {
        ctx.getSharedPreferences("sk_settings", Context.MODE_PRIVATE)
                .edit().putBoolean("vivo_guard", on).apply();
    }

    /** 已知安全类包名 */
    public static String[] securityPackages() {
        return SECURITY_PKGS.clone();
    }

    /** 要隐藏的路径 */
    public static String[] hidePaths() {
        return HIDE_PATHS.clone();
    }
}
