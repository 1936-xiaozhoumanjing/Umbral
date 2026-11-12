package io.umbral.um;

import java.util.ArrayList;
import java.util.List;

/**
 * UM 模板库 —— 内置几套常用隐藏规则，一键生成。
 *
 * ══════════════════════════════════════════════════════
 *  为什么需要模板
 * ══════════════════════════════════════════════════════
 *
 *  手写一条规则要三步：查目标 App 的 uid、查文件的 dev/ino、拼成一行。
 *  对普通用户来说太麻烦，而这个库把「常见隐藏需求」固化下来：
 *  选模板 → 选目标 App → 自动算好 dev/ino 并下发。
 *
 * ══════════════════════════════════════════════════════
 *  模板怎么工作
 * ══════════════════════════════════════════════════════
 *
 *  模板只存「路径列表 + 动作」。应用时：
 *      对每条路径执行 stat -c "%d %i" 拿到 dev/ino
 *      生成规则： <uid> <dev> <ino> hide
 *  路径不存在就跳过（不同设备装的东西不一样，不能因此失败）。
 *
 *  ⚠️ 诚实说明哪些能治哪些不能：
 *      能治：靠「扫文件/目录存不存在」的检测（MT、Termux、KSU 残留）
 *      治不了：USB调试、Bootloader 解锁、TEE —— 这些不是文件存在性问题
 */
public final class UmTemplates {

    /** 一个模板 */
    public static final class Tpl {
        public String id;
        public String name;
        public String desc;
        public String action = "hide";
        /** 要隐藏的路径；不存在会自动跳过 */
        public String[] paths;
        /** 这模板能对付什么检测、不能对付什么 */
        public String note;

        @Override
        public String toString() {
            return name;
        }
    }

    /**
     * 仓库 —— 现在只有一个内置官方目录，将来可以接远程网址。
     *
     * 远程仓库的格式和 MarketIndex 一致（schema/name/items），
     * 落地时只需要在这里加一个 Repo{kind=REMOTE, url=...}，
     * 列表和下发逻辑一行都不用改。
     */
    public static final class Repo {
        public static final int BUILTIN = 0;
        public static final int REMOTE = 1;

        public String id;
        public String name;
        public String desc;
        public int kind = BUILTIN;
        public String url;          /* 远程仓库地址，内置的为 null */
        public java.util.List<Tpl> items = new ArrayList<>();
    }

    /** 当前可用的仓库列表（目前只有内置官方目录） */
    public static List<Repo> repos() {
        List<Repo> l = new ArrayList<>();
        Repo r = new Repo();
        r.id = "official";
        r.name = "影核官方";
        r.desc = "内置常用隐藏模板";
        r.kind = Repo.BUILTIN;
        r.items = all();
        l.add(r);
        return l;
    }

    private UmTemplates() {
    }

    /** 全部模板 */
    public static List<Tpl> all() {
        List<Tpl> l = new ArrayList<>();

        /*
         * 一键隐藏绝大多数危险目录。
         *
         * 覆盖：改机/破解工具、脚本环境、root 框架、注入框架、常见作弊工具。
         * 路径不存在会自动跳过，所以列表长一点没关系。
         */
        l.add(tpl("danger_all", "一键隐藏危险目录（推荐）",
                "把常见的破解/root/注入/作弊工具目录一次全隐藏",
                "能治：扫这些目录存在性的检测（MT、Termux、KSU、Magisk、Frida、Xposed、GG 等）\n"
                        + "治不了：USB调试、Bootloader 解锁、TEE、已安装应用包名列表",
                "hide",
                /* ── 改机 / 文件管理 ── */
                "/sdcard/MT2", "/storage/emulated/0/MT2", "/data/media/0/MT2",
                "/sdcard/Android/data/bin.mt.plus", "/data/data/bin.mt.plus",
                "/data/user/0/bin.mt.plus",
                "/sdcard/Android/data/com.estrongs.android.pop",
                /* ── 脚本 / 终端 ── */
                "/data/data/com.termux", "/data/user/0/com.termux",
                "/sdcard/Android/data/com.termux", "/sdcard/.termux",
                "/data/data/org.connectbot", "/sdcard/Android/data/org.connectbot",
                /* ── root 框架 ── */
                "/data/adb/ksu", "/data/adb/ksud", "/data/adb/modules",
                "/data/adb/modules_update", "/data/adb/magisk", "/data/adb/ap",
                "/data/adb/apd", "/sbin/.magisk", "/dev/.magisk.unblock",
                "/data/adb/umbral",
                /* ── 注入框架 ── */
                "/data/adb/lspd", "/data/misc/riru", "/data/adb/riru",
                "/data/misc/zygisk", "/data/adb/zygisksu",
                /* ── 作弊 / 破解工具 ── */
                "/sdcard/GameGuardian", "/sdcard/Android/data/catch_.me_.if_.you_.can_",
                "/data/data/com.gameguardian", "/sdcard/LuckyPatcher",
                "/data/data/com.chelpus.luckypatcher",
                "/sdcard/Android/data/com.termux.hack",
                "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
                "/data/local/tmp/gg", "/data/local/tmp/su",
                /* ── 常见外挂/辅助目录 ── */
                "/sdcard/外挂", "/sdcard/特征", "/sdcard/脚本",
                "/sdcard/Auto.js", "/data/data/org.autojs.autojs"));

        l.add(tpl("mt_manager", "隐藏 MT 管理器痕迹",
                "隐藏 MT2 目录和常见残留，对付「MT管理器异常文件」检测",
                "能治：扫 /sdcard/MT2 的检测\n治不了：MT 的包名（那要改 PackageManager）",
                "hide",
                "/sdcard/MT2",
                "/storage/emulated/0/MT2",
                "/data/media/0/MT2",
                "/sdcard/Android/data/bin.mt.plus",
                "/data/data/bin.mt.plus",
                "/data/user/0/bin.mt.plus"));

        l.add(tpl("termux", "隐藏 Termux 痕迹",
                "隐藏 Termux 的数据目录和家目录，对付「检测到 TERMUX」",
                "能治：扫 Termux 数据目录的检测\n治不了：已安装应用的包名列表",
                "hide",
                "/data/data/com.termux",
                "/data/user/0/com.termux",
                "/sdcard/Android/data/com.termux",
                "/sdcard/.termux"));

        l.add(tpl("ksu", "隐藏 KernelSU 痕迹",
                "隐藏 KSU 的目录与二进制，对付「检测到 KSU」",
                "能治：扫 /data/adb/ksu 的检测\n治不了：内核里有没有 KSU 驱动（那要靠隐藏清洗）",
                "hide",
                "/data/adb/ksu",
                "/data/adb/ksud",
                "/data/adb/modules",
                "/data/adb/modules_update"));

        l.add(tpl("self", "隐藏影核自身",
                "隐藏影核的模块与规则目录，避免自己被扫到",
                "推荐对所有检测类 App 启用",
                "hide",
                "/data/adb/umbral",
                "/data/local/tmp/sk_root.ko"));

        l.add(tpl("magisk", "隐藏 Magisk 残留",
                "隐藏 Magisk 的常见路径，对付「检测到 Magisk」",
                "能治：扫 /data/adb/magisk 的检测",
                "hide",
                "/data/adb/magisk",
                "/sbin/.magisk",
                "/dev/.magisk.unblock"));

        l.add(tpl("deny_mods", "模块目录不可访问（不隐藏）",
                "不删除条目，只把访问改成「拒绝」，某些检测对比目录存在性时会露馅更少",
                "与 hide 的区别：hide 报「不存在」，deny 报「权限不足」",
                "deny",
                "/data/adb/modules",
                "/data/adb/umbral"));


        /*
         * ══════════════════════════════════════════════════════
         *  一键隐藏环境 —— root 暴露点全清单
         * ══════════════════════════════════════════════════════
         *
         * 检测器找 root，靠的是「这些东西存不存在 / 内容对不对」。
         * 下面按类别把已知的暴露点列全，路径不存在会自动跳过，
         * 所以列表长一点没有副作用。
         *
         * 一、su 二进制（最经典的检测点，十几个常见位置）
         * 二、Magisk 全家（目录、数据库、日志、开机脚本、模块目录）
         * 三、KernelSU 全家
         * 四、影核自己（连我们自己的痕迹也一起藏）
         * 五、超级用户 APK / daemon / 库
         * 六、busybox
         * 七、属性文件（ro.debuggable / ro.secure / test-keys 这些）
         * 八、内核模块与内核接口（/proc/modules、/proc/kallsyms、sysfs）
         * 九、恢复模式与临时缓存
         * 十、注入框架（Xposed / LSPosed / Riru / Frida）
         */
        l.add(tpl("hide_root_env", "一键隐藏环境（root 暴露点全隐藏）",
                "把 su、Magisk、KSU、影核自身、模块、注入框架、属性文件一次全隐藏",
                "能治：扫路径存在性、扫 su 二进制、扫 Magisk/KSU 目录、扫模块列表、扫注入框架\n"
                        + "治不了：USB 调试、Bootloader 解锁状态、TEE/Play Integrity、"
                        + "getprop 内存映射读取、已安装应用包名列表",
                "hide",

                /* ── 一、su 二进制 ── */
                "/system/bin/su", "/system/xbin/su", "/system/sbin/su",
                "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
                "/sbin/su", "/su/bin/su", "/vendor/bin/su",
                "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
                "/debug_ramdisk/su", "/system_ext/bin/su",

                /* ── 二、Magisk ── */
                "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/magisk_simple",
                "/data/magisk", "/data/magisk.img", "/data/magisk_merge.img",
                "/sbin/.magisk", "/sbin/.core", "/dev/.magisk.unblock",
                "/cache/.disable_magisk", "/cache/magisk.log", "/init.magisk.rc",
                "/data/adb/post-fs-data.d", "/data/adb/service.d",
                "/data/adb/modules", "/data/adb/modules_update",

                /* ── 三、KernelSU ── */
                "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ap", "/data/adb/apd",
                "/data/adb/ksu_log", "/data/adb/ksu/modules",

                /* ── 四、影核自己 ── */
                "/data/adb/umbral", "/data/adb/umbral/sk_root.ko",
                "/data/adb/umbral/su", "/data/adb/umbral/grants.conf",
                "/data/adb/umbral/manager.uid", "/data/adb/umbral/um",
                "/data/adb/umbral/bin",
                /* ── 四·补：本轮新识别出的暴露点，全部加进隐藏清单 ── */
                "/data/local/tmp/umbral",          /* su / umbrald / magisk / ksud / resetprop */
                "/data/local/tmp/umbral/su",
                "/data/local/tmp/umbral/umbrald",
                "/data/local/tmp/umbral/bin",
                "/data/local/tmp/umbral/daemon",
                "/data/local/tmp/umbral/signature.txt",
                "/data/local/tmp/umbral/props.txt",
                "/data/local/tmp/umbral/.last_boot",
                "/data/local/tmp/umbral/manager.uid",
                "/proc/modules",                    /* 里面会露出 sk_root */
                "/proc/kallsyms",                   /* 里面有 sk_* 符号 */
                "/proc/umbral", "/sys/module/sk_root",

                /* ── 五、超级用户 APK / daemon / 库 ── */
                "/system/app/Superuser.apk", "/system/app/SuperSU",
                "/system/etc/init.d/99SuperSUDaemon",
                "/system/xbin/daemonsu", "/system/xbin/sugote",
                "/system/xbin/supolicy", "/system/lib/libsupol.so",
                "/data/data/com.topjohnwu.magisk",
                "/data/user/0/com.topjohnwu.magisk",
                "/data/data/eu.chainfire.supersu",
                "/data/user/0/eu.chainfire.supersu",
                "/data/data/me.weishu.kernelsu",
                "/data/user/0/me.weishu.kernelsu",

                /* ── 六、busybox / 工具集 ── */
                "/system/xbin/busybox", "/system/bin/busybox",
                "/data/local/busybox", "/system/xbin/tcpdump",

                /* ── 七、属性文件（ro.debuggable / ro.secure / test-keys）── */
                "/system/build.prop", "/vendor/build.prop",
                "/default.prop", "/prop.default",

                /* ── 八、内核模块与内核接口 ── */
                "/proc/modules", "/proc/kallsyms", "/proc/umbral",

                /* ── 九、恢复模式与缓存 ── */
                "/cache/recovery", "/cache/recovery/command",
                "/data/recovery", "/data/adb/su",
                "/data/su.img", "/data/adb/edxposed",

                /* ── 十、注入框架 ── */
                "/data/adb/lspd", "/data/adb/riru", "/data/misc/riru",
                "/data/misc/lspd", "/data/misc/xposed",
                "/system/framework/XposedBridge.jar",
                "/system/lib64/libxposed_art.so",
                "/data/local/tmp/frida-server",
                "/data/local/tmp/re.frida.server",
                "/data/local/tmp/frida-server-16"));

        return l;
    }

    private static Tpl tpl(String id, String name, String desc, String note,
                           String action, String... paths) {
        Tpl t = new Tpl();
        t.id = id;
        t.name = name;
        t.desc = desc;
        t.note = note;
        t.action = action;
        t.paths = paths;
        return t;
    }

    /**
     * 把模板展开成规则行。
     *
     * @param uid  目标应用 uid
     * @return 规则行列表（可直接写入 /proc/umbral/um）；路径不存在的不包含在内
     */
    public static List<String> buildRules(int uid, Tpl t) {
        List<String> out = new ArrayList<>();
        for (String p : t.paths) {
            long[] di = statDevIno(p);
            if (di == null) {
                continue;       /* 路径不存在，跳过 */
            }
            /*
             * ★ 带标签格式 ★
             *   .umb 文件由 UmModule.rules() 解析，它要的是
             *       uid <u> dev <d> ino <i> <动作>
             *   而 /proc/umbral/um 要的是裸格式 <u> <d> <i> <动作>。
             *   两者不同，混用会报「第 N 行不认识」。
             */
            out.add("uid " + uid + " dev " + di[0] + " ino " + di[1]
                    + " " + t.action);
        }
        return out;
    }

    /**
     * 把带标签的规则行转成 /proc/umbral/um 要的裸格式。
     *   uid 10528 dev 108 ino 1052442 hide   →   10528 108 1052442 hide
     */
    public static String toBare(String labeled) {
        String[] f = labeled.trim().split("\\s+");
        if (f.length >= 6 && "uid".equals(f[0]) && "dev".equals(f[2])
                && "ino".equals(f[4])) {
            StringBuilder sb = new StringBuilder();
            sb.append(f[1]).append(' ').append(f[3]).append(' ').append(f[5]);
            if (f.length >= 7) {
                sb.append(' ').append(f[6]);
            }
            return sb.toString();
        }
        return labeled;
    }

    /** 对一个路径取 dev / ino；拿不到返回 null */
    private static long[] statDevIno(String path) {
        try {
            io.umbral.sk.Shell.R r = io.umbral.sk.Shell.plain(
                    "stat -c '%d %i' '" + path + "' 2>/dev/null");
            String s = r.out.trim();
            if (s.isEmpty()) {
                return null;
            }
            String[] f = s.split("\\s+");
            if (f.length < 2) {
                return null;
            }
            return new long[]{Long.parseLong(f[0]), Long.parseLong(f[1])};
        } catch (Throwable e) {
            return null;
        }
    }
}
