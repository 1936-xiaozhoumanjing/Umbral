package io.umbral.sk;

import io.umbral.R;

import android.os.Build;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;

/**
 * 影核 内核侧桥接层。
 *
 * 定位：管理器（PDP）与内核模块（PEP）之间唯一的通信面。
 * 内核模块尚未就位时，所有查询都应优雅降级，界面显示"未连接"。
 *
 * 约定的内核接口（待内核模块实现）：
 *   /proc/umbral/version     → 模块版本字符串
 *   /proc/umbral/mode        → 工作模式：lkm | builtin | kernel
 *   /proc/umbral/status      → 0=正常
 */
public final class SkBridge {

    public static final String MANAGER_VERSION = "0.90";

    public static final int MODE_NONE    = 0;
    public static final int MODE_LKA     = 1;
    public static final int MODE_BUILTIN = 2;
    public static final int MODE_KERNEL  = 3;

    private static Boolean sConnected;
    private static String sVersion;
    private static int sMode = -1;

    private SkBridge() {
    }

    /** 内核版本串，直接来自系统属性 */
    public static String kernelVersion() {
        String v = System.getProperty("os.version", "");
        return v.isEmpty() ? "unknown" : v;
    }

    public static int sdkInt() {
        return Build.VERSION.SDK_INT;
    }

    public static String androidVersion() {
        return Build.VERSION.RELEASE;
    }

    public static String deviceModel() {
        return Build.MODEL == null ? "unknown" : Build.MODEL;
    }

    /** 主 ABI，例如 arm64-v8a */
    public static String arch() {
        String[] abis = Build.SUPPORTED_ABIS;
        if (abis == null || abis.length == 0) {
            return "unknown";
        }
        return abis[0];
    }

    /** SELinux 模式：Enforcing / Permissive */
    public static String selinuxMode() {
        // 1) 直接读 selinuxfs（普通 App 多数会被 SELinux 拒绝）
        String v = readFile("/sys/fs/selinux/enforce");
        if (v != null) {
            return "1".equals(v.trim()) ? "Enforcing" : "Permissive";
        }
        // 2) 退一步执行 getenforce
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"getenforce"});
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String line = r.readLine();
            r.close();
            if (line != null && !line.trim().isEmpty()) {
                return line.trim();
            }
        } catch (Exception ignored) {
        }
        // 3) Android 强制要求 SELinux，读不到即按默认值给出
        return "Enforcing";
    }

    /** 内核模块是否在线 */
    public static boolean isConnected() {
        if (sConnected == null) {
            sConnected = probe();
        }
        return sConnected;
    }

    public static void invalidate() {
        sConnected = null;
        sVersion = null;
        sMode = -1;
    }

    private static boolean probe() {
        /*
         * 直接读 /proc/umbral/version —— 被自己模块授权后根本不需要 su。
         * 这里绝不能先走 su 探测：那会进 KSU 内核状态机，而我们的钩子
         * 把这个进程的 SELinux 检查全放行了，状态不一致会 panic。
         */
        String direct = ModuleControl.readDirect("/proc/umbral/version");
        if (direct != null && !direct.trim().isEmpty()) {
            sConnected = Boolean.TRUE;
            sVersion = direct.trim();
            sMode = ModuleControl.MODE_NONE;
            return true;
        }
        /* 没有直接通路才退到 su（模块没加载 / 没被授权的情况） */
        String v = suRead("/proc/umbral/version");
        if (v != null && !v.trim().isEmpty()) {
            sConnected = Boolean.TRUE;
            sVersion = v.trim();
            sMode = ModuleControl.MODE_NONE;
            return true;
        }
        sConnected = Boolean.FALSE;
        sVersion = null;
        sMode = ModuleControl.MODE_NONE;
        return false;
    }

    public static String version() {
        if (sVersion != null) {
            return sVersion;
        }
        String v = readFile("/proc/umbral/version");
        sVersion = (v == null || v.trim().isEmpty()) ? "-" : v.trim();
        return sVersion;
    }

    public static int mode() {
        if (sMode >= 0) {
            return sMode;
        }
        String m = readFile("/proc/umbral/mode");
        if (m == null) {
            sMode = isConnected() ? MODE_LKA : MODE_NONE;
        } else {
            m = m.trim().toLowerCase();
            if (m.contains("builtin")) {
                sMode = MODE_BUILTIN;
            } else if (m.contains("kernel")) {
                sMode = MODE_KERNEL;
            } else {
                sMode = MODE_LKA;
            }
        }
        return sMode;
    }

    public static String modeLabel(android.content.Context c) {
        switch (mode()) {
            case MODE_LKA:
                return "LKA";
            case MODE_BUILTIN:
                return c.getString(R.string.mode_builtin);
            case MODE_KERNEL:
                return c.getString(R.string.mode_kernel);
            default:
                return c.getString(R.string.not_connected);
        }
    }

    /**
     * 影子权限实际用的 hook 后端。
     *
     * 内核模块启动时按优先级探测，可能是：
     *   kretprobe:invoke_syscall          后端 A（ARM64 主力）
     *   kprobe:__traceiter_sys_enter      后端 B
     *   kprobe:syscall-entry              后端 C（汇编入口兜底）
     *
     * 不同设备内核支持的能力不一样，所以这里必须由内核告诉我们实际用了哪条。
     */
    public static String backend() {
        String b = readFile("/proc/umbral/backend");
        if (b == null || b.trim().isEmpty()) return "-";
        return b.trim();
    }

    /** 后端是否处于「全 syscall 提权」的降级模式（后端 C） */
    public static boolean backendIsDegraded() {
        String b = backend();
        return b.startsWith("kprobe:syscall-entry");
    }

    /**
     * 影子权限运行统计。
     *
     * @return { seen, elevated, reverted }
     *   seen     经过 hook 的 syscall 数
     *   elevated 实际提权次数
     *   reverted 还原次数
     *   elevated 与 reverted 应该相等 —— 不相等说明有 cred 计数异常
     */
    public static long[] stats() {
        long[] out = new long[3];
        String s = readFile("/proc/umbral/stats");
        if (s == null) return out;
        for (String line : s.split("\n")) {
            String[] p = line.trim().split("\\s+");
            if (p.length < 2) continue;
            try {
                long v = Long.parseLong(p[1]);
                if ("seen".equals(p[0]))          out[0] = v;
                else if ("elevated".equals(p[0])) out[1] = v;
                else if ("reverted".equals(p[0])) out[2] = v;
            } catch (NumberFormatException ignored) { }
        }
        return out;
    }

    /** elevated 和 reverted 对不上 → cred 计数异常，要报警 */
    public static boolean credLeaked() {
        long[] st = stats();
        return st[1] != st[2];
    }

    /**
     * 通过 su 读一个文件。
     *
     * 为什么需要：/proc/umbral 下的文件标签是 `u:object_r:proc:s0`，
     * 而管理器跑在 `u:r:untrusted_app` 域，直接 read 会被 SELinux 拒绝
     * （avc: denied { read } ... tclass=file）。
     *
     * 所以这里走 su。注意 su 读 /proc/umbral/token 时，得到的是 **su 目标 uid**
     * 对应的 token，不是管理器的 —— 需要特定 uid 的 token 用 readAsUid()。
     */
    public static String suRead(String path) {
        /*
         * 先直接读。被我们自己的模块授权之后，caps 满 + SELinux 放行，
         * 读 /proc/umbral/* 根本不需要 su。
         *
         * ★ 这一步是崩溃修复 ★
         *   一旦启动 su，就会进 KSU 的内核状态机；而我们把这个进程的
         *   SELinux 检查全部放行了，KSU 那套允许列表逻辑会看到不该出现的
         *   序列 —— 实测会让设备 panic。所以有直接通路就绝不碰 su。
         */
        String direct = ModuleControl.readDirect(path);
        if (direct != null) {
            return direct;
        }
        return exec(new String[]{"su", "-c", "cat " + path});
    }

    /**
     * 以指定 uid 身份读文件。
     *
     * /proc/umbral/token 的内容是按 current_uid() 派生的，所以想拿某个 uid 的
     * token，必须真的以那个 uid 去读：su &lt;uid&gt; -c "cat /proc/umbral/token"。
     * 用 root 读只能拿到 root 自己的 token。
     */
    public static String readAsUid(int uid, String path) {
        return exec(new String[]{"su", String.valueOf(uid), "-c", "cat " + path});
    }

    /** 执行命令并把 stdout 作为字符串返回；非 0 退出或空白都返回 null */
    private static String exec(String[] cmd) {
        Process p = null;
        BufferedReader r = null;
        try {
            p = Runtime.getRuntime().exec(cmd);
            r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            int rc = p.waitFor();
            if (rc != 0) {
                return null;
            }
            String out = sb.toString();
            return out.isEmpty() ? null : out;
        } catch (Exception e) {
            return null;
        } finally {
            if (r != null) {
                try { r.close(); } catch (Exception ignored) { }
            }
            if (p != null) {
                p.destroy();
            }
        }
    }

    /**
     * 本进程自己的影子权限 token（64 个 hex 字符）。
     *
     * 拿到之后需要把它写进本进程地址空间 0x1000000000 处的 32 字节，
     * 内核才会在敏感 syscall 上给本进程提权。
     *
     * ⚠ 写那块内存需要 mmap(MAP_FIXED)，纯 Java 做不到 —— 需要 JNI。
     *   这一版先把「取 token」跑通，注入留给 native 层。
     */
    public static String selfToken() {
        return readAsUid(android.os.Process.myUid(), "/proc/umbral/token");
    }

    /** 指定 uid 的 token。用于管理器给别的 App 授权。 */
    public static String tokenForUid(int uid) {
        return readAsUid(uid, "/proc/umbral/token");
    }

    /** /proc/umbral/stats 的原始文本（六项计数 + backend） */
    public static String statsRaw() {
        return readFile("/proc/umbral/stats");
    }

    /** /proc/umbral/selftest 的原始文本（结构偏移、hook 位图、cred 指针） */
    public static String selftestRaw() {
        return readFile("/proc/umbral/selftest");
    }

    /**
     * 从 /proc/umbral/stats 里取单个计数器。
     *
     * stats 的格式是每行「名字  数值」，例如：
     *     seen        497243
     *     elevated    5
     * 取不到就返回 -1，调用方据此区分「没有这个值」和「真的是 0」。
     */
    public static long stat(String key) {
        String s = statsRaw();
        if (s == null) {
            return -1;
        }
        for (String line : s.split("\n")) {
            String[] p = line.trim().split("\\s+");
            if (p.length >= 2 && key.equals(p[0])) {
                try {
                    return Long.parseLong(p[1]);
                } catch (NumberFormatException ignored) {
                    return -1;
                }
            }
        }
        return -1;
    }

    /**
     * 从 selftest 里取某个字段（整数形式）。
     *
     * selftest 的格式是「名字  值」，名字右对齐有多个空格，
     * 所以按空白切分后取最后一段。
     */
    public static String selftestField(String key) {
        String s = selftestRaw();
        if (s == null) {
            return null;
        }
        for (String line : s.split("\n")) {
            String t = line.trim();
            int i = t.indexOf(' ');
            if (i <= 0) {
                i = t.indexOf('\t');
            }
            if (i <= 0) {
                continue;
            }
            if (t.substring(0, i).equals(key)) {
                return t.substring(i).trim();
            }
        }
        return null;
    }

    private static String readFile(String path) {
        File f = new File(path);
        /*
         * 注意：不能在这里「exists() 为 false 就直接 return null」。
         * SELinux 拦 untrusted_app 读 /proc/umbral 时，连 stat 都可能失败，
         * exists() 会返回 false —— 那就把 su 退路也一起跳过了，
         * 表现为模块明明加载了、界面却始终「未连接」。
         */
        if (f.exists()) {
            BufferedReader r = null;
            try {
                r = new BufferedReader(new FileReader(f));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                return sb.toString();
            } catch (Exception ignored) {
                /* 直读被 SELinux 拦，落到下面的 su 退路 */
            } finally {
                if (r != null) {
                    try { r.close(); } catch (Exception ignored) { }
                }
            }
        }
        return suRead(path);
    }
}
