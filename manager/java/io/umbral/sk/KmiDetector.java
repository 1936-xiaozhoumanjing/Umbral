package io.umbral.sk;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 检测设备的 KMI（Kernel Module Interface）。
 *
 * ── 为什么要分「基础 KMI」和「完整 KMI」──
 *
 * 内核版本串长这样：
 *
 *   6.6.30-android15-8-g54dcbfbef792-ab12368803-4k
 *   │││││ │        │ │
 *   │││││ │        │ └─ vendor build 标记（红魔的）
 *   │││││ │        └─── KMI 次版本号 "8"
 *   │││││ └──────────── Android 版本 "android15"
 *   │└┴┴─────────────── 内核版本 "6.6.30"
 *
 *   baseKmi = android15-6.6       ← GKI 承诺的锁定粒度，一个模块覆盖全部小版本
 *   fullKmi = android15-6.6-8     ← 厂商基于哪个 GKI 快照定制，L2 级别用
 *
 * ── 查找策略 ──
 *
 *   ① 先找 fullKmi（精确匹配厂商定制内核）
 *   ② 再找 baseKmi（标准 GKI，覆盖该 KMI 下所有小版本）
 *   ③ 都没有 → 不支持，只注入 init 包装器
 *
 * 这样「一个 KMI 一次编译」的承诺成立，同时给厂商定制留了后门。
 */
public final class KmiDetector {

    /**
     * 匹配形如 6.6.30-android15-8 或 6.6.30-android15
     *
     * group(1) = 6      （内核主版本）
     * group(2) = 6      （内核次版本）
     * group(3) = 15     （Android 版本）
     * group(4) = 8      （KMI 次版本，可能为 null）
     */
    private static final Pattern RE = Pattern.compile(
            "(\\d+)\\.(\\d+)\\S*?-android(\\d+)(?:-(\\d+))?");

    /** 宽松兜底：至少能拿到 androidNN + N.N */
    private static final Pattern RE_LOOSE = Pattern.compile(
            "(\\d+\\.\\d+)(?:\\S+)?(android\\d+)");

    private KmiDetector() {}

    /** 解析结果 */
    public static final class Info {
        /** 基础 KMI，如 "android15-6.6"；解析失败为 null */
        public String base;
        /** 完整 KMI，如 "android15-6.6-8"；没有次版本号时等于 base */
        public String full;
        /** 原始内核版本串 */
        public String raw;

        public boolean ok() { return base != null; }

        /** 有没有区分出次版本号 */
        public boolean hasMinor() {
            return full != null && base != null && !full.equals(base);
        }
    }

    /**
     * 从一段内核版本串里解析。
     */
    public static Info parse(String version) {
        Info info = new Info();
        info.raw = version;
        if (version == null || version.isEmpty()) return info;

        Matcher m = RE.matcher(version);
        if (m.find()) {
            String kern = m.group(1) + "." + m.group(2);      // "6.6"
            String andr = "android" + m.group(3);             // "android15"
            String minor = m.group(4);                        // "8" 或 null
            info.base = andr + "-" + kern;
            info.full = (minor != null) ? info.base + "-" + minor : info.base;
            return info;
        }

        // 兜底
        Matcher m2 = RE_LOOSE.matcher(version);
        if (m2.find()) {
            info.base = m2.group(2) + "-" + m2.group(1);
            info.full = info.base;
        }
        return info;
    }

    /** 检测本机 KMI。 */
    public static Info detect() {
        // ① os.version 就是 uts.release，不需要任何权限
        Info i = parse(System.getProperty("os.version"));
        if (i.ok()) return i;

        // ② /proc/version 里的 "Linux version ..."
        i = parse(readFirstLine("/proc/version"));
        if (i.ok()) return i;

        return new Info();
    }

    /** 本机完整内核版本串（给界面显示） */
    public static String kernelRelease() {
        String v = System.getProperty("os.version");
        if (v != null && !v.isEmpty()) return v;
        String line = readFirstLine("/proc/version");
        if (line != null) {
            int i = line.indexOf("version ");
            if (i >= 0) {
                String rest = line.substring(i + 8).trim();
                int sp = rest.indexOf(' ');
                return sp > 0 ? rest.substring(0, sp) : rest;
            }
        }
        return null;
    }

    private static String readFirstLine(String path) {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(path));
            return r.readLine();
        } catch (Throwable t) {
            return null;
        } finally {
            if (r != null) try { r.close(); } catch (Throwable ignored) {}
        }
    }
}
