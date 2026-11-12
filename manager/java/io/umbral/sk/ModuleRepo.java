package io.umbral.sk;

import io.umbral.R;

import android.content.Context;
import android.os.Build;

import java.io.IOException;
import java.io.InputStream;

/**
 * 内核模块库。
 *
 * 目录约定（打包在 APK 的 assets 里）：
 *
 *   assets/
 *     arm64-v8a/
 *       umbral_init                        ← 通用 init 包装器，任何 aarch64 设备都能用
 *       android15-6.6/umbral.ko            ← 标准 GKI（L1，覆盖该 KMI 下所有小版本）
 *       android15-6.6-8/umbral.ko          ← 特定 GKI 快照（L2，厂商定制内核用）
 *       android14-6.1/umbral.ko
 *       android13-5.15/umbral.ko
 *       android12-5.10/umbral.ko
 *
 * 查找顺序：精确（full）→ 通用（base）→ 没有则只注入 umbral_init。
 *
 * ⚠ 绝不注入不匹配的模块 —— 内核会报
 *   ".gnu.linkonce.this_module section size must match the kernel's built
 *    struct module size at run time"
 *   或者 CFI failure，然后 panic / 卡 logo。
 *
 * ⚠ 另一个坑：aapt2 在 Windows 上会把子目录分隔符打成 '\'。
 *   所以所有 assets 打开都必须走 {@link #openAsset}。
 */
public final class ModuleRepo {

    private ModuleRepo() {}

    /** 当前设备主 ABI，例如 "arm64-v8a" */
    public static String primaryAbi() {
        String[] abis = Build.SUPPORTED_ABIS;
        return (abis != null && abis.length > 0) ? abis[0] : "arm64-v8a";
    }

    /** assets 里 umbral_init 的路径 */
    public static String skInitPath() {
        return primaryAbi() + "/umbral_init";
    }

    /** 某个 KMI 对应的模块路径（正斜杠形式） */
    public static String modulePath(String kmi) {
        return primaryAbi() + "/" + kmi + "/umbral.ko";
    }

    /**
     * 打开一个 asset，自动兼容两种路径分隔符。
     * aapt2 在 Windows 上把子目录写成 '\'，Linux 上写成 '/'。
     */
    public static InputStream openAsset(Context ctx, String path) throws IOException {
        try {
            return ctx.getAssets().open(path);
        } catch (IOException first) {
            String alt = path.replace('/', '\\');
            if (alt.equals(path)) throw first;
            try {
                return ctx.getAssets().open(alt);
            } catch (IOException ignored) {
                throw first;
            }
        }
    }

    /** 读整个 asset 成字节数组 */
    public static byte[] readAsset(Context ctx, String path) {
        InputStream in = null;
        try {
            in = openAsset(ctx, path);
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        } catch (Throwable t) {
            return null;
        } finally {
            if (in != null) try { in.close(); } catch (Throwable ignored) {}
        }
    }

    /** 这个 KMI 的模块在不在，在就返回路径 */
    public static String findModule(Context ctx, String kmi) {
        if (kmi == null || kmi.isEmpty()) return null;
        String path = modulePath(kmi);
        InputStream in = null;
        try {
            in = openAsset(ctx, path);
            byte[] buf = new byte[4];
            int n = in.read(buf);
            if (n == 4 && (buf[0] & 0xFF) == 0x7F
                    && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') {
                return path;
            }
            return null;
        } catch (Throwable t) {
            return null;
        } finally {
            if (in != null) try { in.close(); } catch (Throwable ignored) {}
        }
    }

    /**
     * 一次性问清楚：本机 KMI、模块在哪、是通用还是定制版。
     */
    public static Support support(Context ctx) {
        Support s = new Support();
        KmiDetector.Info info = KmiDetector.detect();

        s.rawRelease = info.raw;
        s.baseKmi = info.base;
        s.fullKmi = info.full;
        s.abi = primaryAbi();

        // ① 先找精确匹配（厂商定制内核的 GKI 快照）
        if (info.hasMinor()) {
            String p = findModule(ctx, info.full);
            if (p != null) {
                s.modulePath = p;
                s.matchedKmi = info.full;
                s.supported = true;
                s.custom = true;      // 用的是针对该快照的专用模块
                return s;
            }
        }

        // ② 再找通用 KMI
        if (info.base != null) {
            String p = findModule(ctx, info.base);
            if (p != null) {
                s.modulePath = p;
                s.matchedKmi = info.base;
                s.supported = true;
                s.custom = false;
                return s;
            }
        }

        return s;   // 不支持
    }

    /** 支持情况快照 */
    public static final class Support {
        public String rawRelease;   // 完整内核串
        public String baseKmi;      // "android15-6.6"
        public String fullKmi;      // "android15-6.6-8"
        public String abi;          // "arm64-v8a"

        public String modulePath;   // 命中的 assets 路径，null = 没有
        public String matchedKmi;   // 实际用的是哪个目录
        public boolean supported;   // 能不能上完整 root 能力
        public boolean custom;      // true = 用的是针对具体快照的专用模块

        /** 给界面看的一句话（需要 Context 取本地化文案） */
        public String describe(android.content.Context c) {
            if (baseKmi == null) {
                return c.getString(R.string.kmi_unknown);
            }
            if (!supported) {
                return c.getString(R.string.kmi_unsupported, c.getString(R.string.display_name));
            }
            if (custom) {
                return c.getString(R.string.kmi_supported_custom, matchedKmi);
            }
            return c.getString(R.string.kmi_supported, matchedKmi);
        }

        /** 给界面看的详细说明（支持时可能为空） */
        public String detail(android.content.Context c) {
            if (baseKmi == null) {
                return c.getString(R.string.kmi_no_info);
            }
            if (supported) return null;
            return "模块库里没有 " + baseKmi
                    + (fullKmi != null && !fullKmi.equals(baseKmi) ? " / " + fullKmi : "")
                    + " 的模块（" + abi + "）。\n"
                    + "我们的官方源暂时不支持您的内核版本进行 root。";
        }
    }
}
