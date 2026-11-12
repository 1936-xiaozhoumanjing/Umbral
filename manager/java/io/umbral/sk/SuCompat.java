package io.umbral.sk;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;

/**
 * su 兼容层：把 su 壳脚本写到 /data/adb/umbral/su。
 *
 * ★ 为什么由 App 自己写（不靠内核）★
 *
 * 内核里 sk_create_su() 用的是「拿 pid1 的 cred → filp_open → kernel_write」，
 * 那条链任何一步失败都是静默的（实测：脚本根本不存在）。
 * 而 App 有影子权限，直接写 /data/adb 是通的（自检已证明能读写）。
 *
 * 所以改成 App 启动时自己写一份，写完 setExecutable(true)。
 * 文件属主是 App 自己，exec 权限足够。
 *
 * ★ 脚本内容对齐 KernelSU / Magisk 的 su 行为 ★
 *
 *   su -c "命令"   → 用 sh -c 跑
 *   su 命令 参数   → 直接 exec
 *   su             → 给一个交互 shell
 *
 * 第一件事是把自己登记成超级用户（写 /proc/umbral/grant），
 * 内核下一个系统调用就把它 commit_creds 成真 uid 0。
 */
public final class SuCompat {

    public static final String PATH = "/data/local/tmp/umbral/su";

    private static final String SCRIPT =
            "#!/system/bin/sh\n"
            + "# 影核 su 兼容层 —— 由 Umbral 管理器自动写入\n"
            + "PATH=/sbin:/system/sbin:/system/bin:/system/xbin:/data/adb/umbral\n"
            + "export PATH\n"
            + "\n"
            + "# ① 登记为超级用户：内核下一个 syscall 就会换成真 uid 0\n"
            + "printf '%s 1' \"$$\" | dd of=/proc/umbral/grant conv=notrunc 2>/dev/null\n"
            + "\n"
            + "# ② 校验：没变成 0 就退出（不假装成功）\n"
            + "if [ \"$(id -u)\" != \"0\" ]; then\n"
            + "  echo 'su: permission denied' >&2\n"
            + "  exit 1\n"
            + "fi\n"
            + "\n"
            + "# ③ 切 SELinux 域（uid 0 只解决 DAC，MAC 还看域）\n"
            + "for d in u:r:su:s0 u:r:magisk:s0 u:r:ksu:s0; do\n"
            + "  if echo \"$d\" > /proc/self/attr/current 2>/dev/null; then break; fi\n"
            + "done\n"
            + "\n"
            + "# ④ 三种调用形式\n"
            + "if [ \"$1\" = \"-c\" ]; then\n"
            + "  shift\n"
            + "  exec /system/bin/sh -c \"$*\"\n"
            + "fi\n"
            + "if [ $# -gt 0 ]; then\n"
            + "  exec \"$@\"\n"
            + "fi\n"
            + "exec /system/bin/sh\n";

    private SuCompat() {
    }

    /** 真二进制 su 的落地路径（和脚本同一个位置，内核重定向目标不变） */
    public static final String BIN_ASSET = "bin/su";

    /*
     * ★ aapt2 在 Windows 上会把 assets 的路径分隔符写成反斜杠 ★
     *
     * 实测 getAssets().list("") 返回 bin\su —— 条目名里是 "\" 不是 "/"，
     * 于是 open("bin/su") 直接 FileNotFoundException。
     * 两个都试一遍，谁存在用谁。
     */
    private static final String[] ASSET_CANDIDATES = {"bin/su", "bin\\su"};

    /** 找到真正能打开的 asset 流（顺序试两个候选名） */
    private static java.io.InputStream openAssetStream(Context ctx)
            throws java.io.IOException {
        for (String name : ASSET_CANDIDATES) {
            try {
                return ctx.getAssets().open(name);
            } catch (Throwable ignored) {
            }
        }
        throw new java.io.FileNotFoundException("bin/su（含反斜杠变体都试过了）");
    }

    /** 最近一次 ensure 失败的原因（自检会读它） */
    public static String lastError = "";
    /** 实际能看到的 assets 清单（排查「文件在 APK 里却 open 不到」用）*/
    public static String assetList = "";

    /**
     * 优先级：
     *   ① assets/bin/su（真正的 ELF 二进制，3.4MB 静态链接）
     *   ② 内置脚本（兜底，万一 assets 读不出来）
     *
     * 为什么要有二进制：KSU/Magisk 的 su 都是 ELF，
     * 脚本在 `su --version`、读文件头判断类型这类场景下行为不同。
     */
    public static boolean ensure(Context ctx) {
        /* ① 先试真二进制 */
        if (ctx != null) {
            try {
                File f = new File(PATH);
                /*
                 * 目录必须先建 —— /data/local/tmp/umbral 原来不存在，
                 * FileOutputStream 会直接 ENOENT 而不是自己建父目录。
                 */
                File dir = f.getParentFile();
                if (dir != null && !dir.exists()) {
                    //noinspection ResultOfMethodCallIgnored
                    dir.mkdirs();
                }
                java.io.InputStream in = openAssetStream(ctx);
                /*
                 * ★ 不能用 in.available() 判断长度 ★
                 * assets 流是压缩的，available() 返回的不是文件总长（实测返回 0），
                 * 于是「长度相同 → 跳过写入」，结果一直留着旧脚本。
                 * 改成：先完整读进内存，再按字节数比。
                 */
                java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
                byte[] tmpBuf = new byte[64 * 1024];
                int tn;
                while ((tn = in.read(tmpBuf)) > 0) {
                    bo.write(tmpBuf, 0, tn);
                }
                in.close();
                byte[] want = bo.toByteArray();
                /*
                 * ★ 不再按长度跳过 ★
                 * 之前「长度相同就不写」，结果有时留着旧的 shell 脚本，
                 * 表现是 su 报 "su: permission denied"（那是脚本里的文案）。
                 * 现在：磁盘上的文件前 4 字节不是 ELF 就一律重写。
                 */
                boolean isElf = false;
                if (f.exists() && f.length() >= 4) {
                    java.io.FileInputStream ck = null;
                    try {
                        ck = new java.io.FileInputStream(f);
                        byte[] h = new byte[4];
                        if (ck.read(h) == 4) {
                            isElf = (h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F');
                        }
                    } catch (Throwable ignored) {
                    } finally {
                        try { if (ck != null) ck.close(); } catch (Exception ignored) { }
                    }
                }
                long len = f.exists() ? f.length() : -1;
                if (!isElf || len != want.length) {
                    FileOutputStream fo = new FileOutputStream(f, false);
                    fo.write(want);
                    fo.flush();
                    fo.getFD().sync();
                    fo.close();
                    //noinspection ResultOfMethodCallIgnored
                    f.setExecutable(true, false);
                }
                if (f.exists() && f.canExecute()) {
                    return true;
                }
            } catch (Throwable t) {
                lastError = t.getClass().getSimpleName() + ": " + t.getMessage();
                /* 把 assets 根目录和 bin 目录的真实清单记下来 */
                try {
                    StringBuilder sb = new StringBuilder();
                    String[] top = ctx.getAssets().list("");
                    sb.append("root=[");
                    if (top != null) {
                        for (String x : top) {
                            sb.append(x).append(',');
                        }
                    }
                    sb.append("] bin=[");
                    try {
                        String[] b = ctx.getAssets().list("bin");
                        if (b != null) {
                            for (String x : b) {
                                sb.append(x).append(',');
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                    sb.append(']');
                    assetList = sb.toString();
                } catch (Throwable ignored) {
                }
            }
        }
        return writeScript();
    }

    /** 兜底：写脚本版 */
    private static boolean writeScript() {
        FileOutputStream fo = null;
        try {
            File f = new File(PATH);
            File dir = f.getParentFile();
            if (dir != null && !dir.exists()) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
            }
            byte[] want = SCRIPT.getBytes("UTF-8");

            /* 已经是想要的内容就只补权限 */
            if (f.exists() && f.length() == want.length) {
                if (!f.canExecute()) {
                    //noinspection ResultOfMethodCallIgnored
                    f.setExecutable(true, false);
                }
                return true;
            }

            fo = new FileOutputStream(f, false);
            fo.write(want);
            fo.flush();
            fo.getFD().sync();
            fo.close();
            fo = null;

            /*noinspection ResultOfMethodCallIgnored*/
            f.setExecutable(true, false);
            /*noinspection ResultOfMethodCallIgnored*/
            f.setReadable(true, false);

            return f.exists() && f.canExecute();
        } catch (Throwable t) {
            return false;
        } finally {
            try { if (fo != null) fo.close(); } catch (Exception ignored) { }
        }
    }

    public static boolean installed() {
        File f = new File(PATH);
        return f.exists() && f.canExecute();
    }

    /** 兼容命令（magisk / resetprop / ksud）的落地目录 */
    public static final String BIN_DIR = "/data/local/tmp/umbral/bin";

    private static final String[] SHIMS = {"magisk", "resetprop", "ksud", "umbrald"};

    /**
     * 把 magisk / resetprop / ksud 三个兼容壳写到磁盘上。
     *
     * 为什么需要：模块脚本（如 playintegrityfix 的 post-fs-data.sh）
     * 直接调 `magisk --path`、`resetprop -w`，缺了这两个命令脚本就报
     * "inaccessible or not found" 然后整段逻辑废掉。
     */
    public static int installShims(Context ctx) {
        int ok = 0;
        File dir = new File(BIN_DIR);
        if (!dir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
        }
        for (String name : SHIMS) {
            FileOutputStream fo = null;
            try {
                java.io.InputStream in = null;
                /*
                 * 实测 aapt2 把 assets 里的路径拍成 "bin\magisk" 这种形式
                 * （getAssets().list("") 直接返回带反斜杠的整串），
                 * 所以三个候选都要试。
                 */
                for (String cand : new String[]{"bin/" + name, "bin\\" + name, name}) {
                    try {
                        in = ctx.getAssets().open(cand);
                        break;
                    } catch (Throwable ignored) {
                    }
                }
                if (in == null) {
                    continue;
                }
                java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
                byte[] b = new byte[8192];
                int n;
                while ((n = in.read(b)) > 0) {
                    bo.write(b, 0, n);
                }
                in.close();
                File f = new File(dir, name);
                fo = new FileOutputStream(f, false);
                fo.write(bo.toByteArray());
                fo.flush();
                fo.getFD().sync();
                fo.close();
                fo = null;
                //noinspection ResultOfMethodCallIgnored
                f.setExecutable(true, false);
                //noinspection ResultOfMethodCallIgnored
                f.setReadable(true, false);
                ok++;
            } catch (Throwable ignored) {
            } finally {
                try { if (fo != null) fo.close(); } catch (Exception ignored) { }
            }
        }
        return ok;
    }
}
