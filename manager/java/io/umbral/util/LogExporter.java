package io.umbral.util;

import android.content.Context;
import android.content.Intent;
import android.os.Build;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 日志导出 —— 一次性把所有可诊断信息收集成一份中文报告。
 *
 * ══════════════════════════════════════════════════════
 *  为什么要有这个
 * ══════════════════════════════════════════════════════
 *
 *  出问题时最需要的是「现场」。但内核模块崩了 pstore 常常是空的，
 *  设备没 root 时连 dmesg 都读不了 —— 等于什么都看不到。
 *
 *  所以这个导出必须做到：
 *    ① 不依赖 root（读不到的东西如实写「读不到，原因：xxx」）
 *    ② 全部中文（内核路径、英文状态词都翻译过来）
 *    ③ 一份文件包含所有功能的状态，不用来回问
 */
public final class LogExporter {

    private LogExporter() {
    }

    /** 导出结果：既有文件，也有可用于分享的 content:// URI */
    public static final class Out {
        public File file;
        public android.net.Uri uri;      /* 用于分享，系统下载目录的 URI */
        public String displayPath;       /* 给用户看的路径 */

        public boolean ok() {
            return file != null && file.exists();
        }
    }

    /**
     * 收集并写出一份报告。
     *
     * 优先写进系统「下载」目录（MediaStore.Downloads）——
     * 这样分享时可以直接用它的 content:// URI，不需要 FileProvider，
     * 用户也能在文件管理器里直接找到。
     */
    public static Out export(Context ctx) {
        Out r = new Out();
        String text = build(ctx);

        String ts = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.CHINA).format(new Date());
        String name = "影核日志_" + ts + ".txt";

        /* ① 系统下载目录（Android 10+） */
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                android.content.ContentValues cv = new android.content.ContentValues();
                cv.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, name);
                cv.put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "text/plain");
                cv.put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH,
                        android.os.Environment.DIRECTORY_DOWNLOADS);

                android.net.Uri uri = ctx.getContentResolver().insert(
                        android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                if (uri != null) {
                    java.io.OutputStream os = ctx.getContentResolver().openOutputStream(uri);
                    if (os != null) {
                        os.write(text.getBytes("UTF-8"));
                        os.flush();
                        os.close();
                        r.uri = uri;
                        r.displayPath = "内部存储/Download/" + name;
                        r.file = new File(ctx.getExternalFilesDir(null), name);
                        try {
                            java.io.FileOutputStream fo = new java.io.FileOutputStream(r.file);
                            fo.write(text.getBytes("UTF-8"));
                            fo.close();
                        } catch (Exception ignored) {
                        }
                        return r;
                    }
                }
            } catch (Throwable ignored) {
            }
        }

        /* ② 退路：App 私有外部目录 */
        File dir = ctx.getExternalFilesDir(null);
        if (dir == null) {
            dir = ctx.getFilesDir();
        }
        File out = new File(dir, name);
        FileOutputStream fo = null;
        try {
            fo = new FileOutputStream(out);
            fo.write(text.getBytes("UTF-8"));
            fo.flush();
            r.file = out;
            r.displayPath = out.getAbsolutePath();
            return r;
        } catch (Exception e) {
            return r;
        } finally {
            close(fo);
        }
    }

    /** 收集报告正文 */
    private static String build(Context ctx) {
        StringBuilder b = new StringBuilder(64 * 1024);

        head(b);
        device(b, ctx);
        moduleState(b, ctx);
        grantTable(b);
        umRules(b);
        umStatRules(b);
        statRules(b);
        moduleFiles(b);
        traceLog(b, ctx);
        appLog(b, ctx);

        b.append("\n");
        b.append("════════════════ 报告结束 ════════════════\n");
        return b.toString();
    }

    /** 以**文件**形式分享报告 */
    public static void share(Context ctx, Out r) {
        if (r == null || r.uri == null) {
            /* 没有 content URI 时至少把路径告诉用户 */
            if (r != null && r.file != null) {
                try {
                    Intent i = new Intent(Intent.ACTION_SEND);
                    i.setType("text/plain");
                    i.putExtra(Intent.EXTRA_TEXT, "日志已保存到：" + r.file.getAbsolutePath());
                    ctx.startActivity(Intent.createChooser(i, "分享日志路径"));
                } catch (Throwable ignored) {
                }
            }
            return;
        }
        try {
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setType("text/plain");
            i.putExtra(Intent.EXTRA_STREAM, r.uri);
            i.putExtra(Intent.EXTRA_SUBJECT, "影核诊断报告");
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            ctx.startActivity(Intent.createChooser(i, "分享日志文件"));
        } catch (Throwable ignored) {
        }
    }

    // ══════════════════ 各段 ══════════════════

    private static void head(StringBuilder b) {
        b.append("════════════════ 影核诊断报告 ════════════════\n");
        b.append("生成时间：")
                .append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.CHINA).format(new Date()))
                .append('\n');
        b.append("说明：下面每一项都是实测读取的结果。读不到的会写明原因，不会留空。\n");
    }

    private static void device(StringBuilder b, Context ctx) {
        b.append("\n──── 一、设备与管理器 ────\n");
        b.append("管理器版本：").append(io.umbral.sk.SkBridge.MANAGER_VERSION).append('\n');
        b.append("设备型号：").append(nullSafe(io.umbral.sk.SkBridge.deviceModel())).append('\n');
        b.append("Android 版本：").append(nullSafe(io.umbral.sk.SkBridge.androidVersion()))
                .append("（SDK ").append(io.umbral.sk.SkBridge.sdkInt()).append("）\n");
        b.append("架构：").append(nullSafe(io.umbral.sk.SkBridge.arch())).append('\n');
        b.append("内核版本：").append(safe(new java.util.concurrent.Callable<String>() {
            public String call() { return io.umbral.sk.SkBridge.kernelVersion(); }
        })).append('\n');
        b.append("SELinux：").append(nullSafe(io.umbral.sk.SkBridge.selinuxMode())).append('\n');
        b.append("管理器 uid：").append(android.os.Process.myUid()).append('\n');
        b.append("包名：").append(ctx.getPackageName()).append('\n');
        b.append("厂商：").append(nullSafe(Build.MANUFACTURER)).append('\n');
        b.append("构建指纹：").append(nullSafe(Build.FINGERPRINT)).append('\n');
    }

    private static void moduleState(StringBuilder b, Context ctx) {
        b.append("\n──── 二、内核模块状态 ────\n");
        boolean loaded = io.umbral.sk.ModuleControl.isLoaded();
        boolean nodeExists = new File("/proc/umbral").exists();
        /* 权限自检：影子权限不留痕迹，只能靠"实际做一次"来判断 */
        {
            io.umbral.sk.Privilege pv = io.umbral.sk.Privilege.detect(ctx);

            b.append("权限自查：").append(pv.label()).append('\n');
            b.append("  说明：").append(pv.reason).append('\n');
            b.append("  geteuid==0：").append(pv.euidZero ? "是" : "否").append('\n');
            b.append("  能读 /proc/umbral/version：").append(pv.canReadProc ? "是" : "否").append('\n');
            b.append("  能列 /data/adb/modules：").append(pv.canReadAdb ? "是" : "否").append('\n');
        }
        b.append("模块加载情况：")
                .append(loaded ? "已加载且可读（正常）"
                        : (nodeExists ? "已加载，但读不到（未授权给本管理器）"
                                      : "未加载（/proc/umbral 不存在）"))
                .append('\n');
        if (!loaded && nodeExists) {
            b.append("说明：内核模块确实在运行，但管理器这个 uid 没有被授予权限。\n")
             .append("      需要模块启动时自动授权管理器（v0.43 之后支持），\n")
             .append("      或者用真 root 执行：echo \"uid:管理器uid 1\" > /proc/umbral/grant\n");
        }
        b.append("模块模式：").append(nullSafe(io.umbral.sk.SkBridge.modeLabel(ctx))).append('\n');

        b.append("\n[内核版本节点 /proc/umbral/version]\n");
        dump(b, "/proc/umbral/version");

        b.append("\n[整体状态 /proc/umbral/status]\n");
        dump(b, "/proc/umbral/status");

        b.append("\n[后端 /proc/umbral/backend]\n");
        dump(b, "/proc/umbral/backend");

        b.append("\n[计数统计 /proc/umbral/stats]\n");
        dump(b, "/proc/umbral/stats");

        b.append("\n[自检 /proc/umbral/selftest]\n");
        dump(b, "/proc/umbral/selftest");

        b.append("\n[BTF 自适应 /proc/umbral/btf]\n");
        dump(b, "/proc/umbral/btf");

        b.append("\n[运行模式 /proc/umbral/mode]\n");
        dump(b, "/proc/umbral/mode");
    }

    private static void grantTable(StringBuilder b) {
        b.append("\n──── 三、授权表 ────\n");
        b.append("（uid 授权：影子 / 超级用户；pid 授权：按进程）\n");
        dump(b, "/proc/umbral/grants");
    }

    private static void umRules(StringBuilder b) {
        b.append("\n──── 四、UM 规则（内核判定点一：文件可见性）────\n");
        b.append("说明：hide=当作不存在  deny=拒绝访问  eperm=不允许  ok=强制放行\n");
        dump(b, "/proc/umbral/um");
    }

    private static void umStatRules(StringBuilder b) {
        b.append("\n──── 五、UM 属性伪造（内核判定点二：stat 结果）────\n");
        b.append("说明：对指定 uid 报告假的大小/权限，其他人看到真实值。\n");
        dump(b, "/proc/umbral/umstat");

        b.append("\n[属性伪造调试探针 /proc/umbral/umdbg]\n");
        dump(b, "/proc/umbral/umdbg");
    }

    private static void statRules(StringBuilder b) {
        b.append("\n──── 六、隐藏清洗 ────\n");
        String lsmod = sh("lsmod 2>/dev/null | grep -c sk_root");
        b.append("lsmod 里出现次数：").append(trimOr(lsmod, "读不到")).append('\n');
        String procmod = sh("grep -c '^sk_root' /proc/modules 2>/dev/null");
        b.append("/proc/modules 里出现次数：").append(trimOr(procmod, "读不到")).append('\n');
        String sysmod = sh("ls -d /sys/module/sk_root 2>/dev/null");
        b.append("sysfs 目录：").append(trimOr(sysmod, "不存在（已清洗）")).append('\n');
        b.append("说明：次数为 0 表示已隐藏干净。\n");
    }

    private static void moduleFiles(StringBuilder b) {
        b.append("\n──── 七、模块与 UM 文件 ────\n");
        b.append("[模块本体]\n");
        b.append(trimOr(sh("ls -l /data/adb/umbral/ 2>&1"), "读不到（可能需要 root）")).append('\n');

        b.append("\n[UM 规则目录]\n");
        b.append(trimOr(sh("ls -l /data/adb/umbral/um/ 2>&1"), "读不到")).append('\n');

        b.append("\n[开机加载文件]\n");
        b.append(trimOr(sh("ls -l /data/adb/umbral/um/boot.umbc 2>&1"), "没有该文件")).append('\n');

        b.append("\n[manager.uid]\n");
        b.append(trimOr(sh("cat /data/adb/umbral/manager.uid 2>&1"), "没有该文件")).append('\n');

        b.append("\n[ZIP 模块目录]\n");
        b.append(trimOr(sh("ls /data/adb/modules/ 2>&1"), "读不到")).append('\n');
    }

    private static void traceLog(StringBuilder b, Context ctx) {
        b.append("\n──── 八、启动追踪（App 自己记的）────\n");
        File f = new File(ctx.getFilesDir(), "trace.log");
        if (!f.exists()) {
            b.append("没有追踪文件（说明启动过程没有记录，通常是正常启动）。\n");
            return;
        }
        BufferedReader r = null;
        try {
            r = new BufferedReader(new InputStreamReader(
                    new java.io.FileInputStream(f), "UTF-8"));
            String line;
            int n = 0;
            while ((line = r.readLine()) != null && n < 400) {
                b.append(line).append('\n');
                n++;
            }
            if (n >= 400) {
                b.append("……（超过 400 行，已截断）\n");
            }
        } catch (Exception e) {
            b.append("读追踪文件失败：").append(chineseError(e)).append('\n');
        } finally {
            close(r);
        }
    }

    private static void appLog(StringBuilder b, Context ctx) {
        b.append("\n──── 九、系统日志（与影核相关）────\n");
        b.append("说明：Android 15 上普通应用读不到 logcat/dmesg，读不到是正常的。\n");

        String lc = sh("logcat -d -t 400 2>&1 | grep -i umbral");
        if (lc.trim().isEmpty()) {
            b.append("logcat：没有相关内容（或没有权限读取）\n");
        } else {
            b.append("logcat：\n").append(lc).append('\n');
        }

        String dm = sh("dmesg 2>&1 | grep -i umbral | tail -60");
        if (dm.contains("Permission denied") || dm.contains("not permitted")) {
            b.append("dmesg：没有权限读取（这是正常的，需要真 root）\n");
        } else if (dm.trim().isEmpty()) {
            b.append("dmesg：没有相关内容\n");
        } else {
            b.append("dmesg：\n").append(dm).append('\n');
        }

        String dr = sh("ls -t /data/system/dropbox/ 2>&1 | head -5");
        b.append("\n最近的崩溃记录（dropbox）：\n")
                .append(trimOr(dr, "读不到（需要 root）")).append('\n');
    }

    // ══════════════════ 工具 ══════════════════

    private static void dump(StringBuilder b, String path) {
        File f = new File(path);
        if (!f.exists()) {
            b.append("  （不存在：模块未加载）\n");
            return;
        }
        BufferedReader r = null;
        try {
            r = new BufferedReader(new InputStreamReader(
                    new java.io.FileInputStream(f), "UTF-8"));
            String line;
            int n = 0;
            while ((line = r.readLine()) != null && n < 200) {
                b.append("  ").append(line).append('\n');
                n++;
            }
            if (n == 0) {
                b.append("  （空）\n");
            }
        } catch (Exception e) {
            b.append("  读不到：").append(chineseError(e)).append('\n');
        } finally {
            close(r);
        }
    }

    /** 把英文异常翻译成中文说明 */
    private static String chineseError(Exception e) {
        String m = String.valueOf(e.getMessage());
        if (m.contains("EACCES") || m.contains("Permission denied")) {
            return "权限不足（SELinux 或文件权限拦截，需要模块已授权）";
        }
        if (m.contains("ENOENT") || m.contains("No such file")) {
            return "文件不存在";
        }
        return "读取失败（" + e.getClass().getSimpleName() + "）";
    }

    private static String sh(String cmd) {
        Process p = null;
        try {
            p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            InputStream in = p.getInputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                bo.write(buf, 0, n);
            }
            InputStream es = p.getErrorStream();
            while ((n = es.read(buf)) > 0) {
                bo.write(buf, 0, n);
            }
            p.waitFor();
            return bo.toString("UTF-8");
        } catch (Exception e) {
            return "";
        } finally {
            if (p != null) {
                p.destroy();
            }
        }
    }

    /** 包一层异常保护，任何一项失败都不让整份报告崩掉 */
    private static String safe(java.util.concurrent.Callable<String> c) {
        try {
            return nullSafe(c.call());
        } catch (Throwable t) {
            return "读取失败";
        }
    }

    private static String nullSafe(String s) {
        return (s == null || s.isEmpty()) ? "未知" : s;
    }

    private static String trimOr(String s, String def) {
        if (s == null) {
            return def;
        }
        String t = s.trim();
        return t.isEmpty() ? def : t;
    }

    private static void close(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignored) {
            }
        }
    }
}
