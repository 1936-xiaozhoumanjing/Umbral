package io.umbral.launcher;

import android.content.Context;
import android.net.Uri;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * 启动器的文件仓库与执行器。
 *
 * 为什么要把选中的文件复制进应用私有目录：
 *
 *   ① Scoped Storage 下，文件选择器给的 Uri 只是一次性授权，
 *      进程重启后可能失效，不能长期持有
 *   ② /storage/emulated 通常挂载为 noexec，直接在那上面跑会 EACCES
 *   ③ 私有目录路径稳定，便于 chmod 和后续重跑
 *
 * 执行方式按扩展名分流：
 *   .sh        → /system/bin/sh <file>
 *   其它可执行 → 直接 exec
 *   .ko        → 目前只做提示（加载模块需要 root，见 ready() 说明）
 */
public final class LauncherStore {

    private static final String DIR = "launcher";

    private LauncherStore() {
    }

    /** 私有目录：filesDir/launcher/ */
    public static File dir(Context ctx) {
        File d = new File(ctx.getFilesDir(), DIR);
        if (!d.exists() && !d.mkdirs()) {
            // 建不出来就让后续操作自然失败，调用方看返回值
            return d;
        }
        return d;
    }

    /**
     * 列出已添加的脚本（按修改时间倒序）。
     *
     * 只列**文件**，不列子目录 —— 这是执行器，不是文件管理器。
     * 隐藏文件也不列，避免把 .guard_* 之类的临时文件暴露出来。
     */
    public static List<File> list(Context ctx) {
        File[] fs = dir(ctx).listFiles();
        List<File> out = new ArrayList<File>();
        if (fs != null) {
            for (File f : fs) {
                if (f.isFile() && !f.getName().startsWith(".")) {
                    out.add(f);
                }
            }
            java.util.Collections.sort(out, new Comparator<File>() {
                @Override
                public int compare(File a, File b) {
                    return Long.compare(b.lastModified(), a.lastModified());
                }
            });
        }
        return out;
    }

    /**
     * 把外部 Uri 指向的文件复制进私有目录。
     *
     * @return 复制后的文件，失败返回 null
     */
    public static File importUri(Context ctx, Uri uri, String displayName) {
        String name = sanitize(displayName);
        if (name == null || name.isEmpty()) {
            name = "script_" + System.currentTimeMillis() + ".sh";
        }

        File dst = new File(dir(ctx), name);
        // 重名时加序号，不覆盖已有文件
        int n = 1;
        while (dst.exists()) {
            dst = new File(dir(ctx), withSuffix(name, "_" + n));
            n++;
        }

        InputStream in = null;
        OutputStream out = null;
        try {
            in = ctx.getContentResolver().openInputStream(uri);
            if (in == null) {
                return null;
            }
            out = new FileOutputStream(dst);
            byte[] buf = new byte[64 * 1024];
            int r;
            while ((r = in.read(buf)) > 0) {
                out.write(buf, 0, r);
            }
            out.flush();
        } catch (Exception e) {
            try {
                if (dst.exists()) {
                    dst.delete();
                }
            } catch (Exception ignored) {
            }
            return null;
        } finally {
            closeQuietly(in);
            closeQuietly(out);
        }

        // 所有者可执行（对 .sh 也设上，免得 sh 自己再检查）
        try {
            dst.setExecutable(true, false);
            dst.setReadable(true, false);
        } catch (Exception ignored) {
        }

        return dst;
    }

    public static boolean remove(File f) {
        try {
            return f != null && f.delete();
        } catch (Exception e) {
            return false;
        }
    }

    /** 执行结果 */
    public static final class RunResult {
        public boolean ok;
        public int exitCode;
        public String output;
        public String error;
    }

    /**
     * 执行一个文件。
     *
     * 注意：这一版执行出来的进程是普通应用 uid —— 内核侧的「跨 exec 传递
     * 影子授权」（路径 B）还没实现。等那边补上，这里不需要改。
     */
    public static RunResult run(Context ctx, File f) {
        RunResult r = new RunResult();
        if (f == null || !f.exists()) {
            r.error = "file not found";
            return r;
        }

        String name = f.getName().toLowerCase();
        String[] cmd;

        if (name.endsWith(".sh")) {
            cmd = new String[]{"/system/bin/sh", f.getAbsolutePath()};
        } else if (name.endsWith(".ko")) {
            // 加载内核模块需要 root，这里先如实回报
            r.error = "insmod requires root";
            return r;
        } else {
            cmd = new String[]{f.getAbsolutePath()};
        }

        /*
         * ★ 三档执行身份 ★
         *
         *   shadow（影子用户）  直接跑 —— 靠内核判定放行，不换 uid
         *   super （超级用户）  走 su 子进程 —— 真 uid 0 + su 域
         *   full  （完全影子）  直接跑 —— 不碰 MAC，系统路径走 /proc/umbral/io
         *
         * 选择存在 sk_settings 里，默认影子。
         * su 那一路把命令包成一条带引号的字符串交给 su -c，
         * 这样参数里的空格、引号都不会被拆错。
         */
        String mode = ctx.getSharedPreferences("sk_settings",
                android.content.Context.MODE_PRIVATE)
                .getString("launcher_mode", "shadow");
        if ("super".equals(mode) && (cmd.length == 0 || !"su".equals(cmd[0]))) {
            StringBuilder line = new StringBuilder();
            for (String c : cmd) {
                if (line.length() > 0) {
                    line.append(' ');
                }
                line.append('\'').append(c.replace("'", "'\\''")).append('\'');
            }
            cmd = new String[]{"su", "-c", line.toString()};
        }

        Process p = null;
        BufferedReader out = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            pb.directory(ctx.getFilesDir());
            p = pb.start();

            out = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = out.readLine()) != null) {
                sb.append(line).append('\n');
                if (sb.length() > 64 * 1024) {
                    sb.append("… (truncated)\n");
                    break;
                }
            }
            r.exitCode = p.waitFor();
            r.output = sb.toString();
            r.ok = (r.exitCode == 0);
            return r;
        } catch (Exception e) {
            r.error = e.getClass().getSimpleName() + ": " + e.getMessage();
            return r;
        } finally {
            closeQuietly(out);
            if (p != null) {
                p.destroy();
            }
        }
    }


    // ══════════════════════════════════════════════════════
    // 文件属性：权限 / 重命名 / 读内容
    //
    // 为什么用 chmod 命令而不是 File.setExecutable()：
    //   File.setExecutable/setReadable/setWritable 只能改**属主**那三位，
    //   group/other 改不了，也没法一次设成 700/755/644 这种组合。
    //   我们的文件都在应用私有目录，本来就只有属主会访问，
    //   但既然要给用户一个「调权限」的入口，就用真正的 chmod，显示也准确。
    // ══════════════════════════════════════════════════════

    /** 权限位（三位八进制，如 0700 / 0755 / 0644） */
    public static final int[] MODE_PRESETS = {
            0700, 0755, 0644, 0600, 0750, 0777
    };

    /** 把 st_mode 的低 9 位格式化成 rwxr-xr-x */
    public static String modeString(int mode) {
        StringBuilder sb = new StringBuilder(9);
        sb.append((mode & 0400) != 0 ? 'r' : '-');
        sb.append((mode & 0200) != 0 ? 'w' : '-');
        sb.append((mode & 0100) != 0 ? 'x' : '-');
        sb.append((mode & 0040) != 0 ? 'r' : '-');
        sb.append((mode & 0020) != 0 ? 'w' : '-');
        sb.append((mode & 0010) != 0 ? 'x' : '-');
        sb.append((mode & 0004) != 0 ? 'r' : '-');
        sb.append((mode & 0002) != 0 ? 'w' : '-');
        sb.append((mode & 0001) != 0 ? 'x' : '-');
        return sb.toString();
    }

    /** 读当前权限位，读不到返回 -1 */
    public static int currentMode(File f) {
        if (f == null || !f.exists()) {
            return -1;
        }
        // Java 没有直接的 stat，用 ls 拿更可靠：Android 的 toybox ls -l 输出首列就是权限
        String out = execCapture(new String[]{"ls", "-l", f.getAbsolutePath()});
        if (out == null || out.length() < 10) {
            return -1;
        }
        String perms = out.trim().substring(0, 10);
        int mode = 0;
        int[] bit = {0400, 0200, 0100, 0040, 0020, 0010, 0004, 0002, 0001};
        for (int i = 0; i < 9; i++) {
            if (perms.charAt(i + 1) != '-') {
                mode |= bit[i];
            }
        }
        return mode;
    }

    /** 改权限。返回是否有变化（改完回读校验） */
    public static boolean chmod(File f, int mode) {
        if (f == null || !f.exists()) {
            return false;
        }
        String octal = String.format(java.util.Locale.US, "%o", mode);
        execCapture(new String[]{"chmod", octal, f.getAbsolutePath()});
        return currentMode(f) == mode;
    }

    /**
     * 重命名。
     *
     * 只允许改名字，不允许带路径分隔符 —— 防止被用作把文件挪到别处。
     */
    public static File rename(File f, String newName) {
        if (f == null || !f.exists() || newName == null) {
            return null;
        }
        String clean = sanitize(newName);
        if (clean == null || clean.isEmpty() || clean.contains("/")) {
            return null;
        }
        File dst = new File(f.getParentFile(), clean);
        if (dst.exists()) {
            return null;
        }
        return f.renameTo(dst) ? dst : null;
    }

    /** 读文本内容（最多 limit 字节），用于脚本预览 */
    public static String readText(File f, int limit) {
        if (f == null || !f.exists()) {
            return null;
        }
        java.io.FileInputStream in = null;
        try {
            in = new java.io.FileInputStream(f);
            byte[] buf = new byte[Math.min(limit, (int) Math.max(1, f.length()))];
            int n = in.read(buf);
            if (n <= 0) {
                return "";
            }
            return new String(buf, 0, n, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        } finally {
            closeQuietly(in);
        }
    }

    /** 跑一条命令，返回 stdout+stderr（合并） */
    private static String execCapture(String[] cmd) {
        Process p = null;
        BufferedReader r = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            p = pb.start();
            r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            p.waitFor();
            return sb.toString();
        } catch (Exception e) {
            return null;
        } finally {
            closeQuietly(r);
            if (p != null) {
                p.destroy();
            }
        }
    }


    // ══════════════════════════════════════════════════════
    // 目录浏览（文件管理器用）
    // ══════════════════════════════════════════════════════

    /** 外部存储根。多数设备是 /storage/emulated/0，取不到就退回 /sdcard */
    public static File externalRoot() {
        File a = new File("/storage/emulated/0");
        if (a.isDirectory()) {
            return a;
        }
        return new File("/sdcard");
    }

    /** 能不能进这个目录（能读到就当作能进） */
    public static boolean canBrowse(File d) {
        if (d == null || !d.isDirectory()) {
            return false;
        }
        String[] t = d.list();
        return t != null;
    }

    /**
     * 列目录：文件夹在前，文件在后，各自按名字排序。
     *
     * 隐藏文件（以 . 开头）不显示 —— 我们自己写的 .guard_* 临时文件
     * 也不该出现在列表里。
     */
    public static List<File> listDir(File dir) {
        List<File> out = new ArrayList<File>();
        File[] fs = dir == null ? null : dir.listFiles();
        if (fs == null) {
            return out;
        }
        List<File> dirs = new ArrayList<File>();
        List<File> files = new ArrayList<File>();
        for (File f : fs) {
            String n = f.getName();
            if (n.startsWith(".")) {
                continue;
            }
            if (f.isDirectory()) {
                dirs.add(f);
            } else {
                files.add(f);
            }
        }
        Comparator<File> byName = new Comparator<File>() {
            @Override
            public int compare(File a, File b) {
                return a.getName().compareToIgnoreCase(b.getName());
            }
        };
        java.util.Collections.sort(dirs, byName);
        java.util.Collections.sort(files, byName);
        out.addAll(dirs);
        out.addAll(files);
        return out;
    }

    /** 在目录下建子目录，重名就加序号 */
    public static File mkdir(File parent, String name) {
        String clean = sanitize(name);
        if (parent == null || clean == null || clean.isEmpty()) {
            return null;
        }
        File d = new File(parent, clean);
        int i = 1;
        while (d.exists()) {
            d = new File(parent, clean + "_" + i);
            i++;
            if (i > 99) {
                return null;
            }
        }
        return d.mkdirs() ? d : null;
    }

    /** 递归删除（目录也能删） */
    public static boolean deleteDeep(File f) {
        if (f == null || !f.exists()) {
            return false;
        }
        if (f.isDirectory()) {
            File[] kids = f.listFiles();
            if (kids != null) {
                for (File k : kids) {
                    deleteDeep(k);
                }
            }
        }
        return f.delete();
    }

    /** 能不能当文本打开：按扩展名判断，避免把二进制塞进编辑器 */
    public static boolean isTextFile(File f) {
        if (f == null || !f.isFile()) {
            return false;
        }
        String n = f.getName().toLowerCase();
        String[] ok = { ".sh", ".txt", ".conf", ".cfg", ".ini", ".json", ".xml",
                        ".prop", ".rc", ".log", ".md", ".pro", ".rules", ".lst" };
        for (String e : ok) {
            if (n.endsWith(e)) {
                return true;
            }
        }
        return false;
    }

    /** 可执行脚本（能直接跑） */
    public static boolean isRunnable(File f) {
        if (f == null || !f.isFile()) {
            return false;
        }
        String n = f.getName().toLowerCase();
        return n.endsWith(".sh") || n.endsWith(".ko");
    }

    /** 文件大小 + 修改时间，给列表项用 */
    public static String describe(File f) {
        if (f == null) {
            return "-";
        }
        long size = f.length();
        String sz;
        if (size < 1024) {
            sz = size + " B";
        } else if (size < 1024 * 1024) {
            sz = String.format(java.util.Locale.US, "%.1f KB", size / 1024.0);
        } else {
            sz = String.format(java.util.Locale.US, "%.1f MB", size / (1024.0 * 1024.0));
        }
        String t = new java.text.SimpleDateFormat("MM-dd HH:mm", java.util.Locale.US)
                .format(new java.util.Date(f.lastModified()));
        return sz + "  ·  " + t;
    }

    // ── 工具 ──

    private static String sanitize(String name) {
        if (name == null) {
            return null;
        }
        // 去掉路径分隔符和常见非法字符，防止目录穿越
        return name.replaceAll("[/\\\\:*?\"<>|\\x00-\\x1f]", "_").trim();
    }

    private static String withSuffix(String name, String suffix) {
        int dot = name.lastIndexOf('.');
        if (dot <= 0) {
            return name + suffix;
        }
        return name.substring(0, dot) + suffix + name.substring(dot);
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
