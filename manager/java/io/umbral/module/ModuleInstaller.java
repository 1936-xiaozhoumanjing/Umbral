package io.umbral.module;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 影核自己的 ZIP 模块安装器 —— 不依赖 ksud / Magisk。
 *
 * ══════════════════════════════════════════════════════
 *  为什么自己写
 * ══════════════════════════════════════════════════════
 *
 *  我们的内核模块能提供真 root（超级用户模式 commit_creds 到 uid 0），
 *  管理器被授予 super 后，它 spawn 的 sh 就是 uid 0 进程，
 *  完全可以直接解压 ZIP、建目录、改权限 —— 没有任何理由再调 ksud。
 *
 *  ksud 只在「用 KernelSU 当 root」时存在；换到我们自己的 root 后
 *  它根本不存在，依赖它就是把自己锁死在别人的生态里。
 *
 * ══════════════════════════════════════════════════════
 *  模块标准（Magisk / KernelSU 通用）
 * ══════════════════════════════════════════════════════
 *
 *  ZIP 内容：
 *      module.prop          必需，含 id / name / version
 *      system/              可选，要挂载的文件（我们的加载器暂不处理）
 *      post-fs-data.sh      可选，开机早期脚本
 *      service.sh           可选，开机后期脚本
 *      uninstall.sh         可选，卸载时执行
 *      (META-INF/ 忽略)
 *
 *  安装后：
 *      /data/adb/modules/<id>/       模块本体
 *      /data/adb/modules/<id>/disable  存在 = 已禁用
 *      /data/adb/modules/<id>/remove   存在 = 下次开机卸载
 */
public final class ModuleInstaller {

    public static final String MODULES_DIR = "/data/adb/modules";

    /*
     * KSU 两段式安装：先写这里，重启时才合并进 MODULES_DIR
     * （装坏了不影响正在生效的旧版本）
     */
    public static final String MODULES_UPDATE_DIR = "/data/adb/modules_update";

    private ModuleInstaller() {
    }

    /** 安装结果 */
    public static final class Result {
        public boolean ok;
        public String id;
        public String name;
        public String error;
        public int files;
        public final List<String> warnings = new ArrayList<>();

        public String summary() {
            if (!ok) {
                return "安装失败：" + error;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("已安装 ").append(name).append("（").append(id).append("）");
            sb.append("，共 ").append(files).append(" 个文件");
            if (!warnings.isEmpty()) {
                sb.append("\n注意：");
                for (String w : warnings) {
                    sb.append("\n· ").append(w);
                }
            }
            sb.append("\n重启后生效");
            return sb.toString();
        }
    }

    // ══════════════════ 安装 ══════════════════

    public static Result install(Context ctx, String zipPath) {
        Result r = new Result();

        /*
         * ★ content:// 必须先落地成普通文件 ★
         *
         * 用户从文件选择器选 ZIP 时，拿到的是 content:// 这种 URI，
         * 不是文件路径。直接 new ZipFile(new File(uri)) 一定抛
         * 「读压缩包失败：No such file or directory」——
         * 那就是你看到的报错。
         *
         * 所以先把它拷到 App 缓存目录，再当普通文件用。
         */
        zipPath = materialize(ctx, zipPath);
        if (zipPath == null) {
            /* 交给外层统一的 catch 去填 r.error，不自己造 Result */
            throw new IllegalStateException("无法读取这个压缩包（拷贝到缓存失败）");
        }

        File zip = new File(zipPath);
        if (!zip.isFile()) {
            r.error = "文件不存在";
            return r;
        }

        /* ① 先读 module.prop 拿 id —— 这一步不需要 root */
        String id = null;
        String name = null;
        ZipFile zf = null;
        try {
            zf = new ZipFile(zip);
            ZipEntry prop = zf.getEntry("module.prop");
            if (prop == null) {
                r.error = "不是模块包：缺少 module.prop";
                return r;
            }
            String text = readEntry(zf, prop);
            id = propValue(text, "id");
            name = propValue(text, "name");
            if (id == null || id.isEmpty()) {
                r.error = "module.prop 里没有 id";
                return r;
            }
            if (!id.matches("[A-Za-z0-9_.\\-]+")) {
                r.error = "模块 id 含非法字符：" + id;
                return r;
            }
            if (name == null || name.isEmpty()) {
                name = id;
            }
        } catch (Exception e) {
            /*
             * 错误信息必须足够定位问题：
             *   异常类型 + 原始消息 + 实际打开的是哪个文件 + 多大
             * 只有 "读压缩包失败：null" 这种是没法查的。
             */
            /*
             * ★ 把「bad compression method: N」翻译成人话 ★
             *
             * Java 的 ZipFile 只支持 0(Store) 和 8(Deflate)。
             * 其它方法一律报 invalid CEN header，用户完全看不懂。
             * Magisk / KernelSU 的安装器同样只认 0/8，所以这不是我们的短板，
             * 而是那个包本身不是标准模块打包方式。
             */
            /*
             * ★ 先试自己的读取器 ★
             *
             * java.util.zip 只认 Store/Deflate。遇到 XZ(95)、LZMA(14)、
             * Zstd(93) 会在解析目录阶段就抛，连文件列表都读不到。
             * ZipReader 自己解析中央目录，按 method 分派解码，
             * XZ 走 JNI（设备自带 liblzma）。
             */
            try {
                io.umbral.module.ZipReader zr =
                        new io.umbral.module.ZipReader(zip);
                java.util.List<io.umbral.module.ZipReader.Entry> list = zr.entries();
                io.umbral.module.ZipReader.Entry propE = zr.find(list, "module.prop");
                if (propE == null) {
                    r.error = "不是模块包：缺少 module.prop";
                    dumpError(ctx, zipPath, r.error);
                    return r;
                }
                String text2 = new String(zr.read(propE), "UTF-8");
                String id2 = propValue(text2, "id");
                String name2 = propValue(text2, "name");
                if (id2 == null || id2.isEmpty()) {
                    r.error = "module.prop 里没有 id";
                    dumpError(ctx, zipPath, r.error);
                    return r;
                }
                if (!id2.matches("[A-Za-z0-9_.\\-]+")) {
                    r.error = "模块 id 含非法字符：" + id2;
                    dumpError(ctx, zipPath, r.error);
                    return r;
                }
                /* 解压到 staging */
                java.io.File staging2 = new java.io.File(ctx.getCacheDir(), "mod_" + id2);
                deleteRec2(staging2);
                //noinspection ResultOfMethodCallIgnored
                staging2.mkdirs();
                for (io.umbral.module.ZipReader.Entry e2 : list) {
                    if (e2.name.endsWith("/")) {
                        continue;
                    }
                    java.io.File out2 = new java.io.File(staging2, e2.name);
                    java.io.File par2 = out2.getParentFile();
                    if (par2 != null) {
                        //noinspection ResultOfMethodCallIgnored
                        par2.mkdirs();
                    }
                    java.io.FileOutputStream fo2 = new java.io.FileOutputStream(out2);
                    try {
                        fo2.write(zr.read(e2));
                        fo2.flush();
                        fo2.getFD().sync();
                    } finally {
                        fo2.close();
                    }
                }
                r.ok = true;
                r.id = id2;
                r.name = name2;
                r.files = list.size();
                return r;
            } catch (Throwable t2) {
                /* 自己的读取器也失败：继续走下面的原始报错，但把两条都记下来 */
                dumpError(ctx, zipPath,
                        "ZipReader: " + t2 + "\n原始: " + e);
            }

            String msg0 = String.valueOf(e.getMessage());
            int mk = msg0.indexOf("bad compression method:");
            if (mk >= 0) {
                String num = msg0.substring(mk + "bad compression method:".length()).trim();
                String how;
                if ("14".equals(num)) {
                    how = "LZMA";
                } else if ("93".equals(num)) {
                    how = "Zstandard";
                } else if ("95".equals(num)) {
                    how = "XZ";
                } else if ("98".equals(num)) {
                    how = "PPMd";
                } else {
                    how = "方法 " + num;
                }
                r.error = "这个压缩包用了 " + how + " 压缩（方法 " + num + "）。\n\n"
                        + "影核只支持标准 ZIP（Deflate / 不压缩），"
                        + "Magisk 和 KernelSU 的安装器也一样只认这两种。\n\n"
                        + "解决方法：\n"
                        + "用 7-Zip / Windows 自带压缩重新打包，"
                        + "压缩方式选「Deflate」或「仅存储」，然后重新导入。";
                dumpError(ctx, zipPath, r.error);
                return r;
            }
            long sz = -1;
            try { sz = zip.length(); } catch (Throwable ignored) { }
            r.error = "读压缩包失败：[" + e.getClass().getSimpleName() + "] "
                    + e.getMessage() + "\n路径：" + zipPath + "\n大小：" + sz + " 字节";
            dumpError(ctx, zipPath, r.error);
            return r;
        } finally {
            closeQuietly(zf);
        }

        r.id = id;
        r.name = name;

        /* ② 在 App 私有目录先解压一遍（不需要 root） */
        File staging = new File(ctx.getCacheDir(), "mod_" + id);
        deleteTree(staging);
        if (!staging.mkdirs()) {
            r.error = "建不了临时目录";
            return r;
        }

        int n = 0;
        try {
            zf = new ZipFile(zip);
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                String nm = e.getName();
                if (nm == null) {
                    continue;
                }
                /* META-INF 是签名目录，装了也没用 */
                if (nm.startsWith("META-INF/")) {
                    continue;
                }
                /* 防目录穿越：不允许绝对路径和 .. */
                if (nm.startsWith("/") || nm.contains("..")) {
                    r.warnings.add("跳过可疑路径：" + nm);
                    continue;
                }
                File out = new File(staging, nm);
                if (e.isDirectory()) {
                    out.mkdirs();
                    continue;
                }
                File parent = out.getParentFile();
                if (parent != null && !parent.exists() && !parent.mkdirs()) {
                    r.warnings.add("建目录失败：" + nm);
                    continue;
                }
                InputStream in = null;
                FileOutputStream fo = null;
                try {
                    in = zf.getInputStream(e);
                    fo = new FileOutputStream(out);
                    byte[] buf = new byte[32768];
                    int rd;
                    while ((rd = in.read(buf)) > 0) {
                        fo.write(buf, 0, rd);
                    }
                    fo.flush();
                    n++;
                } catch (Exception ex) {
                    r.warnings.add("解压失败：" + nm);
                } finally {
                    closeQuietly(fo);
                    closeQuietly(in);
                }
            }
        } catch (Exception e) {
            r.error = "解压失败：" + e.getMessage();
            return r;
        } finally {
            closeQuietly(zf);
        }

        if (n == 0) {
            r.error = "压缩包里没有文件";
            return r;
        }
        r.files = n;

        /* ③ 用 root 身份搬到 /data/adb/modules_update/<id>（重启后合并）*/
        String err = moveIntoPlace(staging.getAbsolutePath(), id);
        if (err != null) {
            r.error = err;
            return r;
        }

        /* ④ 修权限：脚本必须可执行，其它 0644 */
        err = fixPermissions(id);
        if (err != null) {
            r.warnings.add("改权限失败（脚本可能不会执行）：" + err);
        }

        deleteTree(staging);
        r.ok = true;
        return r;
    }

    // ══════════════════ 卸载 / 启用禁用 ══════════════════

    /** 立即删除模块目录 */
    public static String uninstall(String id) {
        if (!safeId(id)) {
            return "非法模块 id";
        }
        return sh("rm -rf '" + MODULES_DIR + "/" + id + "'");
    }

    /** 标记为下次开机卸载（模块自己有 uninstall.sh 时用这个） */
    public static String markRemove(String id, boolean remove) {
        if (!safeId(id)) {
            return "非法模块 id";
        }
        String flag = MODULES_DIR + "/" + id + "/remove";
        return remove ? sh("touch '" + flag + "'") : sh("rm -f '" + flag + "'");
    }

    public static String setEnabled(String id, boolean enable) {
        if (!safeId(id)) {
            return "非法模块 id";
        }
        String flag = MODULES_DIR + "/" + id + "/disable";
        return enable ? sh("rm -f '" + flag + "'") : sh("touch '" + flag + "'");
    }

    public static boolean isEnabled(String id) {
        return !new File(MODULES_DIR + "/" + id + "/disable").exists();
    }

    // ══════════════════ 内部 ══════════════════

    /**
     * 把暂存目录搬到最终位置。
     *
     * 优先用我们自己的 root（超级用户模式下 sh 就是 uid 0）；
     * 没有的话退回 su（兼容还装着 KernelSU 的设备）。
     */
    private static String moveIntoPlace(String staging, String id) {
        String dst = MODULES_DIR + "/" + id;

        String cmd = "mkdir -p '" + MODULES_DIR + "'"
                + " && rm -rf '" + dst + "'"
                + " && cp -a '" + staging + "' '" + dst + "'"
                + " && chown -R 0:0 '" + dst + "'"
                + " && chmod 755 '" + dst + "'"
                + " && echo UMBRAL_OK";

        /* ① 直接跑（我们自己 root 时，当前进程/子进程已是 uid 0） */
        String out = shroot(cmd);
        if (out != null && out.contains("UMBRAL_OK")) {
            return null;
        }

        /* ② 退回 su（有 KernelSU/其他 su 时） */
        out = sh("su -c \"" + cmd.replace("\"", "\\\"") + "\"");
        if (out != null && out.contains("UMBRAL_OK")) {
            return null;
        }

        return "写入 " + dst + " 失败（需要 root：请确认管理器已被授予超级用户模式）";
    }

    /** 脚本要可执行，其余 0644 */
    private static String fixPermissions(String id) {
        String d = MODULES_DIR + "/" + id;
        String cmd = "find '" + d + "' -type f -name '*.sh' -exec chmod 755 {} \\; ; "
                + "find '" + d + "' -type f ! -name '*.sh' -exec chmod 644 {} \\; ; "
                + "chmod 755 '" + d + "' ; echo UMBRAL_OK";
        String out = shroot(cmd);
        if (out != null && out.contains("UMBRAL_OK")) {
            return null;
        }
        out = sh("su -c \"" + cmd.replace("\"", "\\\"") + "\"");
        if (out != null && out.contains("UMBRAL_OK")) {
            return null;
        }
        return "chmod 失败";
    }

    /** 跑一条 shell，返回标准输出+标准错误；失败返回 null */
    /**
     * 以真 root 执行。
     *
     * 走 Shell.root：fork 一个 sh，让它自己写 /proc/umbral/grant 提权，
     * 在子进程里跑命令。App 主进程 uid 不变，不会被系统杀。
     */
    private static String shroot(String cmd) {
        return io.umbral.sk.Shell.root(cmd).out;
    }

    private static String sh(String cmd) {
        Process p = null;
        try {
            p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            InputStream in = p.getInputStream();
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) > 0) {
                bo.write(b, 0, n);
            }
            InputStream es = p.getErrorStream();
            while ((n = es.read(b)) > 0) {
                bo.write(b, 0, n);
            }
            p.waitFor();
            return bo.toString("UTF-8");
        } catch (Exception e) {
            return null;
        } finally {
            if (p != null) {
                p.destroy();
            }
        }
    }

    private static boolean safeId(String id) {
        return id != null && id.matches("[A-Za-z0-9_.\\-]+");
    }

    private static String readEntry(ZipFile zf, ZipEntry e) throws Exception {
        InputStream in = null;
        try {
            in = zf.getInputStream(e);
            java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) > 0) {
                o.write(b, 0, n);
            }
            return o.toString("UTF-8");
        } finally {
            closeQuietly(in);
        }
    }

    private static String propValue(String text, String key) {
        if (text == null) {
            return null;
        }
        for (String line : text.split("\n")) {
            String t = line.trim();
            if (t.startsWith(key + "=")) {
                return t.substring(key.length() + 1).trim();
            }
        }
        return null;
    }

    private static void deleteTree(File f) {
        if (f == null || !f.exists()) {
            return;
        }
        File[] kids = f.listFiles();
        if (kids != null) {
            for (File k : kids) {
                deleteTree(k);
            }
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * 把 content:// 或普通路径统一变成「可读的本地文件路径」。
     *
     * 已经是普通文件 → 原样返回
     * content:// → 用 ContentResolver 打开流，拷到 cache 目录
     * 失败 → 返回 null（调用方给出明确错误）
     */
    private static String materialize(Context ctx, String path) {
        if (path == null) {
            return null;
        }
        File direct = new File(path);
        if (direct.exists() && direct.canRead()) {
            return path;
        }
        java.io.InputStream in = null;
        java.io.FileOutputStream out = null;
        try {
            android.net.Uri uri = android.net.Uri.parse(path);
            in = ctx.getContentResolver().openInputStream(uri);
            if (in == null) {
                return null;
            }
            File dst = new File(ctx.getCacheDir(), "install_" + System.nanoTime() + ".zip");
            out = new java.io.FileOutputStream(dst);
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            out.flush();
            out.getFD().sync();
            return dst.getAbsolutePath();
        } catch (Throwable t) {
            return null;
        } finally {
            try { if (in != null) in.close(); } catch (Exception ignored) { }
            try { if (out != null) out.close(); } catch (Exception ignored) { }
        }
    }


    /**
     * ★ 安装失败时把完整错误写到外部目录 ★
     *
     * 为什么必须这么做：
     *   对话框 / Toast 会把长文本截断，用户根本看不到后半段，
     *   更没法把它发给开发者。
     *
     * /sdcard/Android/data/io.umbral/files/ 这个位置
     *   用户在文件管理器能看到（不用 root）
     *   开发者用 adb 也能直接拉
     *
     * 所以：失败一律落一份完整日志，界面只提示一句「详情见文件」。
     */
    public static void dumpError(Context ctx, String zipPath, String err) {
        java.io.FileOutputStream fo = null;
        try {
            java.io.File dir = ctx.getExternalFilesDir(null);
            if (dir == null) {
                return;
            }
            java.io.File f = new java.io.File(dir, "install_error.txt");
            fo = new java.io.FileOutputStream(f, false);
            StringBuilder sb = new StringBuilder();
            sb.append("时间：").append(new java.util.Date()).append("\n");
            sb.append("压缩包：").append(zipPath).append("\n");
            try {
                java.io.File z = new java.io.File(zipPath);
                sb.append("大小：").append(z.getAbsolutePath()).append(" / ")
                  .append(z.length()).append(" 字节 / 可读=")
                  .append(z.canRead()).append("\n");
            } catch (Throwable ignored) {
            }
            sb.append("\n===== 错误 =====\n").append(err).append("\n");
            fo.write(sb.toString().getBytes("UTF-8"));
            fo.flush();
            fo.getFD().sync();
        } catch (Throwable ignored) {
        } finally {
            try { if (fo != null) fo.close(); } catch (Exception ignored) { }
        }
    }


    private static void deleteRec2(java.io.File f) {
        if (f == null || !f.exists()) {
            return;
        }
        java.io.File[] cs = f.listFiles();
        if (cs != null) {
            for (java.io.File c : cs) {
                deleteRec2(c);
            }
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }
}
