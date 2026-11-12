package io.umbral.data;

import io.umbral.sk.RootSource;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * KPM（KernelPatch Module）仓库。
 *
 * KPM 是运行时打进内核的补丁模块（.kpm 为 ELF 载体），
 * 与「模块」（常驻的 systemless 目录）本质不同：
 *   - 模块：开机挂载，长期存在
 *   - KPM：手动加载/卸载，卸下即无痕
 *
 * 路径约定：
 *   /data/adb/sk/kpm/<id>.kpm      模块本体
 *   /data/adb/sk/kpm/<id>.prop     可选元数据（module.prop 同名格式）
 *
 * 内核接口契约（待 影核 内核模块实现）：
 *   /proc/umbral/kpm/ctl                写入 "load <abs_path>" / "unload <id>"
 *   /proc/umbral/kpm/list               读出已加载的 id，每行一个
 *   /proc/umbral/kpm/version            引擎版本
 */
public final class KpmRepository {

    public static final String BASE_DIR = "/data/adb/sk";
    public static final String KPM_DIR = BASE_DIR + "/kpm";
    public static final String ENGINE_CTL = "/proc/umbral/kpm/ctl";
    public static final String ENGINE_LIST = "/proc/umbral/kpm/list";
    public static final String ENGINE_VER = "/proc/umbral/kpm/version";

    /*
     * 真实 KPM 生态在 APatch / KernelPatch 那边，路径和我们的不同。
     * 「兼容」的含义是：能看见别人的 KPM，而不是只认自己的目录。
     */
    public static final String APATCH_DIR   = "/data/adb/ap";
    public static final String KP_MOD_DIR   = "/data/adb/kp";
    /** APatch 的 KPM 存放位置（不同版本可能在这儿或 ap/ 下） */
    public static final String[] KPM_DIRS = {
            "/data/adb/sk/kpm",      /* 我们自己的 */
            "/data/adb/ap/kpm",      /* APatch */
            "/data/adb/kp/kpm",      /* KernelPatch */
    };

    private KpmRepository() {
    }

    /** 引擎是否就绪：优先自有 /proc 接口，其次看是否借到别家 kpatch */
    /** 系统里有没有 APatch / KernelPatch（真实 KPM 引擎） */
    public static boolean hasApatch() {
        return new java.io.File(APATCH_DIR).exists()
                || new java.io.File(KP_MOD_DIR).exists();
    }

    /** 引擎描述：说清楚是哪一种，或者为什么没有 */
    public static String engineName() {
        if (isEngineReady()) {
            return "影核 KPM";
        }
        if (hasApatch()) {
            return "KernelPatch (APatch)";
        }
        return "无";
    }

    public static boolean isEngineReady() {
        if (new File(ENGINE_CTL).exists() || new File(ENGINE_VER).exists()) {
            return true;
        }
        return false;
    }

    public static String engineDesc() {
        if (isEngineReady()) {
            String v = RootSource.execSu("cat " + ENGINE_VER + " 2>/dev/null");
            if (v != null && !v.trim().isEmpty()) {
                return "KernelPatch " + v.trim();
            }
            return "KernelPatch 已就绪";
        }
        return "KernelPatch 引擎未接入（待内核模块）";
    }

    /** 已加载的 KPM id 集合（读 /proc/umbral/kpm/list） */
    public static List<String> loadedIds() {
        List<String> out = new ArrayList<>();
        File f = new File(ENGINE_LIST);
        if (!f.exists()) {
            return out;
        }
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(f));
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) {
                    out.add(line);
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (Exception ignored) {
                }
            }
        }
        return out;
    }

    /** 扫描全部 KPM。会阻塞（su），后台线程调用。 */
    public static List<KpmEntry> listAll(android.content.Context ctx) {
        List<String> loaded = loadedIds();

        List<KpmEntry> viaSu = scanViaSu(loaded);
        if (!viaSu.isEmpty()) {
            return viaSu;
        }
        return scanMirror(ctx, loaded);
    }

    private static List<KpmEntry> scanViaSu(List<String> loaded) {
        List<KpmEntry> out = new ArrayList<>();
        String dirs = "";
        for (String d : KPM_DIRS) {
            dirs += " " + d;
        }
        String script = "for D in" + dirs + "; do for f in $D/*.kpm; do "
                + "[ -f \"$f\" ] || continue; "
                + "id=$(basename \"$f\" .kpm); "
                + "sz=$(stat -c %s \"$f\" 2>/dev/null || echo 0); "
                + "mt=$(stat -c %Y \"$f\" 2>/dev/null || echo 0); "
                + "echo \"===BEGIN:$id:$sz:$mt\"; "
                + "cat " + KPM_DIR + "/$id.prop 2>/dev/null; "
                + "echo \"===END\"; "
                + "done; done";
        String dump = RootSource.execSu(script);
        if (dump == null || dump.trim().isEmpty()) {
            return out;
        }

        KpmEntry cur = null;
        StringBuilder propBuf = new StringBuilder();
        for (String raw : dump.split("\n")) {
            String line = raw.trim();
            if (line.startsWith("===BEGIN:")) {
                String[] parts = line.substring("===BEGIN:".length()).split(":");
                cur = new KpmEntry();
                cur.id = parts.length > 0 ? parts[0] : "";
                cur.name = cur.id;
                cur.version = "";
                cur.author = "";
                cur.description = "";
                cur.size = parts.length > 1 ? parseLong(parts[1]) : 0;
                cur.mtime = parts.length > 2 ? parseLong(parts[2]) * 1000L : 0;
                cur.path = KPM_DIR + "/" + cur.id + ".kpm";
                cur.loaded = loaded.contains(cur.id);
                propBuf.setLength(0);
                continue;
            }
            if (line.equals("===END")) {
                if (cur != null) {
                    applyProp(cur, propBuf.toString());
                    out.add(cur);
                }
                cur = null;
                continue;
            }
            if (cur != null) {
                propBuf.append(raw).append('\n');
            }
        }
        sort(out);
        return out;
    }

    private static List<KpmEntry> scanMirror(android.content.Context ctx, List<String> loaded) {
        List<KpmEntry> out = new ArrayList<>();
        if (ctx == null) {
            return out;
        }
        File dir = new File(ctx.getFilesDir(), "kpm_mirror");
        File[] files = dir.listFiles();
        if (files == null) {
            return out;
        }
        for (File f : files) {
            String n = f.getName();
            if (!n.endsWith(".kpm")) {
                continue;
            }
            KpmEntry e = new KpmEntry();
            e.id = n.substring(0, n.length() - 4);
            e.name = e.id;
            e.version = "";
            e.author = "";
            e.description = "";
            e.size = f.length();
            e.mtime = f.lastModified();
            e.path = f.getAbsolutePath();
            e.loaded = loaded.contains(e.id);
            applyProp(e, readText(new File(dir, e.id + ".prop")));
            out.add(e);
        }
        sort(out);
        return out;
    }

    private static void sort(List<KpmEntry> out) {
        Collections.sort(out, new Comparator<KpmEntry>() {
            @Override
            public int compare(KpmEntry a, KpmEntry b) {
                if (a.loaded != b.loaded) {
                    return a.loaded ? -1 : 1;
                }
                return a.name.compareToIgnoreCase(b.name);
            }
        });
    }

    private static void applyProp(KpmEntry e, String text) {
        if (text == null || text.isEmpty()) {
            return;
        }
        for (String raw : text.split("\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int i = line.indexOf('=');
            if (i <= 0) {
                continue;
            }
            String k = line.substring(0, i).trim();
            String v = line.substring(i + 1).trim();
            if ("id".equals(k) && !v.isEmpty()) {
                e.id = v;
            } else if ("name".equals(k) && !v.isEmpty()) {
                e.name = v;
            } else if ("version".equals(k)) {
                e.version = v;
            } else if ("author".equals(k)) {
                e.author = v;
            } else if ("description".equals(k)) {
                e.description = v;
            }
        }
    }

    /**
     * 加载一个 KPM。
     * 返回 null 表示成功，否则返回错误说明。
     */
    public static String load(KpmEntry e) {
        if (!isEngineReady()) {
            return "KernelPatch 引擎未就绪";
        }
        String out = RootSource.execSu(
                "echo 'load " + e.path + "' > " + ENGINE_CTL + " && echo OK");
        if (out != null && out.contains("OK")) {
            return null;
        }
        return "加载失败";
    }

    /** 卸载一个 KPM */
    public static String unload(KpmEntry e) {
        if (!isEngineReady()) {
            return "KernelPatch 引擎未就绪";
        }
        String out = RootSource.execSu(
                "echo 'unload " + e.id + "' > " + ENGINE_CTL + " && echo OK");
        if (out != null && out.contains("OK")) {
            return null;
        }
        return "卸载失败";
    }

    private static long parseLong(String s) {
        try {
            return Long.parseLong(s.trim());
        } catch (Exception e) {
            return 0;
        }
    }

    private static String readText(File f) {
        if (f == null || !f.exists()) {
            return "";
        }
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(f));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
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
