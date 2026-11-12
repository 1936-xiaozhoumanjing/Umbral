package io.umbral.um;

/**
 * Vivo / iQOO 专用隐藏模板 —— 反 root 对抗。
 *
 * 和通用「一键隐藏环境」的区别：
 *   · 更针对 vivo 安全中心的扫描方式（它们会直接读 /proc/modules、
 *     /proc/kallsyms、/sys/module/*，通用模板里这几项是可选的，
 *     这里全部列为必需）
 *   · 只下发给安全类应用的 uid，不污染其它应用
 */
public final class VivoTemplates {

    private VivoTemplates() {
    }

    /** 把 VivoGuard 的路径列表包成规则行 */
    public static java.util.List<String> buildRules(int uid) {
        java.util.ArrayList<String> out = new java.util.ArrayList<>();
        for (String p : io.umbral.sk.VivoGuard.hidePaths()) {
            out.add("uid " + uid + " path " + p + " hide");
        }
        return out;
    }

    /**
     * 用「路径 → dev/ino」的方式生成真正的规则行。
     *
     * UM 的规则是 (uid, dev, ino, action)，所以每条路径要先 stat。
     * 路径不存在就跳过（不同机型装的东西不一样）。
     */
    public static java.util.List<String> buildStatRules(int uid) {
        java.util.ArrayList<String> out = new java.util.ArrayList<>();
        for (String p : io.umbral.sk.VivoGuard.hidePaths()) {
            String[] devIno = statDevIno(p);
            if (devIno == null) {
                continue;
            }
            out.add("uid " + uid + " dev " + devIno[0] + " ino " + devIno[1] + " hide");
        }
        return out;
    }

    /** stat -c "%d %i" —— 用 Java 的 File 拿不到 dev/ino，退回走 shell */
    private static String[] statDevIno(String path) {
        try {
            io.umbral.sk.Shell.R r = io.umbral.sk.Shell.suFirst(
                    "stat -c '%d %i' " + path + " 2>/dev/null");
            if (r.out == null) {
                return null;
            }
            String s = r.out.trim();
            if (s.isEmpty()) {
                return null;
            }
            String[] parts = s.split("\\s+");
            if (parts.length < 2) {
                return null;
            }
            return new String[]{parts[0], parts[1]};
        } catch (Throwable t) {
            return null;
        }
    }
}
