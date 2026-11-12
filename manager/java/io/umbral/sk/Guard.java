package io.umbral.sk;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 系统守护 —— 内核拦截「谁动了关键分区」，这里负责读状态和开关。
 *
 * ══════════════════════════════════════════════════════
 *  内核侧做了什么
 * ══════════════════════════════════════════════════════
 *
 *  任何进程试图写 /system /vendor /product /system_ext /odm
 *  /data/system /metadata 这些分区，写入立刻返回 -EPERM（一个字节都写不进去），
 *  同时把肇事者（uid / pid / 进程名 / 尝试次数）记在环形表里。
 *
 *  豁免只有两个：真 root(uid 0) 和管理器自己。
 *  即使是已授予影子/超级用户权限的 App，去动关键分区也会被拦。
 *
 *  ⚠️ /data/adb 刻意不算关键目录 —— 那是我们自己的工作目录。
 *
 * ══════════════════════════════════════════════════════
 *  /proc/umbral/guard 格式
 * ══════════════════════════════════════════════════════
 *
 *    state   on
 *    blocked 17
 *    devs    6
 *    dev     65082
 *    offenders 2
 *    hit  uid=10560 pid=4321 comm=cheat count=9
 *
 *  写：on / off / clear / refresh（必须用 writeProc，不能用 FileOutputStream）
 */
public final class Guard {

    private Guard() {
    }

    /** 一个肇事进程 */
    public static final class Offender {
        public int uid;
        public int pid;
        public String comm = "";
        public int count;

        /** 应用名（由上层用 uid 反查填进） */
        public String label;
        /** 包名（可能多个，同一 uid 共享） */
        public String pkg;
    }

    /** 状态快照 */
    public static final class State {
        public boolean on;
        public long blocked;
        public int devs;
        public int offenders;
        public final List<Offender> hits = new ArrayList<>();

        public boolean hasOffenders() {
            return !hits.isEmpty();
        }
    }

    /** 读取当前状态；模块不可用时返回 null */
    public static State read() {
        File f = new File("/proc/umbral/guard");
        if (!f.exists()) {
            return null;
        }
        State st = new State();
        BufferedReader r = null;
        try {
            r = new BufferedReader(new InputStreamReader(new FileInputStream(f), "UTF-8"));
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.startsWith("state")) {
                    st.on = line.endsWith("on");
                } else if (line.startsWith("blocked")) {
                    st.blocked = num(line);
                } else if (line.startsWith("devs")) {
                    st.devs = (int) num(line);
                } else if (line.startsWith("offenders")) {
                    st.offenders = (int) num(line);
                } else if (line.startsWith("hit ")) {
                    Offender o = new Offender();
                    o.uid = (int) field(line, "uid=");
                    o.pid = (int) field(line, "pid=");
                    o.count = (int) field(line, "count=");
                    int k = line.indexOf("comm=");
                    if (k >= 0) {
                        int s0 = k + 5;
                        int s1 = line.indexOf(" count=", s0);
                        o.comm = s1 > s0 ? line.substring(s0, s1) : line.substring(s0);
                    }
                    st.hits.add(o);
                }
            }
        } catch (Throwable t) {
            return st;
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (Exception ignored) {
                }
            }
        }
        return st;
    }

    /** 开启 / 关闭 */
    public static boolean setEnabled(boolean on) {
        return Shell.writeProc("/proc/umbral/guard", on ? "on" : "off");
    }

    /** 清空肇事记录与计数 */
    public static boolean clear() {
        return Shell.writeProc("/proc/umbral/guard", "clear");
    }

    /** 重新扫描关键挂载点（数据分区刚挂载完时用） */
    public static boolean refresh() {
        return Shell.writeProc("/proc/umbral/guard", "refresh");
    }

    // ── 解析工具 ──

    private static long num(String line) {
        int k = line.indexOf(' ');
        while (k >= 0 && k < line.length() && line.charAt(k) == ' ') {
            k++;
        }
        if (k < 0) {
            return 0;
        }
        try {
            return Long.parseLong(line.substring(k).trim());
        } catch (Exception e) {
            return 0;
        }
    }

    private static long field(String line, String key) {
        int k = line.indexOf(key);
        if (k < 0) {
            return 0;
        }
        int s = k + key.length();
        int e = s;
        while (e < line.length() && (Character.isDigit(line.charAt(e)) || line.charAt(e) == '-')) {
            e++;
        }
        try {
            return Long.parseLong(line.substring(s, e));
        } catch (Exception ex) {
            return 0;
        }
    }
}
