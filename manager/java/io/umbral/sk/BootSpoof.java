package io.umbral.sk;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 启动状态伪装（propfix 模块的热加载/卸载 + 状态检测）。
 *
 * 三个判据（缺一不可）：
 *   p1  getprop ro.boot.verifiedbootstate        —— 属性区（所有 App 读的就是它）
 *   p2  /proc/cmdline 里的 androidboot.verifiedbootstate —— 内核原始串
 *   p3  propfix 模块是否已加载（/sys/module/propfix 存在）
 *
 * 为什么 p1/p2 必须一起看：
 *   属性区是由 cmdline 生成的。只改一边会出现 getprop=green / cmdline=orange，
 *   这种“不一致”本身比 orange 更可疑，任何反作弊都会当成篡改信号。
 */
public final class BootSpoof {

    public static final String ASSET = "propfix.ko";
    public static final String KO_NAME = "propfix.ko";

    private BootSpoof() {}

    /** 状态快照 */
    public static final class State {
        public String propVbs = "?";      // p1: ro.boot.verifiedbootstate
        public String cmdVbs = "?";       // p2: cmdline 里的取值
        public int flashLocked = -1;      // ro.boot.flash.locked
        public boolean loaded;            // p3: 模块已加载
        public boolean consistent;        // p1 == p2
        public boolean spoofed;           // p1==green 且 p2==green
        public String hint = "";
    }

    public static State probe() {
        State s = new State();
        s.propVbs = getprop("ro.boot.verifiedbootstate");
        s.cmdVbs = grepCmdline("androidboot.verifiedbootstate=");
        String fl = getprop("ro.boot.flash.locked");
        try { s.flashLocked = Integer.parseInt(fl.trim()); } catch (Exception ignored) {}
        s.loaded = new File("/sys/module/propfix").exists();

        s.consistent = s.propVbs.equals(s.cmdVbs);
        s.spoofed = "green".equals(s.propVbs) && "green".equals(s.cmdVbs);
        if (!s.consistent) {
            s.hint = "属性与 cmdline 不一致（" + s.propVbs + " / " + s.cmdVbs + "）→ 必须一起伪装";
        } else if (!s.spoofed) {
            s.hint = "当前为 " + s.propVbs + "，可点开关伪装为 green";
        } else {
            s.hint = "已伪装（green / flash.locked=" + s.flashLocked + "）";
        }
        return s;
    }

    /** 开：提取 assets 里的 propfix.ko → insmod → 立刻删除磁盘文件 */
    public static String enable(Context ctx) {
        if (new File("/sys/module/propfix").exists()) return "already loaded";
        File dst = new File(ctx.getFilesDir(), KO_NAME);
        try {
            if (!extract(ctx, ASSET, dst)) return "asset missing: " + ASSET;
            dst.setReadable(true, false);
            String r = insmod(dst.getAbsolutePath(), "hide=1");
            dst.delete();   // 磁盘上不留 .ko
            return r;
        } catch (Throwable t) {
            dst.delete();
            return "err: " + t.getMessage();
        }
    }

    /** 关：先恢复可见性（kmexit 语义），再卸载 */
    public static String disable(Context ctx) {
        // propfix 无 proc 通道，直接 rmmod（它的 exit 会恢复 tainted 与 modules 链表）
        String r = sh("rmmod propfix");
        return r == null || r.isEmpty() ? "unloaded" : r;
    }

    // ---------------- 内部 ----------------

    private static boolean extract(Context ctx, String asset, File dst) {
        try (InputStream in = ctx.getAssets().open(asset);
             FileOutputStream out = new FileOutputStream(dst)) {
            byte[] b = new byte[64 * 1024];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
            out.flush();
            return dst.length() > 0;
        } catch (Throwable t) {
            return false;
        }
    }

    private static String insmod(String path, String args) {
        // 影子授权下可直接 insmod；失败再退 su
        String r = sh("insmod " + path + " " + args);
        if (r != null && r.toLowerCase().contains("not permitted")) {
            r = sh("su -c 'insmod " + path + " " + args + "'");
        }
        return r == null ? "" : r;
    }

    private static String getprop(String key) {
        String v = sh("getprop " + key);
        return v == null || v.isEmpty() ? "?" : v.trim();
    }

    private static String grepCmdline(String key) {
        String line = sh("cat /proc/cmdline");
        if (line == null) return "?";
        for (String tok : line.trim().split("\\s+")) {
            if (tok.startsWith(key)) return tok.substring(key.length());
        }
        return "?";
    }

    private static String sh(String cmd) {
        List<String> out = new ArrayList<>();
        try {
            Process p = new ProcessBuilder("/system/bin/sh", "-c", cmd)
                    .redirectErrorStream(true).start();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String l;
                while ((l = r.readLine()) != null) out.add(l);
            }
            p.waitFor();
        } catch (Throwable t) {
            return "err: " + t.getMessage();
        }
        StringBuilder sb = new StringBuilder();
        for (String l : out) sb.append(l).append('\n');
        return sb.toString().trim();
    }
}
