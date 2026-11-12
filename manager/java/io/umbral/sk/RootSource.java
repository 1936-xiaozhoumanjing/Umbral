package io.umbral.sk;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * root 来源检测。
 *
 * 影核 还只是个管理器时，设备上的 root 往往来自别家（KernelSU / Magisk /
 * APatch）。本类负责问清楚：现在这个 root 是谁给的？
 *
 *   NONE       没有任何 root
 *   SK_ROOT    影核 自己的内核模块（自有）
 *   KERNELSU   KernelSU 给的（借来的）
 *   MAGISK     Magisk 给的（借来的）
 *   APATCH     APatch 给的（借来的）
 *   OTHER      其他 su 实现（借来的）
 *
 * 借来的 root 一样能用：模块读写、KPM 管理、/data/adb 访问全部走它，
 * 等 影核 内核模块上线后再无缝切成"自有"。
 */
public final class RootSource {

    public static final int NONE     = 0;
    public static final int SK_ROOT  = 1;
    public static final int KERNELSU = 2;
    public static final int MAGISK   = 3;
    public static final int APATCH   = 4;
    public static final int OTHER    = 5;

    public int type = NONE;
    /** su 是否真的能跑起来并返回 uid=0 */
    public boolean available = false;
    public String label = "无";
    public String detail = "";
    public String selinuxContext = "";

    private RootSource() {
    }

    /** 自有（影核 内核模块提供） */
    public boolean isOwned() {
        return type == SK_ROOT;
    }

    /** 借来的（别家管理器提供） */
    public boolean isBorrowed() {
        return available && type != SK_ROOT && type != NONE;
    }

    /** 有 root 可用（自有或借来都算） */
    public boolean usable() {
        return available;
    }

    /**
     * 执行一次检测。会起 su 进程，必须在后台线程调用。
     * 首次调用时 KSU / Magisk 会弹授权框，用户需要点允许。
     */
    public static RootSource detect() {
        RootSource r = new RootSource();

        // ---- 1) 自有内核模块优先 ----
        String skVer = readFile("/proc/umbral/version");
        if (skVer != null) {
            r.type = SK_ROOT;
            r.available = true;
            r.label = "影核";
            r.detail = skVer.trim().isEmpty() ? "自有内核模块" : skVer.trim();
            return r;
        }

        // ---- 2) 问 su ----
        String idOut = execSu("id");
        if (idOut == null || !idOut.contains("uid=0")) {
            r.type = NONE;
            r.available = false;
            r.label = "无";
            r.detail = "未检测到可用的 su";
            return r;
        }
        r.available = true;

        // ---- 3) 从 SELinux 上下文判来源 ----
        String ctxOut = execSu("cat /proc/self/attr/current");
        if (ctxOut != null) {
            r.selinuxContext = ctxOut.trim();
        }
        String probe = (r.selinuxContext + " " + idOut).toLowerCase();

        if (probe.contains(":ksu:")) {
            r.type = KERNELSU;
            r.label = "KSU";
            r.detail = "KernelSU";
        } else if (probe.contains(":magisk:")) {
            r.type = MAGISK;
            r.label = "Magisk";
            r.detail = "借来的 root（Magisk）";
        } else if (probe.contains(":apd:") || probe.contains(":kpatch:")) {
            r.type = APATCH;
            r.label = "APatch";
            r.detail = "借来的 root（APatch）";
        } else {
            r.type = OTHER;
            r.label = "其他管理器";
            r.detail = "借来的 root";
        }
        return r;
    }

    /** 同步执行 su 命令，最多等 15 秒（留出用户点授权框的时间） */
    public static String execSu(String cmd) {
        Process p = null;
        BufferedReader r = null;
        try {
            p = Runtime.getRuntime().exec(new String[]{"/system/bin/su", "-c", cmd});
            r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            boolean done = p.waitFor(15, TimeUnit.SECONDS);
            if (!done) {
                return null;
            }
            if (p.exitValue() != 0) {
                return null;
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (Exception ignored) {
                }
            }
            if (p != null) {
                try {
                    p.destroy();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private static String readFile(String path) {
        File f = new File(path);
        if (!f.exists()) {
            return null;
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
            return null;
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
