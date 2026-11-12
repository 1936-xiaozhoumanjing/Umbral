package io.umbral.sk;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * 特权命令执行 —— 让**子进程**变成真 root，而不是 App 自己。
 *
 * ══════════════════════════════════════════════════════
 *  为什么不能直接给 App 进程 root
 * ══════════════════════════════════════════════════════
 *
 *  我们的「超级用户模式」是 commit_creds 把进程变成 uid 0。
 *  如果对管理器自己这么干：
 *      ActivityManager 发现进程 uid 变成了 0（和安装时记录的 10563 不符）
 *      → 判定进程异常 → 直接杀掉
 *      → 表现就是「管理器进不去」
 *
 *  这是 Android 的机制，绕不过。所有正经 root 管理器（Magisk/KernelSU）
 *  也都是同一个设计：**本体不升权，fork 一个子进程去升权**。
 *
 * ══════════════════════════════════════════════════════
 *  具体做法
 * ══════════════════════════════════════════════════════
 *
 *  1. 管理器本体持有【影子权限】—— uid 不变、能读 /proc/umbral、能写 grant
 *  2. 需要特权时，fork 一个 sh，让它做的第一件事是：
 *         echo <自己的 pid> 1 > /proc/umbral/grant
 *     内核收到后把该 pid 记为「超级用户模式」
 *  3. 子进程的下一个 syscall 触发 commit_creds → 它变成 uid 0
 *  4. 在子进程里跑完整条命令，输出回来，然后退出
 *  5. App 主进程全程 uid 10563，不会被杀
 *
 *  子进程能写 grant，是因为它和本体同 uid，而本体已被授予影子权限；
 *  加上内核把 /proc/umbral/grant 加进了白名单（不受「root 属主只读」限制）。
 */
public final class Shell {

    /** 上次执行的输出（方便界面上直接显示） */
    public static volatile String lastOutput = "";

    private Shell() {
    }

    /** 结果 */
    public static final class R {
        public int code = -1;
        public String out = "";
        public boolean ok() {
            return code == 0;
        }
    }

    /**
     * 以真 root 身份执行一段 shell。
     *
     * 子进程自己写 grant 把自己提权，所以调用方不需要任何前置授权，
     * 只要管理器本体有影子权限（能写 /proc/umbral/grant）即可。
     */
    /**
     * 直接往 /proc 文件写（不走 shell）。
     *
     * ★ 必须用 ParcelFileDescriptor ★
     *   FileOutputStream 和 sh 的 > 重定向都会带 O_TRUNC，
     *   proc 文件拒绝 O_TRUNC，open 直接失败 —— 且报的是 EACCES/EPERM，
     *   看起来像权限问题，其实跟权限无关。这个坑踩过两次。
     */
    public static boolean writeProc(String path, String content) {
        android.os.ParcelFileDescriptor pfd = null;
        java.io.FileOutputStream fo = null;
        try {
            pfd = android.os.ParcelFileDescriptor.open(
                    new java.io.File(path),
                    android.os.ParcelFileDescriptor.MODE_WRITE_ONLY);
            fo = new java.io.FileOutputStream(pfd.getFileDescriptor());
            fo.write(content.getBytes("UTF-8"));
            fo.flush();
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            try { if (fo != null) fo.close(); } catch (Exception ignored) { }
            try { if (pfd != null) pfd.close(); } catch (Exception ignored) { }
        }
    }

    /**
     * 写**普通文件**（可创建、可覆盖）。
     *
     * 和 writeProc 的区别：proc 文件不接受 O_CREAT/O_TRUNC，
     * 普通文件（ext4/f2fs）恰恰需要它们。两个场景不能共用一个方法。
     */
    public static boolean writeFile(String path, String content) {
        java.io.FileOutputStream fo = null;
        try {
            java.io.File f = new java.io.File(path);
            java.io.File dir = f.getParentFile();
            if (dir != null && !dir.exists()) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
            }
            fo = new java.io.FileOutputStream(f);
            fo.write(content.getBytes("UTF-8"));
            fo.flush();
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            try { if (fo != null) fo.close(); } catch (Exception ignored) { }
        }
    }

    public static R root(String cmd) {
        return run(cmd, true);
    }

    /** 以当前身份执行（不升权） */
    /**
     * ★ 特权命令：优先走 su（真 uid 0 子进程）★
     *
     * 为什么不再依赖「影子权限下的普通 sh」：
     *   影子的放行是按「提权窗口」+「uid」两套判据混着用的，
     *   实测 App 主进程有权限，而它 fork 的 sh 子进程会被拒
     *   （诊断日志：能列 /data/adb/modules=是，但 ls /data/adb/=Permission denied）。
     *
     *   所以凡是需要读写 root 目录的操作，一律走 su：
     *     exec("su") → 内核重定向到 /data/adb/umbral/su
     *     → 那个 sh 写 /proc/umbral/grant 登记自己 → 内核把它变成真 uid 0
     *     → 干活 → 退出
     *
     *   失败时退回普通 sh，保证非特权命令仍然能跑。
     */
    public static R suFirst(String cmd) {
        R r = root(cmd);
        if (r.ok() || r.out != null && r.out.length() > 0) {
            return r;
        }
        return plain(cmd);
    }

    public static R plain(String cmd) {
        return run(cmd, false);
    }

    private static R run(String cmd, boolean elevate) {
        R r = new R();
        Process p = null;
        try {
            String script;
            if (elevate) {
                /*
                 * 关键的两句：
                 *   echo $$ 1 > /proc/umbral/grant   把本 shell 的 pid 登记为超级用户
                 *   之后的命令就在 uid 0 下执行
                 * $$ 是 sh 自己的 pid，必须由它自己写 —— 父进程事先不知道
                 */
                script = "printf %s \"$$ 1\" | dd of=/proc/umbral/grant conv=notrunc 2>/dev/null; "
                        + "if [ \"$(id -u)\" != \"0\" ]; then "
                        + "  sleep 0.02; fi; "
                        + cmd
                        + "; echo \"__RC=$?\"";
            } else {
                script = cmd + "; echo \"__RC=$?\"";
            }

            p = Runtime.getRuntime().exec(new String[]{"sh", "-c", script});

            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            InputStream in = p.getInputStream();
            InputStream es = p.getErrorStream();
            byte[] buf = new byte[8192];
            int n;
            /* 交替读两个流，避免缓冲区塞满死锁 */
            for (int guard = 0; guard < 100000; guard++) {
                boolean got = false;
                while (in.available() > 0 && (n = in.read(buf)) > 0) {
                    bo.write(buf, 0, n);
                    got = true;
                }
                while (es.available() > 0 && (n = es.read(buf)) > 0) {
                    bo.write(buf, 0, n);
                    got = true;
                }
                if (!got) {
                    if (!p.isAlive()) {
                        break;
                    }
                    try {
                        Thread.sleep(5);
                    } catch (InterruptedException ignored) {
                    }
                }
            }
            r.code = p.waitFor();

            String out = bo.toString("UTF-8");
            /* 抽出我们附加的返回码，剩下的才是真正输出 */
            int k = out.lastIndexOf("__RC=");
            if (k >= 0) {
                out = out.substring(0, k);
            }
            r.out = out.trim();
            lastOutput = r.out;
            return r;
        } catch (Exception e) {
            r.out = "执行失败：" + e.getClass().getSimpleName();
            lastOutput = r.out;
            return r;
        } finally {
            if (p != null) {
                p.destroy();
            }
        }
    }
}
