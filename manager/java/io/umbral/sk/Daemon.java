package io.umbral.sk;

import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;

/**
 * 常驻命令守护进程（对齐 magiskd / ksud 的角色）。
 *
 * ══════════════════════════════════════════════════════
 *  为什么要有它
 * ══════════════════════════════════════════════════════
 *
 *  Magisk 有 magiskd、KSU 有 ksud —— 都是一个开机就活着、
 *  以 root 身份等命令的进程。su 客户端把命令交给它，
 *  由它 fork 出 root 子进程执行。
 *
 *  好处：
 *    · root 身份只建立一次，不用每条命令都重新提权
 *    · 环境变量（MODPATH/PATH）在一个地方维护
 *    · 模块脚本的连续调用不会每次都付一次 execve 的开销
 *
 * ══════════════════════════════════════════════════════
 *  我们这版的实现（文件队列，不用 unix socket）
 * ══════════════════════════════════════════════════════
 *
 *   App 侧                     守护进程（sh 循环）
 *   ────────                   ──────────────────
 *   写 cmd 文件        →       每 50ms 看一眼
 *                              有命令就 eval，输出写 out 文件
 *   读 out 文件        ←
 *   写 .ack 文件       →       rm cmd，等下一条
 *
 *  用文件而不是 socket 的原因：不需要额外权限、不需要 netlink、
 *  App 和 sh 都能直接读写，出问题好排查。
 *
 *  ★ 它能不能是 root，取决于内核的 execve 赋权（v1.10+）★
 *    没赋权时它就是个普通 sh —— 队列机制照样能验证，
 *    但执行出来的命令没有 root 权限。
 */
public final class Daemon {

    /*
     * 守护目录从 /data/local/tmp/umbral/daemon 挪到 App 私有目录。
     *
     * 原因：/data/local/tmp 的标签是 shell_data_file，由 App 派生的 sh 子进程
     * 每秒写一次 hb 心跳 → 每次都产生 4 条 avc: denied（permissive=1 仍然记录）。
     * 实测审计队列被打爆（audit_lost 累计 9000+，rate limit exceeded 500+ 次），
     * 进而把 system_server 拖住：整机画面冻结、只剩状态栏。
     *
     * 放在 /data/user/0/io.umbral/files 下，属主就是本 App，
     * 同 uid 访问不产生任何 avc 记录，也不需要任何特权。
     */
    private static final String DIR = "/data/user/0/io.umbral/files/daemon";
    private static final String CMD = DIR + "/cmd";
    private static final String OUT = DIR + "/out";
    private static final String ACK = DIR + "/ack";
    private static final String PID = DIR + "/pid";
    private static final String HB = DIR + "/hb";

    private static volatile boolean started;

    private Daemon() {
    }

    public static String dir() {
        return DIR;
    }

    /**
     * 启动守护循环（幂等：已经在跑就不重复起）。
     *
     * @return 守护进程 pid；失败 -1
     */
    public static synchronized int start() {
        if (started) {
            int p = readInt(PID);
            if (p > 0) {
                return p;
            }
        }

        File d = new File(DIR);
        if (!d.exists()) {
            //noinspection ResultOfMethodCallIgnored
            d.mkdirs();
        }
        /*
         * ★ 必须删 pid 文件 ★
         * 否则下面「等 pid」的循环会立刻读到上一次（已死）的 pid，
         * 判定「已经在跑」直接返回，命令写进 cmd 文件却没人消费 —— 
         * 表现就是 out 永远为空。
         */
        clearFile(PID);
        clearFile(CMD);
        clearFile(OUT);
        clearFile(ACK);
        started = false;

        /*
         * 守护循环本体。
         *   · 把自己的 pid 写出来，便于 App 判断活没活
         *   · 每 50ms 检查 cmd 文件；有内容就执行，输出写到 out
         *   · 执行完写 ack，App 收到 ack 才读 out（避免读到半截）
         */
        /*
         * ★ 输出重定向必须落在 eval 那一句上 ★
         *
         * 上一版写成 ( eval "$c" ) > OUT 2>&1，结果 out 文件永远是空的：
         * 子 shell 的输出被外层进程的 stdout（我们没读的管道）抢走了。
         * 现在把重定向直接跟在 eval 后面，并且起进程时把 stdout 丢给 /dev/null，
         * 不再依赖父进程读管道。
         */
        String script = "echo $$ > " + PID + "; "
                + "n=0; "
                + "while true; do "
                + "  n=$((n+1)); echo $n > " + HB + "; "
                + "  if [ -s " + CMD + " ]; then "
                + "    c=$(cat " + CMD + "); "
                + "    rm -f " + CMD + "; "
                + "    eval \"$c\" > " + OUT + " 2>&1; "
                + "    echo done > " + ACK + "; "
                + "  fi; "
                + "  sleep 1; "
                + "done";

        try {
            new ProcessBuilder("/system/bin/sh", "-c", script)
                    .redirectOutput(new File("/dev/null"))
                    .redirectError(new File("/dev/null"))
                    .start();
        } catch (Throwable t) {
            return -1;
        }

        /* 等它把 pid 写出来 */
        for (int i = 0; i < 60; i++) {
            int p = readInt(PID);
            if (p > 0) {
                started = true;
                return p;
            }
            sleepQuietly(20);
        }
        return -1;
    }

    /**
     * 通过守护进程执行一条命令（同步等结果）。
     *
     * @return 命令输出；超时或守护没起来返回 null
     */
    public static String run(String command, int timeoutMs) {
        /*
         * ★ 实测结论：文件轮询式守护在当前环境跑不住 ★
         *
         * 心跳只到 1 —— 循环第一轮之后就停了（子进程被回收/sleep 行为差异）。
         * 而 SuBridge（每次起一个 sh、App 代写 grant、握手放行）已经在
         * 模块引擎里连续跑通十几次命令、输出完整。
         *
         * 所以：Daemon.run 直接走 SuBridge 这条已验证的通路，
         * 常驻进程留到 v111 刷入、su 真能到 uid 0 之后再回来做
         * （那时才有意义 —— 现在常驻的也是一个普通 sh）。
         */
        try {
            SuBridge.R r = SuBridge.root(command);
            return r.out == null ? "" : r.out;
        } catch (Throwable t) {
            /* SuBridge 兜底失败 → 再退到轮询守护 */
        }

        int pid = start();
        if (pid <= 0) {
            return null;
        }

        long mark = System.currentTimeMillis() / 1000L;
        clearFile(ACK);

        FileOutputStream fo = null;
        try {
            /* 原子写：先写 .tmp 再 mv，避免守护读到半截内容 */
            fo = new FileOutputStream(CMD + ".tmp", false);
            fo.write(command.getBytes("UTF-8"));
            fo.flush();
            fo.getFD().sync();
            fo.close();
            fo = null;
            java.io.File tmpF = new java.io.File(CMD + ".tmp");
            java.io.File dstF = new java.io.File(CMD);
            //noinspection ResultOfMethodCallIgnored
            tmpF.renameTo(dstF);
        } catch (Throwable t) {
            try { if (fo != null) fo.close(); } catch (Exception ignored) { }
            return null;
        }

        /* 等 ack */
        long deadline = System.currentTimeMillis() + Math.max(1000, timeoutMs);
        while (System.currentTimeMillis() < deadline) {
            if (new File(ACK).exists()) {
                break;
            }
            sleepQuietly(20);
        }
        if (!new File(ACK).exists()) {
            return null;
        }
        return readAll(new File(OUT));
    }

    public static int pid() {
        return readInt(PID);
    }

    // ── 工具 ──

    private static void clearFile(String path) {
        try {
            new FileOutputStream(new File(path), false).close();
        } catch (Throwable ignored) {
        }
    }

    private static int readInt(String path) {
        RandomAccessFile f = null;
        try {
            File file = new File(path);
            if (!file.exists() || file.length() == 0) {
                return -1;
            }
            f = new RandomAccessFile(file, "r");
            String s = f.readLine();
            if (s == null) {
                return -1;
            }
            return Integer.parseInt(s.trim());
        } catch (Throwable t) {
            return -1;
        } finally {
            try { if (f != null) f.close(); } catch (Exception ignored) { }
        }
    }

    private static String readAll(File f) {
        RandomAccessFile r = null;
        try {
            if (!f.exists()) {
                return "";
            }
            r = new RandomAccessFile(f, "r");
            byte[] b = new byte[(int) Math.min(f.length(), 1024 * 1024)];
            r.readFully(b);
            return new String(b, "UTF-8");
        } catch (Throwable t) {
            return "";
        } finally {
            try { if (r != null) r.close(); } catch (Exception ignored) { }
        }
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {
        }
    }

    /** 守护循环的迭代计数（能读到说明循环真的在转） */
    public static String heartbeat() {
        return readAll(new File(HB));
    }
}
