package io.umbral.launcher;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * 一次脚本执行会话。
 *
 * 和 LauncherStore.run() 的区别：那个是「跑完再给结果」，这个要**边跑边喂**。
 *
 *   输出：子进程的 stdout+stderr 合流，逐块回调给界面（实时滚动）
 *   输入：界面把用户敲的字写进子进程 stdin，脚本里的 read 就能收到
 *
 * 为什么用 ProcessBuilder 而不是 Runtime.exec：
 *   ProcessBuilder 能设工作目录、能重定向错误流、还能后续拿 stdin。
 *
 * ⚠ 已知限制：靠 getevent 读音量键的脚本在这里收不到按键 —— 那需要读
 *   /dev/input 或 root 权限，普通应用办不到。能读 stdin 的脚本正常可用。
 */
public final class LauncherSession {

    /** 回调都在**后台线程**上，界面层自己切主线程 */
    public interface Listener {
        void onOutput(String chunk);

        void onExit(int code);
    }

    private final Process proc;
    private final OutputStream stdin;
    private final Thread pump;
    private volatile boolean alive = true;

    private LauncherSession(Process proc) {
        this.proc = proc;
        this.stdin = proc.getOutputStream();
        this.pump = null;
    }

    /**
     * 启动一个脚本。
     *
     * .sh 走 /system/bin/sh，其它（含已 chmod +x 的二进制）直接 exec。
     */
    public static LauncherSession start(final File script, final File workDir,
                                        final Listener listener) throws IOException {
        return start(script, workDir, false, listener);
    }

    /**
     * 启动脚本。
     *
     * @param asRoot true = 通过 su 以 root 身份执行
     */
    public static LauncherSession start(final File script, final File workDir,
                                        final boolean asRoot,
                                        final Listener listener) throws IOException {
        String name = script.getName().toLowerCase();
        if (name.endsWith(".ko")) {
            throw new IOException("insmod requires root");
        }

        String[] cmd;
        if (asRoot) {
            /*
             * root 模式：把整条命令交给 su -c。
             *
             * 为什么要写成一整条 shell 串而不是 su + argv：
             *   su -c 只接受一个字符串，它自己会交给 shell 解析。
             *   里面有 cd / export，是为了让脚本拿到的环境和普通模式一致
             *   —— 否则 root 下 PATH 可能是空的，脚本里的 ls 都找不到。
             */
            StringBuilder sb = new StringBuilder();
            if (workDir != null && workDir.isDirectory()) {
                sb.append("cd ").append(quote(workDir.getAbsolutePath()))
                  .append(" 2>/dev/null; ");
            }
            sb.append("export PATH=/system/bin:/system/xbin:/vendor/bin; ");
            sb.append("export HOME=")
              .append(quote(workDir == null ? "/" : workDir.getAbsolutePath()))
              .append("; ");
            sb.append("export TERM=dumb; ");
            if (name.endsWith(".sh")) {
                sb.append("exec /system/bin/sh ").append(quote(script.getAbsolutePath()));
            } else {
                sb.append("exec ").append(quote(script.getAbsolutePath()));
            }
            /*
             * ★ 不用 su —— 走我们自己的提权子进程 ★
             *
             * su 是 KernelSU/Magisk 才有的东西；换成我们的 root 之后它不存在。
             * 改成：让 sh 自己把 pid 登记进 /proc/umbral/grant，
             * 内核下一个 syscall 就把它 commit_creds 成 uid 0。
             *
             * $$ 是 sh 自己的 pid，必须由它自己写（父进程不知道）。
             */
            String pre = "printf %s \"$$ 1\" | dd of=/proc/umbral/grant conv=notrunc 2>/dev/null; ";
            cmd = new String[]{"sh", "-c", pre + sb.toString()};
        } else if (name.endsWith(".sh")) {
            cmd = new String[]{"/system/bin/sh", script.getAbsolutePath()};
        } else {
            cmd = new String[]{script.getAbsolutePath()};
        }

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);          // 错误流合进输出，终端里一并显示
        if (workDir != null && workDir.isDirectory()) {
            pb.directory(workDir);
        }
        // 给脚本一个像样的环境，否则 PATH 缺失会让常见命令找不到
        pb.environment().put("PATH", "/system/bin:/system/xbin:/vendor/bin");
        pb.environment().put("HOME", workDir == null ? "/" : workDir.getAbsolutePath());
        pb.environment().put("TERM", "dumb");   // 不要 ANSI 转义，TextView 显示不了

        final Process proc = pb.start();
        final LauncherSession s = new LauncherSession(proc);

        // 输出泵：读一行回调一次，行内不缓冲 —— 交互式脚本的提示常常没有换行
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                BufferedReader r = null;
                try {
                    r = new BufferedReader(new InputStreamReader(
                            proc.getInputStream(), StandardCharsets.UTF_8));
                    char[] buf = new char[1024];
                    int n;
                    while ((n = r.read(buf)) > 0) {
                        if (listener != null) {
                            listener.onOutput(new String(buf, 0, n));
                        }
                    }
                } catch (Exception ignored) {
                } finally {
                    closeQuietly(r);
                    s.alive = false;
                    int code = -1;
                    try {
                        code = proc.waitFor();
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    }
                    if (listener != null) {
                        listener.onExit(code);
                    }
                }
            }
        }, "umbral-term-pump");
        t.setDaemon(true);
        t.start();

        return s;
    }

    /** 把文字写进脚本的 stdin。会自动补换行吗？不 —— 调用方决定。 */
    public void send(String text) {
        if (text == null || stdin == null) {
            return;
        }
        try {
            stdin.write(text.getBytes(StandardCharsets.UTF_8));
            stdin.flush();
        } catch (Exception ignored) {
        }
    }

    /** 回车 / 确认 */
    public void sendLine(String text) {
        send((text == null ? "" : text) + "\n");
    }

    /** 结束进程（先温和 destroy，必要时强杀） */
    public void stop() {
        alive = false;
        try {
            proc.destroy();
        } catch (Exception ignored) {
        }
        // 给 200ms 让它自己退，不退就强杀
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException ignored) {
                }
                try {
                    if (proc.isAlive()) {
                        proc.destroyForcibly();
                    }
                } catch (Exception ignored) {
                }
            }
        }, "umbral-term-kill").start();
    }

    public boolean isAlive() {
        try {
            return alive && proc.isAlive();
        } catch (Exception e) {
            return false;
        }
    }

    /** shell 单引号转义：' → '\'' */
    private static String quote(String s) {
        if (s == null) {
            return "''";
        }
        return "'" + s.replace("'", "'\\''") + "'";
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
