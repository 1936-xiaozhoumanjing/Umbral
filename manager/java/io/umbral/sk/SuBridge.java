package io.umbral.sk;

import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;

/**
 * ★ App 代写 grant 的提权通道（对齐 magiskd 的做法）★
 *
 * 为什么不能在 shell 里自己写：
 *   实测 `printf '%s 1' $$ | dd of=/proc/umbral/grant conv=notrunc`
 *   写入成功（7 字节、无 EPERM），但内核的 pid 授权表 count 一直是 0
 *   —— 因为真正执行 write 的是 dd 进程，内核拿到的 current 不是那个 shell。
 *
 * 所以改成「App 帮子进程登记」：
 *   ① App 起一个 sh，sh 先把自己的 pid 写进一个文件，然后**等**一个 go 文件
 *   ② App 轮询那个 pid 文件，读到 pid
 *   ③ App 自己用 ParcelFileDescriptor 写 /proc/umbral/grant："<pid> 1"
 *   ④ App 创建 go 文件，sh 继续执行命令
 *   ⑤ sh 的下一个系统调用 → 内核 commit_creds → 真 uid 0
 *
 * 关键点：
 *   · 写 grant 的是 App（有影子权限，sk_writer_allowed 认它）
 *   · 登记的是 sh 的 pid（内容里的 pid）
 *   · 写 proc 文件必须用 ParcelFileDescriptor（不能 O_TRUNC）
 */
public final class SuBridge {

    private static final String DIR = "/data/adb/umbral";
    private static final String PID_FILE = DIR + "/.pid";
    private static final String GO_FILE = DIR + "/.go";

    private SuBridge() {
    }

    /** 一条命令的执行结果 */
    public static final class R {
        public int code = -1;
        public String out = "";
        public int pid = -1;
        public boolean promoted;
        /** 实际写进 /proc/umbral/grant 的字符串（排查 pid/uid 混淆用） */
        public String writePayload = "";

        public boolean ok() {
            return code == 0;
        }
    }

    /**
     * 用「App 代写 grant」的方式执行命令，尽量让它拿到真 uid 0。
     */
    /** 默认 20 秒超时 */
    public static R root(String cmd) {
        return root(cmd, 20000);
    }

    /** 带超时的版本 —— service.sh 这类常驻脚本必须给上限 */
    public static R root(String cmd, int timeoutMs) {
        /*
         * ★ 直接 exec su 二进制（传统 su 的调用方式）★
         *
         * 内核的 execve 钩子只在「被 exec 的文件名恰好是 su」时才赋权。
         * 之前我们起的是 /system/bin/sh，内核看到名字是 sh → 跳过 → 永远 10563。
         * 所以这里必须先走 su，让它自己 sh -c 执行命令。
         *
         * su 不在（没落地）时退回原来的 sh + 代写 grant 握手路径。
         */
        R direct = runViaSuBinary(cmd, timeoutMs);
        if (direct != null) {
            return direct;
        }

        R r = new R();

        /* 清掉上次的握手文件 */
        deleteQuietly(PID_FILE);
        deleteQuietly(GO_FILE);

        /* 目标 shell：先报告 pid，然后等 go */
        String script = "echo $$ > " + PID_FILE + "; "
                + "i=0; while [ ! -f " + GO_FILE + " ] && [ $i -lt 200 ]; do "
                + "sleep 0.01; i=$((i+1)); done; "
                + "id -u; " + cmd;

        Process p;
        try {
            p = new ProcessBuilder("/system/bin/sh", "-c", script)
                    .redirectErrorStream(true)
                    .start();
        } catch (Throwable t) {
            r.out = "启动 shell 失败: " + t;
            return r;
        }

        /* 等它把 pid 写出来（最多 1.5 秒） */
        int childPid = -1;
        for (int i = 0; i < 150; i++) {
            childPid = readInt(PID_FILE);
            if (childPid > 0) {
                break;
            }
            sleepQuietly(10);
        }
        r.pid = childPid;

        /* App 代写 grant —— 把实际写进去的字符串记下来（pid/uid 混了要一眼看得出）*/
        r.writePayload = "";
        if (childPid > 0) {
            r.writePayload = childPid + " 1";
            r.promoted = writeProc("/proc/umbral/grant", r.writePayload);
        }

        /* 放行 */
        touch(GO_FILE);

        /* 收输出（★ 必须带超时：service.sh 有前台常驻型脚本） */
        try {
            final StringBuilder sb = new StringBuilder();
            final Process proc = p;
            Thread reader = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        java.io.BufferedReader br = new java.io.BufferedReader(
                                new java.io.InputStreamReader(proc.getInputStream()));
                        String line;
                        while ((line = br.readLine()) != null) {
                            sb.append(line).append('\n');
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
            reader.setDaemon(true);
            reader.start();

            boolean finished = p.waitFor(Math.max(1000, timeoutMs),
                    java.util.concurrent.TimeUnit.MILLISECONDS);
            if (finished) {
                reader.join(600);
                r.code = p.exitValue();
                r.out = sb.toString().trim();
            } else {
                /* 常驻脚本：强制结束，但保留已读到的输出 */
                p.destroyForcibly();
                r.out = sb.toString().trim() + "\n[超时 " + timeoutMs + "ms，已强制结束]";
                r.code = -2;
            }
        } catch (Throwable t) {
            r.out = String.valueOf(t);
        }

        deleteQuietly(PID_FILE);
        deleteQuietly(GO_FILE);
        return r;
    }

    /**
     * 用真 su 二进制执行：su -c "命令"
     *
     * @return 结果；su 不存在时返回 null（让调用方退回握手路径）
     */
    private static R runViaSuBinary(String cmd, int timeoutMs) {
        File su = new File("/data/local/tmp/umbral/su");
        if (!su.exists()) {
            return null;
        }
        R r = new R();
        r.writePayload = "su -c（execve 赋权路径）";
        Process p;
        try {
            p = new ProcessBuilder(su.getAbsolutePath(), "-c", cmd)
                    .redirectErrorStream(true)
                    .start();
        } catch (Throwable t) {
            return null;
        }
        try {
            final StringBuilder sb = new StringBuilder();
            final Process proc = p;
            Thread reader = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        java.io.BufferedReader br = new java.io.BufferedReader(
                                new java.io.InputStreamReader(proc.getInputStream()));
                        String line;
                        while ((line = br.readLine()) != null) {
                            sb.append(line).append('\n');
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
            reader.setDaemon(true);
            reader.start();

            boolean finished = p.waitFor(Math.max(1000, timeoutMs),
                    java.util.concurrent.TimeUnit.MILLISECONDS);
            if (finished) {
                reader.join(600);
                r.code = p.exitValue();
                r.out = sb.toString().trim();
            } else {
                p.destroyForcibly();
                r.out = sb.toString().trim() + "\n[超时 " + timeoutMs + "ms，已强制结束]";
                r.code = -2;
            }
            r.promoted = true;
            return r;
        } catch (Throwable t) {
            return null;
        }
    }

    // ── 工具 ──

    /** 写 proc 文件：必须 ParcelFileDescriptor（不能带 O_TRUNC） */
    public static boolean writeProc(String path, String content) {
        ParcelFileDescriptor pfd = null;
        try {
            pfd = ParcelFileDescriptor.open(new File(path),
                    ParcelFileDescriptor.MODE_WRITE_ONLY);
            FileOutputStream o = new FileOutputStream(pfd.getFileDescriptor());
            o.write(content.getBytes("UTF-8"));
            o.flush();
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            try { if (pfd != null) pfd.close(); } catch (Exception ignored) { }
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

    private static void touch(String path) {
        try {
            new FileOutputStream(new File(path), false).close();
        } catch (Throwable ignored) {
        }
    }

    private static void deleteQuietly(String path) {
        try {
            //noinspection ResultOfMethodCallIgnored
            new File(path).delete();
        } catch (Throwable ignored) {
        }
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {
        }
    }
}
