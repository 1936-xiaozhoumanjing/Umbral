package io.umbral.module;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;

import io.umbral.sk.Shell;

/**
 * su 可用性自检。
 *
 * 为什么需要：
 *   「执行 action.sh」按钮、装模块、跑任何特权命令，全都要靠 su 子进程。
 *   而我在 adb 里看不到 App 内部到底有没有真拿到 uid 0
 *   （日志里 elevated 一直是 0）。
 *
 * 所以让 App 自己跑几条命令，把结果写到外部目录，我从 adb 读。
 */
public final class SuProbe {

    private SuProbe() {
    }

    public static void run(final Context ctx) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                StringBuilder sb = new StringBuilder();

                /* ── KSU 式提权节点 /proc/umbral/escape ── */
                probe(sb, "escape 节点", "cat /proc/umbral/escape 2>&1");
                /*
                 * ★ 不再在自检里写 escape ★
                 *
                 * 之前这里会让 App 进程自己变成 uid 0，
                 * 结果整个应用以 root 身份运行 —— 既是暴露点，
                 * 又会让自己的 DAC 规则反噬（写不了 /data/adb/umbral）。
                 *
                 * 正确做法：App 保持普通身份，需要 root 时由 su 二进制
                 * 自己去写 escape（每次命令一个子进程）。
                 */
                sb.append("[App 身份] uid=").append(android.os.Process.myUid())
                  .append("（保持普通身份，不主动 escape）\n");

                /* escape 之后立刻查一次 id（App 自己不该变成 root，只作对照）*/
                probe(sb, "escape 后 id", "id -u");

                /* ── App 代写 grant 的通道 ── */
                try {
                    io.umbral.sk.SuBridge.R br1 = io.umbral.sk.SuBridge.root("id -u");
                    sb.append("[SuBridge: id -u] 写入内容=[")
                      .append(br1.writePayload).append("] pid=").append(br1.pid)
                      .append(" 提权=").append(br1.promoted)
                      .append(" code=").append(br1.code)
                      .append(" out=").append(br1.out).append('\n');
                    io.umbral.sk.SuBridge.R br2 = io.umbral.sk.SuBridge.root("ls /data/adb");
                    sb.append("[SuBridge: ls /data/adb] code=").append(br2.code)
                      .append(" out=").append(br2.out.replace("\n", " ")).append('\n');
                    io.umbral.sk.SuBridge.R br3 = io.umbral.sk.SuBridge.root(
                            "echo test > /data/adb/.sbprobe && cat /data/adb/.sbprobe");
                    sb.append("[SuBridge: 写文件] code=").append(br3.code)
                      .append(" out=").append(br3.out).append('\n');
                } catch (Throwable t) {
                    sb.append("[SuBridge] 异常: ").append(t).append('\n');
                }

                /* ── 原始执行（stderr 合并进 stdout，能看到真实错误）── */
                probeRaw(sb, "原生 sh: 写 grant",
                        "printf '%s 1' $$ | dd of=/proc/umbral/grant conv=notrunc");
                probeRaw(sb, "原生 sh: 直接 echo > grant（对照）",
                        "echo '10563 1' > /proc/umbral/grant");
                probeRaw(sb, "原生 sh: 写完 id -u", "id -u");
                probeRaw(sb, "当前 shell 的 pid", "echo $$");
                probeRaw(sb, "grant 节点权限", "ls -l /proc/umbral/grant");

                /* ⓪ 内核版本 + 授权表 */
                probe(sb, "内核版本", "cat /proc/umbral/version");
                probe(sb, "授权表", "cat /proc/umbral/grants");
                probe(sb, "写 grant（看 stderr）",
                        "printf '%s 1' $$ | dd of=/proc/umbral/grant conv=notrunc");
                probe(sb, "写完再查授权表", "cat /proc/umbral/grants");

                /*
                 * 探测设备上已装的 KernelSU：如果它还能用，
                 * 也许可以借它拿到真 root 去 insmod 我们的新模块，
                 * 那样就不用刷机就能验证 execve 赋权。
                 */
                probe(sb, "ksu 目录", "ls -la /data/adb/ksu 2>&1 | head -12");
                probe(sb, "ksu bin", "ls -la /data/adb/ksu/bin 2>&1 | head -8");
                probe(sb, "ksud 路径", "which ksud su 2>&1; ls -l /data/adb/ksu/bin/su 2>&1");
                probe(sb, "ksu allowlist", "ls -la /data/adb/ksu/*.db /data/adb/ksu/*.json 2>&1 | head -6");

                /* ① 直接执行 id（不经过 su）—— 基线 */
                probe(sb, "直接 id -u", "/system/bin/id -u");
                /* ② 经过 su */
                probe(sb, "su: id -u", "id -u");
                /* ③ su 读 /data/adb */
                probe(sb, "su: ls /data/adb/modules", "ls /data/adb/modules | head -3");
                /* ④ su 写一个测试文件 */
                probe(sb, "su: 写 /data/adb/.probe", "echo ok > /data/adb/.probe && cat /data/adb/.probe");

                /* 守护进程：起没起来 + 能不能执行命令 */
                try {
                    int dpid = io.umbral.sk.Daemon.start();
                    sb.append("守护进程 pid=").append(dpid).append('\n');
                    String out = io.umbral.sk.Daemon.run("id -u", 3000);
                    sb.append("守护心跳=").append(io.umbral.sk.Daemon.heartbeat().trim())
                      .append('\n');
                    sb.append("守护执行 id -u → ").append(out == null ? "超时" : out.trim())
                      .append('\n');
                } catch (Throwable t) {
                    sb.append("守护进程异常: ").append(t).append('\n');
                }

                sb.append("签名摘要: ").append(io.umbral.sk.SignatureCheck.digest)
                  .append("  (").append(io.umbral.sk.SignatureCheck.identity).append(")\n");
                sb.append("assets 清单: ")
                  .append(io.umbral.sk.SuCompat.assetList).append('\n');
                sb.append("SuCompat.lastError: ")
                  .append(io.umbral.sk.SuCompat.lastError).append('\n');

                /* ⑤ su 是二进制还是脚本 */
                try {
                    java.io.FileInputStream fi = new java.io.FileInputStream("/data/local/tmp/umbral/su");
                    byte[] h = new byte[4];
                    int got = fi.read(h);
                    fi.close();
                    String kind = (got == 4 && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F')
                            ? "ELF 二进制" : new String(h, 0, Math.max(0, got), "UTF-8");
                    sb.append("su 类型: ").append(kind).append('\n');
                } catch (Throwable t) {
                    sb.append("su 类型: 读取失败 ").append(t).append('\n');
                }

                /* ⑥ su 文件是否存在 */
                File su = new File("/data/local/tmp/umbral/su");
                sb.append("su 脚本: ").append(su.exists() ? ("存在 " + su.length() + " 字节")
                        : "不存在").append('\n');

                try {
                    io.umbral.Dbg.write(ctx, "su_status.txt", sb.toString());
                    File f = new File(ctx.getFilesDir(), "su_status.txt");
                    FileOutputStream fo = new FileOutputStream(f);
                    fo.write(sb.toString().getBytes("UTF-8"));
                    fo.flush();
                    fo.getFD().sync();
                    fo.close();
                } catch (Throwable ignored) {
                }
            }
        }).start();
    }

    private static void probe(StringBuilder sb, String label, String cmd) {
        try {
            Shell.R r = Shell.root(cmd);
            sb.append("[").append(label).append("] code=").append(r.code)
                    .append(" ok=").append(r.ok())
                    .append(" out=").append(r.out == null ? "null" : r.out.trim())
                    .append('\n');
        } catch (Throwable t) {
            sb.append("[").append(label).append("] 异常: ").append(t).append('\n');
        }
    }

    /** 直接用 ProcessBuilder 跑，stderr 合并进 stdout —— 不吞任何错误 */
    private static void probeRaw(StringBuilder sb, String label, String cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c", cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            StringBuilder o = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                o.append(line).append(" | ");
            }
            int code = p.waitFor();
            sb.append("[").append(label).append("] code=").append(code)
                    .append(" out=").append(o.length() == 0 ? "（空）" : o.toString())
                    .append('\n');
        } catch (Throwable t) {
            sb.append("[").append(label).append("] 异常: ").append(t).append('\n');
        }
    }
}
