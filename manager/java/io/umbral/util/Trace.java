package io.umbral.util;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;

/**
 * 崩溃追踪 —— 把 App 的执行步骤写到磁盘，重启后能看到崩在哪一步。
 *
 * 为什么需要：
 *   设备 panic 后 pstore / last_kmsg 都是空的（这台 NX769J 就没留过记录），
 *   dmesg 也跟着重启一起没了。唯一活下来的东西是文件系统。
 *
 * ★ 必须 fsync ★
 *   第一版用 FileWriter + flush，崩溃后拉出来的日志是
 *   「长度 595 字节、内容全是 0x00」—— 这是文件系统 delayed allocation
 *   的典型特征：size 是元数据（有日志保护，先落了），数据还在 page cache
 *   里没写下去，panic 之后就成了空洞。
 *   所以每一步写入后必须 getFD().sync()，否则这个日志在崩溃场景下毫无用处
 *   —— 而崩溃场景恰恰是它唯一的使用场景。
 */
public final class Trace {

    private static final String FILE = "trace.log";
    private static final long MAX = 512 * 1024;

    private Trace() {
    }

    public static void step(Context ctx, String msg) {
        if (ctx == null) {
            return;
        }
        FileOutputStream out = null;
        try {
            File f = new File(ctx.getFilesDir(), FILE);
            if (f.length() > MAX) {
                //noinspection ResultOfMethodCallIgnored
                f.delete();
            }
            out = new FileOutputStream(f, true);
            out.write((System.currentTimeMillis() + "  " + msg + "\n").getBytes("UTF-8"));
            out.flush();
            /* 这一句是这个类存在的全部意义 */
            out.getFD().sync();
        } catch (Throwable t) {
            android.util.Log.e("UMBRAL_TRACE", "step failed: " + msg, t);
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    public static void clear(Context ctx) {
        try {
            //noinspection ResultOfMethodCallIgnored
            new File(ctx.getFilesDir(), FILE).delete();
        } catch (Throwable ignored) {
        }
    }
}
