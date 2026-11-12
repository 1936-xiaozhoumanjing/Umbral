package io.umbral;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;

/**
 * 自检日志的落盘通道 —— 同时写两份。
 *
 * ══════════════════════════════════════════════════════
 *  为什么两份
 * ══════════════════════════════════════════════════════
 *
 *  用户要求把自检文件藏起来（戊4/戊5）：任何文件管理器都能翻到
 *  /sdcard/Android/data/io.umbral/files/*.txt，等于把内部状态摊给人看。
 *
 *  但开发期我又必须能从 adb 读到这些内容来判断功能通没通。
 *
 *  所以：
 *    ① 主体写 App 私有目录 getFilesDir()——别的应用看不到
 *    ② 镜像写 /data/local/tmp/umbral/logs/ 并设 0644
 *       /data/local/tmp 属于 shell，adb shell 能读；
 *       而整个 /data/local/tmp/umbral 目录已经在自隐藏模块的清单里，
 *       对安全类扫描是「不存在」的
 *
 *  发布版可以只留 ①：把 MIRROR 改成 false 即可。
 */
public final class Dbg {

    /** 是否写镜像（调试期 true） */
    private static final boolean MIRROR = true;

    public static final String MIRROR_DIR = "/data/local/tmp/umbral/logs";

    private Dbg() {
    }

    /** 写主文件（私有目录）并镜像一份 */
    public static void write(Context ctx, String name, String text) {
        byte[] data;
        try {
            data = text.getBytes("UTF-8");
        } catch (Throwable t) {
            return;
        }

        /* ① 私有目录 */
        try {
            File f = new File(ctx.getFilesDir(), name);
            FileOutputStream fo = new FileOutputStream(f, false);
            fo.write(data);
            fo.flush();
            fo.getFD().sync();
            fo.close();
        } catch (Throwable ignored) {
        }

        /* ② 镜像到 /data/local/tmp/umbral/logs（adb 可读） */
        if (!MIRROR) {
            return;
        }
        try {
            /*
             * 父目录 /data/local/tmp/umbral 是 App 建的（原本 0700），
             * adb shell 根本进不去 → 镜像也就读不到。
             * 这里把整条链路放开到 o+rx（对安全类扫描仍然靠自隐藏模块屏蔽）。
             */
            File umbralRoot = new File("/data/local/tmp/umbral");
            if (umbralRoot.exists()) {
                //noinspection ResultOfMethodCallIgnored
                umbralRoot.setReadable(true, false);
                //noinspection ResultOfMethodCallIgnored
                umbralRoot.setExecutable(true, false);
            }
            File dir = new File(MIRROR_DIR);
            if (!dir.exists()) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
                //noinspection ResultOfMethodCallIgnored
                dir.setReadable(true, false);
                //noinspection ResultOfMethodCallIgnored
                dir.setExecutable(true, false);
            }
            File f = new File(dir, name);
            FileOutputStream fo = new FileOutputStream(f, false);
            fo.write(data);
            fo.flush();
            fo.getFD().sync();
            fo.close();
            //noinspection ResultOfMethodCallIgnored
            f.setReadable(true, false);
        } catch (Throwable ignored) {
        }
    }
}
