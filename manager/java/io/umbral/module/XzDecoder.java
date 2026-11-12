package io.umbral.module;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

/**
 * XZ 解码器（JNI 调设备自带的 liblzma.so）。
 *
 * ★ 为什么走 assets 而不是 lib/ ★
 *
 * Android 15 要求 APK 里的原生库按 16KB 页对齐存放，
 * 而我们的 build.ps1 是手工建 zip，做不到对齐
 * → System.loadLibrary 找不到库（实测 lib/arm64/libumbral_xz.so 根本没被解出来）。
 *
 * 改成：.so 放 assets，首次使用时拷到 filesDir，再 System.load(绝对路径)。
 * 这条路不依赖任何对齐规则，最稳。
 */
public final class XzDecoder {

    private static Context appCtx;
    public static String lastError;

    private static boolean tried;
    private static boolean available;

    private XzDecoder() {
    }

    /** 由 ManagerApplication / 任意 Activity 启动时调一次 */
    public static void attach(Context ctx) {
        if (appCtx == null && ctx != null) {
            appCtx = ctx.getApplicationContext();
        }
    }

    public static synchronized boolean available() {
        if (tried) {
            return available;
        }
        tried = true;

        /* ① 先试标准位置（如果哪天对齐做好了，这条更快） */
        try {
            System.loadLibrary("umbral_xz");
            available = true;
            return true;
        } catch (Throwable ignored) {
        }

        /* ② assets 落盘再 load */
        Context ctx = appCtx;
        if (ctx == null) {
            return false;
        }
        InputStream in = null;
        FileOutputStream out = null;
        try {
            File so = new File(ctx.getFilesDir(), "libumbral_xz.so");
            in = ctx.getAssets().open("lib/arm64-v8a/libumbral_xz.so");
            out = new FileOutputStream(so);
            byte[] buf = new byte[16 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            out.flush();
            out.getFD().sync();
            out.close();
            out = null;
            in.close();
            in = null;

            System.load(so.getAbsolutePath());
            available = true;
        } catch (Throwable t) {
            available = false;
        } finally {
            try { if (in != null) in.close(); } catch (Exception ignored) { }
            try { if (out != null) out.close(); } catch (Exception ignored) { }
        }
        return available;
    }

    /**
     * 解压 XZ 数据。
     *
     * ★ 优先纯 Java 实现（org.tukaani.xz）★
     *
     * 原因：Android 的 linker namespace 不允许 App dlopen 系统私有的
     * liblzma.so（它不在 /system/etc/public.libraries.txt 白名单里），
     * 所以 JNI 那条路在真机上 dlopen 一定失败。
     *
     * 纯 Java 解码器没有这个限制，也不需要任何 native 库。
     * JNI 保留作为兜底（万一将来系统把它加进白名单）。
     */
    public static byte[] decode(byte[] in) {
        if (in == null || in.length == 0) {
            return null;
        }
        /* ① 纯 Java */
        try {
            java.io.ByteArrayInputStream bi = new java.io.ByteArrayInputStream(in);
            org.tukaani.xz.XZInputStream xz = new org.tukaani.xz.XZInputStream(bi);
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream(
                    Math.max(1024, in.length * 4));
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = xz.read(buf)) > 0) {
                bo.write(buf, 0, n);
            }
            xz.close();
            byte[] out = bo.toByteArray();
            if (out.length > 0) {
                return out;
            }
        } catch (Throwable t) {
            lastError = t.getClass().getName() + ": " + t.getMessage();
        }
        /* ② JNI 兜底 */
        if (!available()) {
            return null;
        }
        try {
            return nativeDecode(in);
        } catch (Throwable t) {
            lastError = (lastError == null ? "" : lastError + " | ")
                    + "JNI: " + t.getClass().getName() + ": " + t.getMessage();
            return null;
        }
    }

    private static native byte[] nativeDecode(byte[] in);

    /** 上一次解码失败时 liblzma 的返回码（0=成功；9=数据错误；10=缓冲不够） */
    public static native int lastRc();
}
