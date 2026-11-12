package io.umbral.module;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;

/**
 * ZIP 自检 —— 把缓存里最新的 picked_*.zip 跑一遍 ZipReader，
 * 每一步结果写进 /sdcard/Android/data/io.umbral/files/ziptest.txt。
 *
 * 为什么要这么一个东西：
 *   我没法操作 UI，也没法读 App 私有目录里的那个 ZIP，
 *   所以让 App 自己在启动时把 ZIP 解析过程全记下来，
 *   我从外部目录读结果就能定位 ZipReader 卡在哪一步。
 */
public final class ZipSelfTest {

    private ZipSelfTest() {
    }

    public static void run(final Context ctx) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                StringBuilder sb = new StringBuilder();
                try {
                    File cache = ctx.getCacheDir();
                    File[] fs = cache.listFiles();
                    File target = null;
                    if (fs != null) {
                        for (File f : fs) {
                            if (f.getName().startsWith("picked_") && f.getName().endsWith(".zip")) {
                                if (target == null || f.lastModified() > target.lastModified()) {
                                    target = f;
                                }
                            }
                        }
                    }

                    /*
                     * 缓存里没有（安装完就被删了）→ 去 /sdcard 里找最新的 .zip。
                     * 这样不用用户重新选一次文件也能自检。
                     */
                    if (target == null) {
                        File lf = new File(ctx.getFilesDir(), "last_failed.zip");
                        if (lf.exists()) {
                            target = lf;
                        }
                    }

                    if (target == null) {
                        String[] dirs = {"/sdcard/Download", "/sdcard/Documents",
                                "/sdcard", "/storage/emulated/0/Download"};
                        for (String d : dirs) {
                            File[] zs = new File(d).listFiles();
                            if (zs == null) {
                                continue;
                            }
                            for (File f : zs) {
                                if (f.isFile() && f.getName().toLowerCase().endsWith(".zip")) {
                                    if (target == null || f.lastModified() > target.lastModified()) {
                                        target = f;
                                    }
                                }
                            }
                        }
                    }
                    sb.append("缓存目录: ").append(cache.getAbsolutePath()).append('\n');
                    sb.append("找到 ZIP: ")
                            .append(target == null ? "无"
                                    : target.getName() + " (" + target.length() + " 字节)")
                            .append('\n');

                    if (target != null) {
                        ZipReader zr = new ZipReader(target);

                        sb.append("\n① entries()\n");
                        java.util.List<ZipReader.Entry> list = zr.entries();
                        sb.append("   条目数: ").append(list.size()).append('\n');
                        int shown = 0;
                        for (ZipReader.Entry e : list) {
                            if (shown++ < 15) {
                                sb.append("   - ").append(e.name)
                                        .append("  method=").append(e.method)
                                        .append("  csize=").append(e.compressedSize)
                                        .append("  size=").append(e.size).append('\n');
                            }
                        }

                        sb.append("\n② 读 module.prop\n");
                        ZipReader.Entry pe = zr.find(list, "module.prop");
                        if (pe == null) {
                            sb.append("   没有 module.prop\n");
                        } else {
                            sb.append("   条目方法=").append(pe.method).append('\n');
                            byte[] raw = zr.read(pe);
                            sb.append("   解出 ").append(raw.length).append(" 字节\n");
                            sb.append(new String(raw, "UTF-8")).append('\n');
                        }
                    }
                } catch (Throwable t) {
                    sb.append("\nXzDecoder.lastRc=").append(io.umbral.module.XzDecoder.lastRc()).append('\n');
                    sb.append("\n异常: ").append(t.getClass().getName())
                            .append(": ").append(t.getMessage()).append('\n')
                            .append(android.util.Log.getStackTraceString(t));
                }

                try {
                    io.umbral.Dbg.write(ctx, "ziptest.txt", sb.toString());
                    File f = new File(ctx.getFilesDir(), "ziptest.txt");
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
}
