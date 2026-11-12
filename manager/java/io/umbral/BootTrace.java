package io.umbral;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;

import java.io.File;
import java.io.FileOutputStream;

/**
 * 最早期的崩溃探针。
 *
 * ContentProvider.onCreate() 是整个 App 进程里**最早**能跑自己代码的地方：
 *   比 Application.attachBaseContext 早，比任何 Activity 早，
 *   也在 ART 完成大部分静态初始化之后。
 *
 * 所以：如果崩溃发生在 onCreate 里打断点都来不及的阶段，
 * 这个探针能告诉我们「进程起来了没有」。
 *
 * 写入同样必须 fsync —— 崩溃场景下不加 fsync 的文件内容会变成空洞。
 */
public class BootTrace extends ContentProvider {

    @Override
    public boolean onCreate() {
        android.util.Log.i("UMBRAL_TRACE", "provider onCreate, filesDir="
                + (getContext() == null ? "null" : String.valueOf(getContext().getFilesDir())));
        write("provider:onCreate");
        return true;
    }

    private void write(String msg) {
        FileOutputStream out = null;
        try {
            File f = new File(getContext().getFilesDir(), "trace.log");
            if (f.length() > 512 * 1024) {
                //noinspection ResultOfMethodCallIgnored
                f.delete();
            }
            out = new FileOutputStream(f, true);
            out.write((System.currentTimeMillis() + "  " + msg + "\n").getBytes("UTF-8"));
            out.flush();
            out.getFD().sync();
        } catch (Throwable t) {
            android.util.Log.e("UMBRAL_TRACE", "provider write failed: " + msg, t);
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
