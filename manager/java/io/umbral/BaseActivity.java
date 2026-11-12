package io.umbral;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;

/**
 * 所有界面的基类。
 *
 * 两件事必须在 super.onCreate() 之前完成：
 *   1. 语言（attachBaseContext）—— 比 onCreate 更早，否则资源已经按旧语言解析
 *   2. 配色（setTheme）      —— 必须在贴布局之前
 */
public class BaseActivity extends Activity {

    @Override
    protected void attachBaseContext(Context newBase) {
        super.attachBaseContext(LocaleHelper.wrap(newBase));
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        /*
         * 崩溃现场落盘：Android 15 上 logcat / dropbox 都被 SELinux 挡住，
         * 拿不到堆栈就没法定位。这里自己记一份到外部目录，adb 能直接读。
         *
         * 注意：文件路径必须在 handler 内部才去取 ——
         *       onCreate 里 super 之前调 getExternalFilesDir 会抛异常，
         *       那样 catch 吞掉之后 handler 根本没装上（踩过）。
         */
        try {
            final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
            Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
                @Override
                public void uncaughtException(Thread t, Throwable e) {
                    try {
                        java.io.File f = new java.io.File(getExternalFilesDir(null), "crash.txt");
                        java.io.FileOutputStream fo = new java.io.FileOutputStream(f, true);
                        fo.write(("=== " + new java.util.Date() + " ===\n"
                                + android.util.Log.getStackTraceString(e) + "\n\n").getBytes("UTF-8"));
                        fo.close();
                    } catch (Throwable ignored) {
                    }
                    if (prev != null) {
                        prev.uncaughtException(t, e);
                    }
                }
            });
        } catch (Throwable ignored) {
        }

        ThemeManager.apply(this);
        super.onCreate(savedInstanceState);
    }
}
