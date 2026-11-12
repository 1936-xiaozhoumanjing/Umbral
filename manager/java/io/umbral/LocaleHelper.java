package io.umbral;

import android.app.Activity;
import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Build;
import android.os.LocaleList;

import java.util.Locale;

/**
 * 应用内语言切换。
 *
 * 支持：跟随系统 / English / 简体中文 / 日本語 / 한국어 / Русский
 *
 * 注意一个刻意的区分：
 *   · app_name（launcher 图标名）只在 values/ 里定义 → 永远显示 "Umbral"
 *   · display_name（应用内标题）各语言不同 → 中文环境显示「影核」
 * 所以桌面上永远是英文名，界面内跟随这里的设置。
 *
 * 实现方式：
 *   API 24+ 用 createConfigurationContext + LocaleList（不动全局 Configuration）
 *   这样只影响本应用，不污染系统
 */
public final class LocaleHelper {

    private static final String PREFS = "sk_settings";
    private static final String KEY = "app_locale";

    /** 索引与 locale tag 的对应；索引 0 = 跟随系统 */
    public static final String[] TAGS = {"", "en", "zh-CN", "ja", "ko", "ru"};

    /** 各语言的自称（不翻译，任何语言下都显示自己的写法） */
    private static final String[] SELF_NAMES = {"English", "简体中文", "日本語", "한국어", "Русский"};

    private LocaleHelper() {
    }

    /** 当前选择的索引（0 = 跟随系统） */
    public static int index(Context c) {
        int v = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getInt(KEY, 0);
        return (v < 0 || v >= TAGS.length) ? 0 : v;
    }

    public static void setIndex(Context c, int i) {
        if (i < 0 || i >= TAGS.length) i = 0;
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putInt(KEY, i).apply();
    }

    /** 当前应生效的 Locale；null = 跟随系统 */
    public static Locale locale(Context c) {
        int i = index(c);
        if (i == 0) return null;
        return parse(TAGS[i]);
    }

    private static Locale parse(String tag) {
        if (tag == null || tag.isEmpty()) return null;
        int dash = tag.indexOf('-');
        if (dash < 0) return new Locale(tag);
        return new Locale(tag.substring(0, dash), tag.substring(dash + 1));
    }

    /**
     * 用指定语言包装 Context。
     * 在 Activity.attachBaseContext() 里调用即可让整个界面切换到目标语言。
     */
    public static Context wrap(Context base) {
        Locale loc = locale(base);
        if (loc == null) return base;               // 跟随系统，不动

        Resources res = base.getResources();
        Configuration cfg = new Configuration(res.getConfiguration());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            cfg.setLocales(new LocaleList(loc));
        } else {
            cfg.setLocale(loc);
        }
        return base.createConfigurationContext(cfg);
    }

    /** 某个索引在界面上显示的名字 */
    public static String label(Context c, int i) {
        if (i == 0) return c.getString(R.string.lang_system);
        if (i < 1 || i > SELF_NAMES.length) return SELF_NAMES[0];
        return SELF_NAMES[i - 1];
    }

    /** 全部选项的显示名（含"跟随系统"） */
    public static String[] allLabels(Context c) {
        String[] out = new String[TAGS.length];
        for (int i = 0; i < TAGS.length; i++) out[i] = label(c, i);
        return out;
    }

    /** 切换后重建界面使语言生效 */
    public static void applyTo(Activity a) {
        a.recreate();
    }
}
