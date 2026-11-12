package io.umbral;

import android.app.Activity;
import android.content.Context;

/**
 * 4 套配色：
 *   0 浅色 / 1 深色 / 2 淡蓝色 / 3 淡粉色
 *
 * 必须在每个 Activity 的 super.onCreate() 之前 setTheme()。
 */
public final class ThemeManager {

    public static final int LIGHT = 0;
    public static final int DARK  = 1;
    public static final int BLUE  = 2;
    public static final int PINK  = 3;

    private static final String PREFS = "sk_settings";
    private static final String KEY = "theme";

    private static final int[] THEMES = {
            R.style.Theme_Umbral_Light,
            R.style.Theme_Umbral_Dark,
            R.style.Theme_Umbral_Blue,
            R.style.Theme_Umbral_Pink
    };

    private static final int[] NAMES_RES = {
            R.string.theme_light, R.string.theme_dark, R.string.theme_blue, R.string.theme_pink
    };

    private ThemeManager() {
    }

    public static int get(Context c) {
        int v = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getInt(KEY, DARK);
        return (v < 0 || v >= THEMES.length) ? DARK : v;
    }

    public static void set(Context c, int v) {
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putInt(KEY, v).apply();
    }

    public static String name(Context c) {
        return c.getString(NAMES_RES[get(c)]);
    }

    public static String[] names(Context c) {
        String[] out = new String[NAMES_RES.length];
        for (int i = 0; i < out.length; i++) out[i] = c.getString(NAMES_RES[i]);
        return out;
    }

    public static void apply(Activity a) {
        a.setTheme(THEMES[get(a)]);
    }
}
