package io.umbral.util;

import android.content.Context;
import android.util.TypedValue;

/** 从当前主题里取颜色（配合 ?attr/sk_xxx 使用） */
public final class Ui {

    private Ui() {
    }

    public static int tc(Context ctx, int attr) {
        TypedValue tv = new TypedValue();
        if (ctx != null && ctx.getTheme().resolveAttribute(attr, tv, true)) {
            return tv.data;
        }
        return 0xFF888888;
    }
}
