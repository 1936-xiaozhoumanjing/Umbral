package io.umbral.data;

import android.graphics.drawable.Drawable;

/** 一个可被授权的应用条目 */
public class AppEntry {
    public String packageName;
    public String label;
    public Drawable icon;
    public int uid;
    public boolean granted;
    /** 授权模式：-1 无 / 0 影子 / 1 超级用户 */
    public int grantMode = -1;
    public boolean system;

    /** 首次安装时间（毫秒）—— 列表据此倒序，最新安装的最上面 */
    public long firstInstallTime;
    /** 最近更新时间（毫秒） */
    public long lastUpdateTime;

    public String versionName;
    public long versionCode;
    public int targetSdk;

    /** 拼音缓存（搜索用，首次匹配时计算） */
    public String pinyinFull;
    public String pinyinInitials;
}
