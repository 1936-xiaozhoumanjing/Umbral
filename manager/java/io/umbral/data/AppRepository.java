package io.umbral.data;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;

import io.umbral.sk.ModuleControl;
import io.umbral.util.Pinyin;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 应用授权仓库。
 *
 * 排序规则：按首次安装时间倒序 —— 最新装上的一定在最上面。
 * 已授权的应用用状态 chip + 绿点标记，不再单独置顶。
 */
public final class AppRepository {

    /*
     * 授权状态现在**完全来自内核**（/proc/umbral/grants），不再存本地偏好。
     *
     * 为什么必须这样：
     *   以前存 SharedPreferences，那只是个 UI 标记 —— 开关拨了，
     *   内核里什么都没发生，App 依然没有权限。用户看到「已授权」却不管用，
     *   这是最坏的一种谎。现在开关直接对应内核里的一条 uid 记录。
     */
    private AppRepository() {
    }

    /** uid → 模式（-1 无 / 0 影子 / 1 超级用户），一次读全表 */
    public static Map<Integer, Integer> kernelUidModes() {
        Map<Integer, Integer> m = new HashMap<>();
        String raw = ModuleControl.grantsRaw();
        if (raw == null) {
            return m;
        }
        for (String line : raw.split("\n")) {
            String t = line.trim();
            if (!t.startsWith("uid ")) {
                continue;
            }
            String[] parts = t.split(" ");
            if (parts.length < 3) {
                continue;
            }
            try {
                int uid = Integer.parseInt(parts[1]);
                m.put(uid, "super".equals(parts[2])
                        ? ModuleControl.MODE_SUPER : ModuleControl.MODE_SHADOW);
            } catch (Exception ignored) {
            }
        }
        return m;
    }

    /** 某个包的 uid */
    public static int uidOf(Context ctx, String pkg) {
        try {
            return ctx.getPackageManager().getApplicationInfo(pkg, 0).uid;
        } catch (Exception e) {
            return -1;
        }
    }

    /** 某个包当前的授权模式 */
    public static int modeOf(Context ctx, String pkg) {
        int uid = uidOf(ctx, pkg);
        if (uid < 0) {
            return ModuleControl.MODE_NONE;
        }
        Integer m = kernelUidModes().get(uid);
        return m == null ? ModuleControl.MODE_NONE : m;
    }

    public static Set<String> grantedSet(Context ctx) {
        Map<Integer, Integer> modes = kernelUidModes();
        Set<String> out = new HashSet<>();
        if (modes.isEmpty()) {
            return out;
        }
        for (AppEntry e : query(ctx, false, false)) {
            if (modes.containsKey(e.uid)) {
                out.add(e.packageName);
            }
        }
        return out;
    }

    public static boolean isGranted(Context ctx, String pkg) {
        return modeOf(ctx, pkg) != ModuleControl.MODE_NONE;
    }

    /** 授权（默认影子模式） */
    public static void grant(Context ctx, String pkg) {
        grant(ctx, pkg, ModuleControl.MODE_SHADOW);
    }

    /** 授权，指定模式 */
    public static boolean grant(Context ctx, String pkg, int mode) {
        int uid = uidOf(ctx, pkg);
        if (uid < 0) {
            return false;
        }
        return ModuleControl.grantUid(uid, mode);
    }

    public static boolean revoke(Context ctx, String pkg) {
        int uid = uidOf(ctx, pkg);
        if (uid < 0) {
            return false;
        }
        return ModuleControl.revokeUid(uid);
    }

    public static boolean revokeAll(Context ctx) {
        return ModuleControl.clearAll();
    }

    public static int grantedCount(Context ctx) {
        return kernelUidModes().size();
    }

    /** 全部应用，按安装时间倒序 */
    /**
     * 全部应用。
     *
     * ★ 包含系统应用 ★
     *   用户要求「一次性显示所有已安装应用，包括 Shell」。
     *   com.android.shell（uid 2000）是系统应用，之前被
     *   `isSystem && !includeSystem` 这条过滤掉了，导致列表里没有。
     *
     *   排序仍然把用户应用放前面，系统应用垫底，避免一屏全是系统包。
     */
    public static List<AppEntry> listAll(Context ctx) {
        return query(ctx, false, true);
    }

    /** 已授权应用，按安装时间倒序 */
    public static List<AppEntry> listGranted(Context ctx) {
        return query(ctx, true, false);
    }

    private static List<AppEntry> query(Context ctx, boolean onlyGranted, boolean includeSystem) {
        PackageManager pm = ctx.getPackageManager();
        Map<Integer, Integer> modes = kernelUidModes();
        List<AppEntry> out = new ArrayList<>();

        List<PackageInfo> pkgs;
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            pkgs = pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0));
        } else {
            pkgs = pm.getInstalledPackages(0);
        }

        String self = ctx.getPackageName();
        for (PackageInfo pi : pkgs) {
            ApplicationInfo ai = pi.applicationInfo;
            if (ai == null) {
                continue;
            }
            boolean isSystem = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (isSystem && !includeSystem) {
                continue;
            }
            if (self.equals(pi.packageName)) {
                continue;
            }
            boolean isSystemApp = isSystem;
            Integer gm = modes.get(ai.uid);
            boolean g = (gm != null);
            if (onlyGranted && !g) {
                continue;
            }

            AppEntry e = new AppEntry();
            e.packageName = pi.packageName;
            e.label = String.valueOf(pm.getApplicationLabel(ai));
            try {
                e.icon = pm.getApplicationIcon(ai);
            } catch (Exception ignored) {
            }
            e.uid = ai.uid;
            e.granted = g;
            e.grantMode = (gm == null) ? ModuleControl.MODE_NONE : gm;
            e.system = isSystem;
            e.firstInstallTime = pi.firstInstallTime;
            e.lastUpdateTime = pi.lastUpdateTime;
            e.versionName = pi.versionName == null ? "" : pi.versionName;
            e.versionCode = (int) pi.getLongVersionCode();
            e.targetSdk = ai.targetSdkVersion;
            out.add(e);
        }

        // 最新安装的排最上面
        Collections.sort(out, new Comparator<AppEntry>() {
            @Override
            public int compare(AppEntry a, AppEntry b) {
                return Long.compare(b.firstInstallTime, a.firstInstallTime);
            }
        });
        return out;
    }

    /**
     * 按关键字过滤。
     *
     * 匹配三种：
     *   1) 中文原名      "库洛"   → 库洛米
     *   2) 全拼          "kulomi" → 库洛米
     *   3) 拼音首字母    "klm"    → 库洛米
     *
     * 不匹配包名。
     */
    public static List<AppEntry> filter(List<AppEntry> src, String keyword) {
        if (keyword == null || keyword.trim().isEmpty()) {
            return src;
        }
        String k = keyword.trim().toLowerCase().replace(" ", "");
        if (k.isEmpty()) {
            return src;
        }
        List<AppEntry> out = new ArrayList<>();
        for (AppEntry e : src) {
            if (e.pinyinFull == null) {
                e.pinyinFull = Pinyin.full(e.label);
                e.pinyinInitials = Pinyin.initials(e.label);
            }
            if (e.label.toLowerCase().contains(k)
                    || e.pinyinFull.contains(k)
                    || e.pinyinInitials.contains(k)) {
                out.add(e);
            }
        }
        return out;
    }

    public static AppEntry find(Context ctx, String pkg) {
        for (AppEntry e : listAll(ctx)) {
            if (e.packageName.equals(pkg)) {
                return e;
            }
        }
        return null;
    }
}
