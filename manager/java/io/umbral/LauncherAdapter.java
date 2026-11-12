package io.umbral;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import java.io.File;
import java.util.List;

import io.umbral.launcher.LauncherStore;

/**
 * 启动器列表适配器。
 *
 * 每项：图标 + 文件名 + 大小/时间/权限 + ⋮ 菜单 + 「执行」按钮。
 *
 * 为什么移除放进 ⋮ 菜单而不是做成第二个按钮：
 * 移除是低频且不可撤销的操作，不该和「执行」并排摆着误触。
 * 长按整行也保留移除行为，作为快捷方式。
 */
public class LauncherAdapter extends BaseAdapter {

    public interface OnRun {
        void run(File f);
    }

    public interface OnMenu {
        /** anchor 是被点的那个 ⋮ 按钮，用来定位弹出菜单 */
        void menu(File f, View anchor);
    }

    public interface OnRemove {
        void remove(File f);
    }

    private final LayoutInflater inf;
    private final Context ctx;
    private final List<File> items;
    private final OnRun onRun;
    private final OnMenu onMenu;
    private final OnRemove onRemove;

    public LauncherAdapter(Context ctx, List<File> items,
                           OnRun onRun, OnMenu onMenu, OnRemove onRemove) {
        this.ctx = ctx;
        this.inf = LayoutInflater.from(ctx);
        this.items = items;
        this.onRun = onRun;
        this.onMenu = onMenu;
        this.onRemove = onRemove;
    }

    @Override
    public int getCount() {
        return items == null ? 0 : items.size();
    }

    @Override
    public Object getItem(int position) {
        return items.get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View v = convertView;
        if (v == null) {
            v = inf.inflate(R.layout.item_launcher, parent, false);
        }

        final File f = items.get(position);

        TextView name = v.findViewById(R.id.tv_launcher_name);
        TextView meta = v.findViewById(R.id.tv_launcher_meta);
        TextView run = v.findViewById(R.id.btn_launcher_run);
        ImageView menu = v.findViewById(R.id.btn_launcher_menu);

        if (name != null) {
            name.setText(f.getName());
        }
        if (meta != null) {
            // 大小 · 时间 · 权限（rwxr-xr-x），一眼能看出能不能执行
            int mode = LauncherStore.currentMode(f);
            String desc = LauncherStore.describe(f);
            if (mode >= 0) {
                desc = desc + "  ·  " + LauncherStore.modeString(mode);
            }
            meta.setText(desc);
        }
        if (run != null) {
            run.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    if (onRun != null) {
                        onRun.run(f);
                    }
                }
            });
        }
        if (menu != null) {
            menu.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    if (onMenu != null) {
                        onMenu.menu(f, view);
                    }
                }
            });
        }

        v.setOnLongClickListener(new View.OnLongClickListener() {
            @Override
            public boolean onLongClick(View view) {
                if (onRemove != null) {
                    onRemove.remove(f);
                }
                return true;
            }
        });

        return v;
    }
}
