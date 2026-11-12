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
import java.util.Locale;

import io.umbral.launcher.LauncherStore;

/**
 * 文件管理器适配器。
 *
 * 布局照 MT 管理器：图标 / 名称 + 元信息 / 权限列 / 执行 / ⋮，一行约 56dp。
 *
 * 三类条目：
 *   目录     文件夹图标，点一下进去，权限列显示子项数量
 *   可执行   脚本图标 + 执行按钮（.sh / .ko）
 *   文本     文件图标，点一下进编辑器
 */
public class FileAdapter extends BaseAdapter {

    public interface OnOpen {
        void open(File f);
    }

    public interface OnRun {
        void run(File f);
    }

    public interface OnMenu {
        void menu(File f, View anchor);
    }

    private final LayoutInflater inf;
    private final List<File> items;
    private final OnOpen onOpen;
    private final OnRun onRun;
    private final OnMenu onMenu;

    public FileAdapter(Context ctx, List<File> items,
                       OnOpen onOpen, OnRun onRun, OnMenu onMenu) {
        this.inf = LayoutInflater.from(ctx);
        this.items = items;
        this.onOpen = onOpen;
        this.onRun = onRun;
        this.onMenu = onMenu;
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
            v = inf.inflate(R.layout.item_file, parent, false);
        }

        final File f = items.get(position);
        boolean isDir = f.isDirectory();
        boolean runnable = LauncherStore.isRunnable(f);

        TextView name = v.findViewById(R.id.tv_file_name);
        TextView meta = v.findViewById(R.id.tv_file_meta);
        TextView perm = v.findViewById(R.id.tv_file_perm);
        ImageView icon = v.findViewById(R.id.iv_file_icon);
        ImageView run = v.findViewById(R.id.btn_file_run);
        ImageView menu = v.findViewById(R.id.btn_file_menu);

        if (name != null) {
            name.setText(f.getName());
        }

        // 元信息：目录给子项数，文件给大小 + 时间
        if (meta != null) {
            if (isDir) {
                File[] kids = f.listFiles();
                int n = kids == null ? 0 : kids.length;
                meta.setText(String.format(Locale.US, "%d 项", n));
            } else {
                meta.setText(LauncherStore.describe(f));
            }
        }

        // 权限列：目录不显示权限（没意义），文件显示 rwx 九位
        if (perm != null) {
            if (isDir) {
                perm.setText("");
            } else {
                int mode = LauncherStore.currentMode(f);
                perm.setText(mode >= 0 ? LauncherStore.modeString(mode) : "");
            }
        }

        if (icon != null) {
            if (isDir) {
                icon.setImageResource(R.drawable.ic_folder);
            } else if (runnable) {
                icon.setImageResource(R.drawable.ic_terminal);
            } else {
                icon.setImageResource(R.drawable.ic_file);
            }
        }

        if (run != null) {
            run.setVisibility(runnable ? View.VISIBLE : View.GONE);
            if (runnable) {
                run.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        if (onRun != null) {
                            onRun.run(f);
                        }
                    }
                });
            }
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

        v.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (onOpen != null) {
                    onOpen.open(f);
                }
            }
        });

        return v;
    }
}
