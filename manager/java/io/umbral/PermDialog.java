package io.umbral;

import android.content.Context;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.util.Locale;

import io.umbral.launcher.LauncherStore;

/**
 * 权限对话框（MT 管理器风格）。
 *
 * 九位分别对应 所有者/用户组/其他 x 读/写/执行，顶部实时显示八进制。
 *
 * 为什么不用「选预设档位」：之前那版只有 6 个档位，用户想设 0740 这种
 * 就没有；而且要对照别人截图里的权限时，勾选比换算更直观。
 */
public final class PermDialog {

    public interface OnApplied {
        void applied(File f, boolean ok);
    }

    private PermDialog() {
    }

    public static void show(final Context ctx, final File f, final OnApplied cb) {
        int mode = LauncherStore.currentMode(f);
        if (mode < 0) {
            Toast.makeText(ctx, R.string.launcher_perm_fail, Toast.LENGTH_SHORT).show();
            return;
        }

        View v = LayoutInflater.from(ctx).inflate(R.layout.dialog_permissions, null);

        final CheckBox ur = v.findViewById(R.id.cb_u_r);
        final CheckBox uw = v.findViewById(R.id.cb_u_w);
        final CheckBox ux = v.findViewById(R.id.cb_u_x);
        final CheckBox gr = v.findViewById(R.id.cb_g_r);
        final CheckBox gw = v.findViewById(R.id.cb_g_w);
        final CheckBox gx = v.findViewById(R.id.cb_g_x);
        final CheckBox or = v.findViewById(R.id.cb_o_r);
        final CheckBox ow = v.findViewById(R.id.cb_o_w);
        final CheckBox ox = v.findViewById(R.id.cb_o_x);

        ur.setChecked((mode & 0400) != 0);
        uw.setChecked((mode & 0200) != 0);
        ux.setChecked((mode & 0100) != 0);
        gr.setChecked((mode & 0040) != 0);
        gw.setChecked((mode & 0020) != 0);
        gx.setChecked((mode & 0010) != 0);
        or.setChecked((mode & 0004) != 0);
        ow.setChecked((mode & 0002) != 0);
        ox.setChecked((mode & 0001) != 0);

        final TextView octal = v.findViewById(R.id.tv_perm_octal);

        CompoundButton.OnCheckedChangeListener upd = new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton b, boolean checked) {
                int m = 0;
                if (ur.isChecked()) m |= 0400;
                if (uw.isChecked()) m |= 0200;
                if (ux.isChecked()) m |= 0100;
                if (gr.isChecked()) m |= 0040;
                if (gw.isChecked()) m |= 0020;
                if (gx.isChecked()) m |= 0010;
                if (or.isChecked()) m |= 0004;
                if (ow.isChecked()) m |= 0002;
                if (ox.isChecked()) m |= 0001;
                octal.setText(String.format(Locale.US, "%04o  %s",
                        m, LauncherStore.modeString(m)));
            }
        };
        ur.setOnCheckedChangeListener(upd);
        uw.setOnCheckedChangeListener(upd);
        ux.setOnCheckedChangeListener(upd);
        gr.setOnCheckedChangeListener(upd);
        gw.setOnCheckedChangeListener(upd);
        gx.setOnCheckedChangeListener(upd);
        or.setOnCheckedChangeListener(upd);
        ow.setOnCheckedChangeListener(upd);
        ox.setOnCheckedChangeListener(upd);
        upd.onCheckedChanged(null, false);

        new android.app.AlertDialog.Builder(ctx)
                .setTitle(f.getName())
                .setView(v)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface d, int which) {
                        int m = 0;
                        if (ur.isChecked()) m |= 0400;
                        if (uw.isChecked()) m |= 0200;
                        if (ux.isChecked()) m |= 0100;
                        if (gr.isChecked()) m |= 0040;
                        if (gw.isChecked()) m |= 0020;
                        if (gx.isChecked()) m |= 0010;
                        if (or.isChecked()) m |= 0004;
                        if (ow.isChecked()) m |= 0002;
                        if (ox.isChecked()) m |= 0001;
                        boolean ok = LauncherStore.chmod(f, m);
                        Toast.makeText(ctx,
                                ok ? ctx.getString(R.string.launcher_perm_applied,
                                        String.format(Locale.US, "%04o", m))
                                   : ctx.getString(R.string.launcher_perm_fail),
                                Toast.LENGTH_SHORT).show();
                        if (cb != null) {
                            cb.applied(f, ok);
                        }
                    }
                })
                .show();
    }
}
