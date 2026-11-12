package io.umbral.adapter;

import io.umbral.util.Ui;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import io.umbral.R;
import io.umbral.data.AppEntry;

import java.util.List;

/**
 * 应用列表适配器。
 * 点击整行进入「应用详情」，真正的授予/撤销在详情页里做（两步授权）。
 */
public class AppAdapter extends BaseAdapter {

    public interface OnOpenListener {
        void onOpen(AppEntry entry);
    }

    private final Context ctx;
    private final List<AppEntry> data;
    private final OnOpenListener listener;

    public AppAdapter(Context ctx, List<AppEntry> data, OnOpenListener l) {
        this.ctx = ctx;
        this.data = data;
        this.listener = l;
    }

    public List<AppEntry> getData() {
        return data;
    }

    @Override
    public int getCount() {
        return data.size();
    }

    @Override
    public AppEntry getItem(int position) {
        return data.get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder h;
        if (convertView == null) {
            convertView = LayoutInflater.from(ctx).inflate(R.layout.item_app, parent, false);
            h = new ViewHolder();
            h.icon = convertView.findViewById(R.id.iv_app_icon);
            h.name = convertView.findViewById(R.id.tv_app_name);
            h.pkg = convertView.findViewById(R.id.tv_app_pkg);
            h.uid = convertView.findViewById(R.id.tv_app_uid);
            h.status = convertView.findViewById(R.id.tv_app_status);
            convertView.setTag(h);
        } else {
            h = (ViewHolder) convertView.getTag();
        }

        final AppEntry e = data.get(position);
        h.name.setText(e.label);
        h.pkg.setText(e.packageName);
        h.uid.setText("UID " + e.uid);
        if (e.icon != null) {
            h.icon.setImageDrawable(e.icon);
        } else {
            h.icon.setImageResource(R.drawable.ic_apps);
        }

        if (e.granted) {
            h.status.setText(R.string.granted);
            h.status.setTextColor(Ui.tc(ctx, R.attr.sk_success));
        } else {
            h.status.setText(R.string.not_granted);
            h.status.setTextColor(Ui.tc(ctx, R.attr.sk_on_surface_variant));
        }

        convertView.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (listener != null) {
                    listener.onOpen(e);
                }
            }
        });

        return convertView;
    }

    private static class ViewHolder {
        ImageView icon;
        TextView name;
        TextView pkg;
        TextView uid;
        TextView status;
    }
}
