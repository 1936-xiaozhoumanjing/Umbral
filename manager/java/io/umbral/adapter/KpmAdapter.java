package io.umbral.adapter;

import io.umbral.util.Ui;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import io.umbral.R;
import io.umbral.data.KpmEntry;

import java.util.List;

public class KpmAdapter extends BaseAdapter {

    public interface OnActionListener {
        void onAction(KpmEntry entry);
    }

    private final Context ctx;
    private final List<KpmEntry> data;
    private final OnActionListener listener;

    public KpmAdapter(Context ctx, List<KpmEntry> data, OnActionListener l) {
        this.ctx = ctx;
        this.data = data;
        this.listener = l;
    }

    @Override
    public int getCount() {
        return data.size();
    }

    @Override
    public KpmEntry getItem(int position) {
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
            convertView = LayoutInflater.from(ctx).inflate(R.layout.item_kpm, parent, false);
            h = new ViewHolder();
            h.name = convertView.findViewById(R.id.tv_kpm_name);
            h.meta = convertView.findViewById(R.id.tv_kpm_meta);
            h.dot = convertView.findViewById(R.id.v_kpm_dot);
            h.action = convertView.findViewById(R.id.btn_kpm_action);
            convertView.setTag(h);
        } else {
            h = (ViewHolder) convertView.getTag();
        }

        final KpmEntry e = data.get(position);
        h.name.setText(e.name);
        h.meta.setText(e.meta());
        h.dot.setBackgroundResource(e.loaded ? R.drawable.dot_loaded : R.drawable.dot_off);
        h.action.setText(e.loaded ? R.string.kpm_unload : R.string.kpm_load);
        h.action.setTextColor(Ui.tc(ctx, 
                e.loaded ? R.attr.sk_error : R.attr.sk_chip_text));

        View.OnClickListener click = new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (listener != null) {
                    listener.onAction(e);
                }
            }
        };
        h.action.setOnClickListener(click);

        return convertView;
    }

    private static class ViewHolder {
        TextView name;
        TextView meta;
        View dot;
        TextView action;
    }
}
