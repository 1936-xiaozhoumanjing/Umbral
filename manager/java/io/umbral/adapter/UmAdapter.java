package io.umbral.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import java.util.List;

import io.umbral.R;
import io.umbral.um.UmRepository;
import io.umbral.util.Ui;

/** UM 列表适配器 */
public class UmAdapter extends BaseAdapter {

    private final Context ctx;
    private final List<UmRepository.Item> items;

    public UmAdapter(Context ctx, List<UmRepository.Item> items) {
        this.ctx = ctx;
        this.items = items;
    }

    @Override
    public int getCount() {
        return items.size();
    }

    @Override
    public Object getItem(int i) {
        return items.get(i);
    }

    @Override
    public long getItemId(int i) {
        return i;
    }

    @Override
    public View getView(int pos, View convert, ViewGroup parent) {
        View v = convert;
        if (v == null) {
            v = LayoutInflater.from(ctx).inflate(R.layout.item_um, parent, false);
        }
        UmRepository.Item it = items.get(pos);

        TextView name = v.findViewById(R.id.tv_um_name);
        TextView meta = v.findViewById(R.id.tv_um_meta);
        TextView err = v.findViewById(R.id.tv_um_err);
        final UmRepository.Item item = it;
        android.widget.Button btnReapply = v.findViewById(R.id.btn_um_reapply);
        if (btnReapply != null) {
            btnReapply.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    /* 直接下发，不依赖外部接口 —— 结果用 Toast 立刻反馈 */
                    try {
                        String err = io.umbral.um.UmRepository.apply(item);
                        android.widget.Toast.makeText(ctx,
                                err == null ? "已重新下发" : ("失败：" + err),
                                android.widget.Toast.LENGTH_SHORT).show();
                    } catch (Throwable t) {
                        android.widget.Toast.makeText(ctx, "异常：" + t,
                                android.widget.Toast.LENGTH_LONG).show();
                    }
                }
            });
        }

        /*
         * 模块 id 形如 "一键隐藏环境_1794481806079"
         * 尾部那串数字是创建时间戳，给用户看毫无意义 —— 去掉。
         */
        String shown = it.id == null ? "" : it.id.replaceAll("_\\d{6,}$", "");
        name.setText(shown);

        android.widget.Button btnEdit = v.findViewById(R.id.btn_um_editapps);
        if (btnEdit != null) {
            btnEdit.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View vv) {
                    try {
                        android.content.Intent i2 = new android.content.Intent(
                                ctx, io.umbral.UmRepoActivity.class);
                        String nm = item.id == null ? "" : item.id.replaceAll("_\\d{6,}$", "");
                        i2.putExtra("edit_name", nm);
                        i2.putExtra("edit_item", item.id);
                        i2.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
                        ctx.startActivity(i2);
                    } catch (Throwable t) {
                        android.widget.Toast.makeText(ctx, "打不开应用选择：" + t,
                                android.widget.Toast.LENGTH_LONG).show();
                    }
                }
            });
        }
        String m = it.meta();
        try {
            int apps = io.umbral.um.UmRepository.countApps(it);
            /* 0 也照实显示 —— 之前只在 >0 时显示，出问题时反而看不出来 */
            m = "已对 " + apps + " 个应用生效 · " + m;
        } catch (Throwable ignored) {
        }
        meta.setText(m);

        if (it.error == null) {
            err.setVisibility(View.GONE);
        } else {
            err.setVisibility(View.VISIBLE);
            err.setText(it.error);
            err.setTextColor(Ui.tc(ctx, R.attr.sk_error));
        }
        return v;
    }
}
