package io.umbral.flash;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import io.umbral.BaseActivity;
import io.umbral.R;
import io.umbral.sk.SkBridge;
import io.umbral.util.Ui;

import java.io.InputStream;

public class FlashActivity extends BaseActivity {

    private static final int REQ_PICK = 2001;

    private TextView tvPath;
    private TextView tvInfo;
    private TextView tvStep;
    private View btnPick;
    private View btnPatch;
    private View btnFlash;

    private Uri pickedUri;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_flash);

        tvPath = findViewById(R.id.tv_flash_path);
        tvInfo = findViewById(R.id.tv_flash_info);
        tvStep = findViewById(R.id.tv_flash_step);
        btnPick = findViewById(R.id.btn_pick_image);
        btnPatch = findViewById(R.id.btn_patch);
        btnFlash = findViewById(R.id.btn_flash);

        findViewById(R.id.btn_back).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });

        btnPick.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startPickImage();
            }
        });

        btnPatch.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (!localMode) {
                    Toast.makeText(FlashActivity.this,
                            getString(R.string.toast_direct_needs_root), Toast.LENGTH_LONG).show();
                    return;
                }
                if (pickedUri == null) {
                    Toast.makeText(FlashActivity.this, R.string.toast_pick_image_first, Toast.LENGTH_SHORT).show();
                    return;
                }
                doPatch();
            }
        });

        btnFlash.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showFlashGuide();
            }
        });

        // 安装方式单选
        final View optLocal = findViewById(R.id.opt_local);
        final View optDirect = findViewById(R.id.opt_direct);
        final android.widget.ImageView radioLocal = findViewById(R.id.radio_local);
        final android.widget.ImageView radioDirect = findViewById(R.id.radio_direct);

        optLocal.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                localMode = true;
                refreshMode(radioLocal, radioDirect);
            }
        });
        optDirect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                localMode = false;
                refreshMode(radioLocal, radioDirect);
            }
        });

        // 分区自动检测，无需用户选择

        // 强制备份
        findViewById(R.id.row_backup).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                forceBackup = !forceBackup;
                ((android.widget.ImageView) findViewById(R.id.cb_backup))
                        .setImageResource(forceBackup
                                ? R.drawable.ic_status_check
                                : R.drawable.ic_radio_off);
            }
        });

        partition = autoPartition();
        refreshMode(radioLocal, radioDirect);
        updateButtons();

        // 测试入口：am start ... --es file /sdcard/xxx.img [--ez auto true]
        String directPath = getIntent().getStringExtra("file");
        if (directPath != null && !directPath.isEmpty()) {
            java.io.File f = new java.io.File(directPath);
            if (f.exists()) {
                tvPath.setText(directPath + "  (" + getString(R.string.unit_bytes, String.valueOf(f.length())) + ")");
                lastPickedPath = directPath;
                parseImageFile(f);
                updateButtons();
                if (getIntent().getBooleanExtra("auto", false)) {
                    tvStep.setText(R.string.patch_auto);
                    doPatchFile(f);
                }
            } else {
                tvPath.setText(getString(R.string.err_file_missing, directPath));
            }
        }
    }

    private void parseImageFile(final java.io.File f) {
        tvInfo.setText(R.string.reading);
        new Thread(new Runnable() {
            @Override
            public void run() {
                String msg;
                try {
                    java.io.FileInputStream in = new java.io.FileInputStream(f);
                    byte[] head = new byte[4096];
                    int n = in.read(head);
                    in.close();
                    msg = BootPatch.parseHeaderInfo(head, n);
                } catch (Exception e) {
                    msg = "读取失败: " + e.getMessage();
                }
                final String m = msg;
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        tvInfo.setText(m);
                    }
                });
            }
        }).start();
    }

    private void doPatchFile(final java.io.File f) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String result;
                try {
                    result = BootPatch.patchFile(FlashActivity.this, f);
                } catch (Exception e) {
                    result = "修补异常: " + e.toString();
                }
                final String r = result;
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        tvStep.setText(r);
                    }
                });
            }
        }).start();
    }

    private boolean localMode = true;
    private String partition = "init_boot_a";
    private boolean forceBackup = true;
    /** 自动检测当前活动槽：init_boot_a 或 init_boot_b */
    private String autoPartition() {
        String slot = getProp("ro.boot.slot_suffix");
        if (slot == null || slot.isEmpty()) {
            String s = getProp("ro.boot.slot");
            if (s != null && !s.isEmpty()) slot = "_" + s;
        }
        if (slot == null) slot = "_a";
        return "init_boot" + slot;
    }

    private String getProp(String key) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"getprop", key});
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String line = r.readLine();
            r.close();
            return line == null ? "" : line.trim();
        } catch (Exception e) {
            return "";
        }
    }

    /** 检测设备上有哪些可刷分区 */
    private java.util.List<String> detectPartitions() {
        java.util.List<String> list = new java.util.ArrayList<String>();
        java.io.File dir = new java.io.File("/dev/block/by-name");
        String[] cands = {"init_boot", "boot", "vendor_boot"};
        for (String base : cands) {
            for (String suffix : new String[]{"_a", "_b", ""}) {
                java.io.File f = new java.io.File(dir, base + suffix);
                if (f.exists()) {
                    list.add(base + suffix);
                }
            }
        }
        if (list.isEmpty()) {
            list.add("init_boot_a");
            list.add("init_boot_b");
            list.add("boot_a");
            list.add("boot_b");
        }
        return list;
    }

    private void refreshMode(android.widget.ImageView a, android.widget.ImageView b) {
        a.setImageResource(localMode ? R.drawable.ic_radio_on : R.drawable.ic_radio_off);
        b.setImageResource(localMode ? R.drawable.ic_radio_off : R.drawable.ic_radio_on);
        a.setImageTintList(android.content.res.ColorStateList.valueOf(
                Ui.tc(this, localMode ? R.attr.sk_primary : R.attr.sk_on_surface_variant)));
        b.setImageTintList(android.content.res.ColorStateList.valueOf(
                Ui.tc(this, localMode ? R.attr.sk_on_surface_variant : R.attr.sk_primary)));

        // 备份只在"直接安装"模式下有意义
        int vis = localMode ? View.GONE : View.VISIBLE;
        View rb = findViewById(R.id.row_backup);
        if (rb != null) rb.setVisibility(vis);
        View divBackup = findViewById(R.id.div_backup);
        if (divBackup != null) divBackup.setVisibility(vis);
    }

    private void updateButtons() {
        boolean hasFile = pickedUri != null;
        btnPatch.setEnabled(hasFile);
        btnPatch.setAlpha(hasFile ? 1f : 0.5f);
        btnFlash.setEnabled(hasFile);
        btnFlash.setAlpha(hasFile ? 1f : 0.5f);
    }

    private static final String[] PREFERRED_PICKERS = {
            "bin.mt.plus",
            "bin.mt.plus.canary"
    };

    /** MT 管理器优先，没有再用系统选择器 */
    private void startPickImage() {
        Intent base = new Intent(Intent.ACTION_GET_CONTENT);
        base.addCategory(Intent.CATEGORY_OPENABLE);
        base.setType("*/*");

        android.content.pm.PackageManager pm = getPackageManager();

        for (String pkg : PREFERRED_PICKERS) {
            if (!isPkgInstalled(pkg)) {
                continue;
            }
            Intent mt = new Intent(base);
            mt.setPackage(pkg);
            if (mt.resolveActivity(pm) != null) {
                Toast.makeText(this, R.string.toast_via_mt, Toast.LENGTH_SHORT).show();
                try {
                    startActivityForResult(mt, REQ_PICK);
                    return;
                } catch (Exception ignored) {
                }
            }
        }

        Intent saf = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        saf.addCategory(Intent.CATEGORY_OPENABLE);
        saf.setType("*/*");
        if (saf.resolveActivity(pm) != null) {
            try {
                startActivityForResult(saf, REQ_PICK);
                return;
            } catch (Exception ignored) {
            }
        }

        try {
            startActivityForResult(Intent.createChooser(base, "选择镜像文件"), REQ_PICK);
        } catch (Exception e) {
            Toast.makeText(this, R.string.toast_no_picker, Toast.LENGTH_SHORT).show();
        }
    }

    private boolean isPkgInstalled(String pkg) {
        try {
            getPackageManager().getPackageInfo(pkg, 0);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_PICK && resultCode == RESULT_OK && data != null) {
            pickedUri = data.getData();
            tvPath.setText(displayName(pickedUri));
            lastPickedPath = null;
            parseImage(pickedUri);
            updateButtons();
        }
    }

    private String displayName(Uri uri) {
        String s = uri.getLastPathSegment();
        return s == null ? uri.toString() : s;
    }

    /** 读前 4096 字节，解析 boot header */
    private void parseImage(final Uri uri) {
        tvInfo.setText(R.string.reading);
        new Thread(new Runnable() {
            @Override
            public void run() {
                String msg;
                try {
                    InputStream in = getContentResolver().openInputStream(uri);
                    byte[] head = new byte[4096];
                    int n = in.read(head);
                    in.close();
                    if (n < 64) {
                        msg = "文件太小，不是 boot 镜像";
                    } else {
                        msg = BootPatch.parseHeaderInfo(head, n);
                    }
                } catch (Exception e) {
                    msg = "读取失败: " + e.getMessage();
                }
                final String m = msg;
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        tvInfo.setText(m);
                    }
                });
            }
        }).start();
    }

    private String lastPickedPath = null;

    private void doPatch() {
        if (lastPickedPath != null) {
            android.content.Intent i = new android.content.Intent(
                    FlashActivity.this, PatchProgressActivity.class);
            i.putExtra(PatchProgressActivity.EXTRA_PATH, lastPickedPath);
            startActivity(i);
            return;
        }
        tvStep.setText(R.string.patching);
        btnPatch.setEnabled(false);
        new Thread(new Runnable() {
            @Override
            public void run() {
                String result;
                try {
                    result = BootPatch.patch(FlashActivity.this, pickedUri);
                } catch (Exception e) {
                    result = "修补失败: " + e.getMessage();
                }
                final String r = result;
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        tvStep.setText(r);
                        btnPatch.setEnabled(true);
                    }
                });
            }
        }).start();
    }

    private void showFlashGuide() {
        String kernel = SkBridge.kernelVersion();
        String ksu = SkBridge.isConnected() ? "已刷入" : "未刷入";
        StringBuilder sb = new StringBuilder();
        sb.append("修补产物在 App 私有目录：\n");
        sb.append(getFilesDir().getAbsolutePath()).append("/out/\n\n");
        sb.append("当前内核：\n").append(kernel).append("\n\n");
        sb.append("影核 状态：").append(ksu).append("\n\n");
        sb.append("刷入方式（任选其一）：\n\n");
        sb.append("① 电脑 fastboot（推荐）\n");
        sb.append("   adb reboot bootloader\n");
        sb.append("   fastboot flash init_boot_a <修补后的文件>\n");
        sb.append("   fastboot reboot\n\n");
        sb.append("② 已有 root 时直接 dd\n");
        sb.append("   su -c \"dd if=<修补后的文件> of=/dev/block/by-name/init_boot_a\"\n\n");
        sb.append("③ 救砖\n");
        sb.append("   fastboot flash init_boot_a <原厂备份>");

        new AlertDialog.Builder(this)
                .setTitle(R.string.flash_guide_title)
                .setMessage(sb.toString())
                .setPositiveButton("知道了", null)
                .show();
    }
}
