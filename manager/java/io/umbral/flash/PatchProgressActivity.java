package io.umbral.flash;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import io.umbral.BaseActivity;
import io.umbral.R;
import io.umbral.util.Ui;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Deque;
import java.util.Locale;

/**
 * 刷入进度页 —— Magisk 风格逐行日志
 *
 * ⚠ 关键设计：日志必须「排队 + 按节奏吐」。
 *   修补本身只要 400ms 左右，如果每条 log() 都立刻 ui.post，
 *   主线程会在几毫秒内把几十行全刷完，用户看到的就是「闪一下就完成」，
 *   逐行动画完全看不到。
 *
 *   所以这里把日志放进队列，由 Handler 每隔 LOG_INTERVAL 毫秒吐一行。
 *   完成/失败也要排队，等队列吐完再改状态，否则「完成」会插到中间。
 */
public class PatchProgressActivity extends BaseActivity implements PatchProgress {

    public static final String EXTRA_PATH = "path";

    /** 每行日志之间的间隔（毫秒）。40 行 ≈ 2 秒，观感接近 Magisk */
    private static final long LOG_INTERVAL = 55;

    private TextView tvLog;
    private TextView tvStatus;
    private ProgressBar progressBar;
    private ScrollView scroll;
    private ImageView ivDone;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss", Locale.US);
    private final StringBuilder sb = new StringBuilder();

    /** 待显示的日志队列 */
    private final Deque<String> pending = new ArrayDeque<>();
    /** 是否正在吐日志（防止多个 drain 循环并存） */
    private boolean draining = false;
    /** 修补结束后的收尾动作，等队列清空才执行 */
    private Runnable finishAction = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_patch_progress);

        tvLog = findViewById(R.id.tv_patch_log);
        tvStatus = findViewById(R.id.tv_patch_status);
        progressBar = findViewById(R.id.pb_patch);
        scroll = findViewById(R.id.sv_patch_log);
        ivDone = findViewById(R.id.iv_patch_done);

        findViewById(R.id.btn_close).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });

        String path = getIntent().getStringExtra(EXTRA_PATH);
        if (path == null || path.isEmpty()) {
            log("X 没有指定镜像文件");
            failNow("失败");
            return;
        }

        final File f = new File(path);
        if (!f.exists()) {
            log("X 文件不存在: " + path);
            failNow("失败");
            return;
        }

        log("影核 修补器 v" + SkBridgeVersion());
        log("目标: " + f.getName());
        log("");
        startPatch(f);
    }

    private String SkBridgeVersion() {
        try {
            return io.umbral.sk.SkBridge.MANAGER_VERSION;
        } catch (Throwable t) {
            return "";
        }
    }

    private void startPatch(final File f) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String result;
                boolean ok = true;
                try {
                    result = BootPatch.patchFile(PatchProgressActivity.this, f,
                            PatchProgressActivity.this);
                } catch (Throwable e) {
                    result = "异常: " + e;
                    ok = false;
                }
                final String r = (result == null) ? "" : result;
                final boolean success = ok && r.startsWith("修补完成");
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        log("");
                        if (success) {
                            log("=== 完成 ===");
                            onFinished("完成", true, r);
                        } else {
                            log("=== 失败 ===");
                            log(r);
                            onFinished("失败", false, r);
                        }
                    }
                });
            }
        }).start();
    }

    // ══════════════ 日志队列 ══════════════

    @Override
    public void log(final String line) {
        ui.post(new Runnable() {
            @Override
            public void run() {
                pending.add(line == null ? "" : line);
                if (!draining) {
                    draining = true;
                    ui.post(drainRunnable);
                }
            }
        });
    }

    private final Runnable drainRunnable = new Runnable() {
        @Override
        public void run() {
            String line = pending.poll();
            if (line == null) {
                // 队列空了：如果修补已结束，现在才真正改状态
                draining = false;
                if (finishAction != null) {
                    Runnable a = finishAction;
                    finishAction = null;
                    a.run();
                }
                return;
            }

            if (line.isEmpty()) {
                sb.append('\n');
            } else {
                sb.append('[').append(fmt.format(new Date())).append("] ")
                        .append(line).append('\n');
            }
            tvLog.setText(sb.toString());
            scroll.post(new Runnable() {
                @Override
                public void run() {
                    scroll.fullScroll(View.FOCUS_DOWN);
                }
            });

            // 还有就继续，节奏由 LOG_INTERVAL 控制
            if (!pending.isEmpty()) {
                ui.postDelayed(this, LOG_INTERVAL);
            } else {
                draining = false;
                if (finishAction != null) {
                    Runnable a = finishAction;
                    finishAction = null;
                    ui.postDelayed(a, LOG_INTERVAL);
                }
            }
        }
    };

    /**
     * 修补结束：把状态更新排到队列末尾，保证「完成」出现在最后一行之后。
     */
    private void onFinished(final String statusText, final boolean ok, final String result) {
        finishAction = new Runnable() {
            @Override
            public void run() {
                setStatus(statusText, ok);
                if (ok) {
                    progressBar.setProgress(100, true);
                }
                // 成功时把产物路径也显示出来，用户要能看见去哪儿拿文件
                if (ok && result != null && !result.isEmpty()) {
                    int i = result.indexOf("输出: ");
                    if (i >= 0) {
                        int e = result.indexOf('\n', i);
                        String outPath = (e > 0) ? result.substring(i + 4, e) : result.substring(i + 4);
                        sb.append('\n').append("产物: ").append(outPath).append('\n');
                        tvLog.setText(sb.toString());
                    }
                }
            }
        };
        // drain 循环会负责调用 finishAction；如果队列已空就立刻调度
        if (!draining) {
            draining = true;
            ui.post(drainRunnable);
        }
    }

    /** 出错时立即收尾（不用排队，因为还没开始修补） */
    private void failNow(String text) {
        ui.postDelayed(new Runnable() {
            @Override
            public void run() {
                if (finishAction != null) {
                    finishAction.run();
                    finishAction = null;
                }
            }
        }, 400);
        finishAction = new Runnable() {
            @Override
            public void run() {
                setStatus(text, false);
            }
        };
    }

    // ══════════════ 进度条 ══════════════

    @Override
    public void progress(final int percent) {
        ui.post(new Runnable() {
            @Override
            public void run() {
                // 第二参数 true = 走平滑动画，不瞬间跳变
                progressBar.setProgress(percent, true);
                if (percent < 100) {
                    tvStatus.setText(getString(R.string.in_progress, String.valueOf(percent)));
                }
            }
        });
    }

    private void setStatus(String text, boolean ok) {
        tvStatus.setText(text);
        tvStatus.setTextColor(Ui.tc(this, ok ? R.attr.sk_success : R.attr.sk_error));
        ivDone.setImageResource(ok ? R.drawable.ic_status_check : R.drawable.ic_status_cross);
        ivDone.setImageTintList(android.content.res.ColorStateList.valueOf(
                Ui.tc(this, ok ? R.attr.sk_success : R.attr.sk_error)));
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        ui.removeCallbacksAndMessages(null);
    }
}
