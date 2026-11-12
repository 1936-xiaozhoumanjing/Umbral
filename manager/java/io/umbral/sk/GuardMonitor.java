package io.umbral.sk;

import android.content.Context;

import java.util.HashMap;
import java.util.Map;

import io.umbral.data.AppEntry;
import io.umbral.data.AppRepository;

/**
 * 系统守护的常驻监听。
 *
 * ══════════════════════════════════════════════════════
 *  它做什么
 * ══════════════════════════════════════════════════════
 *
 *  每 2 秒读一次 /proc/umbral/guard。
 *  一旦 blocked 计数变大（说明刚才有人试图写关键分区被内核拦下）：
 *    ① 把肇事 uid 反查成「应用名 + 包名」
 *    ② 回调给界面 → 界面强制跳回主页并弹告警
 *    ③ 告警里列出：应用名 / 包名 / uid / pid / 尝试次数
 *
 *  为什么要轮询而不是等内核推送：
 *    内核侧没有需要新增的通道（/proc 只能读），
 *    2 秒一次的开销可以忽略（读一个几十字节的伪文件）。
 *
 *  什么时候跑：
 *    只在「系统守护」开关打开时跑。关掉立刻停，零开销。
 */
public final class GuardMonitor {

    /** 告警回调（在主线程调用） */
    public interface Listener {
        /**
         * @param hits 本次新增的肇事进程（已填好 label / pkg）
         */
        void onIntrusion(Guard.State st);
    }

    private static volatile boolean running;
    private static Thread thread;
    private static long lastBlocked = -1;
    private static Listener listener;

    private GuardMonitor() {
    }

    /** 开始监听（幂等） */
    public static void start(Context ctx, Listener l) {
        listener = l;
        if (running) {
            return;
        }
        running = true;
        lastBlocked = -1;

        final Context app = ctx.getApplicationContext();
        thread = new Thread(new Runnable() {
            @Override
            public void run() {
                Map<Integer, String[]> names = new HashMap<>();
                while (running) {
                    try {
                        Thread.sleep(2000);
                    } catch (InterruptedException e) {
                        break;
                    }
                    if (!running) {
                        break;
                    }
                    Guard.State st = Guard.read();
                    if (st == null || !st.on) {
                        continue;
                    }
                    if (lastBlocked < 0) {
                        lastBlocked = st.blocked;
                        continue;
                    }
                    if (st.blocked <= lastBlocked) {
                        continue;
                    }
                    lastBlocked = st.blocked;

                    /* 反查应用名 / 包名（同一 uid 可能对应多个包） */
                    for (Guard.Offender o : st.hits) {
                        if (o.label != null && !o.label.isEmpty()) {
                            continue;
                        }
                        String[] np = names.get(o.uid);
                        if (np == null) {
                            np = resolve(app, o.uid);
                            names.put(o.uid, np);
                        }
                        o.label = np[0];
                        o.pkg = np[1];
                    }

                    final Guard.State snap = st;
                    final Listener cb = listener;
                    if (cb != null) {
                        try {
                            new android.os.Handler(android.os.Looper.getMainLooper())
                                    .post(new Runnable() {
                                        @Override
                                        public void run() {
                                            cb.onIntrusion(snap);
                                        }
                                    });
                        } catch (Throwable ignored) {
                        }
                    }
                }
            }
        }, "guard-monitor");
        thread.setDaemon(true);
        thread.start();
    }

    /** 停止监听 */
    public static void stop() {
        running = false;
        if (thread != null) {
            thread.interrupt();
            thread = null;
        }
    }

    public static boolean isRunning() {
        return running;
    }

    /** uid → {应用名, 包名} */
    private static String[] resolve(Context ctx, int uid) {
        try {
            java.util.List<AppEntry> all = AppRepository.listAll(ctx);
            for (AppEntry e : all) {
                if (e.uid == uid) {
                    return new String[]{e.label, e.packageName};
                }
            }
        } catch (Throwable ignored) {
        }
        /* 系统固定 uid 的常见名字 */
        if (uid == 0) {
            return new String[]{"root（系统）", "uid 0"};
        }
        if (uid == 1000) {
            return new String[]{"system（系统）", "uid 1000"};
        }
        if (uid == 2000) {
            return new String[]{"Shell（ADB）", "uid 2000"};
        }
        return new String[]{"未知进程", "uid " + uid};
    }
}
