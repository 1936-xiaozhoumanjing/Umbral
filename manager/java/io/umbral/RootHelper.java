package io.umbral;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * root 能力探测。
 *
 * 为什么要单独一个类：启动器每次执行都可能要用 root，而探测 su 是有代价的
 * （要起进程、可能弹出授权框），必须缓存结果，不能每次点都问一遍。
 *
 * 三种状态：
 *   GRANTED      su 可用且已授权
 *   DENIED       su 存在但没给我们授权（或用户点了拒绝）
 *   UNAVAILABLE  根本没有 su
 *
 * 超时 3 秒：KSU / Magisk 的 su 在等用户点授权框时不会立刻返回，
 * 这里不能无限等 —— 超时就按「未授权」处理，让用户知道要先去授权。
 */
public final class RootHelper {

    public static final int UNKNOWN = 0;
    public static final int GRANTED = 1;
    public static final int DENIED = 2;
    public static final int UNAVAILABLE = 3;

    private static int cached = UNKNOWN;
    private static long cachedAt = 0;

    /** 缓存 60 秒，避免频繁起进程；但别永远缓存，用户可能刚授权 */
    private static final long TTL = 60 * 1000;

    private RootHelper() {
    }

    public static int check() {
        return check(false);
    }

    public static int check(boolean force) {
        /*
         * 我们的模块已经连上 → 直接用 /proc/umbral，**不要去探 su**。
         * 探 su 会进 KSU 内核状态机，而这个进程的 SELinux 检查已被放行，
         * 两边状态不一致会 panic（实测）。
         */
        if (io.umbral.sk.ModuleControl.readDirect("/proc/umbral/version") != null) {
            /* 有 /proc/umbral 就是我们的 root 在跑 */
            return GRANTED;
        }

        long now = System.currentTimeMillis();
        if (!force && cached != UNKNOWN && (now - cachedAt) < TTL) {
            return cached;
        }
        int r = probe();
        cached = r;
        cachedAt = now;
        return r;
    }

    public static void invalidate() {
        cached = UNKNOWN;
    }

    private static int probe() {
        Process p = null;
        try {
            ProcessBuilder pb = new ProcessBuilder("su", "-c", "id");
            pb.redirectErrorStream(true);
            p = pb.start();

            final Process fp = p;
            final BufferedReader rd = new BufferedReader(
                    new InputStreamReader(fp.getInputStream()));

            // 用后台线程读，主线程限时等待，避免 su 等授权时卡死
            final String[] out = new String[1];
            Thread t = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        StringBuilder sb = new StringBuilder();
                        String line;
                        while ((line = rd.readLine()) != null) {
                            sb.append(line).append('\n');
                            if (sb.length() > 4096) {
                                break;
                            }
                        }
                        out[0] = sb.toString();
                    } catch (Exception ignored) {
                    }
                }
            });
            t.setDaemon(true);
            t.start();

            long deadline = System.currentTimeMillis() + 3000;
            while (System.currentTimeMillis() < deadline) {
                try {
                    if (!p.isAlive()) {
                        break;
                    }
                } catch (Exception e) {
                    break;
                }
                try {
                    Thread.sleep(60);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            // 超时了就当没授权：su 还活着说明卡在授权框上
            if (p.isAlive()) {
                p.destroy();
                return DENIED;
            }

            String s = out[0] == null ? "" : out[0];
            if (s.contains("uid=0")) {
                return GRANTED;
            }
            return s.isEmpty() ? UNAVAILABLE : DENIED;
        } catch (java.io.IOException e) {
            // 起不来 = 没有 su
            return UNAVAILABLE;
        } catch (Exception e) {
            return UNAVAILABLE;
        } finally {
            if (p != null) {
                try {
                    p.destroy();
                } catch (Exception ignored) {
                }
            }
        }
    }
}
