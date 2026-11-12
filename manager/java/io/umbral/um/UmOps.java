package io.umbral.um;

import java.util.ArrayList;
import java.util.List;

/**
 * UM 模块的「内核动作」段 —— 让 UM 模块能调用内核级能力。
 *
 * ══════════════════════════════════════════════════════
 *  为什么需要这一层
 * ══════════════════════════════════════════════════════
 *
 *  UM 模块本身是**纯数据**（规则表），它跑在解释器里，没有能力调内核函数。
 *  但用户要求「UM 模块能 hook 任意应用进程」，而 hook 必须在内核侧做。
 *
 *  所以拆成两半：
 *     · UM 模块只**声明**要做什么（[ops] 段，纯文本）
 *     · 管理器负责**代发**：翻译成对 /proc/umbral/procmem 或
 *       /proc/umbral_kmem/call 的 write，用 su 身份执行
 *     · 每条结果回写到模块状态，卡片上能看到哪条成功、哪条失败
 *
 *  这样 UM 模块不需要任何内核调用能力，权限不会从"数据"扩散成"代码执行"。
 *
 * ══════════════════════════════════════════════════════
 *  格式（写在 UM 模块文本里的 [ops] 段）
 * ══════════════════════════════════════════════════════
 *
 *      [ops]
 *      op=hook   pid=12345 from=0x7f12345000 to=0x7f12348000
 *      op=unhook pid=12345
 *      op=bread  pid=12345 addr=0x7f12345000 len=64
 *      op=vma    pid=12345
 *      op=syms   pid=12345 lib=libUE4.so filter=Transform
 *      op=phymap pid=12345 addr=0x7f12345000
 *      op=watch  pid=12345 addr=0x7f12345000
 *      op=watchoff pid=12345
 *
 *  行首 # 为注释；空行忽略；不认识的 op 记一条失败，不中断其它条。
 */
public final class UmOps {

    /** 一条内核动作 */
    public static final class Entry {
        public String op;
        public int pid;
        public long from;
        public long to;
        public long addr;
        public int len;
        public String lib = "";
        public String filter = "";
        /** 执行结果；null = 尚未执行 */
        public String result;
        public boolean ok;

        public String describe() {
            switch (op) {
                case "hook":
                    return "hook pid=" + pid + " from=" + hex(from) + " to=" + hex(to);
                case "unhook":
                    return "unhook pid=" + pid;
                case "bread":
                    return "bread pid=" + pid + " addr=" + hex(addr) + " len=" + len;
                case "vma":
                    return "vma pid=" + pid;
                case "syms":
                    return "syms pid=" + pid + " lib=" + lib
                            + (filter.isEmpty() ? "" : " filter=" + filter);
                case "phymap":
                    return "phymap pid=" + pid + " addr=" + hex(addr);
                case "watch":
                    return "watch pid=" + pid + " addr=" + hex(addr);
                case "watchoff":
                    return "watchoff pid=" + pid;
                default:
                    return op + " (未知)";
            }
        }
    }

    private UmOps() {
    }

    private static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }

    /**
     * 从 UM 模块文本里解析 [ops] 段。
     * 没有该段返回空表（不是错误 —— 大多数模块不需要内核动作）。
     */
    public static List<Entry> parse(String moduleText) {
        List<Entry> out = new ArrayList<>();
        if (moduleText == null) {
            return out;
        }
        boolean inOps = false;
        for (String raw : moduleText.split("\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (line.startsWith("[")) {
                inOps = line.equalsIgnoreCase("[ops]");
                continue;
            }
            if (!inOps) {
                continue;
            }
            Entry e = parseLine(line);
            if (e != null) {
                out.add(e);
            }
        }
        return out;
    }

    private static Entry parseLine(String line) {
        Entry e = new Entry();
        boolean seenOp = false;
        for (String tok : line.split("\\s+")) {
            int eq = tok.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String k = tok.substring(0, eq).toLowerCase();
            String v = tok.substring(eq + 1);
            switch (k) {
                case "op":
                    e.op = v.toLowerCase();
                    seenOp = true;
                    break;
                case "pid":
                    e.pid = (int) num(v, 10);
                    break;
                case "from":
                    e.from = num(v, 16);
                    break;
                case "to":
                    e.to = num(v, 16);
                    break;
                case "addr":
                    e.addr = num(v, 16);
                    break;
                case "len":
                    e.len = (int) num(v, 10);
                    break;
                case "lib":
                    e.lib = v;
                    break;
                case "filter":
                    e.filter = v;
                    break;
                default:
                    break;
            }
        }
        return seenOp ? e : null;
    }

    /** 支持 0x 前缀的十六进制，也支持纯十进制 */
    private static long num(String v, int radix) {
        try {
            if (v.startsWith("0x") || v.startsWith("0X")) {
                return Long.parseLong(v.substring(2), 16);
            }
            return Long.parseLong(v, radix);
        } catch (Throwable t) {
            return 0;
        }
    }

    /**
     * 把一条动作翻译成「写哪个节点、写什么内容」。
     * @return {路径, 内容}；不支持的动作返回 null
     */
    public static String[] toProcWrite(Entry e) {
        String procmem = "/proc/umbral/procmem";
        String kmem = "/proc/umbral_kmem/call";
        switch (e.op) {
            case "hook":
                return new String[]{procmem, "jmp " + e.pid + " " + hex(e.from)
                        + " " + hex(e.to)};
            case "unhook":
                return new String[]{procmem, "jmpundo " + e.pid};
            case "bread":
                return new String[]{kmem, "bread " + e.pid + " " + hex(e.addr)
                        + ":" + (e.len <= 0 ? 64 : e.len)};
            case "vma":
                return new String[]{kmem, "vma " + e.pid};
            case "syms":
                return new String[]{kmem, "syms " + e.pid + " " + e.lib
                        + (e.filter.isEmpty() ? "" : " " + e.filter)};
            case "phymap":
                return new String[]{kmem, "phymap " + e.pid + " " + hex(e.addr)};
            case "watch":
                return new String[]{kmem, "watch " + e.pid + " " + hex(e.addr)
                        + (e.len <= 0 ? "" : " " + e.len)};
            case "watchoff":
                return new String[]{kmem, "watchoff " + e.pid};
            default:
                return null;
        }
    }

    /**
     * 逐条执行并回写结果。
     * 单条失败不影响后续（和内核侧的"单项失败隔离"一致）。
     *
     * @return 成功条数
     */
    public static int runAll(List<Entry> list) {
        int ok = 0;
        if (list == null) {
            return 0;
        }
        for (Entry e : list) {
            String[] w = toProcWrite(e);
            if (w == null) {
                e.ok = false;
                e.result = "不支持的动作";
                continue;
            }
            try {
                io.umbral.sk.SuBridge.R r = io.umbral.sk.SuBridge.root(
                        "printf '%s' '" + w[1].replace("'", "'\\''")
                                + "' > " + w[0] + " && echo __OK__", 30000);
                String out = r.out == null ? "" : r.out;
                e.ok = out.contains("__OK__");
                e.result = e.ok ? "已下发" : ("失败：" + out.trim());
                if (e.ok) {
                    ok++;
                }
            } catch (Throwable t) {
                e.ok = false;
                e.result = "异常：" + t;
            }
        }
        return ok;
    }
}
