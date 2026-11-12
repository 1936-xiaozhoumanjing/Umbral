package io.umbral.launcher;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 脚本安全检查。
 *
 * ══════════════════════════════════════════════════════════════════
 *  它做什么
 * ══════════════════════════════════════════════════════════════════
 *
 *  在脚本**开始执行之前**把内容读出来，扫一遍危险命令。
 *  命中致命规则就直接拒绝执行，命中警告规则要用户明确确认。
 *
 * ══════════════════════════════════════════════════════════════════
 *  它的边界（必须清楚，别当成万能）
 * ══════════════════════════════════════════════════════════════════
 *
 *  · 这是**静态文本匹配**，不是沙箱。base64 混淆过的命令、
 *    运行时拼出来的路径（如 P=/da; rm -rf ${P}ta）、通过别的程序
 *    间接删除，都拦不住。
 *
 *  · 真正的运行时拦截需要在内核里 hook 文件删除类系统调用
 *    （do_unlinkat / do_rmdir）后直接把进程干掉 —— 那是模块该干的活，
 *    当前这版没有 root 通道，做不到。
 *
 *  · 但即使如此，静态扫描仍然能挡掉绝大多数「复制来的脚本里带了一条
 *    顺手 rm -rf」的事故，成本极低，值得做。
 *
 * 所以定位是：**第一道闸，不是唯一一道闸。**
 */
public final class ScriptGuard {

    /** 一条命中记录 */
    public static final class Finding {
        public final int line;        // 行号（1 起）
        public final String text;     // 那一行的内容（已裁剪）
        public final String reason;   // 命中的规则说明
        public final boolean fatal;   // true = 拒绝执行

        Finding(int line, String text, String reason, boolean fatal) {
            this.line = line;
            this.text = text;
            this.reason = reason;
            this.fatal = fatal;
        }
    }

    /** 扫描结果 */
    public static final class Report {
        public final List<Finding> findings = new ArrayList<Finding>();

        public boolean hasFatal() {
            for (Finding f : findings) {
                if (f.fatal) {
                    return true;
                }
            }
            return false;
        }

        public boolean clean() {
            return findings.isEmpty();
        }
    }

    /** 单行最多留这么长，避免把超长一行整个塞进对话框 */
    private static final int MAX_LINE = 160;

    /** 文件最多读这么多字节，防止误选大文件把界面卡住 */
    private static final int MAX_READ = 512 * 1024;

    /**
     * 致命规则：命中即拒绝执行。
     *
     * 判定标准：这条命令一旦执行，可能抹掉系统分区、引导分区或整个用户数据。
     */
    private static final Object[][] FATAL = {
            // rm 递归删除根目录或关键分区
            {"rm\\s+(-[a-zA-Z]*[rR][a-zA-Z]*\\s+)+/(\\s|$|\\*)",
                    "递归删除根目录"},
            {"rm\\s+[^\\n]*\\s+/(data|system|vendor|product|odm|boot|persist|efs|metadata|modem|firmware)(/|\\s|$)",
                    "删除系统/用户数据分区"},
            {"rm\\s+[^\\n]*\\s+/dev/block",
                    "删除块设备节点"},
            // dd 写块设备 = 直接把分区内容冲掉
            {"\\bdd\\b[^\\n]*\\bof\\s*=\\s*/dev/(block|sd|mmcblk)",
                    "向块设备写入数据"},
            {"\\bdd\\b[^\\n]*\\bof\\s*=\\s*/(data|system|boot|vendor)",
                    "向分区写入数据"},
            // 格式化
            {"\\b(mkfs|mkfs\\.[a-z0-9]+|mke2fs|make_ext4fs|make_f2fs|mkswap)\\b",
                    "格式化分区"},
            {"\\bwipe\\s+(data|all|system|userdata)\\b",
                    "擦除分区"},
            // 重定向到块设备
            {">\\s*/dev/block/",
                    "重定向写入块设备"},
            // 重新挂载为可写（后面往往跟着破坏性操作）
            {"\\bmount\\b[^\\n]*-o\\s+remount[^\\n]*\\s/\\s*$",
                    "把根分区重挂为可写"},
            // 关掉 SELinux
            {"\\bsetenforce\\s+0\\b",
                    "关闭 SELinux 强制模式"},
            // 触发内核崩溃 / 强制重启
            {">\\s*/proc/sysrq-trigger",
                    "触发内核 SysRq"},
            {"\\breboot\\s+(recovery|bootloader|edl)\\b",
                    "重启进入 recovery/bootloader/EDL"},
            // fork 炸弹
            {":\\s*\\(\\s*\\)\\s*\\{[^}]*:\\s*\\|\\s*:\\s*&",
                    "fork 炸弹"},
    };

    /**
     * 警告规则：允许执行，但必须让用户明确确认。
     */
    private static final Object[][] WARN = {
            {"rm\\s+-[a-zA-Z]*[rR][a-zA-Z]*\\b",
                    "递归删除"},
            {"\\brm\\s+-[a-zA-Z]*f",
                    "强制删除"},
            {"\\bchmod\\s+-R\\b",
                    "递归改权限"},
            {"\\bchown\\s+-R\\b",
                    "递归改属主"},
            {"\\bmv\\b[^\\n]*\\s/(data|system|vendor)/",
                    "移动系统目录下的内容"},
            {">\\s*/(data|system|vendor)/",
                    "覆写系统目录下的文件"},
    };

    private ScriptGuard() {
    }

    /** 扫一个脚本文件 */
    public static Report scan(File f) {
        Report r = new Report();
        if (f == null || !f.exists() || !f.isFile()) {
            return r;
        }

        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(
                    new FileInputStream(f), StandardCharsets.UTF_8));
            String raw;
            int no = 0;
            int bytes = 0;
            while ((raw = br.readLine()) != null) {
                no++;
                bytes += raw.length();
                if (bytes > MAX_READ) {
                    break;
                }

                // 跳过注释行：注释里的危险词不该触发拦截
                String line = raw;
                String trimmed = line.trim();
                if (trimmed.startsWith("#")) {
                    continue;
                }

                String shown = trimmed.length() > MAX_LINE
                        ? trimmed.substring(0, MAX_LINE) + "…"
                        : trimmed;

                boolean hitFatal = matchAny(FATAL, line, no, shown, r);
                if (!hitFatal) {
                    matchAny(WARN, line, no, shown, r);
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (Exception ignored) {
                }
            }
        }
        return r;
    }

    /** 返回 true 表示命中了致命规则 */
    private static boolean matchAny(Object[][] rules, String line, int no,
                                    String shown, Report r) {
        boolean fatalHit = false;
        for (Object[] rule : rules) {
            Pattern p = Pattern.compile((String) rule[0], Pattern.CASE_INSENSITIVE);
            Matcher m = p.matcher(line);
            if (m.find()) {
                boolean isFatal = (rules == FATAL);
                r.findings.add(new Finding(no, shown, (String) rule[1], isFatal));
                if (isFatal) {
                    fatalHit = true;
                }
            }
        }
        return fatalHit;
    }

    /** 把结果整理成给人看的几行 */
    public static String summarize(Report r) {
        if (r == null || r.clean()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (Finding f : r.findings) {
            sb.append(f.fatal ? "✗ " : "! ")
              .append("第 ").append(f.line).append(" 行：")
              .append(f.reason).append('\n')
              .append("    ").append(f.text).append('\n');
            if (++n >= 6) {                 // 最多列 6 条，够说明问题了
                sb.append("… 还有更多\n");
                break;
            }
        }
        return sb.toString().trim();
    }
}
