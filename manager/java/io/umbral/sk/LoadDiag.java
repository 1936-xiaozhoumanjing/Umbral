package io.umbral.sk;

/**
 * Classify why the kernel refused to load our module.
 *
 * Every branch here corresponds to a different real kernel message. They look
 * similar but need completely different fixes, so guessing wastes the user's
 * time -- this turns the raw text into one clear verdict plus the next action.
 */
public final class LoadDiag {

    public static final int OK = 0;
    public static final int VERMAGIC = 1;     /* fixable: rewrite vermagic */
    public static final int SYMBOL_CRC = 2;   /* fixable: use no-__versions build + IGNORE flags */
    public static final int NO_SYMBOL_VER = 3;/* fixable: same as above */
    public static final int SIGNATURE = 4;    /* not fixable without signing */
    public static final int UNKNOWN_SYMBOL = 5;/* not fixable: needs rebuild vs that kernel */
    public static final int RELOC = 6;        /* layout mismatch, needs rebuild */
    public static final int PERMISSION = 7;   /* capability / SELinux, not a module problem */
    public static final int UNKNOWN = 99;

    private static String lastVerdict = "未尝试";

    private LoadDiag() {
    }

    public static String lastVerdict() {
        return lastVerdict;
    }

    /** one-line human explanation for a verdict code */
    public static String explain(int code) {
        switch (code) {
            case OK:              return "加载成功";
            case VERMAGIC:        return "vermagic 不匹配 → 需要改写 vermagic（打包装箱时已尝试）";
            case SYMBOL_CRC:      return "符号 CRC 不符 → 需换「无 __versions」变体并用 IGNORE_MODVERSIONS 加载";
            case NO_SYMBOL_VER:   return "内核要求符号版本而我们没带 → 同上（换无 CRC 变体 + IGNORE）";
            case SIGNATURE:       return "模块签名被强制校验 → 无签名则无法加载，需改用不校验签名的内核";
            case UNKNOWN_SYMBOL:  return "符号不存在 → 跨内核分支，必须用该机型内核源码重编";
            case RELOC:           return "重定位/结构布局不符 → 同样必须重编";
            case PERMISSION:      return "权限被拒 → 缺 CAP_SYS_MODULE 或被 SELinux 拦，属授权问题不是模块问题";
            default:              return "无法识别的失败原因，请把原文发给开发者";
        }
    }

    /**
     * classify raw insmod / finit_module / dmesg text.
     * Case-insensitive; empty or null means "no output" which we treat as unknown
     * rather than success -- a silent insmod is not proof of a loaded module.
     */
    public static int classify(String raw) {
        if (raw == null || raw.trim().length() == 0) {
            lastVerdict = explain(UNKNOWN) + "（没有输出）";
            return UNKNOWN;
        }
        String s = raw.toLowerCase();
        int code;
        if (s.contains("version magic") && s.contains("should be")) {
            code = VERMAGIC;
        } else if (s.contains("disagrees about version of symbol")) {
            code = SYMBOL_CRC;
        } else if (s.contains("no symbol version for")) {
            code = NO_SYMBOL_VER;
        } else if (s.contains("module verification failed") || s.contains("key was rejected")
                || s.contains("signature") && s.contains("invalid")) {
            code = SIGNATURE;
        } else if (s.contains("unknown symbol") || s.contains("unknown relocation")) {
            code = s.contains("unknown relocation") ? RELOC : UNKNOWN_SYMBOL;
        } else if (s.contains("operation not permitted") || s.contains("permission denied")
                || s.contains("avc:  denied")) {
            code = PERMISSION;
        } else if (s.contains("invalid module format") || s.contains("exec format error")) {
            code = RELOC;   /* 常见于 __this_module 尺寸不符 */
        } else {
            code = UNKNOWN;
        }
        lastVerdict = explain(code);
        return code;
    }

    /** convenience: classify and produce a log-ready line */
    public static String report(String raw) {
        int c = classify(raw);
        String trimmed = (raw == null) ? "" : raw.trim().replace('\n', ' ');
        if (trimmed.length() > 300) {
            trimmed = trimmed.substring(0, 300) + "…";
        }
        return "insmod[" + c + "] " + explain(c) + " | 原文: " + trimmed;
    }
}