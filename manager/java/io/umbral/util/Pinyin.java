package io.umbral.util;

import android.icu.text.Transliterator;

import java.text.Normalizer;

/**
 * 中文 → 拼音，用于搜索。
 *
 * 用 android.icu 自带的 Han-Latin 转换器，不需要内置字典：
 *   "库洛米"     → "ku luo mi"     → full = "kuluomi",  initials = "klm"
 *   "第五人格"   → "di wu ren ge"  → full = "diwurenge", initials = "dwrg"
 *
 * 非中文字符原样保留（小写），例如 "库洛米 V39.0.0" → "kuluomiv39.0.0"。
 */
public final class Pinyin {

    private static Transliterator sTrans;
    private static boolean sUnavailable;

    private Pinyin() {
    }

    private static Transliterator tr() {
        if (sUnavailable) {
            return null;
        }
        if (sTrans == null) {
            try {
                sTrans = Transliterator.getInstance("Han-Latin");
            } catch (Throwable t) {
                sUnavailable = true;
                return null;
            }
        }
        return sTrans;
    }

    private static boolean hasHan(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 0x4E00 && c <= 0x9FFF) {
                return true;
            }
        }
        return false;
    }

    /** "库洛米 V39" → "ku luo mi v39"（带空格，去声调，小写） */
    public static String syllables(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        if (!hasHan(s)) {
            return s.toLowerCase();
        }
        Transliterator t = tr();
        if (t == null) {
            return s.toLowerCase();
        }
        String py;
        try {
            py = t.transliterate(s);
        } catch (Throwable e) {
            return s.toLowerCase();
        }
        // 去掉声调符号：wēi → wei
        py = Normalizer.normalize(py, Normalizer.Form.NFD).replaceAll("\\p{M}", "");
        return py.toLowerCase().trim();
    }

    /** 全拼："库洛米" → "kuluomi" */
    public static String full(String s) {
        return syllables(s).replaceAll("[\\s']+", "");
    }

    /** 首字母："第五人格" → "dwrg" */
    public static String initials(String s) {
        String syl = syllables(s);
        if (syl.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        boolean start = true;
        for (int i = 0; i < syl.length(); i++) {
            char c = syl.charAt(i);
            if (c == ' ' || c == '\'' || c == '-' || c == '.') {
                start = true;
                continue;
            }
            if (start) {
                sb.append(c);
                start = false;
            }
        }
        return sb.toString();
    }
}
