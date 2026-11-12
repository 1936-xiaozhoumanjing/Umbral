package io.umbral.market;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 市场索引 —— 模块市场和 KPM 市场共用同一套格式。
 *
 * ══════════════════════════════════════════════════════
 *  为什么两个市场共用一个格式
 * ══════════════════════════════════════════════════════
 *
 *  模块（ZIP）、KPM（.kpm）、UM（.umb）三者的差别只在「下载下来怎么装」，
 *  而「有哪些、叫什么、从哪下、校验值是多少」这件事一模一样。
 *  所以索引格式统一，界面也就能共用一套列表。
 *
 * ══════════════════════════════════════════════════════
 *  索引格式
 * ══════════════════════════════════════════════════════
 *
 *  {
 *    "schema": 1,
 *    "name": "影核官方源",
 *    "updated": "2026-11-11",
 *    "items": [
 *      {
 *        "id": "hide_paths",
 *        "kind": "um",                  // um | zip | kpm
 *        "name": "隐藏指定路径",
 *        "desc": "对指定 uid 隐藏一组文件",
 *        "author": "umbral",
 *        "version": "1.0",
 *        "url": "https://.../hide_paths.umb",
 *        "sha256": "…64 hex…",
 *        "size": 1234
 *      }
 *    ]
 *  }
 *
 *  sha256 是**必填**的：市场里下的东西要装进内核，没有校验值等于闭眼执行。
 *
 * ══════════════════════════════════════════════════════
 *  为什么自己写 JSON 解析
 * ══════════════════════════════════════════════════════
 *
 *  org.json 只有 Android 有，电脑上跑不了 —— 那样这个类就没法做单元测试。
 *  而我们解析的是一份**格式受控**的索引（不是任意 JSON5），
 *  一个 200 行的子集解析器足够，换来的是「能在电脑上验证」。
 */
public final class MarketIndex {

    public static final int SCHEMA = 1;

    /** 三种条目类型 */
    public static final String KIND_UM = "um";
    public static final String KIND_ZIP = "zip";
    public static final String KIND_KPM = "kpm";

    public int schema = SCHEMA;
    public String name = "";
    public String updated = "";
    public final List<Item> items = new ArrayList<>();

    /** 解析过程中的非致命问题（缺字段、整数格式错等） */
    public final List<String> warnings = new ArrayList<>();

    public static final class Item {
        public String id = "";
        public String kind = "";
        public String name = "";
        public String desc = "";
        public String author = "";
        public String version = "";
        public String url = "";
        public String sha256 = "";
        public long size;

        public boolean installable() {
            return !id.isEmpty() && !url.isEmpty() && sha256.length() == 64
                    && (KIND_UM.equals(kind) || KIND_ZIP.equals(kind) || KIND_KPM.equals(kind));
        }

        @Override
        public String toString() {
            return kind + "/" + id + " v" + version;
        }
    }

    // ══════════════════ 解析 ══════════════════

    public static MarketIndex parse(String json) throws MarketException {
        Object root = new Parser(json).parseDocument();
        if (!(root instanceof Map)) {
            throw new MarketException("索引根节点不是对象");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) root;

        MarketIndex idx = new MarketIndex();
        idx.schema = asInt(m.get("schema"), SCHEMA, "schema", idx.warnings);
        if (idx.schema != SCHEMA) {
            throw new MarketException("不支持的索引版本 " + idx.schema);
        }
        idx.name = asStr(m.get("name"));
        idx.updated = asStr(m.get("updated"));

        Object rawItems = m.get("items");
        if (!(rawItems instanceof List)) {
            throw new MarketException("缺少 items 数组");
        }
        int i = 0;
        for (Object o : (List<?>) rawItems) {
            i++;
            if (!(o instanceof Map)) {
                idx.warnings.add("items[" + i + "] 不是对象，已跳过");
                continue;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> im = (Map<String, Object>) o;
            Item it = new Item();
            it.id = asStr(im.get("id"));
            it.kind = asStr(im.get("kind"));
            it.name = asStr(im.get("name"));
            it.desc = asStr(im.get("desc"));
            it.author = asStr(im.get("author"));
            it.version = asStr(im.get("version"));
            it.url = asStr(im.get("url"));
            it.sha256 = asStr(im.get("sha256")).toLowerCase();
            it.size = asLong(im.get("size"));

            if (it.name.isEmpty()) {
                it.name = it.id;
            }
            if (!it.installable()) {
                idx.warnings.add("items[" + i + "] (" + it.id + ") 字段不全，不可安装");
            }
            idx.items.add(it);
        }
        return idx;
    }

    private static String asStr(Object o) {
        return (o == null) ? "" : String.valueOf(o);
    }

    private static long asLong(Object o) {
        if (o instanceof Number) {
            return ((Number) o).longValue();
        }
        if (o instanceof String) {
            try {
                return Long.parseLong(((String) o).trim());
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    private static int asInt(Object o, int def, String field, List<String> warn) {
        if (o == null) {
            return def;
        }
        if (o instanceof Number) {
            return ((Number) o).intValue();
        }
        try {
            return Integer.parseInt(String.valueOf(o).trim());
        } catch (NumberFormatException e) {
            warn.add(field + " 不是整数，用默认值 " + def);
            return def;
        }
    }

    /** 市场错误 */
    public static final class MarketException extends Exception {
        public MarketException(String m) {
            super(m);
        }
    }

    // ══════════════════ 极小 JSON 子集解析器 ══════════════════

    /**
     * 只支持：对象 / 数组 / 字符串 / 数字 / true / false / null。
     * 不支持注释、尾逗号、单引号 —— 索引格式是我们自己定的，不需要那些。
     */
    private static final class Parser {
        private final String s;
        private int p;

        Parser(String s) {
            this.s = (s == null) ? "" : s;
        }

        Object parseDocument() throws MarketException {
            ws();
            Object v = value();
            ws();
            if (p < s.length()) {
                throw err("多余内容");
            }
            return v;
        }

        private Object value() throws MarketException {
            if (p >= s.length()) {
                throw err("意外结束");
            }
            char c = s.charAt(p);
            switch (c) {
                case '{':
                    return object();
                case '[':
                    return array();
                case '"':
                    return string();
                case 't':
                    expect("true");
                    return Boolean.TRUE;
                case 'f':
                    expect("false");
                    return Boolean.FALSE;
                case 'n':
                    expect("null");
                    return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return number();
                    }
                    throw err("不认识的字符 '" + c + "'");
            }
        }

        private Map<String, Object> object() throws MarketException {
            Map<String, Object> m = new LinkedHashMap<>();
            p++;                    /* { */
            ws();
            if (p < s.length() && s.charAt(p) == '}') {
                p++;
                return m;
            }
            while (true) {
                ws();
                if (p >= s.length() || s.charAt(p) != '"') {
                    throw err("对象键必须是字符串");
                }
                String k = string();
                ws();
                if (p >= s.length() || s.charAt(p) != ':') {
                    throw err("键后缺少 ':'");
                }
                p++;
                ws();
                m.put(k, value());
                ws();
                if (p >= s.length()) {
                    throw err("对象未闭合");
                }
                char c = s.charAt(p);
                if (c == ',') {
                    p++;
                    continue;
                }
                if (c == '}') {
                    p++;
                    return m;
                }
                throw err("对象里出现 '" + c + "'");
            }
        }

        private List<Object> array() throws MarketException {
            List<Object> l = new ArrayList<>();
            p++;                    /* [ */
            ws();
            if (p < s.length() && s.charAt(p) == ']') {
                p++;
                return l;
            }
            while (true) {
                ws();
                l.add(value());
                ws();
                if (p >= s.length()) {
                    throw err("数组未闭合");
                }
                char c = s.charAt(p);
                if (c == ',') {
                    p++;
                    continue;
                }
                if (c == ']') {
                    p++;
                    return l;
                }
                throw err("数组里出现 '" + c + "'");
            }
        }

        private String string() throws MarketException {
            p++;                    /* " */
            StringBuilder sb = new StringBuilder();
            while (p < s.length()) {
                char c = s.charAt(p++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (p >= s.length()) {
                        throw err("转义未完成");
                    }
                    char e = s.charAt(p++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (p + 4 > s.length()) {
                                throw err("\\u 转义不完整");
                            }
                            sb.append((char) Integer.parseInt(s.substring(p, p + 4), 16));
                            p += 4;
                            break;
                        default:
                            throw err("不认识的转义 \\" + e);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw err("字符串未闭合");
        }

        private Object number() throws MarketException {
            int start = p;
            if (p < s.length() && s.charAt(p) == '-') {
                p++;
            }
            boolean dot = false;
            while (p < s.length()) {
                char c = s.charAt(p);
                if (c >= '0' && c <= '9') {
                    p++;
                } else if (c == '.' && !dot) {
                    dot = true;
                    p++;
                } else {
                    break;
                }
            }
            String t = s.substring(start, p);
            try {
                if (dot) {
                    return Double.parseDouble(t);
                }
                return Long.parseLong(t);
            } catch (NumberFormatException e) {
                throw err("数字格式错: " + t);
            }
        }

        private void expect(String lit) throws MarketException {
            if (!s.startsWith(lit, p)) {
                throw err("期望 " + lit);
            }
            p += lit.length();
        }

        private void ws() {
            while (p < s.length()) {
                char c = s.charAt(p);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    p++;
                } else {
                    break;
                }
            }
        }

        private MarketException err(String msg) {
            return new MarketException(msg + " (位置 " + p + ")");
        }
    }
}
