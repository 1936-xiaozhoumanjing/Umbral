package io.umbral.data;

/** 一个内核模块条目 */
public class ModuleEntry {

    /** 普通模块（Magisk/KernelSU 风格，目录 + module.prop） */
    public static final int TYPE_MODULE = 0;
    /** KPM（KernelPatch Module，单个 .kpm ELF） */
    public static final int TYPE_KPM = 1;

    public String id;
    public String name;
    public String version;
    public String author;
    public String description;
    public boolean enabled;

    /** TYPE_MODULE / TYPE_KPM */
    public int type = TYPE_MODULE;
    /** KPM 的绝对路径，或模块目录 */
    public String path;

    /** 第二行：v1.0.0 · 作者 */
    public String meta() {
        StringBuilder sb = new StringBuilder();
        if (version != null && !version.isEmpty()) {
            sb.append('v').append(version);
        }
        if (author != null && !author.isEmpty()) {
            if (sb.length() > 0) {
                sb.append("  ·  ");
            }
            sb.append(author);
        }
        if (type == TYPE_KPM) {
            if (sb.length() > 0) {
                sb.append("  ·  ");
            }
            sb.append("KernelPatch");
        }
        return sb.toString();
    }
}
