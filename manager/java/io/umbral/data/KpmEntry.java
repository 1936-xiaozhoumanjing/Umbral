package io.umbral.data;

/** 一个 KPM（KernelPatch Module）条目 */
public class KpmEntry {
    public String id;
    public String name;
    public String version;
    public String author;
    public String description;
    /** 文件字节数 */
    public long size;
    /** 文件修改时间 */
    public long mtime;
    /** 是否已加载到内核 */
    public boolean loaded;
    /** 绝对路径 */
    public String path;

    /** 第二行：v1.0.0 · 作者 · 128 KB */
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
        if (size > 0) {
            if (sb.length() > 0) {
                sb.append("  ·  ");
            }
            sb.append(humanSize(size));
        }
        return sb.toString();
    }

    public static String humanSize(long n) {
        if (n < 1024) {
            return n + " B";
        }
        if (n < 1024 * 1024) {
            return String.format("%.1f KB", n / 1024.0);
        }
        return String.format("%.1f MB", n / 1024.0 / 1024.0);
    }
}
