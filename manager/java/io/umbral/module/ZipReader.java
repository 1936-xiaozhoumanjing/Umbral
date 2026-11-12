package io.umbral.module;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.Inflater;

/**
 * 自己的 ZIP 读取器 —— 为了支持 XZ（method 95）。
 *
 * ══════════════════════════════════════════════════════
 *  为什么不直接用 java.util.zip
 * ══════════════════════════════════════════════════════
 *
 *  ZipFile / ZipInputStream 只支持 Store(0) 和 Deflate(8)。
 *  遇到 XZ(95)、LZMA(14)、Zstd(93) 会直接抛异常，
 *  而且是在解析中央目录阶段就抛，连「有哪些文件」都读不到。
 *
 *  所以这里自己解析中央目录：
 *      EOCD → 中央目录 → 每个条目的本地头 → 原始压缩数据
 *  然后按 method 分派：
 *      0  → 原样
 *      8  → Inflater
 *      95 → XzDecoder（JNI 调 liblzma）
 *  其它 → 明确报错，不再给用户看天书。
 */
public final class ZipReader {

    /** 一个条目 */
    public static final class Entry {
        public String name;
        public int method;
        public long compressedSize;
        public long size;
        public long localHeaderOffset;
    }

    /** 读失败时抛这个，消息直接面向用户 */
    public static final class ZipError extends Exception {
        public ZipError(String m) {
            super(m);
        }
    }

    private final File file;

    public ZipReader(File f) {
        this.file = f;
    }

    /** 解析中央目录，返回全部条目 */
    public List<Entry> entries() throws ZipError {
        try {
            long len = file.length();
            int tailLen = (int) Math.min(len, 65557);      /* EOCD 最长 22 + 注释 65535 */
            byte[] tail = readAt(len - tailLen, tailLen);

            int eocd = -1;
            for (int i = tailLen - 22; i >= 0; i--) {
                if ((tail[i] & 0xff) == 0x50 && (tail[i + 1] & 0xff) == 0x4b
                        && (tail[i + 2] & 0xff) == 0x05 && (tail[i + 3] & 0xff) == 0x06) {
                    eocd = i;
                    break;
                }
            }
            if (eocd < 0) {
                throw new ZipError("不是有效的 ZIP（找不到目录结尾标记）");
            }
            long cdSize = u32(tail, eocd + 12);
            long cdOff = u32(tail, eocd + 16);
            int count = u16(tail, eocd + 10);

            byte[] cd = readAt(cdOff, (int) cdSize);
            List<Entry> out = new ArrayList<>(count);
            int p = 0;
            for (int i = 0; i < count && p + 46 <= cd.length; i++) {
                if ((cd[p] & 0xff) != 0x50 || (cd[p + 1] & 0xff) != 0x4b
                        || (cd[p + 2] & 0xff) != 0x01 || (cd[p + 3] & 0xff) != 0x02) {
                    break;
                }
                Entry e = new Entry();
                e.method = u16(cd, p + 10);
                e.compressedSize = u32(cd, p + 20);
                e.size = u32(cd, p + 24);
                int nameLen = u16(cd, p + 28);
                int extraLen = u16(cd, p + 30);
                int commentLen = u16(cd, p + 32);
                e.localHeaderOffset = u32(cd, p + 42);
                e.name = new String(cd, p + 46, nameLen, "UTF-8");
                out.add(e);
                p += 46 + nameLen + extraLen + commentLen;
            }
            return out;
        } catch (ZipError ex) {
            throw ex;
        } catch (Throwable t) {
            throw new ZipError("解析 ZIP 目录失败：" + t);
        }
    }

    /** 读一个条目的原始压缩数据并解码 */
    public byte[] read(Entry e) throws ZipError {
        try {
            byte[] lh = readAt(e.localHeaderOffset, 30);
            if ((lh[0] & 0xff) != 0x50 || (lh[1] & 0xff) != 0x4b) {
                throw new ZipError("条目头损坏：" + e.name);
            }
            int nameLen = u16(lh, 26);
            int extraLen = u16(lh, 28);
            long dataOff = e.localHeaderOffset + 30 + nameLen + extraLen;

            byte[] raw = readAt(dataOff, (int) e.compressedSize);

            if (e.method == 0) {
                return raw;
            }
            if (e.method == 8) {
                Inflater inf = new Inflater(true);
                try {
                    inf.setInput(raw);
                    ByteArrayOutputStream bo = new ByteArrayOutputStream(
                            e.size > 0 ? (int) e.size : 8192);
                    byte[] buf = new byte[64 * 1024];
                    while (!inf.finished()) {
                        int n = inf.inflate(buf);
                        if (n == 0) {
                            if (inf.needsInput() || inf.needsDictionary()) {
                                break;
                            }
                        } else {
                            bo.write(buf, 0, n);
                        }
                    }
                    return bo.toByteArray();
                } finally {
                    inf.end();
                }
            }
            if (e.method == 95) {
                byte[] out = XzDecoder.decode(raw);
                if (out == null) {
                    throw new ZipError("XZ 解码失败（" + e.name + "）："
                            + (XzDecoder.lastError == null ? "原因未知" : XzDecoder.lastError));
                }
                return out;
            }
            throw new ZipError("不支持的压缩方式 " + e.method + "（条目 " + e.name + "）");
        } catch (ZipError ex) {
            throw ex;
        } catch (Throwable t) {
            throw new ZipError("解压 " + e.name + " 失败：" + t);
        }
    }

    /** 按名字找条目 */
    public Entry find(List<Entry> list, String name) {
        for (Entry e : list) {
            if (e.name.equals(name)) {
                return e;
            }
        }
        return null;
    }

    // ── 小工具 ──

    /** 单个条目最大 128 MB（防止损坏的 size 字段把内存吃光） */
    private static final int MAX_ENTRY = 128 * 1024 * 1024;

    private byte[] readAt(long off, int len) throws Exception {
        if (len == 0) {
            return new byte[0];
        }
        if (len < 0 || len > MAX_ENTRY) {
            throw new ZipError("条目大小异常（" + len + " 字节），拒绝解压");
        }
        InputStream in = new BufferedInputStream(new FileInputStream(file));
        try {
            long skip = off;
            while (skip > 0) {
                long s = in.skip(skip);
                if (s <= 0) {
                    break;
                }
                skip -= s;
            }
            byte[] b = new byte[len];
            int got = 0;
            while (got < len) {
                int n = in.read(b, got, len - got);
                if (n <= 0) {
                    break;
                }
                got += n;
            }
            if (got != len) {
                throw new ZipError("文件被截断（想读 " + len + " 字节，只读到 " + got + "）");
            }
            return b;
        } finally {
            try { in.close(); } catch (Exception ignored) { }
        }
    }

    private static int u16(byte[] b, int p) {
        return (b[p] & 0xff) | ((b[p + 1] & 0xff) << 8);
    }

    private static long u32(byte[] b, int p) {
        return (b[p] & 0xffL) | ((b[p + 1] & 0xffL) << 8)
                | ((b[p + 2] & 0xffL) << 16) | ((b[p + 3] & 0xffL) << 24);
    }
}
