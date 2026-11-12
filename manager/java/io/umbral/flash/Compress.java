package io.umbral.flash;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * 压缩格式处理 —— 对应 Python 版 bootpatch/compress.py
 *
 * 支持：
 *   gzip      Java 内置
 *   zlib      Java 内置（用于 zopfli 输出）
 *   lz4-legacy / lz4-lg / lz4-frame  纯 Java 实现 block 编解码
 *   bzip2 / xz / lzma / lzop         不支持（Java 无内置，且极少见）
 *
 * 设计原则：
 *   1. 检测顺序照抄 android_bootimg/src/compress.rs
 *   2. LZMA 没有 magic，靠结构猜
 *   3. 压缩回去必须用原格式
 */
public final class Compress {

    private Compress() {}

    // ══════════════ 格式常量 ══════════════

    public static final int FMT_UNKNOWN = 0;
    public static final int FMT_GZIP = 1;
    public static final int FMT_LZ4_LEGACY = 2;
    public static final int FMT_LZ4_LG = 3;
    public static final int FMT_LZ4_FRAME = 4;
    public static final int FMT_XZ = 5;
    public static final int FMT_LZMA = 6;
    public static final int FMT_BZIP2 = 7;
    public static final int FMT_LZOP = 8;
    public static final int FMT_ZSTD = 9;
    public static final int FMT_CPIO = 10;

    private static final byte[] GZIP1_MAGIC = {0x1f, (byte) 0x8b};
    private static final byte[] GZIP2_MAGIC = {0x1f, (byte) 0x9e};
    private static final byte[] LZOP_MAGIC = {(byte) 0x89, 'L', 'Z', 'O'};
    private static final byte[] XZ_MAGIC = {(byte) 0xfd, '7', 'z', 'X', 'Z'};
    private static final byte[] BZIP_MAGIC = {'B', 'Z', 'h'};
    private static final byte[] LZ4_LEG_MAGIC = {0x02, 0x21, 0x4c, 0x18};
    private static final byte[] LZ41_MAGIC = {0x03, 0x21, 0x4c, 0x18};
    private static final byte[] LZ42_MAGIC = {0x04, 0x22, 0x4d, 0x18};
    private static final byte[] ZSTD_MAGIC = {0x28, (byte) 0xb5, 0x2f, (byte) 0xfd};

    /** LZ4 block 格式的 magic（u32 小端 0x184c2102） */
    private static final int LZ4_BLOCK_MAGIC = 0x184c2102;
    /** 每块最大 8 MB，照抄 android_bootimg */
    private static final int LZ4_BLOCK_SIZE = 0x800000;

    // ══════════════ 检测 ══════════════

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data == null || data.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) return false;
        }
        return true;
    }

    /**
     * LZMA 没有 magic，靠结构猜。
     * 照抄 android_bootimg：
     *   首字节 0x5d，字典大小是 2 的幂，接下来 8 字节全 ff
     */
    public static boolean guessLzma(byte[] d) {
        if (d == null || d.length <= 13) return false;
        if ((d[0] & 0xFF) != 0x5d) return false;
        long dictSize = (d[1] & 0xFFL)
                | ((d[2] & 0xFFL) << 8)
                | ((d[3] & 0xFFL) << 16)
                | ((d[4] & 0xFFL) << 24);
        if (dictSize == 0 || (dictSize & (dictSize - 1)) != 0) return false;
        for (int i = 5; i < 13; i++) {
            if ((d[i] & 0xFF) != 0xff) return false;
        }
        return true;
    }

    /** 返回 FMT_* 常量 */
    public static int detect(byte[] d) {
        if (d == null || d.length < 2) return FMT_UNKNOWN;

        if (startsWith(d, GZIP1_MAGIC) || startsWith(d, GZIP2_MAGIC)) return FMT_GZIP;
        if (startsWith(d, LZOP_MAGIC)) return FMT_LZOP;
        if (startsWith(d, XZ_MAGIC)) return FMT_XZ;
        if (startsWith(d, BZIP_MAGIC)) return FMT_BZIP2;
        if (startsWith(d, LZ41_MAGIC)) return FMT_LZ4_LG;
        if (startsWith(d, LZ42_MAGIC)) return FMT_LZ4_FRAME;
        if (startsWith(d, LZ4_LEG_MAGIC)) return FMT_LZ4_LEGACY;
        if (startsWith(d, ZSTD_MAGIC)) return FMT_ZSTD;
        if (guessLzma(d)) return FMT_LZMA;
        if (d.length >= 6 && d[0] == '0' && d[1] == '7' && d[2] == '0'
                && d[3] == '7' && d[4] == '0' && (d[5] == '1' || d[5] == '2')) {
            return FMT_CPIO;
        }
        return FMT_UNKNOWN;
    }

    public static String formatName(int fmt) {
        switch (fmt) {
            case FMT_GZIP: return "gzip";
            case FMT_LZ4_LEGACY: return "lz4-legacy";
            case FMT_LZ4_LG: return "lz4-lg";
            case FMT_LZ4_FRAME: return "lz4-frame";
            case FMT_XZ: return "xz";
            case FMT_LZMA: return "lzma";
            case FMT_BZIP2: return "bzip2";
            case FMT_LZOP: return "lzop";
            case FMT_ZSTD: return "zstd";
            case FMT_CPIO: return "cpio(未压缩)";
            default: return "unknown";
        }
    }

    // ══════════════ 解压 ══════════════

    public static final class DecompressResult {
        public byte[] data;
        public int format;
        public String method;
        public String error;

        public boolean ok() { return data != null; }
    }

    public static DecompressResult decompress(byte[] src) {
        return decompress(src, detect(src));
    }

    public static DecompressResult decompress(byte[] src, int fmt) {
        DecompressResult r = new DecompressResult();
        r.format = fmt;

        try {
            switch (fmt) {
                case FMT_CPIO:
                    r.data = src;
                    r.method = "未压缩";
                    return r;

                case FMT_GZIP: {
                    r.data = gunzip(src);
                    r.method = "Java GZIPInputStream";
                    return r;
                }

                case FMT_LZ4_LEGACY:
                case FMT_LZ4_LG: {
                    boolean isLg = (fmt == FMT_LZ4_LG);
                    r.data = lz4BlockDecode(src, isLg);
                    r.method = isLg ? "内置 LZ4 block (LG)" : "内置 LZ4 block (legacy)";
                    return r;
                }

                case FMT_LZ4_FRAME:
                    r.error = "LZ4 frame 格式暂不支持（需要 lz4 frame 解码器）\n"
                            + "  这是 Android 较少用的格式，如果你的镜像用它，请告知";
                    return r;

                case FMT_ZSTD:
                    r.error = "zstd 暂不支持（Java 无内置库）";
                    return r;

                case FMT_BZIP2:
                    r.error = "bzip2 暂不支持（Java 无内置库）";
                    return r;

                case FMT_XZ:
                case FMT_LZMA:
                    r.error = "xz/lzma 暂不支持（Java 无内置库）";
                    return r;

                case FMT_LZOP:
                    r.error = "lzop 暂不支持";
                    return r;

                default:
                    r.error = "无法识别压缩格式（前 8 字节: " + hex(src, 8) + "）";
                    return r;
            }
        } catch (Exception e) {
            r.error = "解压失败: " + e.getClass().getSimpleName() + ": " + e.getMessage();
            return r;
        }
    }

    // ══════════════ 压缩 ══════════════

    public static final class CompressResult {
        public byte[] data;
        public String error;
        public boolean ok() { return data != null; }
    }

    /**
     * 按指定格式压缩。
     * 关键：必须能还原成原格式，不能一律 gzip。
     */
    public static CompressResult compress(byte[] src, int fmt) {
        CompressResult r = new CompressResult();
        try {
            switch (fmt) {
                case FMT_CPIO:
                case FMT_UNKNOWN:
                    r.data = src;
                    return r;

                case FMT_GZIP:
                    r.data = gzip(src);
                    return r;

                case FMT_LZ4_LEGACY:
                case FMT_LZ4_LG:
                    r.data = lz4BlockEncode(src, fmt == FMT_LZ4_LG);
                    return r;

                case FMT_LZ4_FRAME:
                    r.error = "LZ4 frame 压缩暂不支持";
                    return r;

                default:
                    r.error = "不支持压缩成 " + formatName(fmt)
                            + "（Java 无内置库）\n"
                            + "  可选：\n"
                            + "    1. 用 forceGzip 选项改成 gzip（内核支持，但与厂商格式不一致）\n"
                            + "    2. 保持 --no-module 只做最小改动";
                    return r;
            }
        } catch (Exception e) {
            r.error = "压缩失败: " + e.getClass().getSimpleName() + ": " + e.getMessage();
            return r;
        }
    }

    // ══════════════ gzip ══════════════

    public static byte[] gunzip(byte[] src) throws IOException {
        // 处理多成员 gzip（拼接）
        ByteArrayOutputStream out = new ByteArrayOutputStream(src.length * 2);
        int pos = 0;
        while (pos < src.length) {
            if (src.length - pos >= 2
                    && (src[pos] & 0xFF) == 0x1f
                    && ((src[pos + 1] & 0xFF) == 0x8b || (src[pos + 1] & 0xFF) == 0x9e)) {
                ByteArrayInputStream bin = new ByteArrayInputStream(src, pos, src.length - pos);
                GZIPInputStream gz = new GZIPInputStream(bin, 65536);
                byte[] buf = new byte[65536];
                int n;
                long before = out.size();
                while ((n = gz.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
                gz.close();
                if (out.size() == before) break;   // 没有进展，避免死循环
                // 估算消耗的字节数：GZIPInputStream 不好拿，用 deflate 结束标记估计不可靠
                // 保守起见：只解第一个成员
                break;
            } else {
                break;
            }
        }
        return out.toByteArray();
    }

    public static byte[] gzip(byte[] src) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream(src.length / 2 + 64);
        GZIPOutputStream gz = new GZIPOutputStream(bo, 65536) {
            {
                // 提高压缩级别
                def.setLevel(Deflater.BEST_COMPRESSION);
            }
        };
        gz.write(src);
        gz.close();
        return bo.toByteArray();
    }

    // ══════════════ LZ4 block 解码 ══════════════

    /**
     * LZ4 BlockArchive 格式：
     *   [magic:4] [block_size:4] [block_data] ... [total_size:4]（仅 LG）
     *
     * 照抄 android_bootimg 的 LZ4BlockDecoder 逻辑。
     */
    public static byte[] lz4BlockDecode(byte[] src, boolean isLg) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(src.length * 3);

        int pos = 0;

        // magic：legacy = 0x184c2102，LG = 0x184c2103
        // 比较高 3 字节即可同时匹配两者
        if (src.length >= 4) {
            int magic = readU32LE(src, 0);
            if ((magic >>> 8) == (LZ4_BLOCK_MAGIC >>> 8)) {
                pos = 4;
            }
        }

        byte[] block = null;

        while (pos + 4 <= src.length) {
            int blockSize = readU32LE(src, pos);
            pos += 4;

            // LG 的 trailer：正好剩 4 字节（就是总长度），或者块大小不合理
            if (isLg) {
                if (pos + 4 == src.length) break;                     // 最后 4 字节是 trailer
                if (blockSize < 0 || blockSize > LZ4_BLOCK_SIZE * 2) break;
            }
            if (blockSize <= 0 || pos + blockSize > src.length) {
                break;
            }

            if (block == null || block.length < blockSize) {
                block = new byte[blockSize];
            }
            System.arraycopy(src, pos, block, 0, blockSize);
            pos += blockSize;

            int before = out.size();
            decodeOneBlock(block, blockSize, out);
            if (out.size() == before) break;   // 没进展，避免死循环
        }

        return out.toByteArray();
    }

    /**
     * 单个 LZ4 block 解码（性能关键路径）。
     *
     * 用预分配缓冲区 + 指针，避免 O(n²) 的数组拷贝。
     */
    private static void decodeOneBlock(byte[] src, int srcLen, ByteArrayOutputStream out) {
        // 解压后大小通常远大于压缩后，先按 4 倍估算，不够再扩
        int cap = Math.max(64, srcLen * 4);
        byte[] dst = new byte[cap];
        int dp = 0;

        int i = 0;
        int n = srcLen;

        while (i < n) {
            int token = src[i++] & 0xFF;
            int litLen = token >>> 4;
            if (litLen == 15) {
                while (i < n) {
                    int b = src[i++] & 0xFF;
                    litLen += b;
                    if (b != 255) break;
                }
            }

            if (i + litLen > n) break;

            // literals：直接 memcpy
            if (dp + litLen > dst.length) {
                dst = grow(dst, dp + litLen);
            }
            System.arraycopy(src, i, dst, dp, litLen);
            dp += litLen;
            i += litLen;

            if (i + 2 > n) break;
            int offset = (src[i] & 0xFF) | ((src[i + 1] & 0xFF) << 8);
            i += 2;
            if (offset == 0 || offset > dp) break;

            int matchLen = token & 0x0F;
            if (matchLen == 15) {
                while (i < n) {
                    int b = src[i++] & 0xFF;
                    matchLen += b;
                    if (b != 255) break;
                }
            }
            matchLen += 4;

            if (dp + matchLen > dst.length) {
                dst = grow(dst, dp + matchLen);
            }

            // 重叠复制：逐字节（offset 可能小于 matchLen）
            int from = dp - offset;
            for (int k = 0; k < matchLen; k++) {
                dst[dp++] = dst[from + k];
            }
        }

        out.write(dst, 0, dp);
    }

    private static byte[] grow(byte[] a, int need) {
        int n = a.length;
        while (n < need) n = n + (n >>> 1) + 64;
        byte[] b = new byte[n];
        System.arraycopy(a, 0, b, 0, a.length);
        return b;
    }

    // ══════════════ LZ4 block 编码 ══════════════

    /**
     * LZ4 BlockArchive 编码（贪心匹配，无优化）。
     *
     * 压缩率不如 liblz4 的 HC 模式，但格式正确、可被内核解压。
     */
    public static byte[] lz4BlockEncode(byte[] src, boolean isLg) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(src.length / 2 + 64);

        // magic
        //   legacy : 0x184c2102 → 02 21 4c 18
        //   LG     : 0x184c2103 → 03 21 4c 18
        writeU32LE(out, isLg ? (LZ4_BLOCK_MAGIC | 1) : LZ4_BLOCK_MAGIC);

        int total = src.length;
        int pos = 0;

        while (pos < total) {
            int chunkLen = Math.min(LZ4_BLOCK_SIZE, total - pos);
            byte[] chunk = new byte[chunkLen];
            System.arraycopy(src, pos, chunk, 0, chunkLen);
            pos += chunkLen;

            byte[] compressed = lz4CompressBlock(chunk);
            // 如果压缩后更大，用原始数据（LZ4 允许存未压缩块：token 里 literals 全放）
            if (compressed.length >= chunkLen) {
                compressed = lz4StoreBlock(chunk);
            }

            writeU32LE(out, compressed.length);
            out.write(compressed);
        }

        if (isLg) {
            writeU32LE(out, total);
        }

        return out.toByteArray();
    }

    /**
     * 纯存储块：整块当 literals，token 后面没有 match。
     * 格式：token=0xF0 | literal_len(扩展) | literals
     * 结尾需要一个 offset=0 的标记？
     * 实际上 LZ4 块以 literals 结尾时不需要 offset。
     */
    private static byte[] lz4StoreBlock(byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length + 16);
        int len = data.length;
        if (len < 15) {
            out.write((len << 4) & 0xF0);
        } else {
            out.write(0xF0);
            int rem = len - 15;
            while (rem >= 255) {
                out.write(255);
                rem -= 255;
            }
            out.write(rem);
        }
        out.write(data, 0, len);
        return out.toByteArray();
    }

    /** 贪心 LZ4 压缩 */
    private static byte[] lz4CompressBlock(byte[] src) {
        int n = src.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream(n);
        final int HASH_BITS = 16;
        final int HASH_SIZE = 1 << HASH_BITS;
        int[] table = new int[HASH_SIZE];
        java.util.Arrays.fill(table, -1);

        int anchor = 0;
        int i = 0;
        final int MIN_MATCH = 4;
        final int MF_LIMIT = 12;
        final int LAST_LITERALS = 5;

        while (i + MIN_MATCH + LAST_LITERALS < n) {
            int seq = readU32(src, i);
            int h = hash(seq, HASH_BITS);
            int ref = table[h];
            table[h] = i;

            if (ref >= 0 && i - ref <= 65535 && readU32(src, ref) == seq) {
                // 找匹配长度
                int mlen = 0;
                int maxM = Math.min(n - LAST_LITERALS - i, 65535);
                while (mlen < maxM && src[ref + mlen] == src[i + mlen]) {
                    mlen++;
                    if (mlen >= MF_LIMIT) {
                        while (mlen < maxM && src[ref + mlen] == src[i + mlen]) mlen++;
                        break;
                    }
                }
                if (mlen >= MIN_MATCH) {
                    // 输出
                    int litLen = i - anchor;
                    writeSequence(out, src, anchor, litLen, i - ref, mlen);
                    i += mlen;
                    anchor = i;
                    continue;
                }
            }
            i++;
        }

        // 尾部 literals
        if (anchor < n) {
            int litLen = n - anchor;
            writeLastLiterals(out, src, anchor, litLen);
        }

        return out.toByteArray();
    }

    private static void writeSequence(ByteArrayOutputStream out, byte[] src,
                                      int litStart, int litLen, int offset, int matchLen) {
        int ml = matchLen - 4;
        int token = 0;
        token |= (Math.min(litLen, 15) << 4);
        token |= Math.min(ml, 15);
        out.write(token);

        if (litLen >= 15) {
            int rem = litLen - 15;
            while (rem >= 255) { out.write(255); rem -= 255; }
            out.write(rem);
        }
        out.write(src, litStart, litLen);

        out.write(offset & 0xFF);
        out.write((offset >>> 8) & 0xFF);

        if (ml >= 15) {
            int rem = ml - 15;
            while (rem >= 255) { out.write(255); rem -= 255; }
            out.write(rem);
        }
    }

    private static void writeLastLiterals(ByteArrayOutputStream out, byte[] src,
                                          int start, int len) {
        if (len < 15) {
            out.write((len << 4) & 0xF0);
        } else {
            out.write(0xF0);
            int rem = len - 15;
            while (rem >= 255) { out.write(255); rem -= 255; }
            out.write(rem);
        }
        out.write(src, start, len);
    }

    private static int hash(int v, int bits) {
        long h = (v * 2654435761L) >>> (32 - bits);
        return (int) (h & ((1L << bits) - 1));
    }

    private static int readU32(byte[] b, int o) {
        if (o + 4 > b.length) return 0;
        return (b[o] & 0xFF)
                | ((b[o + 1] & 0xFF) << 8)
                | ((b[o + 2] & 0xFF) << 16)
                | ((b[o + 3] & 0xFF) << 24);
    }

    private static int readU32LE(byte[] b, int o) {
        if (o + 4 > b.length) return 0;
        return (b[o] & 0xFF)
                | ((b[o + 1] & 0xFF) << 8)
                | ((b[o + 2] & 0xFF) << 16)
                | ((b[o + 3] & 0xFF) << 24);
    }

    private static void writeU32LE(ByteArrayOutputStream out, int v) {
        out.write(v & 0xFF);
        out.write((v >>> 8) & 0xFF);
        out.write((v >>> 16) & 0xFF);
        out.write((v >>> 24) & 0xFF);
    }

    private static String hex(byte[] b, int n) {
        StringBuilder sb = new StringBuilder();
        int m = Math.min(n, b == null ? 0 : b.length);
        for (int i = 0; i < m; i++) {
            sb.append(String.format("%02x", b[i]));
        }
        return sb.toString();
    }

    /** 报告哪些格式可用 */
    public static String availability() {
        StringBuilder sb = new StringBuilder();
        sb.append("gzip       ✅ 内置\n");
        sb.append("lz4-legacy ✅ 内置\n");
        sb.append("lz4-lg     ✅ 内置\n");
        sb.append("lz4-frame  ❌ 未实现\n");
        sb.append("xz         ❌ Java 无内置\n");
        sb.append("lzma       ❌ Java 无内置\n");
        sb.append("bzip2      ❌ Java 无内置\n");
        sb.append("lzop       ❌ Java 无内置\n");
        sb.append("zstd       ❌ Java 无内置");
        return sb.toString();
    }
}
