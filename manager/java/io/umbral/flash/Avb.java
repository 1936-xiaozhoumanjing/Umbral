package io.umbral.flash;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * AVB (Android Verified Boot) 处理 —— 对应 Python 版 bootpatch/avb.py
 *
 * 镜像尾部真实结构：
 *     [blocks 结束]
 *          ↓
 *     [avb_tail]           blocks 结束到 original_image_size 之间的数据
 *          ↓ 4K 对齐
 *     [avb_header (AVB0)]  vbmeta，256 字节头 + auth + aux
 *          ↓ 填充 0
 *     [avb_footer (AVBf)]  固定文件最后 64 字节
 *
 * 两个 magic：
 *     AVB0  vbmeta header
 *     AVBf  footer（含 vbmeta_offset / vbmeta_size / original_image_size）
 *
 * 关键：改了内容后 footer 里的两个偏移必须重算，否则 bootloader 找错地方。
 */
public final class Avb {

    private Avb() {}

    public static final int FOOTER_SIZE = 64;
    public static final int VBMETA_HEADER_SIZE = 256;

    private static final byte[] FOOTER_MAGIC = {'A','V','B','f'};
    private static final byte[] VBMETA_MAGIC = {'A','V','B','0'};

    // ══════════════ Footer ══════════════

    /**
     * struct AvbFooter {          // 64 字节，全部大端
     *     uint8_t  magic[4];              // "AVBf"
     *     uint32_t version_major;
     *     uint32_t version_minor;
     *     uint64_t original_image_size;
     *     uint64_t vbmeta_offset;
     *     uint64_t vbmeta_size;
     *     uint8_t  reserved[28];
     * };
     */
    public static final class Footer {
        public final byte[] raw;
        public final int versionMajor, versionMinor;
        public final long originalImageSize;
        public final long vbmetaOffset;
        public final long vbmetaSize;

        Footer(byte[] raw) {
            if (raw.length != FOOTER_SIZE) {
                throw new IllegalArgumentException("footer 必须是 64 字节");
            }
            if (!startsWith(raw, 0, FOOTER_MAGIC)) {
                throw new IllegalArgumentException("footer magic 不是 AVBf");
            }
            this.raw = raw.clone();
            this.versionMajor = be32(raw, 4);
            this.versionMinor = be32(raw, 8);
            this.originalImageSize = be64(raw, 12);
            this.vbmetaOffset = be64(raw, 20);
            this.vbmetaSize = be64(raw, 28);
        }

        public static Footer parse(byte[] data) {
            if (data.length < FOOTER_SIZE) return null;
            int off = data.length - FOOTER_SIZE;
            if (!startsWith(data, off, FOOTER_MAGIC)) return null;
            byte[] raw = new byte[FOOTER_SIZE];
            System.arraycopy(data, off, raw, 0, FOOTER_SIZE);
            return new Footer(raw);
        }

        /**
         * 重算 footer 里的字段，返回新的 64 字节。
         *
         * 这是最关键的一步：改了镜像内容后必须调用，
         * 否则 bootloader 按旧偏移找 vbmeta 会失败。
         */
        public byte[] patch(long newOriginalSize, long newVbmetaOffset) {
            byte[] out = raw.clone();
            putBe64(out, 12, newOriginalSize);
            putBe64(out, 20, newVbmetaOffset);
            return out;
        }

        public String describe() {
            return String.format("AVBf: version=%d.%d orig=%,d vbmeta@%,d size=%,d",
                    versionMajor, versionMinor, originalImageSize,
                    vbmetaOffset, vbmetaSize);
        }
    }

    // ══════════════ Vbmeta header ══════════════

    public static final class VbmetaHeader {
        public final byte[] raw;
        public final int versionMajor, versionMinor;
        public final long authSize, auxSize;
        public final int algorithm;
        public final long rollbackIndex;
        public final int flags;
        public final long descriptorsOffset, descriptorsSize;
        public final String releaseString;

        VbmetaHeader(byte[] raw) {
            if (raw.length < VBMETA_HEADER_SIZE) {
                throw new IllegalArgumentException("vbmeta 头至少 256 字节");
            }
            if (!startsWith(raw, 0, VBMETA_MAGIC)) {
                throw new IllegalArgumentException("vbmeta magic 不是 AVB0");
            }
            this.raw = new byte[VBMETA_HEADER_SIZE];
            System.arraycopy(raw, 0, this.raw, 0, VBMETA_HEADER_SIZE);

            byte[] h = this.raw;
            this.versionMajor = be32(h, 4);
            this.versionMinor = be32(h, 8);
            this.authSize = be64(h, 12);
            this.auxSize = be64(h, 20);
            this.algorithm = be32(h, 28);
            this.rollbackIndex = be64(h, 112);
            this.flags = be32(h, 120);
            this.descriptorsOffset = be64(h, 96);
            this.descriptorsSize = be64(h, 104);

            StringBuilder sb = new StringBuilder();
            for (int i = 128; i < 176 && h[i] != 0; i++) sb.append((char)(h[i] & 0xFF));
            this.releaseString = sb.toString();
        }

        public long totalSize() { return VBMETA_HEADER_SIZE + authSize + auxSize; }
        public boolean isSigned() { return authSize > 0; }

        private static final String[] ALGO = {
                "NONE", "SHA256_RSA2048", "SHA256_RSA4096", "SHA256_RSA8192",
                "SHA512_RSA2048", "SHA512_RSA4096", "SHA512_RSA8192"
        };

        public String algorithmName() {
            return algorithm >= 0 && algorithm < ALGO.length
                    ? ALGO[algorithm] : "UNKNOWN(" + algorithm + ")";
        }
    }

    // ══════════════ AvbInfo ══════════════

    public static final class AvbInfo {
        public Footer footer;
        public VbmetaHeader vbmetaHeader;
        public byte[] vbmetaBlob;   // 完整 vbmeta（header + auth + aux）
        public byte[] avbTail;      // blocks 结束到 original_image_size 之间
        public int blocksEnd;

        public boolean hasTail() { return avbTail != null && avbTail.length > 0; }

        public List<String> describe() {
            List<String> l = new ArrayList<>();
            Footer f = footer;
            VbmetaHeader h = vbmetaHeader;

            l.add("AVBf Footer @ 文件末尾 64 字节");
            l.add(String.format("  version            %d.%d", f.versionMajor, f.versionMinor));
            l.add(String.format("  original_image_size %,d", f.originalImageSize));
            l.add(String.format("  vbmeta_offset      %,d", f.vbmetaOffset));
            l.add(String.format("  vbmeta_size        %,d", f.vbmetaSize));
            l.add("");
            l.add("vbmeta header");
            l.add(String.format("  libavb             %d.%d", h.versionMajor, h.versionMinor));
            l.add(String.format("  algorithm          %s", h.algorithmName()));
            l.add(String.format("  auth block         %,d 字节%s",
                    h.authSize, h.isSigned() ? "" : "（无签名）"));
            l.add(String.format("  aux block          %,d 字节", h.auxSize));
            l.add(String.format("  结构总长           %,d 字节", h.totalSize()));
            l.add(String.format("  rollback_index     %d", h.rollbackIndex));
            l.add(String.format("  flags              0x%x", h.flags));
            l.add(String.format("  release_string     '%s'", h.releaseString));
            l.add(String.format("  descriptors        offset=%d size=%d",
                    h.descriptorsOffset, h.descriptorsSize));

            if (hasTail()) {
                int nz = 0;
                for (byte b : avbTail) if (b != 0) nz++;
                l.add("");
                l.add(String.format("avb_tail           %,d 字节", avbTail.length));
                l.add(String.format("                   其中非零 %d 字节%s",
                        nz, nz == 0 ? "（纯填充）" : "（有厂商数据）"));
            }
            return l;
        }
    }

    // ══════════════ 解析 ══════════════

    /**
     * 解析 AVB 信息。
     *
     * @param data     完整镜像
     * @param blocksEnd blocks 全部结束的位置（未对齐）
     * @return AvbInfo，没有 AVB 返回 null
     */
    public static AvbInfo parse(byte[] data, int blocksEnd) {
        Footer footer = Footer.parse(data);
        if (footer == null) return null;

        long off = footer.vbmetaOffset;
        long size = footer.vbmetaSize;
        if (off < 0 || size <= 0 || off + size > data.length) {
            throw new IllegalArgumentException(String.format(
                    "footer 指向的 vbmeta 越界: offset=%,d size=%,d 文件=%,d",
                    off, size, data.length));
        }

        int o = (int) off;
        int s = (int) size;
        if (!startsWith(data, o, VBMETA_MAGIC)) {
            throw new IllegalArgumentException(String.format(
                    "vbmeta magic 不是 AVB0（在 %,d 处读到 %s）",
                    off, hex(data, o, 4)));
        }

        byte[] blob = new byte[s];
        System.arraycopy(data, o, blob, 0, s);

        VbmetaHeader hdr;
        try {
            hdr = new VbmetaHeader(blob);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("vbmeta 头解析失败: " + e.getMessage());
        }

        // avb_tail：blocks 结束到 original_image_size 之间
        long payload = footer.originalImageSize;
        byte[] tail = null;
        if (payload > blocksEnd) {
            if (payload > data.length) {
                throw new IllegalArgumentException(String.format(
                        "avb original_image_size %,d 超出文件大小 %,d",
                        payload, data.length));
            }
            tail = new byte[(int)(payload - blocksEnd)];
            System.arraycopy(data, blocksEnd, tail, 0, tail.length);
        } else if (payload < blocksEnd) {
            throw new IllegalArgumentException(String.format(
                    "invalid avb original_image_size: footer 说 %,d，但 blocks 已经到 %,d",
                    payload, blocksEnd));
        }

        AvbInfo info = new AvbInfo();
        info.footer = footer;
        info.vbmetaHeader = hdr;
        info.vbmetaBlob = blob;
        info.avbTail = tail;
        info.blocksEnd = blocksEnd;
        return info;
    }

    // ══════════════ 空间检查 ══════════════

    /**
     * 检查是否放得下 AVB 结构。
     *
     * 照抄 patcher.rs:
     *   min_size = payload_end + align(avb_tail_len) + align(4096)
     *            + vbmeta_len + FOOTER_SIZE
     */
    public static final class SpaceCheck {
        public boolean ok;
        public long need;
        public String message;
    }

    public static SpaceCheck checkSpace(long payloadEnd, int pageSize,
                                        AvbInfo info, long fileSize) {
        SpaceCheck r = new SpaceCheck();
        if (info == null) {
            r.ok = true;
            r.need = payloadEnd;
            return r;
        }

        long tailLen = info.hasTail() ? info.avbTail.length : 0;
        long min = payloadEnd;
        min += align(tailLen, pageSize);
        min = align(min, 4096);
        min += info.vbmetaBlob.length;
        min += FOOTER_SIZE;

        r.need = min;
        r.ok = min <= fileSize;
        if (!r.ok) {
            r.message = String.format(
                    "空间不足，放不下 AVB 结构：需要至少 %,d 字节，文件只有 %,d 字节",
                    min, fileSize);
        }
        return r;
    }

    // ══════════════ 写回 ══════════════

    public static final class WriteResult {
        public boolean ok;
        public String message;
        public long newOriginalSize;
        public long newVbmetaOffset;
    }

    /**
     * 把 AVB 结构写进输出缓冲区，并重算 footer 偏移。
     *
     * 关键（坑 #20）：
     *   avb_tail = data[blocksEndRaw .. original_image_size]
     *   它**包含**页对齐填充（blocksEndRaw 到 align 的那段）。
     *   而写 blocks 时每段后面都已经 pad 到页对齐了，
     *   所以 avb_tail 的前 (align(blocksEndRaw) - blocksEndRaw) 字节
     *   已经被 pad 的 0 填上，不能再写一遍。
     *
     * 实测 init_boot：avb_tail 3,914 字节恰好全是 pad → 额外部分 0
     * 实测 boot.img：avb_tail 17,920 字节，其中 16,384 是真实厂商数据
     *
     * @param blocksEndRaw 新镜像里最后一段数据的精确结束位置（未对齐）；
     *                     传 -1 表示不跳过（兼容旧调用）
     */
    public static WriteResult write(ByteArrayOutputStream out, AvbInfo info,
                                    int pageSize, int fileSize, int blocksEndRaw) {
        WriteResult r = new WriteResult();

        if (info == null) {
            r.ok = true;
            r.message = "无 AVB";
            return r;
        }

        // 1. 写 avb_tail（跳过已被 pad 覆盖的部分）
        if (info.hasTail()) {
            int skip = 0;
            if (blocksEndRaw >= 0) {
                int padded = (int)(align(blocksEndRaw, pageSize) - blocksEndRaw);
                if (padded > 0 && padded <= info.avbTail.length) {
                    skip = padded;
                }
            }
            int extraLen = info.avbTail.length - skip;
            if (extraLen > 0) {
                out.write(info.avbTail, skip, extraLen);
                padTo(out, pageSize);
            }
        }

        // 2. 记录新位置
        long totalSize = out.size();
        padTo(out, 4096);
        long vbmetaOffset = out.size();

        // 3. 写 vbmeta
        out.write(info.vbmetaBlob, 0, info.vbmetaBlob.length);

        // 4. 跳到 footer 位置
        int footerPos = fileSize - FOOTER_SIZE;
        if (out.size() > footerPos) {
            r.ok = false;
            r.message = String.format(
                    "AVB 结构放不下：vbmeta 写到 %,d，但 footer 必须在 %,d",
                    out.size(), footerPos);
            return r;
        }
        while (out.size() < footerPos) out.write(0);

        // 5. 写新 footer
        byte[] newFooter = info.footer.patch(totalSize, vbmetaOffset);
        out.write(newFooter, 0, newFooter.length);

        r.ok = true;
        r.newOriginalSize = totalSize;
        r.newVbmetaOffset = vbmetaOffset;
        r.message = String.format(
                "AVB 重算：orig_size=%,d  vbmeta@%,d  (原 %,d)",
                totalSize, vbmetaOffset, info.footer.vbmetaOffset);
        return r;
    }

    /** 兼容旧调用：不跳过 avb_tail 前缀 */
    public static WriteResult write(ByteArrayOutputStream out, AvbInfo info,
                                    int pageSize, int fileSize) {
        return write(out, info, pageSize, fileSize, -1);
    }

    // ══════════════ Descriptor 解析 ══════════════

    public static final class Descriptor {
        public String type;
        public long size;
        public String partition;
        public long imageSize;
        public String algorithm;
        public int saltLen, digestLen, flags;
        public String digest;
        public String key, value;
        public String cmdline;
        public String error;

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder(type);
            if (partition != null) sb.append(" partition=").append(partition);
            if (imageSize > 0) sb.append(" image_size=").append(imageSize);
            if (algorithm != null) sb.append(" algo=").append(algorithm);
            if (digest != null) sb.append(" digest=").append(digest, 0, Math.min(16, digest.length()));
            if (key != null) sb.append(" key=").append(key);
            if (value != null) sb.append(" value=").append(trim(value));
            if (cmdline != null) sb.append(" cmdline=").append(cmdline);
            if (error != null) sb.append(" ERROR=").append(error);
            return sb.toString();
        }

        private static String trim(String s) {
            int i = 0;
            while (i < s.length() && (s.charAt(i) < 32)) i++;
            String t = s.substring(i);
            return t.length() > 50 ? t.substring(0, 50) + "..." : t;
        }
    }

    private static final String[] DESC_TYPES = {
            "PROPERTY", "HASHTREE", "HASH", "KERNEL_CMDLINE", "CHAIN_PARTITION"
    };

    public static List<Descriptor> parseDescriptors(AvbInfo info) {
        List<Descriptor> r = new ArrayList<>();
        if (info == null) return r;

        VbmetaHeader h = info.vbmetaHeader;
        byte[] blob = info.vbmetaBlob;
        long start = VBMETA_HEADER_SIZE + h.authSize + h.descriptorsOffset;
        long end = start + h.descriptorsSize;
        if (end > blob.length) {
            Descriptor d = new Descriptor();
            d.type = "ERROR";
            d.error = "descriptors 越界";
            r.add(d);
            return r;
        }

        int pos = (int) start;
        int lim = (int) end;
        while (pos + 16 <= lim) {
            long dtype = be64(blob, pos);
            long dsize = be64(blob, pos + 8);
            if (dsize <= 0 || pos + 16 + dsize > lim) break;

            Descriptor d = new Descriptor();
            d.type = dtype >= 0 && dtype < DESC_TYPES.length
                    ? DESC_TYPES[(int) dtype] : "type" + dtype;
            d.size = dsize;

            int body = pos + 16;
            int bodyLen = (int) dsize;

            try {
                if (dtype == 2) {
                    // AvbHashDescriptor:
                    //   uint64 image_size @0
                    //   uint8  hash_algorithm[32] @8
                    //   uint32 partition_name_len @40
                    //   uint32 salt_len @44
                    //   uint32 digest_len @48
                    //   uint32 flags @52
                    //   uint8  reserved[60] @56
                    //   然后 partition_name + salt + digest
                    final int FIXED = 116;
                    if (bodyLen < FIXED) {
                        d.error = "body 太短 " + bodyLen;
                    } else {
                        d.imageSize = be64(blob, body);
                        StringBuilder algo = new StringBuilder();
                        for (int i = 0; i < 32 && blob[body + 8 + i] != 0; i++) {
                            algo.append((char)(blob[body + 8 + i] & 0xFF));
                        }
                        d.algorithm = algo.toString();
                        int pnLen = be32(blob, body + 40);
                        d.saltLen = be32(blob, body + 44);
                        d.digestLen = be32(blob, body + 48);
                        d.flags = be32(blob, body + 52);

                        int p = body + FIXED;
                        if (pnLen > 0 && p + pnLen <= blob.length) {
                            StringBuilder pn = new StringBuilder();
                            for (int i = 0; i < pnLen; i++) {
                                pn.append((char)(blob[p + i] & 0xFF));
                            }
                            d.partition = pn.toString();
                        }
                        int dgStart = p + pnLen + d.saltLen;
                        if (d.digestLen > 0 && dgStart + d.digestLen <= blob.length) {
                            StringBuilder dg = new StringBuilder();
                            for (int i = 0; i < d.digestLen; i++) {
                                dg.append(String.format("%02x", blob[dgStart + i]));
                            }
                            d.digest = dg.toString();
                        }
                    }
                } else if (dtype == 3) {
                    // AvbKernelCmdlineDescriptor: uint32 flags + uint32 len + cmdline
                    if (bodyLen >= 8) {
                        d.flags = be32(blob, body);
                        int clen = be32(blob, body + 4);
                        StringBuilder cl = new StringBuilder();
                        for (int i = 0; i < clen && body + 8 + i < blob.length; i++) {
                            cl.append((char)(blob[body + 8 + i] & 0xFF));
                        }
                        d.cmdline = cl.toString();
                    }
                } else if (dtype == 0) {
                    // AvbPropertyDescriptor: uint64 key_len + uint64 val_len + key + val
                    if (bodyLen >= 16) {
                        long klen = be64(blob, body);
                        long vlen = be64(blob, body + 8);
                        int kb = body + 16;
                        StringBuilder k = new StringBuilder();
                        for (int i = 0; i < klen && kb + i < blob.length; i++) {
                            k.append((char)(blob[kb + i] & 0xFF));
                        }
                        d.key = k.toString();
                        int vb = kb + (int) klen;
                        StringBuilder v = new StringBuilder();
                        for (int i = 0; i < vlen && vb + i < blob.length; i++) {
                            v.append((char)(blob[vb + i] & 0xFF));
                        }
                        d.value = v.toString();
                    }
                } else if (dtype == 4) {
                    // AvbChainPartitionDescriptor
                    if (bodyLen >= 8) {
                        d.flags = be32(blob, body);
                        int plen = be32(blob, body + 4);
                        StringBuilder pn = new StringBuilder();
                        for (int i = 0; i < plen && body + 8 + i < blob.length; i++) {
                            pn.append((char)(blob[body + 8 + i] & 0xFF));
                        }
                        d.partition = pn.toString();
                    }
                }
            } catch (Exception e) {
                d.error = e.getClass().getSimpleName() + ": " + e.getMessage();
            }

            r.add(d);
            pos += 16 + dsize;
            pos = (pos + 7) & ~7;
        }
        return r;
    }

    // ══════════════ 工具 ══════════════

    public static long align(long n, long a) {
        return ((n + a - 1) / a) * a;
    }

    private static void padTo(ByteArrayOutputStream out, int page) {
        int rem = out.size() % page;
        if (rem != 0) {
            for (int i = 0; i < page - rem; i++) out.write(0);
        }
    }

    private static boolean startsWith(byte[] d, int off, byte[] p) {
        if (off + p.length > d.length) return false;
        for (int i = 0; i < p.length; i++) if (d[off + i] != p[i]) return false;
        return true;
    }

    private static int be32(byte[] b, int o) {
        if (o + 4 > b.length) return 0;
        return ((b[o] & 0xFF) << 24) | ((b[o+1] & 0xFF) << 16)
                | ((b[o+2] & 0xFF) << 8) | (b[o+3] & 0xFF);
    }

    private static long be64(byte[] b, int o) {
        if (o + 8 > b.length) return 0;
        long hi = be32(b, o) & 0xFFFFFFFFL;
        long lo = be32(b, o + 4) & 0xFFFFFFFFL;
        return (hi << 32) | lo;
    }

    private static void putBe64(byte[] b, int o, long v) {
        b[o]   = (byte)((v >>> 56) & 0xFF);
        b[o+1] = (byte)((v >>> 48) & 0xFF);
        b[o+2] = (byte)((v >>> 40) & 0xFF);
        b[o+3] = (byte)((v >>> 32) & 0xFF);
        b[o+4] = (byte)((v >>> 24) & 0xFF);
        b[o+5] = (byte)((v >>> 16) & 0xFF);
        b[o+6] = (byte)((v >>> 8) & 0xFF);
        b[o+7] = (byte)(v & 0xFF);
    }

    private static String hex(byte[] d, int off, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len && off + i < d.length; i++) {
            sb.append(String.format("%02x", d[off + i]));
        }
        return sb.toString();
    }
}
