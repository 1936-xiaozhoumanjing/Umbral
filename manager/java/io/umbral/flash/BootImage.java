package io.umbral.flash;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Android boot / init_boot / vendor_boot 镜像结构解析
 * —— 对应 Python 版 bootpatch/image.py
 *
 * 偏移表来源：
 *   - AOSP system/tools/mkbootimg/include/bootimg/bootimg.h
 *   - Magisk native/src/boot/bootimg.hpp
 *   - android_bootimg/src/layouts.rs
 *
 * 核心：
 *   每个版本有自己的「字段 → 偏移」表，避免到处写魔法数字。
 *   v4 = v3 + signature_size（追加在 1580）
 */
public final class BootImage {

    private BootImage() {}

    public static final int PAGE = 4096;
    private static final byte[] BOOT_MAGIC = {'A','N','D','R','O','I','D','!'};
    private static final byte[] VENDOR_MAGIC = {'V','N','D','R','B','O','O','T'};

    public static final int KIND_ANDROID = 0;
    public static final int KIND_VENDOR = 1;

    // ══════════════ 布局表 ══════════════

    /**
     * 布局：字段名 -> 偏移（-1 表示该版本没有此字段）
     */
    public static final class Layout {
        public final int totalSize;
        private final Map<String, Integer> offsets = new LinkedHashMap<>();

        Layout(int totalSize, Object... kv) {
            this.totalSize = totalSize;
            for (int i = 0; i + 1 < kv.length; i += 2) {
                offsets.put((String) kv[i], (Integer) kv[i + 1]);
            }
        }

        public int offset(String name) {
            Integer v = offsets.get(name);
            return v == null ? -1 : v;
        }

        public boolean has(String name) { return offsets.containsKey(name); }
        public Map<String, Integer> offsets() { return offsets; }
    }

    // v0~v2（老 boot_img_hdr）
    public static final Layout V0 = new Layout(1632,
            "kernel_size", 8,
            "ramdisk_size", 16,        // ⚠ v0~v2 是 16
            "second_size", 24,
            "page_size", 36,
            "header_version", 40,
            "os_version", 44,
            "name", 48,
            "cmdline", 64,
            "id", 576,
            "extra_cmdline", 608);

    public static final Layout V1 = new Layout(1648,
            "kernel_size", 8,
            "ramdisk_size", 16,
            "second_size", 24,
            "page_size", 36,
            "header_version", 40,
            "os_version", 44,
            "name", 48,
            "cmdline", 64,
            "id", 576,
            "extra_cmdline", 608,
            "recovery_dtbo_size", 1632,
            "recovery_dtbo_offset", 1636,
            "header_size", 1644);

    public static final Layout V2 = new Layout(1660,
            "kernel_size", 8,
            "ramdisk_size", 16,
            "second_size", 24,
            "page_size", 36,
            "header_version", 40,
            "os_version", 44,
            "name", 48,
            "cmdline", 64,
            "id", 576,
            "extra_cmdline", 608,
            "recovery_dtbo_size", 1632,
            "recovery_dtbo_offset", 1636,
            "header_size", 1644,
            "dtb_size", 1648,
            "dtb_addr", 1652);

    // v3（GKI）
    public static final Layout V3 = new Layout(1580,
            "kernel_size", 8,
            "ramdisk_size", 12,        // ⚠ v3+ 是 12
            "os_version", 16,
            "header_size", 20,
            "header_version", 40,
            "cmdline", 44);

    // v4 = v3 + signature_size
    public static final Layout V4 = new Layout(1584,
            "kernel_size", 8,
            "ramdisk_size", 12,
            "os_version", 16,
            "header_size", 20,
            "header_version", 40,
            "cmdline", 44,
            "signature_size", 1580);   // ← 真正的偏移

    // vendor v3
    public static final Layout VENDOR_V3 = new Layout(2112,
            "header_version", 8,
            "page_size", 12,
            "kernel_addr", 16,
            "ramdisk_addr", 20,
            "ramdisk_size", 24,
            "cmdline", 28,
            "tags_addr", 2076,
            "name", 2080,
            "header_size", 2096,
            "dtb_size", 2100,
            "dtb_addr", 2104);

    // vendor v4
    public static final Layout VENDOR_V4 = new Layout(2128,
            "header_version", 8,
            "page_size", 12,
            "kernel_addr", 16,
            "ramdisk_addr", 20,
            "ramdisk_size", 24,
            "cmdline", 28,
            "tags_addr", 2076,
            "name", 2080,
            "header_size", 2096,
            "dtb_size", 2100,
            "dtb_addr", 2104,
            "vendor_ramdisk_table_size", 2112,
            "vendor_ramdisk_table_entry_num", 2116,
            "vendor_ramdisk_table_entry_size", 2120,
            "bootconfig_size", 2124);

    public static Layout layoutOf(int kind, int version) {
        if (kind == KIND_ANDROID) {
            switch (version) {
                case 0: return V0;
                case 1: return V1;
                case 2: return V2;
                case 3: return V3;
                case 4: return V4;
                default: return null;
            }
        } else {
            switch (version) {
                case 3: return VENDOR_V3;
                case 4: return VENDOR_V4;
                default: return null;
            }
        }
    }

    // ══════════════ Header ══════════════

    public static final class Header {
        public final byte[] raw;      // header 区原始字节（可修改）
        public final int kind;
        public final int version;
        public final Layout layout;

        Header(byte[] raw, int kind, int version) {
            this.raw = raw;
            this.kind = kind;
            this.version = version;
            this.layout = layoutOf(kind, version);
        }

        public int get(String name) {
            int off = layout.offset(name);
            if (off < 0 || off + 4 > raw.length) return 0;
            return le32(raw, off);
        }

        public long get64(String name) {
            int off = layout.offset(name);
            if (off < 0 || off + 8 > raw.length) return 0;
            long lo = le32(raw, off) & 0xFFFFFFFFL;
            long hi = le32(raw, off + 4) & 0xFFFFFFFFL;
            return lo | (hi << 32);
        }

        public boolean set(String name, int value) {
            int off = layout.offset(name);
            if (off < 0 || off + 4 > raw.length) return false;
            raw[off] = (byte)(value & 0xFF);
            raw[off+1] = (byte)((value >>> 8) & 0xFF);
            raw[off+2] = (byte)((value >>> 16) & 0xFF);
            raw[off+3] = (byte)((value >>> 24) & 0xFF);
            return true;
        }

        public String getString(String name) {
            int off = layout.offset(name);
            if (off < 0) return "";
            // 字符串字段长度未知，读到 NUL 或 header 末尾
            StringBuilder sb = new StringBuilder();
            for (int i = off; i < raw.length && raw[i] != 0; i++) {
                sb.append((char)(raw[i] & 0xFF));
            }
            return sb.toString();
        }

        /** v3+ 固定 4096；v0~v2 / vendor 从 header 读 */
        public int pageSize() {
            if (kind == KIND_ANDROID && version >= 3) return PAGE;
            int ps = get("page_size");
            if (ps == 0 || (ps & (ps - 1)) != 0) return PAGE;
            return ps;
        }

        /** header 实际占用字节数（对齐到页） */
        public int hdrSpace() {
            int total = layout.totalSize;
            int hs = get("header_size");
            if (hs > 0) total = Math.max(total, hs);
            return align(total, pageSize());
        }

        public int[] osVersionDecoded() {
            int v = get("os_version");
            if (v == 0) return null;
            int osVer = v >>> 11;
            int patch = v & 0x7ff;
            int a = (osVer >> 14) & 0x7f;
            int b = (osVer >> 7) & 0x7f;
            int c = osVer & 0x7f;
            int y = ((patch >> 4) & 0x7f) + 2000;
            int m = patch & 0xf;
            return new int[]{a, b, c, y, m};
        }

        public List<String> describe() {
            List<String> l = new ArrayList<>();
            l.add("header " + (kind == KIND_ANDROID ? "android" : "vendor")
                    + " v" + version);
            l.add(String.format("  page_size     %d", pageSize()));
            l.add(String.format("  header_space  %d", hdrSpace()));
            for (String f : new String[]{
                    "kernel_size", "ramdisk_size", "second_size",
                    "recovery_dtbo_size", "dtb_size", "signature_size",
                    "vendor_ramdisk_table_size", "bootconfig_size", "header_size"}) {
                if (layout.has(f)) {
                    l.add(String.format("  %-22s %,d", f, get(f)));
                }
            }
            int[] ov = osVersionDecoded();
            if (ov != null) {
                l.add(String.format("  os_version    Android %d.%d.%d  patch %d-%02d",
                        ov[0], ov[1], ov[2], ov[3], ov[4]));
            }
            String cl = getString("cmdline");
            if (!cl.isEmpty()) {
                l.add("  cmdline       " + (cl.length() > 80 ? cl.substring(0, 80) + "..." : cl));
            }
            return l;
        }
    }

    // ══════════════ 完整镜像 ══════════════

    public static final class Image {
        public final byte[] data;
        public final Header header;

        public int kernelOff, kernelSize;
        public int ramdiskOff, ramdiskSize;
        public int secondOff, secondSize;
        public int recoveryDtboOff, recoveryDtboSize;
        public int dtbOff, dtbSize;
        public int signatureOff, signatureSize;
        public int vendorTableOff, vendorTableSize;
        public int bootconfigOff, bootconfigSize;

        /** 最后一段数据的精确结束位置（未对齐），AVB 的 avb_tail 以它为起点 */
        public int blocksEndRaw;
        /** 页对齐后的位置，repack 时新数据从这里开始写 */
        public int blocksEnd;

        public byte[] kernel, ramdisk, second, recoveryDtbo, dtb,
                signature, vendorTable, bootconfig;

        Image(byte[] data) {
            this.data = data;
            this.header = parseHeader(data);
            Header h = header;
            int page = h.pageSize();

            int pos = h.hdrSpace();

            kernelOff = pos;
            kernelSize = h.get("kernel_size");
            if (kernelSize > 0) { pos += kernelSize; pos = align(pos, page); }

            ramdiskOff = pos;
            ramdiskSize = h.get("ramdisk_size");
            if (ramdiskSize > 0) { pos += ramdiskSize; pos = align(pos, page); }

            secondOff = pos;
            secondSize = h.get("second_size");
            if (secondSize > 0) { pos += secondSize; pos = align(pos, page); }

            recoveryDtboOff = pos;
            recoveryDtboSize = h.get("recovery_dtbo_size");
            if (recoveryDtboSize > 0) { pos += recoveryDtboSize; pos = align(pos, page); }

            dtbOff = pos;
            dtbSize = h.get("dtb_size");
            if (dtbSize > 0) { pos += dtbSize; pos = align(pos, page); }

            signatureOff = pos;
            signatureSize = h.get("signature_size");
            if (signatureSize > 0) { pos += signatureSize; pos = align(pos, page); }

            vendorTableOff = pos;
            vendorTableSize = h.get("vendor_ramdisk_table_size");
            if (vendorTableSize > 0) { pos += vendorTableSize; pos = align(pos, page); }

            bootconfigOff = pos;
            bootconfigSize = h.get("bootconfig_size");
            if (bootconfigSize > 0) { pos += bootconfigSize; pos = align(pos, page); }

            // 两个 blocksEnd
            int raw = 0;
            if (kernelSize > 0) raw = Math.max(raw, kernelOff + kernelSize);
            if (ramdiskSize > 0) raw = Math.max(raw, ramdiskOff + ramdiskSize);
            if (secondSize > 0) raw = Math.max(raw, secondOff + secondSize);
            if (recoveryDtboSize > 0) raw = Math.max(raw, recoveryDtboOff + recoveryDtboSize);
            if (dtbSize > 0) raw = Math.max(raw, dtbOff + dtbSize);
            if (signatureSize > 0) raw = Math.max(raw, signatureOff + signatureSize);
            if (vendorTableSize > 0) raw = Math.max(raw, vendorTableOff + vendorTableSize);
            if (bootconfigSize > 0) raw = Math.max(raw, bootconfigOff + bootconfigSize);
            blocksEndRaw = raw;
            blocksEnd = align(raw, page);

            if (blocksEndRaw > data.length) {
                throw new IllegalArgumentException(String.format(
                        "镜像不完整：解析出需要 %,d 字节，实际 %,d", blocksEndRaw, data.length));
            }

            kernel = slice(data, kernelOff, kernelSize);
            ramdisk = slice(data, ramdiskOff, ramdiskSize);
            second = slice(data, secondOff, secondSize);
            recoveryDtbo = slice(data, recoveryDtboOff, recoveryDtboSize);
            dtb = slice(data, dtbOff, dtbSize);
            signature = slice(data, signatureOff, signatureSize);
            vendorTable = slice(data, vendorTableOff, vendorTableSize);
            bootconfig = slice(data, bootconfigOff, bootconfigSize);
        }

        public boolean isVendor() { return header.kind == KIND_VENDOR; }

        public List<String> describe() {
            List<String> l = new ArrayList<>(header.describe());
            l.add(String.format("  镜像总大小     %,d", data.length));
            l.add("");
            l.add("段布局：");
            addSeg(l, "header", 0, header.hdrSpace());
            addSeg(l, "kernel", kernelOff, kernelSize);
            addSeg(l, "ramdisk", ramdiskOff, ramdiskSize);
            addSeg(l, "second", secondOff, secondSize);
            addSeg(l, "recovery_dtbo", recoveryDtboOff, recoveryDtboSize);
            addSeg(l, "dtb", dtbOff, dtbSize);
            addSeg(l, "signature", signatureOff, signatureSize);
            addSeg(l, "vendor_table", vendorTableOff, vendorTableSize);
            addSeg(l, "bootconfig", bootconfigOff, bootconfigSize);
            l.add(String.format("  %-16s @%,10d  （未对齐，AVB 用）", "blocks_end_raw", blocksEndRaw));
            l.add(String.format("  %-16s @%,10d  （对齐后，repack 用）", "blocks_end", blocksEnd));
            return l;
        }

        private void addSeg(List<String> l, String name, int off, int size) {
            if (size <= 0) return;
            l.add(String.format("  %-16s @%,10d  %,12d 字节", name, off, size));
        }
    }

    // ══════════════ 解析入口 ══════════════

    public static Header parseHeader(byte[] data) {
        if (data.length < 44) {
            throw new IllegalArgumentException("数据太小，不是 boot 镜像");
        }

        int kind;
        int version;
        if (startsWith(data, BOOT_MAGIC)) {
            kind = KIND_ANDROID;
            version = le32(data, 40);
        } else if (startsWith(data, VENDOR_MAGIC)) {
            kind = KIND_VENDOR;
            version = le32(data, 8);
        } else {
            throw new IllegalArgumentException(String.format(
                    "无法识别的镜像格式\n  magic: %s\n  期望: ANDROID! 或 VNDRBOOT",
                    hex(data, 0, 8)));
        }

        Layout layout = layoutOf(kind, version);
        if (layout == null) {
            throw new IllegalArgumentException(String.format(
                    "不支持的 %s header v%d",
                    kind == KIND_ANDROID ? "android" : "vendor", version));
        }

        // 算出 header 实际占多少
        int total = layout.totalSize;
        int hsOff = layout.offset("header_size");
        if (hsOff >= 0 && hsOff + 4 <= data.length) {
            int hs = le32(data, hsOff);
            if (hs > 0) total = hs;
        }

        int page;
        if (kind == KIND_ANDROID && version >= 3) {
            page = PAGE;
        } else {
            int psOff = layout.offset("page_size");
            page = (psOff >= 0 && psOff + 4 <= data.length) ? le32(data, psOff) : PAGE;
            if (page == 0 || (page & (page - 1)) != 0) page = PAGE;
        }

        int hdrSpace = align(total, page);
        if (data.length < hdrSpace) {
            throw new IllegalArgumentException(String.format(
                    "数据不足 %d 字节（header 需要），只有 %d", hdrSpace, data.length));
        }

        byte[] raw = new byte[hdrSpace];
        System.arraycopy(data, 0, raw, 0, hdrSpace);
        return new Header(raw, kind, version);
    }

    public static Image parse(byte[] data) {
        return new Image(data);
    }

    // ══════════════ 工具 ══════════════

    public static int align(int n, int a) {
        return ((n + a - 1) / a) * a;
    }

    public static int le32(byte[] b, int o) {
        if (o + 4 > b.length) return 0;
        return (b[o] & 0xFF) | ((b[o+1] & 0xFF) << 8)
                | ((b[o+2] & 0xFF) << 16) | ((b[o+3] & 0xFF) << 24);
    }

    public static long le64(byte[] b, int o) {
        if (o + 8 > b.length) return 0;
        long lo = le32(b, o) & 0xFFFFFFFFL;
        long hi = le32(b, o + 4) & 0xFFFFFFFFL;
        return lo | (hi << 32);
    }

    public static void putLe32(byte[] b, int o, int v) {
        b[o] = (byte)(v & 0xFF);
        b[o+1] = (byte)((v >>> 8) & 0xFF);
        b[o+2] = (byte)((v >>> 16) & 0xFF);
        b[o+3] = (byte)((v >>> 24) & 0xFF);
    }

    private static boolean startsWith(byte[] d, byte[] p) {
        if (d.length < p.length) return false;
        for (int i = 0; i < p.length; i++) if (d[i] != p[i]) return false;
        return true;
    }

    private static byte[] slice(byte[] d, int off, int len) {
        if (len <= 0) return new byte[0];
        if (off < 0 || off + len > d.length) return new byte[0];
        byte[] r = new byte[len];
        System.arraycopy(d, off, r, 0, len);
        return r;
    }

    private static String hex(byte[] d, int off, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len && off + i < d.length; i++) {
            sb.append(String.format("%02x", d[off + i]));
        }
        return sb.toString();
    }
}
