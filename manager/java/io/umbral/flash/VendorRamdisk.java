package io.umbral.flash;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * vendor_boot v4 的多 ramdisk 支持
 * —— 对应 Python 版 bootpatch/vendor_ramdisk.py
 *
 * KSU 的查找策略（boot_patch.rs:387）：
 *   优先找名字是 "init_boot" 的，其次找空名的
 *
 * 结构（AOSP bootimg.h）：
 *   struct vendor_ramdisk_table_entry_v4 {
 *       uint32_t ramdisk_size;      // 该 ramdisk 的字节数
 *       uint32_t ramdisk_offset;    // 在 vendor ramdisk section 里的偏移
 *       uint32_t ramdisk_type;      // 类型
 *       char     ramdisk_name[32];
 *       uint32_t board_id[16];
 *   };  // 共 108 字节
 */
public final class VendorRamdisk {

    private VendorRamdisk() {}

    public static final int ENTRY_SIZE = 108;
    public static final int NAME_SIZE = 32;
    public static final int BOARD_ID_COUNT = 16;

    public static final int TYPE_NONE = 0;
    public static final int TYPE_PLATFORM = 1;
    public static final int TYPE_RECOVERY = 2;
    public static final int TYPE_DLKM = 3;

    public static String typeName(int t) {
        switch (t) {
            case TYPE_NONE: return "NONE";
            case TYPE_PLATFORM: return "PLATFORM";
            case TYPE_RECOVERY: return "RECOVERY";
            case TYPE_DLKM: return "DLKM";
            default: return "type" + t;
        }
    }

    // ══════════════ Entry ══════════════

    public static final class Entry {
        public int index;
        public int size;
        public int offset;
        public int type;
        public String name;
        public int[] boardId;
        public byte[] data;

        public String describe() {
            return String.format("#%d  '%s'  %-10s %,9d B @%,9d",
                    index, name, typeName(type), size, offset);
        }
    }

    // ══════════════ 解析 table ══════════════

    /**
     * @param tableData   vendor_ramdisk_table 原始字节
     * @param sectionData vendor ramdisk section 原始字节（多个 ramdisk 串联）
     */
    public static List<Entry> parseTable(byte[] tableData, byte[] sectionData) {
        List<Entry> list = new ArrayList<>();
        int n = tableData.length / ENTRY_SIZE;

        for (int i = 0; i < n; i++) {
            int base = i * ENTRY_SIZE;
            if (base + ENTRY_SIZE > tableData.length) break;

            Entry e = new Entry();
            e.index = i;
            e.size = BootImage.le32(tableData, base);
            e.offset = BootImage.le32(tableData, base + 4);
            e.type = BootImage.le32(tableData, base + 8);

            StringBuilder sb = new StringBuilder();
            for (int k = 0; k < NAME_SIZE; k++) {
                byte b = tableData[base + 12 + k];
                if (b == 0) break;
                sb.append((char)(b & 0xFF));
            }
            e.name = sb.toString();

            e.boardId = new int[BOARD_ID_COUNT];
            for (int k = 0; k < BOARD_ID_COUNT; k++) {
                e.boardId[k] = BootImage.le32(tableData, base + 12 + NAME_SIZE + k * 4);
            }

            // 取数据
            if (e.offset >= 0 && e.size >= 0 && e.offset + e.size <= sectionData.length) {
                e.data = new byte[e.size];
                System.arraycopy(sectionData, e.offset, e.data, 0, e.size);
            } else {
                e.data = new byte[0];
            }

            list.add(e);
        }
        return list;
    }

    // ══════════════ 构建 table ══════════════

    public static byte[] buildTable(List<Entry> entries) {
        byte[] out = new byte[entries.size() * ENTRY_SIZE];
        int p = 0;
        for (Entry e : entries) {
            putLe32(out, p, e.size);
            putLe32(out, p + 4, e.offset);
            putLe32(out, p + 8, e.type);

            byte[] nb = e.name.getBytes(StandardCharsets.UTF_8);
            int copyLen = Math.min(nb.length, NAME_SIZE - 1);
            System.arraycopy(nb, 0, out, p + 12, copyLen);

            for (int k = 0; k < BOARD_ID_COUNT; k++) {
                int v = (e.boardId != null && k < e.boardId.length) ? e.boardId[k] : 0;
                putLe32(out, p + 12 + NAME_SIZE + k * 4, v);
            }
            p += ENTRY_SIZE;
        }
        return out;
    }

    // ══════════════ 查找目标 ══════════════

    /**
     * 按 KSU 的策略找目标 ramdisk。
     * 优先 "init_boot"，其次空名。
     * 返回索引，找不到返回 -1。
     */
    public static int findTarget(List<Entry> entries) {
        for (Entry e : entries) {
            if ("init_boot".equals(e.name)) return e.index;
        }
        for (Entry e : entries) {
            if ("".equals(e.name)) return e.index;
        }
        return -1;
    }

    // ══════════════ 重建 section ══════════════

    /**
     * 重建 vendor ramdisk section：把所有 entry 的数据按顺序拼接，
     * 同时更新每个 entry 的 offset 和 size。
     *
     * 替换某个 ramdisk 后必须调这个 —— 因为大小变了，
     * 后面所有 entry 的 offset 都要跟着变。
     */
    public static byte[] rebuildSection(List<Entry> entries) {
        int total = 0;
        for (Entry e : entries) total += e.data.length;

        byte[] out = new byte[total];
        int p = 0;
        for (Entry e : entries) {
            e.offset = p;
            e.size = e.data.length;
            System.arraycopy(e.data, 0, out, p, e.data.length);
            p += e.data.length;
        }
        return out;
    }

    /** 替换指定索引的 ramdisk 数据，返回新的 section */
    public static byte[] replaceRamdisk(List<Entry> entries, int index, byte[] newData) {
        if (index < 0 || index >= entries.size()) {
            throw new IllegalArgumentException("索引 " + index + " 越界（共 " + entries.size() + " 个）");
        }
        entries.get(index).data = newData;
        return rebuildSection(entries);
    }

    public static List<String> describe(List<Entry> entries, int targetIndex) {
        List<String> l = new ArrayList<>();
        l.add("vendor ramdisk table: " + entries.size() + " 个 entry");
        for (Entry e : entries) {
            String mark = e.index == targetIndex ? "  ← 目标" : "";
            l.add("  " + e.describe() + mark);
            List<Integer> nz = new ArrayList<>();
            if (e.boardId != null) {
                for (int i = 0; i < e.boardId.length; i++) {
                    if (e.boardId[i] != 0) nz.add(i);
                }
            }
            if (!nz.isEmpty()) l.add("       board_id 非零位置: " + nz);
        }
        return l;
    }

    private static void putLe32(byte[] b, int o, int v) {
        b[o] = (byte)(v & 0xFF);
        b[o+1] = (byte)((v >>> 8) & 0xFF);
        b[o+2] = (byte)((v >>> 16) & 0xFF);
        b[o+3] = (byte)((v >>> 24) & 0xFF);
    }
}
