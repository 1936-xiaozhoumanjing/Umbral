package io.umbral.flash;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * cpio newc (070701) 解析与构建 —— 对应 Python 版 bootpatch/cpio.py
 *
 * 从 android_bootimg/src/cpio.rs 学到的关键点：
 *   1. 只认 070701（newc），不认 070702（crc）
 *   2. 字段只保留必要的，其余写回时统一生成
 *   3. TRAILER 不是结束标志 —— 后面可能还有下一段 cpio
 *   4. 跳过 "." 和 ".."
 *   5. TRAILER 后可能有尾部填充（vendor ramdisk 常见），重建时要补回
 */
public final class Cpio {

    private Cpio() {}

    public static final int HDR = 110;
    private static final byte[] MAGIC = {'0', '7', '0', '7', '0', '1'};

    // 文件类型
    public static final int TYPE_MASK = 0170000;
    public static final int TYPE_FIFO = 0010000;
    public static final int TYPE_CHAR = 0020000;
    public static final int TYPE_DIR = 0040000;
    public static final int TYPE_BLOCK = 0060000;
    public static final int TYPE_REGULAR = 0100000;
    public static final int TYPE_SYMLINK = 0120000;
    public static final int TYPE_SOCKET = 0140000;

    // ══════════════ Entry ══════════════

    /**
     * cpio 条目。只保留必要的字段，其余写回时统一生成。
     */
    public static final class Entry {
        public String name;
        public int mode;
        public int uid;
        public int gid;
        public int rdevMajor;
        public int rdevMinor;
        public byte[] data;

        public Entry(String name, int mode, byte[] data) {
            this.name = name;
            this.mode = mode;
            this.data = data != null ? data : new byte[0];
        }

        public static Entry regular(String name, byte[] data, int perm) {
            return new Entry(name, perm | TYPE_REGULAR, data);
        }

        public static Entry dir(String name, int perm) {
            return new Entry(name, perm | TYPE_DIR, new byte[0]);
        }

        public static Entry charDev(String name, int rdevMaj, int rdevMin, int perm) {
            Entry e = new Entry(name, perm | TYPE_CHAR, new byte[0]);
            e.rdevMajor = rdevMaj;
            e.rdevMinor = rdevMin;
            return e;
        }

        public static Entry symlink(String name, String target) {
            return new Entry(name, 0777 | TYPE_SYMLINK,
                    target.getBytes(StandardCharsets.UTF_8));
        }

        public int type() { return mode & TYPE_MASK; }
        public boolean isDir() { return type() == TYPE_DIR; }
        public boolean isChar() { return type() == TYPE_CHAR; }
        public boolean isRegular() { return type() == TYPE_REGULAR; }
        public boolean isSymlink() { return type() == TYPE_SYMLINK; }
        public int perm() { return mode & 07777; }
        public int size() { return data == null ? 0 : data.length; }

        @Override
        public String toString() {
            return String.format("<%s mode=0%o size=%d>", name, mode, size());
        }
    }

    // ══════════════ Segment ══════════════

    public static final class Segment {
        public int start;
        public int end;
        public int trailerPos;
        public Segment(int start, int end, int trailerPos) {
            this.start = start;
            this.end = end;
            this.trailerPos = trailerPos;
        }
    }

    // ══════════════ ParseResult ══════════════

    public static final class ParseResult {
        public List<Entry> entries = new ArrayList<>();
        public List<Segment> segments = new ArrayList<>();
        public List<String> warnings = new ArrayList<>();
        public List<String> errors = new ArrayList<>();
        /** TRAILER 之后的填充字节数 */
        public int tailPadding = 0;

        public boolean ok() { return errors.isEmpty(); }
    }

    // ══════════════ 解析 ══════════════

    public static ParseResult parse(byte[] d) {
        return parse(d, true);
    }

    /**
     * 解析 cpio。
     *
     * 多段处理：遇到 TRAILER 后不结束，而是搜索下一个 070701，找到就继续。
     * 尾部填充：TRAILER 之后的全 0 填充记在 tailPadding 里，重建时补上。
     */
    public static ParseResult parse(byte[] d, boolean allowMultiSegment) {
        ParseResult r = new ParseResult();
        int pos = 0;
        int n = d.length;
        int segStart = 0;

        while (pos + HDR <= n) {
            // magic
            if (!matchesMagic(d, pos)) {
                if (!r.entries.isEmpty()) {
                    r.warnings.add(String.format("@%d magic=%s，停止解析",
                            pos, hex(d, pos, 8)));
                } else {
                    r.errors.add(String.format("@%d 不是 cpio 头（magic=%s）",
                            pos, hex(d, pos, 8)));
                }
                break;
            }

            // 13 个字段
            int[] f = new int[13];
            boolean bad = false;
            for (int k = 0; k < 13; k++) {
                int v = hexAt(d, pos + 6 + k * 8);
                if (v < 0) {
                    r.errors.add(String.format("@%d 字段 %d 不是十六进制", pos, k));
                    bad = true;
                    break;
                }
                f[k] = v;
            }
            if (bad) break;

            int ino = f[0], mode = f[1], uid = f[2], gid = f[3];
            int nlink = f[4], mtime = f[5], size = f[6];
            int dmaj = f[7], dmin = f[8];
            int rmaj = f[9], rmin = f[10];
            int namesize = f[11], check = f[12];

            if (namesize < 1) {
                r.errors.add(String.format("@%d namesize=%d 非法", pos, namesize));
                break;
            }

            int nameEnd = pos + HDR + namesize;
            if (nameEnd > n) {
                r.errors.add(String.format("@%d 名字越界", pos));
                break;
            }

            String name = new String(d, pos + HDR, namesize - 1, StandardCharsets.UTF_8);

            int dataStart = align4(nameEnd);
            if (dataStart + size > n) {
                r.errors.add(String.format("@%d %s 数据越界（需要 %d，数据 %d）",
                        pos, name, dataStart + size, n));
                break;
            }
            int entryEnd = align4(dataStart + size);

            // ── TRAILER：不是结束，而是找下一段 ──
            if ("TRAILER!!!".equals(name)) {
                r.segments.add(new Segment(segStart, dataStart, pos));
                int remain = n - dataStart;

                if (!allowMultiSegment) {
                    r.tailPadding = remain;
                    break;
                }

                int nxt = indexOfMagic(d, dataStart);
                if (nxt < 0) {
                    r.tailPadding = remain;
                    if (remain > 0) {
                        r.warnings.add(String.format(
                                "TRAILER @%d 后有 %d 字节填充（已记录，重建时补上）",
                                pos, remain));
                    }
                    break;
                }

                r.warnings.add(String.format(
                        "TRAILER @%d 后还有数据（从 %d 起是下一段 cpio），继续解析", pos, nxt));
                r.tailPadding = 0;
                pos = nxt;
                segStart = nxt;
                continue;
            }

            // 跳过 . 和 ..
            if (".".equals(name) || "..".equals(name)) {
                pos = entryEnd;
                continue;
            }

            Entry e = new Entry(name, mode, Arrays.copyOfRange(d, dataStart, dataStart + size));
            e.uid = uid;
            e.gid = gid;
            e.rdevMajor = rmaj;
            e.rdevMinor = rmin;
            r.entries.add(e);

            pos = entryEnd;
        }

        if (r.segments.isEmpty() && !r.entries.isEmpty()) {
            r.warnings.add("没有找到 TRAILER!!!");
        }

        return r;
    }

    // ══════════════ 构建 ══════════════

    public static byte[] build(List<Entry> entries) {
        return build(entries, 300000, 0);
    }

    /**
     * 构建 cpio。
     *
     * 字段策略（照抄 android_bootimg）：
     *   ino 递增 / mode,uid,gid 保留 / nlink 恒 1 / mtime 恒 0
     *   devmajor,devminor 恒 0 / rdev 保留 / namesize 计算 / check 恒 0
     *
     * tailPadding：TRAILER 之后补多少字节 0
     *   vendor ramdisk 常见，init_boot 的 ramdisk 不要补（内核严格）
     */
    public static byte[] build(List<Entry> entries, int startIno, int tailPadding) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 << 20);
        int ino = startIno;

        for (Entry e : entries) {
            byte[] nameB = (e.name + "\0").getBytes(StandardCharsets.UTF_8);
            writeHeader(out, ino, e.mode, e.uid, e.gid, e.size(),
                    e.rdevMajor, e.rdevMinor, nameB.length);
            out.write(nameB, 0, nameB.length);
            pad4(out);
            if (e.size() > 0) {
                out.write(e.data, 0, e.size());
                pad4(out);
            }
            ino++;
        }

        // TRAILER
        byte[] tn = "TRAILER!!!\0".getBytes(StandardCharsets.UTF_8);
        writeHeader(out, ino, 0755, 0, 0, 0, 0, 0, tn.length);
        out.write(tn, 0, tn.length);
        pad4(out);

        // 尾部填充
        for (int i = 0; i < tailPadding; i++) out.write(0);

        return out.toByteArray();
    }

    /** 按名字字典序排序后构建（字典序保证父目录先于子项） */
    public static byte[] buildSorted(List<Entry> entries, int startIno, int tailPadding) {
        List<Entry> copy = new ArrayList<>(entries);
        Collections.sort(copy, new Comparator<Entry>() {
            @Override public int compare(Entry a, Entry b) { return a.name.compareTo(b.name); }
        });
        return build(copy, startIno, tailPadding);
    }

    private static void writeHeader(ByteArrayOutputStream out, int ino, int mode,
                                    int uid, int gid, int size,
                                    int rdevMaj, int rdevMin, int nameLen) {
        out.write(MAGIC, 0, 6);
        writeHex8(out, ino);
        writeHex8(out, mode);
        writeHex8(out, uid);
        writeHex8(out, gid);
        writeHex8(out, 1);      // nlink 恒 1
        writeHex8(out, 0);      // mtime 恒 0
        writeHex8(out, size);
        writeHex8(out, 0);      // devmajor 恒 0
        writeHex8(out, 0);      // devminor 恒 0
        writeHex8(out, rdevMaj);
        writeHex8(out, rdevMin);
        writeHex8(out, nameLen);
        writeHex8(out, 0);      // check 恒 0
    }

    private static void writeHex8(ByteArrayOutputStream out, int v) {
        String s = Integer.toHexString(v);
        for (int i = s.length(); i < 8; i++) out.write('0');
        byte[] b = s.getBytes(StandardCharsets.US_ASCII);
        // 只取最后 8 位
        int start = Math.max(0, b.length - 8);
        out.write(b, start, b.length - start);
    }

    private static void pad4(ByteArrayOutputStream out) {
        int rem = out.size() % 4;
        if (rem != 0) {
            for (int i = 0; i < 4 - rem; i++) out.write(0);
        }
    }

    // ══════════════ 查询辅助 ══════════════

    public static Entry find(List<Entry> entries, String name) {
        for (Entry e : entries) if (e.name.equals(name)) return e;
        return null;
    }

    public static List<Entry> findAll(List<Entry> entries, String name) {
        List<Entry> r = new ArrayList<>();
        for (Entry e : entries) if (e.name.equals(name)) r.add(e);
        return r;
    }

    public static int remove(List<Entry> entries, String name) {
        int before = entries.size();
        for (int i = entries.size() - 1; i >= 0; i--) {
            if (entries.get(i).name.equals(name)) entries.remove(i);
        }
        return before - entries.size();
    }

    public static boolean rename(List<Entry> entries, String oldName, String newName) {
        Entry e = find(entries, oldName);
        if (e == null) return false;
        e.name = newName;
        return true;
    }

    /** 统计每个名字出现次数（用于区分「原厂重名」和「我们引入的重名」） */
    public static java.util.Map<String, Integer> countNames(List<Entry> entries) {
        java.util.Map<String, Integer> m = new java.util.HashMap<>();
        for (Entry e : entries) {
            Integer v = m.get(e.name);
            m.put(e.name, v == null ? 1 : v + 1);
        }
        return m;
    }

    /**
     * 只报「比原厂多出来的」重复。
     *
     * 原厂 cpio 可能有重复目录条目（实测 10.5.8 有两个 dev，厂商 mkbootfs 的产物），
     * 内核遇到重复目录会合并，无害，必须原样保留。
     */
    public static List<String> newDuplicates(java.util.Map<String, Integer> orig,
                                             java.util.Map<String, Integer> now) {
        List<String> bad = new ArrayList<>();
        for (java.util.Map.Entry<String, Integer> kv : now.entrySet()) {
            int n = kv.getValue();
            Integer o = orig.get(kv.getKey());
            int oi = (o == null) ? 0 : o;
            if (n > 1 && n > oi) bad.add(kv.getKey() + " ×" + n + "（原 " + oi + "）");
        }
        return bad;
    }

    public static List<String> duplicateNames(List<Entry> entries) {
        Set<String> seen = new HashSet<>();
        List<String> dups = new ArrayList<>();
        for (Entry e : entries) {
            if (!seen.add(e.name)) dups.add(e.name);
        }
        return dups;
    }

    // ══════════════ 第三方 root 方案检测 ══════════════

    /** 各方案的标记文件 */
    public static final Map<String, String[]> KNOWN_PATCH_SIGNATURES;

    static {
        Map<String, String[]> m = new LinkedHashMap<>();
        m.put("KernelSU", new String[]{"kernelsu.ko", "ksuinit", "init.ksu"});
        m.put("Magisk", new String[]{
                ".backup/.magisk", "init.magisk.rc", "overlay/init.magisk.rc",
                "magiskinit", "magisk32", "magisk64", "magiskpolicy", "stub.xz"});
        m.put("APatch", new String[]{"apd", "ap_patch", "kpimg"});
        m.put("Umbral", new String[]{"sk_root.ko", "sk_hello.ko", "init.skroot"});
        KNOWN_PATCH_SIGNATURES = Collections.unmodifiableMap(m);
    }

    public static Map<String, List<String>> detectPatches(List<Entry> entries) {
        Set<String> names = new HashSet<>();
        for (Entry e : entries) names.add(e.name);

        Map<String, List<String>> found = new LinkedHashMap<>();
        for (Map.Entry<String, String[]> kv : KNOWN_PATCH_SIGNATURES.entrySet()) {
            List<String> hits = new ArrayList<>();
            for (String f : kv.getValue()) {
                if (names.contains(f)) hits.add(f);
            }
            if (!hits.isEmpty()) found.put(kv.getKey(), hits);
        }
        return found;
    }

    // ══════════════ 设备节点 ══════════════

    /** name -> {perm, rdevMajor, rdevMinor, required(1/0)} */
    public static final Map<String, int[]> DEVICE_TABLE;

    static {
        Map<String, int[]> m = new LinkedHashMap<>();
        m.put("dev/console", new int[]{0600, 5, 1, 1});
        m.put("dev/null",    new int[]{0666, 1, 3, 1});
        m.put("dev/urandom", new int[]{0600, 1, 9, 1});
        m.put("dev/kmsg",    new int[]{0600, 1, 11, 0});
        m.put("dev/zero",    new int[]{0666, 1, 5, 0});
        m.put("dev/full",    new int[]{0666, 1, 7, 0});
        m.put("dev/random",  new int[]{0666, 1, 8, 0});
        m.put("dev/tty",     new int[]{0666, 5, 0, 0});
        DEVICE_TABLE = Collections.unmodifiableMap(m);
    }

    public static Map<String, String> devicesPresent(List<Entry> entries) {
        Map<String, String> m = new LinkedHashMap<>();
        for (Entry e : entries) {
            if (e.isChar()) m.put(e.name, e.rdevMajor + ":" + e.rdevMinor);
        }
        return m;
    }

    public static List<String> devicesMissing(List<Entry> entries) {
        Set<String> have = new HashSet<>();
        for (Entry e : entries) if (e.isChar()) have.add(e.name);
        List<String> r = new ArrayList<>();
        for (String n : DEVICE_TABLE.keySet()) {
            if (!have.contains(n)) r.add(n);
        }
        return r;
    }

    /** 补齐缺失的设备节点，返回新增的名字列表 */
    public static List<String> ensureDevices(List<Entry> entries) {
        Set<String> have = new HashSet<>();
        for (Entry e : entries) have.add(e.name);
        List<String> added = new ArrayList<>();
        for (Map.Entry<String, int[]> kv : DEVICE_TABLE.entrySet()) {
            if (!have.contains(kv.getKey())) {
                int[] v = kv.getValue();
                entries.add(Entry.charDev(kv.getKey(), v[1], v[2], v[0]));
                added.add(kv.getKey());
            }
        }
        return added;
    }

    /** 修正 rdev 错误的设备节点，返回 "name: from -> to" 列表 */
    public static List<String> fixWrongDevices(List<Entry> entries) {
        List<String> fixed = new ArrayList<>();
        for (Entry e : entries) {
            if (!e.isChar()) continue;
            int[] want = DEVICE_TABLE.get(e.name);
            if (want == null) continue;
            if (e.rdevMajor != want[1] || e.rdevMinor != want[2]) {
                String old = e.rdevMajor + ":" + e.rdevMinor;
                e.rdevMajor = want[1];
                e.rdevMinor = want[2];
                fixed.add(e.name + ": " + old + " -> " + want[1] + ":" + want[2]);
            }
        }
        return fixed;
    }

    /** 找出 rdev 为 0:0 的设备节点（坑 #2） */
    public static List<String> zeroRdevDevices(List<Entry> entries) {
        List<String> r = new ArrayList<>();
        for (Entry e : entries) {
            if (e.isChar() && e.rdevMajor == 0 && e.rdevMinor == 0) r.add(e.name);
        }
        return r;
    }

    // ══════════════ 底层工具 ══════════════

    public static int align4(int n) { return (n + 3) & ~3; }

    private static boolean matchesMagic(byte[] d, int pos) {
        if (pos + 6 > d.length) return false;
        for (int i = 0; i < 6; i++) if (d[pos + i] != MAGIC[i]) return false;
        return true;
    }

    private static int indexOfMagic(byte[] d, int from) {
        for (int i = from; i + 6 <= d.length; i++) {
            if (matchesMagic(d, i)) return i;
        }
        return -1;
    }

    /** 读 8 位十六进制字段，失败返回 -1 */
    private static int hexAt(byte[] d, int off) {
        if (off + 8 > d.length) return -1;
        long v = 0;
        for (int i = 0; i < 8; i++) {
            int c = d[off + i] & 0xFF;
            int x;
            if (c >= '0' && c <= '9') x = c - '0';
            else if (c >= 'a' && c <= 'f') x = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') x = c - 'A' + 10;
            else return -1;
            v = (v << 4) | x;
        }
        if (v > Integer.MAX_VALUE) return (int) v;   // 允许溢出（字段本来就是 32 位无符号）
        return (int) v;
    }

    private static String hex(byte[] d, int off, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len && off + i < d.length; i++) {
            sb.append(String.format("%02x", d[off + i]));
        }
        return sb.toString();
    }
}
