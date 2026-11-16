package io.umbral.sk;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;

/**
 * Patch a .ko's vermagic so it loads on this device.
 *
 * insmod rejects a module whose vermagic differs from uname -r. Our modules are
 * built on PC against GKI trees, so the string never matches a vendor kernel.
 * This rewrites the "vermagic=" entry inside .modinfo, without touching code or
 * data sections.
 *
 * Limitation: if the target kernel has CONFIG_MODVERSIONS and a symbol CRC
 * differs, insmod still fails ("disagrees about version of symbol"). That cannot
 * be fixed here -- it needs a rebuild against that kernel's source.
 */
public final class Vermagic {

    private static final int SHT_STRTAB = 3;

    private Vermagic() {
    }

    /** kernel release as the module loader sees it, e.g. "5.15.197-gfddbe50ead86-dirty" */
    public static String kernelRelease() {
        String v = System.getProperty("os.version");
        if (v != null && v.length() > 0) {
            return v;
        }
        return null;
    }

    /** full vermagic = release + " SMP preempt mod_unload modversions aarch64" */
    public static String buildVermagic(String release) {
        return release + " SMP preempt mod_unload modversions aarch64";
    }

    private static long u64(byte[] b, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) {
            v = (v << 8) | (b[off + i] & 0xFFL);
        }
        return v;
    }

    private static int u32(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    private static int u16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    /** returns the current vermagic, or null */
    public static String current(byte[] ko) {
        if (ko.length < 64 || ko[0] != 0x7F || ko[1] != 'E' || ko[2] != 'L' || ko[3] != 'F') {
            return null;
        }
        long shoff = u64(ko, 0x28);
        int shentsize = u16(ko, 0x3A);
        int shnum = u16(ko, 0x3C);
        int shstrndx = u16(ko, 0x3E);
        if (shnum <= 0 || shoff <= 0 || shoff > ko.length) {
            return null;
        }
        long stroff = 0;
        int s = (int) shoff + shstrndx * shentsize;
        if (s + 24 > ko.length) {
            return null;
        }
        stroff = u64(ko, s + 24);
        for (int i = 0; i < shnum; i++) {
            int h = (int) shoff + i * shentsize;
            if (h + 64 > ko.length) {
                break;
            }
            int nameOff = u32(ko, h);
            long off = u64(ko, h + 24);
            long size = u64(ko, h + 32);
            if (stroff <= 0 || stroff + nameOff >= ko.length) {
                continue;
            }
            int e = (int) stroff + nameOff;
            StringBuilder nb = new StringBuilder();
            while (e < ko.length && ko[e] != 0) {
                nb.append((char) (ko[e] & 0xFF));
                e++;
            }
            if (!".modinfo".equals(nb.toString())) {
                continue;
            }
            byte[] tag = "vermagic=".getBytes();
            for (long p = off; p + tag.length < off + size; p++) {
                boolean hit = true;
                for (int k = 0; k < tag.length; k++) {
                    if (ko[(int) p + k] != tag[k]) {
                        hit = false;
                        break;
                    }
                }
                if (!hit) {
                    continue;
                }
                int q = (int) p + tag.length;
                StringBuilder v = new StringBuilder();
                while (q < ko.length && ko[q] != 0) {
                    v.append((char) (ko[q] & 0xFF));
                    q++;
                }
                return v.toString();
            }
        }
        return null;
    }

    /** overwrite vermagic in place; the new string must not be longer than the old one */
    public static boolean patchInPlace(byte[] ko, String newVermagic) {
        String cur = current(ko);
        if (cur == null || newVermagic == null || newVermagic.equals(cur)) {
            return false;
        }
        byte[] oldE = ("vermagic=" + cur).getBytes();
        byte[] newE = ("vermagic=" + newVermagic).getBytes();
        if (newE.length > oldE.length) {
            return false;   /* refuse: caller must keep a same-or-shorter string */
        }
        for (int i = 0; i + oldE.length <= ko.length; i++) {
            boolean hit = true;
            for (int k = 0; k < oldE.length; k++) {
                if (ko[i + k] != oldE[k]) {
                    hit = false;
                    break;
                }
            }
            if (!hit) {
                continue;
            }
            System.arraycopy(newE, 0, ko, i, newE.length);
            for (int k = newE.length; k < oldE.length; k++) {
                ko[i + k] = 0;
            }
            return true;
        }
        return false;
    }


    /**
     * L3 probe: does this device's kernel enforce symbol CRC checks?
     *
     * CONFIG_MODVERSIONS shows up in two readable places:
     *   · the running kernel's own vermagic (uname -v / /proc/version often carries it)
     *   · presence of /proc/kallsyms symbol CRCs -- not readable without root
     * We can only do a best-effort textual check here; the honest answer is
     * "maybe", which is what we report to the user instead of pretending.
     */
    public static boolean modversionsLikely() {
        try {
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/version"));
            String line = r.readLine();
            r.close();
            if (line != null) {
                String l = line.toLowerCase();
                return l.contains("modversions") || l.contains("smp preempt");
            }
        } catch (Throwable ignored) {
        }
        return true;   /* 拿不到就按"可能有"处理，别给用户假安心 */
    }


    private static void put64(byte[] b, int off, long v) {
        for (int i = 0; i < 8; i++) {
            b[off + i] = (byte) ((v >>> (8 * i)) & 0xFF);
        }
    }

    /**
     * 新串比原串长时的改写：重建 .modinfo 段并追加到文件尾部，改段头的 offset/size。
     * 内核读 .modinfo 靠段头，不要求段在文件里连续，所以这样是安全的。
     *
     * 为什么需要：厂商内核的 uname -r 通常比我们构建树里的 release 串更长
     * （例如 5.15.194-ge6654bf2f6c2 → 5.15.197-gfddbe50ead86-dirty），
     * 旧实现只支持「不变长」，于是 vivo 那类机器永远改不动 vermagic。
     */
    public static byte[] patchLonger(byte[] ko, String newVermagic) {
        String cur = current(ko);
        if (cur == null || newVermagic == null || newVermagic.equals(cur)) {
            return null;
        }
        byte[] oldE = ("vermagic=" + cur).getBytes();
        byte[] newE = ("vermagic=" + newVermagic).getBytes();

        long shoff = u64(ko, 0x28);
        int shentsize = u16(ko, 0x3A);
        int shnum = u16(ko, 0x3C);
        int shstrndx = u16(ko, 0x3E);
        long stroff = u64(ko, (int) shoff + shstrndx * shentsize + 24);

        for (int i = 0; i < shnum; i++) {
            int h = (int) shoff + i * shentsize;
            int nameOff = u32(ko, h);
            int e = (int) stroff + nameOff;
            StringBuilder nb = new StringBuilder();
            while (e < ko.length && ko[e] != 0) {
                nb.append((char) (ko[e] & 0xFF));
                e++;
            }
            if (!".modinfo".equals(nb.toString())) {
                continue;
            }
            long off = u64(ko, h + 24);
            long size = u64(ko, h + 32);
            byte[] blob = new byte[(int) size];
            System.arraycopy(ko, (int) off, blob, 0, (int) size);

            byte[] out = new byte[blob.length + (newE.length - oldE.length)];
            int w = 0, i2 = 0;
            boolean done = false;
            while (i2 < blob.length) {
                if (!done && i2 + oldE.length <= blob.length && matchAt(blob, i2, oldE)) {
                    System.arraycopy(newE, 0, out, w, newE.length);
                    w += newE.length;
                    i2 += oldE.length;
                    done = true;
                } else {
                    out[w++] = blob[i2++];
                }
            }
            if (!done) {
                return null;
            }

            int newOff = (ko.length + 15) & ~15;
            byte[] res = new byte[newOff + w];
            System.arraycopy(ko, 0, res, 0, ko.length);
            System.arraycopy(out, 0, res, newOff, w);
            put64(res, h + 24, newOff);
            put64(res, h + 32, w);
            return res;
        }
        return null;
    }

    private static boolean matchAt(byte[] hay, int at, byte[] needle) {
        for (int k = 0; k < needle.length; k++) {
            if (hay[at + k] != needle[k]) {
                return false;
            }
        }
        return true;
    }

    /** patch a .ko file on disk to the running kernel's vermagic; returns log text */
    public static String patchFile(String path) {
        String rel = kernelRelease();
        if (rel == null) {
            return "vermagic: 读不到运行内核版本，跳过";
        }
        String want = buildVermagic(rel);
        try {
            File f = new File(path);
            byte[] data = readAll(f);
            String cur = current(data);
            if (cur == null) {
                return "vermagic: " + f.getName() + " 里没有 modinfo/vermagic";
            }
            if (cur.equals(want)) {
                return "vermagic: 已匹配 (" + rel + ")" + (modversionsLikely() ? " / 内核开 MODVERSIONS：若 insmod 报 symbol CRC 不符需专用构建" : "");
            }
            if (!patchInPlace(data, want)) {
                byte[] longer = patchLonger(data, want);
                if (longer == null) {
                    return "vermagic: 改写失败（原串 " + cur + "，目标 " + want + "）";
                }
                data = longer;
            }
            if (true) {
                FileOutputStream out = new FileOutputStream(f);
                out.write(data);
                out.close();
                return "vermagic: 已改写 " + cur + " -> " + want + (modversionsLikely() ? " / 内核开 MODVERSIONS：若 insmod 报 symbol CRC 不符需专用构建" : "");
            }
            return "vermagic: 目标串比原串长，需要在打包时换用更短的构建串（原: " + cur + "）";
        } catch (Throwable t) {
            return "vermagic: 失败 " + t;
        }
    }

    private static byte[] readAll(File f) throws IOException {
        InputStream in = new FileInputStream(f);
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            bo.write(buf, 0, n);
        }
        in.close();
        return bo.toByteArray();
    }
}
