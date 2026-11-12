package io.umbral.flash;

import android.content.Context;
import android.net.Uri;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * boot / init_boot / vendor_boot 镜像修补器
 *
 * 完全重写版 —— 逻辑照抄 Magisk + KernelSU + android_bootimg 三份开源实现。
 *
 * 完整流程（对应 android_bootimg/src/patcher.rs）：
 *   解析 → 解 ramdisk → 解 cpio → 解析 AVB → 检查已有修补
 *   → 改 cpio → 重建 → 保持原格式压缩 → 重打包 → AVB 重算
 *   → patch header size 字段
 *
 * 关键改进（相比旧版）：
 *   1. 保持原压缩格式（不再一律 gzip）
 *   2. AVB 位置自动重算（新 ramdisk 变大也能处理）
 *   3. 保留 avb_tail（可能含厂商数据）
 *   4. 保留 boot signature 段
 *   5. 清第三方 root 残留（KSU/Magisk/APatch）
 *   6. 改名冲突自动避让
 *   7. 设备节点按表补齐 + 修正错误 rdev
 *   8. 支持 vendor_boot 多 ramdisk
 *   9. 全量日志（每一步都记录）
 */
public final class BootPatch {

    private BootPatch() {}

    /** 改名候选（按优先级，找第一个不冲突的） */
    private static final String[] RENAME_CANDIDATES = {
            "init.skroot", "init.orig", "init.original",
            "init.bak", "init.sk", "init.android",
    };

    // ══════════════════════════════════════════════════════
    // 对外 API（保持兼容）
    // ══════════════════════════════════════════════════════

    /** 解析 header 信息，用于界面显示 */
    public static String parseHeaderInfo(byte[] head, int len) {
        try {
            byte[] d = new byte[len];
            System.arraycopy(head, 0, d, 0, len);
            BootImage.Header h = BootImage.parseHeader(d);
            StringBuilder sb = new StringBuilder();
            for (String line : h.describe()) {
                sb.append(line).append('\n');
            }
            return sb.toString().trim();
        } catch (Exception e) {
            return "解析失败: " + e.getMessage();
        }
    }

    public static String patchFile(Context ctx, File f) throws Exception {
        return patchFile(ctx, f, null);
    }

    public static String patchFile(Context ctx, File f, PatchProgress cb) throws Exception {
        log(cb, "读取镜像: " + f.getName());
        progress(cb, 3);

        FileInputStream in = new FileInputStream(f);
        ByteArrayOutputStream bo = new ByteArrayOutputStream((int) Math.min(f.length(), 256L << 20));
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        in.close();
        byte[] img = bo.toByteArray();
        log(cb, "  " + img.length + " 字节");

        Result r = doPatch(ctx, img, cb);
        if (!r.ok) return r.error;

        return writeOut(ctx, r.data, cb);
    }

    public static String patch(Context ctx, Uri uri) throws Exception {
        return patch(ctx, uri, null);
    }

    public static String patch(Context ctx, Uri uri, PatchProgress cb) throws Exception {
        log(cb, "读取镜像…");
        progress(cb, 3);

        InputStream in = ctx.getContentResolver().openInputStream(uri);
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        in.close();
        byte[] img = bo.toByteArray();
        log(cb, "  " + img.length + " 字节");

        Result r = doPatch(ctx, img, cb);
        if (!r.ok) return r.error;

        return writeOut(ctx, r.data, cb);
    }

    /**
     * 离线修补（不依赖 Context），便于测试和逐字节验证。
     */
    public static byte[] patchBytes(byte[] img, byte[] skInit, byte[] skKo,
                                    PatchProgress cb) throws Exception {
        Result r = doPatchCore(img, skInit, skKo, cb);
        if (!r.ok) throw new IllegalArgumentException(r.error);
        return r.data;
    }

    // ══════════════════════════════════════════════════════
    // 核心
    // ══════════════════════════════════════════════════════

    private static final class Result {
        boolean ok;
        byte[] data;
        String error;
    }

    private static Result doPatch(Context ctx, byte[] img, PatchProgress cb) throws Exception {
        log(cb, "读取内置资源…");

        // ── init 包装器：按 ABI 取 assets/<abi>/umbral_init ──
        // 这一层是通用的，任何 aarch64 Android 设备都能用。
        String initPath = io.umbral.sk.ModuleRepo.skInitPath();
        byte[] skInit = readAsset(ctx, initPath);
        if (skInit == null) {
            Result r = new Result();
            r.ok = false;
            r.error = "缺少内置 init 包装器 assets/" + initPath;
            log(cb, "X " + r.error);
            return r;
        }
        log(cb, "  init 包装器 " + skInit.length + " B  (" + initPath + ")");

        // ── 内核模块：按目标 KMI 取，取不到就不注入 ──
        //
        // 这一层必须精确匹配内核。内核会检查三样东西：
        //   ① .gnu.linkonce.this_module 段大小 == sizeof(struct module)
        //      实测：标准 upstream 6.6.30 = 1280，ACK android15-6.6 = 1536
        //      差 256 字节来自 ANDROID_KABI_RESERVE ×4 和更大的 mod_arch_specific
        //   ② __versions 里的 module_layout CRC（由 struct module 布局算出）
        //   ③ kCFI 类型哈希（由函数签名算出，跨版本稳定）
        // 任何一条不匹配 → finit_module 失败 / CFI failure → panic 或卡 logo。
        //
        // 查找策略：先精确（full KMI，厂商定制快照）→ 再通用（base KMI）。
        io.umbral.sk.ModuleRepo.Support sup =
                io.umbral.sk.ModuleRepo.support(ctx);
        byte[] skKo = (sup.modulePath != null) ? readAsset(ctx, sup.modulePath) : null;

        if (skKo != null) {
            log(cb, "  内核版本   " + (sup.rawRelease != null ? sup.rawRelease : "?"));
            log(cb, "  基础 KMI   " + sup.baseKmi);
            if (sup.custom) {
                log(cb, "  完整 KMI   " + sup.fullKmi + "（定制内核专用模块）");
            }
            log(cb, "  内核模块   " + skKo.length + " B  (" + sup.modulePath + ")");
        } else {
            log(cb, "  内核版本   " + (sup.rawRelease != null ? sup.rawRelease : "?"));
            log(cb, "  基础 KMI   " + (sup.baseKmi == null ? "识别失败" : sup.baseKmi));
            log(cb, "  内核模块   无（模块库里没有这个 KMI 的 .ko）");
            log(cb, "            → 只注入 init 包装器：系统能正常启动，但没有 root 能力");
        }

        return doPatchCore(img, skInit, skKo, cb);
    }

    private static Result doPatchCore(byte[] img, byte[] skInit, byte[] skKo,
                                      PatchProgress cb) {
        Result res = new Result();

        try {
            // ══════════ 1. 解析镜像 ══════════
            log(cb, "");
            log(cb, "── 1. 解析镜像 ──");
            BootImage.Image image;
            try {
                image = BootImage.parse(img);
            } catch (Exception e) {
                res.ok = false;
                res.error = "镜像解析失败: " + e.getMessage();
                log(cb, "X " + res.error);
                return res;
            }
            for (String line : image.describe()) log(cb, "  " + line);
            progress(cb, 10);

            // vendor_boot 走另一条路
            if (image.isVendor()) {
                return patchVendorCore(img, image, skInit, skKo, cb);
            }

            // ramdisk 必须存在
            if (image.ramdiskSize <= 0) {
                res.ok = false;
                res.error = "这个镜像里 ramdisk_size = 0，没有 ramdisk。\n"
                        + "  可能原因：\n"
                        + "    ① 纯 kernel 镜像（某些设备的 boot.img 不含 ramdisk）\n"
                        + "    ② 设备把 ramdisk 放在 init_boot.img 里（Android 13+ GKI）\n"
                        + "  处理办法：\n"
                        + "    · 如果设备有 init_boot 分区，请提供 init_boot.img\n"
                        + "    · 官方 OTA 包里的 payload.bin 可以提取出来";
                log(cb, "X " + res.error);
                return res;
            }

            // ══════════ 2. 解 ramdisk ══════════
            log(cb, "");
            log(cb, "── 2. 解 ramdisk ──");
            int fmt = Compress.detect(image.ramdisk);
            log(cb, "  格式 " + Compress.formatName(fmt) + "  " + image.ramdiskSize + " 字节");

            Compress.DecompressResult dr = Compress.decompress(image.ramdisk, fmt);
            if (!dr.ok()) {
                res.ok = false;
                res.error = "ramdisk 解压失败: " + dr.error;
                log(cb, "X " + res.error);
                return res;
            }
            log(cb, "  解压 " + dr.data.length + " 字节（" + dr.method + "）");
            progress(cb, 20);

            // ══════════ 3. 解 cpio ══════════
            log(cb, "");
            log(cb, "── 3. 解 cpio ──");
            Cpio.ParseResult pr = Cpio.parse(dr.data);
            if (!pr.ok()) {
                res.ok = false;
                res.error = "cpio 解析失败: " + pr.errors;
                log(cb, "X " + res.error);
                return res;
            }
            for (String w : pr.warnings) log(cb, "  ⚠ " + w);
            log(cb, "  " + pr.entries.size() + " 个条目，"
                    + pr.segments.size() + " 段，尾部填充 " + pr.tailPadding + " 字节");
            progress(cb, 30);

            // ══════════ 4. 解析 AVB ══════════
            log(cb, "");
            log(cb, "── 4. 解析 AVB ──");
            Avb.AvbInfo avbInfo = null;
            try {
                avbInfo = Avb.parse(img, image.blocksEndRaw);
            } catch (Exception e) {
                log(cb, "  ⚠ AVB 解析异常: " + e.getMessage());
            }
            if (avbInfo != null) {
                for (String line : avbInfo.describe()) log(cb, "  " + line);
            } else {
                log(cb, "  没有 AVB 结构");
            }
            progress(cb, 38);

            // ══════════ 5. 检查已有修补 ══════════
            log(cb, "");
            log(cb, "── 5. 检查已有修补 ──");

            // 记录原厂就存在的重名（某些厂商 mkbootfs 会重复输出目录条目，
            // 实测 10.5.8 的 init_boot 有两个 dev 目录。内核遇到重复目录会合并，无害）
            final java.util.Map<String, Integer> origNameCount = Cpio.countNames(pr.entries);
            final List<String> origDups = new ArrayList<>();
            for (java.util.Map.Entry<String, Integer> en : origNameCount.entrySet()) {
                if (en.getValue() > 1) origDups.add(en.getKey() + " ×" + en.getValue());
            }
            if (!origDups.isEmpty()) {
                log(cb, "  原厂重名条目（内核会合并，保留）: " + origDups);
            }

            java.util.Map<String, List<String>> existing = Cpio.detectPatches(pr.entries);
            if (existing.isEmpty()) {
                log(cb, "  没有已存在的 root 方案");
            } else {
                for (java.util.Map.Entry<String, List<String>> e : existing.entrySet()) {
                    log(cb, "  ⚠ 检测到 " + e.getKey() + ": " + e.getValue());
                }
            }

            // ══════════ 6. 改 cpio ══════════
            log(cb, "");
            log(cb, "── 6. 修改 cpio ──");

            // 6.1 清理第三方
            List<String> dropped = new ArrayList<>();
            for (java.util.Map.Entry<String, String[]> kv
                    : Cpio.KNOWN_PATCH_SIGNATURES.entrySet()) {
                if ("Umbral".equals(kv.getKey())) continue;   // 不删自己的
                for (String f : kv.getValue()) {
                    int n = Cpio.remove(pr.entries, f);
                    if (n > 0) dropped.add(f + " ×" + n);
                }
            }
            if (dropped.isEmpty()) log(cb, "  没有第三方组件需要清理");
            else log(cb, "  清理: " + dropped);

            // 6.2 找 first-stage init
            Cpio.Entry initEntry = Cpio.find(pr.entries, "init");
            if (initEntry == null) {
                // 退化：找最小的可执行 ELF 且名字带 init
                Cpio.Entry best = null;
                for (Cpio.Entry e : pr.entries) {
                    if (!e.name.startsWith("init")) continue;
                    if (e.size() < 4) continue;
                    if (!(e.data[0] == 0x7f && e.data[1] == 'E')) continue;
                    if ((e.mode & 0111) == 0) continue;
                    if (best == null || e.size() < best.size()) best = e;
                }
                if (best == null) {
                    res.ok = false;
                    res.error = "找不到 first-stage init（既没有 /init，也没有 init* 的可执行 ELF）";
                    log(cb, "X " + res.error);
                    return res;
                }
                initEntry = best;
                log(cb, "  ⚠ 没有 /init，改用 " + best.name);
            }
            log(cb, String.format("  first-stage init: %s  %,d 字节  0%o",
                    initEntry.name, initEntry.size(), initEntry.perm()));
            progress(cb, 45);

            // 6.3 决定改名目标
            java.util.Set<String> names = new java.util.HashSet<>();
            for (Cpio.Entry e : pr.entries) names.add(e.name);
            String target = null;
            for (String c : RENAME_CANDIDATES) {
                if (!names.contains(c)) { target = c; break; }
            }
            if (target == null) {
                res.ok = false;
                res.error = "所有改名候选都被占用: " + java.util.Arrays.toString(RENAME_CANDIDATES);
                log(cb, "X " + res.error);
                return res;
            }
            List<String> conflicts = new ArrayList<>();
            for (String c : RENAME_CANDIDATES) if (names.contains(c)) conflicts.add(c);
            log(cb, "  改名目标 " + target
                    + (conflicts.isEmpty() ? "" : "（避开已占用: " + conflicts + "）"));

            String oldName = initEntry.name;
            initEntry.name = target;
            log(cb, "  " + oldName + " → " + target + "（原厂 init 保留）");

            // 6.4 修正 rdev
            List<String> fixed = Cpio.fixWrongDevices(pr.entries);
            if (!fixed.isEmpty()) log(cb, "  修正 rdev: " + fixed);
            List<String> stillBad = Cpio.zeroRdevDevices(pr.entries);
            if (!stillBad.isEmpty()) log(cb, "  ⚠ 仍有 rdev=0:0: " + stillBad);

            // 6.5 补设备节点
            List<String> addedDev = Cpio.ensureDevices(pr.entries);
            if (addedDev.isEmpty()) {
                log(cb, "  设备节点已齐全");
            } else {
                for (String dn : addedDev) {
                    int[] v = Cpio.DEVICE_TABLE.get(dn);
                    String tag = (v != null && v[3] == 1) ? "必需" : "建议";
                    log(cb, String.format("  + %-16s rdev=%d:%d  [%s]", dn, v[1], v[2], tag));
                }
            }
            progress(cb, 55);

            // 6.6 注入
            Cpio.remove(pr.entries, "init");
            pr.entries.add(Cpio.Entry.regular("init", skInit, 0755));
            log(cb, "  + init（我们的包装器）" + skInit.length + " 字节");

            if (skKo != null) {
                // 模块的 __this_module.name 是 "sk_root"（编译时由文件名决定），
                // ramdisk 里的文件名必须与之一致，否则 /proc/modules、rmmod、
                // 以及 umbral_init 的日志全都会对不上号。
                // 旧名 sk_hello.ko 一并清掉，避免升级时残留两份。
                Cpio.remove(pr.entries, "sk_root.ko");
                Cpio.remove(pr.entries, "sk_hello.ko");
                pr.entries.add(Cpio.Entry.regular("sk_root.ko", skKo, 0644));
                log(cb, "  + sk_root.ko " + skKo.length + " 字节");
            } else {
                log(cb, "  - 跳过内核模块（本机 KMI 无匹配模块）");
            }

            // 6.7 重名检查 —— 只报「我们新引入的」重名
            //     原厂 cpio 可能本来就有重复目录条目（实测 10.5.8 有两个 dev），
            //     内核遇到重复目录会合并，无害，必须原样保留。
            List<String> badDups = Cpio.newDuplicates(origNameCount, Cpio.countNames(pr.entries));
            if (!badDups.isEmpty()) {
                res.ok = false;
                res.error = "修补引入了新的重名条目: " + badDups;
                log(cb, "X " + res.error);
                return res;
            }
            if (!origDups.isEmpty()) {
                log(cb, "  保留原厂重名 " + origDups);
            }
            log(cb, "  最终 " + pr.entries.size() + " 个条目");
            progress(cb, 62);

            // ══════════ 7. 重建 cpio ══════════
            log(cb, "");
            log(cb, "── 7. 重建 cpio ──");
            byte[] newCpio = Cpio.build(pr.entries, 300000, pr.tailPadding);
            log(cb, String.format("  %,d 字节（原 %,d）", newCpio.length, dr.data.length));

            // 自验
            Cpio.ParseResult chk = Cpio.parse(newCpio);
            byte[] reChk = Cpio.build(chk.entries, 300000, chk.tailPadding);
            if (java.util.Arrays.equals(reChk, newCpio)) {
                log(cb, "  ✅ cpio round-trip 一致");
            } else {
                log(cb, "  ⚠ cpio round-trip 不一致");
            }
            progress(cb, 70);

            // ══════════ 8. 压缩（保持原格式）══════════
            log(cb, "");
            log(cb, "── 8. 压缩 ──");
            byte[] newRd;
            int outFmt = fmt;
            Compress.CompressResult cr = Compress.compress(newCpio, outFmt);
            if (!cr.ok()) {
                // 保持原格式失败，尝试 gzip 兜底
                log(cb, "  ⚠ 保持 " + Compress.formatName(fmt) + " 失败: " + cr.error);
                log(cb, "  → 改用 gzip（内核支持，但与厂商格式不一致）");
                outFmt = Compress.FMT_GZIP;
                cr = Compress.compress(newCpio, outFmt);
                if (!cr.ok()) {
                    res.ok = false;
                    res.error = "压缩失败: " + cr.error;
                    log(cb, "X " + res.error);
                    return res;
                }
            }
            newRd = cr.data;
            log(cb, String.format("  %s  %,d 字节（原 %,d，差 %+,d）",
                    Compress.formatName(outFmt), newRd.length, image.ramdiskSize,
                    newRd.length - image.ramdiskSize));

            Compress.DecompressResult vd = Compress.decompress(newRd, outFmt);
            if (vd.ok() && java.util.Arrays.equals(vd.data, newCpio)) {
                log(cb, "  ✅ 压缩往返一致");
            } else {
                log(cb, "  ⚠ 压缩往返不一致");
            }
            progress(cb, 78);

            // ══════════ 9. 重打包 ══════════
            log(cb, "");
            log(cb, "── 9. 重打包 ──");
            int page = image.header.pageSize();
            ByteArrayOutputStream out = new ByteArrayOutputStream(img.length + (1 << 20));

            out.write(image.header.raw, 0, image.header.raw.length);
            padTo(out, page);

            int kSize = writeSeg(out, image.kernel, "kernel", page, cb);

            // ⚠ ramdisk_size 必须记**实际数据大小**，不是对齐后的大小。
            //   LZ4/gzip 解码器读到 block_size 就停，但 header 说多了会
            //   让内核多解一段 0，导致死循环或 panic。
            int rdOff = out.size();
            out.write(newRd, 0, newRd.length);
            int rdSize = newRd.length;          // ← 实际大小
            lastRawEnd[0] = out.size();          // ← 记录未对齐的结束位置
            padTo(out, page);                    // 物理上仍补到页对齐
            log(cb, String.format("  %-16s @%,10d  %,12d 字节（占 %,d）",
                    "ramdisk(new)", rdOff, rdSize, out.size() - rdOff));

            int secSize = writeSeg(out, image.second, "second", page, cb);
            int dtboSize = writeSeg(out, image.recoveryDtbo, "recovery_dtbo", page, cb);
            int dtbSize = writeSeg(out, image.dtb, "dtb", page, cb);
            int sigSize = writeSeg(out, image.signature, "signature", page, cb);
            int vtSize = writeSeg(out, image.vendorTable, "vendor_table", page, cb);
            int bcSize = writeSeg(out, image.bootconfig, "bootconfig", page, cb);

            int payloadEnd = out.size();
            int blocksRawEnd = lastRawEnd[0];
            log(cb, String.format("  %-16s @%,10d", "blocks 结束", payloadEnd));
            progress(cb, 85);

            // ══════════ 10. AVB ══════════
            log(cb, "");
            log(cb, "── 10. AVB ──");
            int fileSize = img.length;

            if (avbInfo == null) {
                log(cb, "  原镜像无 AVB，不做处理");
                while (out.size() < fileSize) out.write(0);
            } else {
                Avb.SpaceCheck sc = Avb.checkSpace(payloadEnd, page, avbInfo, fileSize);
                if (!sc.ok) {
                    res.ok = false;
                    res.error = sc.message + String.format(
                            "\n  新 ramdisk 比原来大 %+,d 字节",
                            rdSize - image.ramdiskSize);
                    log(cb, "X " + res.error);
                    return res;
                }
                Avb.WriteResult wr = Avb.write(out, avbInfo, page, fileSize, blocksRawEnd);
                if (!wr.ok) {
                    res.ok = false;
                    res.error = wr.message;
                    log(cb, "X " + res.error);
                    return res;
                }
                log(cb, "  " + wr.message);
            }
            progress(cb, 92);

            while (out.size() < fileSize) out.write(0);
            if (out.size() != fileSize) {
                res.ok = false;
                res.error = String.format("重建后大小 %,d 与原镜像 %,d 不一致",
                        out.size(), fileSize);
                log(cb, "X " + res.error);
                return res;
            }

            byte[] result = out.toByteArray();

            // ══════════ 11. patch header ══════════
            log(cb, "");
            log(cb, "── 11. patch header size 字段 ──");
            BootImage.Header hdr = BootImage.parseHeader(result);
            patchSize(hdr, "kernel_size", kSize, cb);
            patchSize(hdr, "ramdisk_size", rdSize, cb);
            patchSize(hdr, "second_size", secSize, cb);
            patchSize(hdr, "recovery_dtbo_size", dtboSize, cb);
            patchSize(hdr, "dtb_size", dtbSize, cb);
            patchSize(hdr, "signature_size", sigSize, cb);
            patchSize(hdr, "vendor_ramdisk_table_size", vtSize, cb);
            patchSize(hdr, "bootconfig_size", bcSize, cb);
            System.arraycopy(hdr.raw, 0, result, 0, hdr.raw.length);

            log(cb, "");
            log(cb, "  ✅ 修补完成  " + result.length + " 字节");
            progress(cb, 100);

            res.ok = true;
            res.data = result;
            return res;

        } catch (Throwable t) {
            res.ok = false;
            res.error = "修补异常: " + t.getClass().getSimpleName() + ": " + t.getMessage();
            log(cb, "X " + res.error);
            return res;
        }
    }

    // ══════════════════════════════════════════════════════
    // vendor_boot 分支
    // ══════════════════════════════════════════════════════

    private static Result patchVendorCore(byte[] img, BootImage.Image image,
                                          byte[] skInit, byte[] skKo, PatchProgress cb) {
        Result res = new Result();
        try {
            log(cb, "");
            log(cb, "── vendor_boot 修补 ──");

            if (image.vendorTableSize <= 0) {
                res.ok = false;
                res.error = "没有 vendor ramdisk table（v3 或单 ramdisk 结构）";
                log(cb, "X " + res.error);
                return res;
            }

            int page = image.header.pageSize();
            List<VendorRamdisk.Entry> entries =
                    VendorRamdisk.parseTable(image.vendorTable, image.ramdisk);
            int target = VendorRamdisk.findTarget(entries);
            for (String s : VendorRamdisk.describe(entries, target)) log(cb, "  " + s);

            if (target < 0) {
                res.ok = false;
                res.error = "找不到合适的 vendor ramdisk（既没有 init_boot 也没有空名）";
                log(cb, "X " + res.error);
                return res;
            }

            VendorRamdisk.Entry te = entries.get(target);
            int fmt = Compress.detect(te.data);
            log(cb, String.format("  目标 #%d  %,d 字节  %s",
                    target, te.size, Compress.formatName(fmt)));

            Compress.DecompressResult dr = Compress.decompress(te.data, fmt);
            if (!dr.ok()) {
                res.ok = false;
                res.error = "解压失败: " + dr.error;
                log(cb, "X " + res.error);
                return res;
            }
            log(cb, "  解压 " + dr.data.length + " 字节（" + dr.method + "）");

            Cpio.ParseResult pr = Cpio.parse(dr.data);
            if (!pr.ok()) {
                res.ok = false;
                res.error = "cpio 解析失败: " + pr.errors;
                log(cb, "X " + res.error);
                return res;
            }
            for (String w : pr.warnings) log(cb, "  ⚠ " + w);
            log(cb, "  " + pr.entries.size() + " 个条目，尾部填充 " + pr.tailPadding + " 字节");

            // 注入
            if (skKo != null) {
                // 模块的 __this_module.name 是 "sk_root"（编译时由文件名决定），
                // ramdisk 里的文件名必须与之一致，否则 /proc/modules、rmmod、
                // 以及 umbral_init 的日志全都会对不上号。
                // 旧名 sk_hello.ko 一并清掉，避免升级时残留两份。
                Cpio.remove(pr.entries, "sk_root.ko");
                Cpio.remove(pr.entries, "sk_hello.ko");
                pr.entries.add(Cpio.Entry.regular("sk_root.ko", skKo, 0644));
                log(cb, "  + sk_root.ko " + skKo.length + " 字节");
            } else {
                log(cb, "  - 跳过内核模块（本机 KMI 无匹配模块）");
            }

            List<String> addedDev = Cpio.ensureDevices(pr.entries);
            if (!addedDev.isEmpty()) log(cb, "  + 设备节点: " + addedDev);

            byte[] newCpio = Cpio.build(pr.entries, 300000, pr.tailPadding);
            Compress.CompressResult cr = Compress.compress(newCpio, fmt);
            if (!cr.ok()) {
                res.ok = false;
                res.error = "压缩失败: " + cr.error;
                log(cb, "X " + res.error);
                return res;
            }
            byte[] newRd = cr.data;
            log(cb, String.format("  新 cpio %,d  新 ramdisk %,d（原 %,d）",
                    newCpio.length, newRd.length, te.size));

            // 替换 + 重算 section/table
            byte[] newSection = VendorRamdisk.replaceRamdisk(entries, target, newRd);
            byte[] newTable = VendorRamdisk.buildTable(entries);
            log(cb, String.format("  新 section %,d  新 table %,d（原 %,d）",
                    newSection.length, newTable.length, image.vendorTableSize));

            // 重打包
            ByteArrayOutputStream out = new ByteArrayOutputStream(img.length + (1 << 20));
            out.write(image.header.raw, 0, image.header.raw.length);
            padTo(out, page);

            int rdOff = out.size();
            out.write(newSection, 0, newSection.length);
            padTo(out, page);
            int rdSize = out.size() - rdOff;

            int dtbSize = writeSeg(out, image.dtb, "dtb", page, cb);

            // vendor table —— header 记实际大小，物理占对齐空间
            int vtOff = out.size();
            out.write(newTable, 0, newTable.length);
            int vtSize = newTable.length;
            padTo(out, page);

            // bootconfig
            int bcOff = out.size();
            out.write(image.bootconfig, 0, image.bootconfig.length);
            int bcSize = image.bootconfig.length;
            lastRawEnd[0] = out.size();   // ← 未对齐的结束位置
            padTo(out, page);

            int payloadEnd = out.size();
            int vBlocksRawEnd = lastRawEnd[0];
            log(cb, "");
            log(cb, "  新布局:");
            log(cb, String.format("    ramdisk      @%,10d  %,12d", rdOff, rdSize));
            log(cb, String.format("    dtb          @%,10d  %,12d", rdOff + rdSize, dtbSize));
            log(cb, String.format("    vendor_table @%,10d  %,12d  (实际 %d，占 %d)",
                    vtOff, vtSize, vtSize, BootImage.align(vtSize, page)));
            log(cb, String.format("    bootconfig   @%,10d  %,12d", bcOff, bcSize));
            log(cb, String.format("    payload_end  @%,10d", payloadEnd));

            // AVB
            Avb.AvbInfo avbInfo = null;
            try {
                avbInfo = Avb.parse(img, image.blocksEndRaw);
            } catch (Exception e) {
                log(cb, "  ⚠ AVB: " + e.getMessage());
            }
            int fileSize = img.length;
            if (avbInfo != null) {
                Avb.SpaceCheck sc = Avb.checkSpace(payloadEnd, page, avbInfo, fileSize);
                if (!sc.ok) {
                    res.ok = false;
                    res.error = sc.message;
                    log(cb, "X " + res.error);
                    return res;
                }
                Avb.WriteResult wr = Avb.write(out, avbInfo, page, fileSize, vBlocksRawEnd);
                if (!wr.ok) {
                    res.ok = false;
                    res.error = wr.message;
                    log(cb, "X " + res.error);
                    return res;
                }
                log(cb, "  " + wr.message);
            }
            while (out.size() < fileSize) out.write(0);
            if (out.size() != fileSize) {
                res.ok = false;
                res.error = "大小不一致 " + out.size() + " vs " + fileSize;
                log(cb, "X " + res.error);
                return res;
            }

            byte[] result = out.toByteArray();

            BootImage.Header hdr = BootImage.parseHeader(result);
            patchSize(hdr, "ramdisk_size", rdSize, cb);
            patchSize(hdr, "dtb_size", dtbSize, cb);
            patchSize(hdr, "vendor_ramdisk_table_size", vtSize, cb);
            patchSize(hdr, "bootconfig_size", bcSize, cb);
            System.arraycopy(hdr.raw, 0, result, 0, hdr.raw.length);

            log(cb, "");
            log(cb, "  ✅ vendor_boot 修补完成  " + result.length + " 字节");

            res.ok = true;
            res.data = result;
            return res;

        } catch (Throwable t) {
            res.ok = false;
            res.error = "vendor 修补异常: " + t.getMessage();
            log(cb, "X " + res.error);
            return res;
        }
    }

    // ══════════════════════════════════════════════════════
    // 工具
    // ══════════════════════════════════════════════════════

    /**
     * 写一段数据并补页对齐。
     *
     * ⚠ 返回值是**实际数据大小**，不是对齐后的大小。
     *   header 里的各 *_size 字段都必须是实际大小：
     *   解码器读到声明的大小就停，声明多了会解到填充的 0。
     */
    private static int writeSeg(ByteArrayOutputStream out, byte[] data, String name,
                                int page, PatchProgress cb) {
        if (data == null || data.length == 0) return 0;
        int off = out.size();
        out.write(data, 0, data.length);
        int size = data.length;              // ← 实际大小
        lastRawEnd[0] = out.size();          // ← 记录未对齐的结束位置
        padTo(out, page);
        log(cb, String.format("  %-16s @%,10d  %,12d 字节（占 %,d）",
                name, off, size, out.size() - off));
        return size;
    }

    /** 最后一个段数据结束的精确位置（未对齐）。AVB 的 avb_tail 以它为起点。 */
    private static final int[] lastRawEnd = {0};

    private static void padTo(ByteArrayOutputStream out, int page) {
        int rem = out.size() % page;
        if (rem != 0) {
            for (int i = 0; i < page - rem; i++) out.write(0);
        }
    }

    private static void patchSize(BootImage.Header hdr, String field, int value,
                                  PatchProgress cb) {
        if (!hdr.layout.has(field)) return;
        int old = hdr.get(field);
        if (old == value) return;
        if (hdr.set(field, value)) {
            log(cb, String.format("  %-24s %,d → %,d", field, old, value));
        }
    }

    private static byte[] readAsset(Context ctx, String name) {
        // 走 ModuleRepo 的兼容层：aapt2 在 Windows 上会把子目录分隔符打成 '\'，
        // 直接 ctx.getAssets().open("arm64-v8a/umbral_init") 会打不开。
        return io.umbral.sk.ModuleRepo.readAsset(ctx, name);
    }

    /**
     * 把产物写到用户能直接看到的地方。
     *
     * 目标路径：/storage/emulated/0/Umbral/init_boot_patched.img
     *          （= /sdcard/Umbral/init_boot_patched.img）
     *
     * 首选「所有文件访问权限」(MANAGE_EXTERNAL_STORAGE) 直接写外部存储根目录下的 Umbral，
     * 这是用户能在 MT 管理器 / 系统文件管理里一眼看到的公共位置。
     *
     * 没授权时退回 App 外部私有目录（Android/data/…），并明确告诉用户去哪儿开权限。
     */
    private static String writeOut(Context ctx, byte[] out, PatchProgress cb) throws Exception {
        final String name = "init_boot_patched.img";
        File target = null;
        boolean inPublic = false;

        // ── 1) 首选：/storage/emulated/0/Umbral/ ──
        try {
            boolean haveAll = true;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                haveAll = android.os.Environment.isExternalStorageManager();
            }
            if (!haveAll) {
                log(cb, "  ⚠ 没有「所有文件访问权限」，产物只能写 App 私有目录");
                log(cb, "    去 设置 → 应用 → 影核 → 权限 → 所有文件访问权限 打开");
            } else {
                File root = android.os.Environment.getExternalStorageDirectory();
                if (root != null) {
                    File dir = new File(root, "Umbral");
                    if (dir.exists() || dir.mkdirs()) {
                        target = new File(dir, name);
                        inPublic = true;
                        log(cb, "  输出目录 /storage/emulated/0/Umbral/");
                    } else {
                        log(cb, "  ⚠ 无法创建 /storage/emulated/0/Umbral/");
                    }
                }
            }
        } catch (Throwable t) {
            log(cb, "  ⚠ 写公共目录失败: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }

        // ── 2) 兜底：App 外部私有目录 ──
        if (target == null) {
            File ext = null;
            try {
                ext = ctx.getExternalFilesDir(null);
            } catch (Throwable ignored) {
            }
            File dir = (ext != null) ? new File(ext, "out") : new File(ctx.getFilesDir(), "out");
            if (!dir.exists() && !dir.mkdirs()) {
                dir = new File(ctx.getFilesDir(), "out");
                if (!dir.exists()) dir.mkdirs();
            }
            target = new File(dir, name);
        }

        log(cb, "写入输出文件…");
        java.io.FileOutputStream fos = new java.io.FileOutputStream(target);
        try {
            fos.write(out);
            fos.flush();
        } finally {
            fos.close();
        }

        final String abs = target.getAbsolutePath();
        log(cb, "  " + abs);
        progress(cb, 100);

        StringBuilder sb = new StringBuilder();
        sb.append("修补完成\n");
        sb.append("输出: ").append(abs).append('\n');
        sb.append("大小: ").append(out.length).append(" 字节\n\n");
        if (inPublic) {
            sb.append("在文件管理器里打开:\n");
            sb.append("  /sdcard/Umbral/\n");
        } else {
            sb.append("提示: 开启「所有文件访问权限」后重试,\n");
            sb.append("      产物会直接写到 /sdcard/Umbral/ (更方便取用)\n");
        }
        return sb.toString();
    }

    private static void log(PatchProgress cb, String s) {
        if (cb != null) cb.log(s);
    }

    private static void progress(PatchProgress cb, int p) {
        if (cb != null) cb.progress(p);
    }


}
