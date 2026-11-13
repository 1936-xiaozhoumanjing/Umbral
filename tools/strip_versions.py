#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
strip_versions.py —— 把 .ko 的 __versions 段置空，并去掉 vermagic 里的 modversions。

等效于用 CONFIG_MODVERSIONS=n 重编的产物，但不需要重跑内核构建树。

原理：模块加载器按段名找到 __versions，再按 sh_size/sizeof(entry) 遍历；
      段大小置 0 就是"零条版本信息"，与不开 MODVERSIONS 的构建语义一致。
      同时把 vermagic 里的 "modversions" 一词删掉，避免加载器再走 CRC 分支。

注意：目标机若开了 CONFIG_MODVERSIONS，加载时会报
        no symbol version for <sym>
      这时必须用 finit_module(fd, "", MODULE_INIT_IGNORE_MODVERSIONS)
      加载（我们的 init 已实现三级回退）。

用法：
    python strip_versions.py --print  a.ko
    python strip_versions.py --strip  a.ko              # 原地
    python strip_versions.py --strip  a.ko -o b.ko      # 另存
"""

import argparse
import struct
import sys


class Elf(object):
    def __init__(self, data):
        if data[:4] != b"\x7fELF" or data[4] != 2:
            raise SystemExit("不是 ELF64 文件")
        self.data = bytearray(data)
        self.shstrndx = struct.unpack_from("<H", self.data, 0x3E)[0]
        self.shoff = struct.unpack_from("<Q", self.data, 0x28)[0]
        self.shentsize = struct.unpack_from("<H", self.data, 0x3A)[0]
        self.shnum = struct.unpack_from("<H", self.data, 0x3C)[0]
        self._sections()

    def _sections(self):
        self.secs = []
        for i in range(self.shnum):
            h = self.shoff + i * self.shentsize
            name_off = struct.unpack_from("<I", self.data, h)[0]
            self.secs.append(h)
        sstr = self.shoff + self.shstrndx * self.shentsize
        stroff = struct.unpack_from("<Q", self.data, sstr + 24)[0]
        for h in self.secs:
            name_off = struct.unpack_from("<I", self.data, h)[0]
            end = self.data.find(b"\0", stroff + name_off)
            setattr(self, "_name_%d" % h, bytes(self.data[stroff + name_off:end]).decode("utf-8", "replace"))

    def name(self, h):
        return getattr(self, "_name_%d" % h)

    def find(self, want):
        for h in self.secs:
            if self.name(h) == want:
                return h
        return None

    def off(self, h):
        return struct.unpack_from("<Q", self.data, h + 24)[0]

    def size(self, h):
        return struct.unpack_from("<Q", self.data, h + 32)[0]

    def vermagic(self):
        h = self.find(".modinfo")
        if h is None:
            return None
        blob = bytes(self.data[self.off(h): self.off(h) + self.size(h)])
        for e in blob.split(b"\0"):
            if e.startswith(b"vermagic="):
                return e[len(b"vermagic="):].decode("utf-8", "replace")
        return None


def strip(elf, out_path):
    h = elf.find("__versions")
    if h is None:
        return "没有 __versions 段，无需处理"

    # sh_type = SHT_NULL(0), sh_size = 0
    struct.pack_into("<I", elf.data, h + 4, 0)
    struct.pack_into("<Q", elf.data, h + 32, 0)

    note = ""
    ver = elf.vermagic()
    if ver and "modversions" in ver:
        newver = " ".join(t for t in ver.split() if t != "modversions")
        mh = elf.find(".modinfo")
        blob = bytes(elf.data[elf.off(mh): elf.off(mh) + elf.size(mh)])
        old_e = b"vermagic=" + ver.encode() + b"\0"
        new_e = b"vermagic=" + newver.encode() + b"\0"
        if len(new_e) <= len(old_e):
            blob2 = blob.replace(old_e, new_e + b"\0" * (len(old_e) - len(new_e)), 1)
            elf.data[elf.off(mh): elf.off(mh) + elf.size(mh)] = blob2
        else:
            blob2 = blob.replace(old_e, new_e, 1)
            off = (len(elf.data) + 15) & ~15
            elf.data.extend(b"\0" * (off - len(elf.data)))
            elf.data.extend(blob2)
            struct.pack_into("<QQ", elf.data, mh + 24, off, len(blob2))
        note = " / vermagic: %s  ->  %s" % (ver, newver)

    with open(out_path, "wb") as f:
        f.write(elf.data)
    return "__versions 已置空" + note


def main():
    ap = argparse.ArgumentParser(description="清空 .ko 的 __versions（等效 CONFIG_MODVERSIONS=n）")
    ap.add_argument("file")
    ap.add_argument("--print", dest="do_print", action="store_true")
    ap.add_argument("--strip", dest="do_strip", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    elf = Elf(open(a.file, "rb").read())
    h = elf.find("__versions")
    print("  文件      : %s" % a.file)
    print("  __versions: %s" % ("存在，sh_size=%d" % elf.size(h) if h else "不存在"))
    print("  vermagic  : %s" % elf.vermagic())

    if not a.do_strip:
        return

    out = a.out or a.file
    msg = strip(elf, out)
    print("  处理      : %s" % msg)
    chk = Elf(open(out, "rb").read())
    h2 = chk.find("__versions")
    print("  回读校验  : __versions sh_size=%s  vermagic=%s" % (
        (chk.size(h2) if h2 else "-"), chk.vermagic()))
    print("  输出      : %s" % out)


if __name__ == "__main__":
    main()
