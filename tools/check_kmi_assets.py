# -*- coding: utf-8 -*-
"""check_kmi_assets.py - consistency gate for the two module variants."""
import os, struct, sys
ROOT = r"E:\sk-root"
A = os.path.join(ROOT, "manager", "assets", "arm64-v8a")

def parse(path):
    d = open(path, "rb").read()
    shoff, = struct.unpack_from("<Q", d, 0x28)
    shent, = struct.unpack_from("<H", d, 0x3A)
    shnum, = struct.unpack_from("<H", d, 0x3C)
    shstr, = struct.unpack_from("<H", d, 0x3E)
    stroff, = struct.unpack_from("<Q", d, shoff + shstr * shent + 24)
    vs = None
    for i in range(shnum):
        h = shoff + i * shent
        no, = struct.unpack_from("<I", d, h)
        sz, = struct.unpack_from("<Q", d, h + 32)
        end = d.find(b"\0", stroff + no)
        if d[stroff + no:end] == b"__versions":
            vs = sz
    i = d.find(b"vermagic=")
    ver = b""
    if i > 0:
        ver = d[i:d.find(b"\0", i)]
    return vs, (b"modversions" in ver)

fails = []
print("  %-16s %-22s %-22s %s" % ("KMI", "main(vs/mv)", "nomv(vs/mv)", "status"))
for d in sorted(os.listdir(A)):
    p = os.path.join(A, d)
    if not os.path.isdir(p) or not d.startswith("android"):
        continue
    m, n = os.path.join(p, "umbral.ko"), os.path.join(p, "umbral_nomv.ko")
    if not (os.path.exists(m) and os.path.exists(n)):
        fails.append(d + ":missing"); continue
    vm, mm = parse(m)
    vn, mn = parse(n)
    ok_m = (vm == 0 and not mm) or (vm and vm > 0 and mm)
    ok_n = (vn == 0 and not mn)
    st = "OK" if (ok_m and ok_n) else "FAIL"
    print("  %-16s %-22s %-22s %s" % (d, "%s/%s" % (vm, "mv" if mm else "-"), "%s/%s" % (vn, "mv" if mn else "-"), st))
    if not (ok_m and ok_n):
        fails.append(d)

bp = open(os.path.join(ROOT, "manager", "java", "io", "umbral", "flash", "BootPatch.java"), encoding="utf-8").read()
inj = bp.count('Cpio.Entry.regular("umbral_nomv.ko"')
ib = open(os.path.join(A, "umbral_init"), "rb").read()
print("  BootPatch injections: %d (>=2)" % inj)
print("  init strings: nomv=%s ignore=%s" % (b"/umbral_nomv.ko" in ib, b"ignore vermagic" in ib))
if inj < 2: fails.append("BootPatch")
if b"/umbral_nomv.ko" not in ib or b"ignore vermagic" not in ib: fails.append("init")
print()
print("  RESULT: " + ("PASS" if not fails else "FAIL -> " + "; ".join(fails)))
sys.exit(1 if fails else 0)