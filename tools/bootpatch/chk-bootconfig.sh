#!/bin/bash
python3 - << 'PYEOF'
import struct

def check(path, label):
    d = open(path,'rb').read()
    print(f"--- {label} ---")
    print(f"  大小 {len(d):,}")

    # bootconfig 魔数（AOSP bootimg.h: BOOTCONFIG_MAGIC，大小端都试）
    tail = d[-8:]
    print(f"  末尾 16 字节: {d[-16:].hex(' ')}")

    found = False
    for magic, name in [
        (b'\xee\xff\xc0\x0c', '0x0CC0FFEE (LE)'),
        (b'\x0c\xc0\xff\xee', '0x0CC0FFEE (BE)'),
        (b'\xee\xff\x0c\x0c', '0x0C0CFFEE (LE)'),
        (b'\x0c\x0c\xff\xee', '0x0C0CFFEE (BE)'),
    ]:
        if d[-4:] == magic:
            size = struct.unpack('<I', d[-8:-4])[0]
            start = len(d) - 8 - size
            print(f"  ✅ 找到 bootconfig！magic={name}  size={size}  start={start:,}")
            if start >= 0:
                print(f"     内容前 200 字节:")
                print(f"     {d[start:start+200]!r}")
            found = True
            break

    if not found:
        print(f"  ❌ 末尾没有 bootconfig 魔数")

    # 搜 androidboot. 关键字
    idx = d.find(b'androidboot.')
    if idx > 0:
        print(f"  ⚠ 在 {idx:,} 处发现 'androidboot.' 字符串")
        print(f"     {d[idx:idx+150]!r}")
    else:
        print(f"  ℹ 全文没有 'androidboot.' 字符串")

    # pad 区内容
    P=4096
    ks = struct.unpack_from('<I', d, 8)[0]
    rs = struct.unpack_from('<I', d, 12)[0]
    roff = P + ((ks+P-1)//P)*P
    rend = roff + rs
    pstart = ((rend+P-1)//P)*P
    pad = d[pstart:]
    nz = [(pstart+i, v) for i,v in enumerate(pad) if v != 0]
    print(f"  pad 区 {pstart:,} ~ {len(d)-1:,}  非零 {len(nz)} 字节")
    if nz:
        print(f"    首个非零 @ {nz[0][0]:,}，内容: {d[nz[0][0]:nz[0][0]+32].hex(' ')}")
    print()

check("/mnt/e/sk-root/boot-backup/init_boot_stock_a.img", "努比亚 init_boot（原厂）")
check("/mnt/e/sk-root/boot-backup/boot_stock_a.img", "努比亚 boot（原厂，100MB）")
PYEOF