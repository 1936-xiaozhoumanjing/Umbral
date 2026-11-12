#!/usr/bin/env python3
"""
自适应 init_boot 修补器

核心思想：不假设任何结构，先探测原厂 ramdisk 里有什么，再决定怎么改。

探测维度：
  1. first-stage init 是哪个条目（按 ELF + 可执行 + 名字）
  2. 已有哪些 init.* 变体（避免改名冲突）
  3. 有哪些第三方 root 方案残留（KSU / Magisk / APatch / 自定义）
  4. 已有哪些设备节点（只补缺的）
  5. 系统版本线索（build.prop）
  6. 压缩格式 / header 版本 / AVB 位置

用法：
  python3 adaptive_patch.py probe <镜像>
  python3 adaptive_patch.py patch <镜像> <sk_init> <sk_hello.ko> <输出> [--no-module]
"""
import struct
import gzip
import subprocess
import sys
import json
import hashlib

PAGE = 4096
HDR = 110

# ── 已知的第三方 root 方案组件（用于清理）──
THIRD_PARTY = {
    'kernelsu.ko':      'KernelSU 内核模块',
    'ksuinit':          'KernelSU init',
    'init.ksu':         'KernelSU 改名的 init',
    'magiskinit':       'Magisk init',
    'magisk32':         'Magisk 32-bit',
    'magisk64':         'Magisk 64-bit',
    'magiskpolicy':     'Magisk policy',
    'stub.xz':          'Magisk stub',
    '.backup':          'Magisk 备份目录',
    'overlay.d':        'Magisk overlay 目录',
    'apd':              'APatch 守护进程',
    'ap_patch':         'APatch',
    'kpimg':            'KernelPatch',
}

# ── 设备节点表：名字 -> (权限, 主设备号, 次设备号, 是否必需) ──
DEVICE_TABLE = {
    'dev/console': (0o600, 5, 1, True),    # init 的 stdio，必需
    'dev/null':    (0o666, 1, 3, True),
    'dev/urandom': (0o600, 1, 9, True),
    'dev/kmsg':    (0o600, 1, 11, False),  # 日志，强烈建议
    'dev/zero':    (0o666, 1, 5, False),
    'dev/full':    (0o666, 1, 7, False),
    'dev/random':  (0o666, 1, 8, False),
    'dev/tty':     (0o666, 5, 0, False),
}

# ── 改名候选：按优先级，找第一个不冲突的 ──
RENAME_CANDIDATES = [
    'init.skroot',      # 我们专用的，几乎不可能冲突
    'init.orig',
    'init.original',
    'init.bak',
    'init.android',
    'init.sk',
]


def align4(n): return (n + 3) & ~3
def align(n, a=PAGE): return ((n + a - 1) // a) * a


# ── 尾部数据探测 ──
#
# ramdisk 之后可能有：
#   · AVB vbmeta 结构（magic "AVB0"，4K 对齐）
#   · bootconfig（Android 12+ 末尾附着：[data][size:4][magic:4]）
#   · 厂商私有数据
#
# 这些都不能抹掉，否则 bootloader 或内核会出问题。

BOOTCONFIG_MAGICS = [
    b'\x0c\x0c\xff\xee',   # 0x0C0CFFEE 小端
    b'\xee\xff\x0c\x0c',   # 0x0C0CFFEE 大端
    b'\x0c\xc0\xff\xee',   # 0x0CC0FFEE 小端
    b'\xee\xff\xc0\x0c',   # 0x0CC0FFEE 大端
]


def find_avb(buf, from_off=PAGE):
    """4K 对齐扫 AVB0 magic"""
    for off in range(align(from_off), len(buf) - 4, PAGE):
        if buf[off:off + 4] == b'AVB0':
            return off
    return -1


def parse_avb_footer(buf):
    """
    解析文件末尾 64 字节的 AVB Footer。

    struct AvbFooter {          // 固定 64 字节，放在镜像最后
        uint8_t  magic[4];              // "AVBf"
        uint32_t version_major;
        uint32_t version_minor;
        uint64_t original_image_size;
        uint64_t vbmeta_offset;         // AVB0 的真实位置
        uint64_t vbmeta_size;           // AVB0 的真实大小
        uint8_t  reserved[28];
    };

    比扫描 "AVB0" 可靠：能拿到签名时的原始大小和 vbmeta 精确位置。
    """
    if len(buf) < 64:
        return None
    foot = buf[-64:]
    if foot[:4] != b'AVBf':
        return None
    ver_maj, ver_min = struct.unpack_from('>II', foot, 4)
    orig_size, vb_off, vb_size = struct.unpack_from('>QQQ', foot, 12)
    return {
        'magic': 'AVBf',
        'version': f'{ver_maj}.{ver_min}',
        'original_image_size': orig_size,
        'vbmeta_offset': vb_off,
        'vbmeta_size': vb_size,
        'footer_pos': len(buf) - 64,
        'consistent': (orig_size == len(buf) - 64),
    }


def find_bootconfig(buf):
    """检测末尾附着的 bootconfig，返回 (start, size) 或 None"""
    if len(buf) < 12:
        return None
    if buf[-4:] not in BOOTCONFIG_MAGICS:
        return None
    size = struct.unpack_from('<I', buf, len(buf) - 8)[0]
    if size == 0 or size > len(buf) - 8:
        return None
    return (len(buf) - 8 - size, size)


def find_tail_data_start(buf, pad_start):
    """
    找 ramdisk 之后第一个有意义数据的位置。
    返回 (offset, [(kind, offset), ...])，没有则 (-1, [])。
    """
    cands = []

    avb = find_avb(buf, pad_start)
    if avb > 0:
        cands.append(('AVB', avb))

    bc = find_bootconfig(buf)
    if bc:
        cands.append(('bootconfig', bc[0]))

    # 兜底：pad 区第一个非零字节
    for off in range(pad_start, len(buf)):
        if buf[off] != 0:
            cands.append(('非零数据', off))
            break

    if not cands:
        return -1, []

    cands.sort(key=lambda x: x[1])
    return cands[0][1], cands


# ══════════════════════════════════════════════
# 镜像层
# ══════════════════════════════════════════════

def parse_image(buf):
    if len(buf) < 64 or buf[:8] != b'ANDROID!':
        raise ValueError(f"不是 boot 镜像（magic={buf[:8]!r}）")

    hver = struct.unpack_from('<I', buf, 40)[0]
    ksize = struct.unpack_from('<I', buf, 8)[0]

    # ── ramdisk_size 的位置随 header 版本变化 ──
    #   v0~v2: ramdisk_size @ offset 16（老 boot_img_hdr）
    #   v3~v4: ramdisk_size @ offset 12
    rsize = struct.unpack_from('<I', buf, 12)[0] if hver >= 3 else struct.unpack_from('<I', buf, 16)[0]

    # ── header_size ──
    #   v0~v2: 不定长（1632 常见）
    #   v3~v4: @ offset 20
    hsize = struct.unpack_from('<I', buf, 20)[0] if hver >= 3 else 1632

    # ── signature_size（仅 v4）──
    # 参照 AOSP bootimg.h：
    #   boot_img_hdr_v3 = magic(8)+ksize(4)+rsize(4)+osver(4)+hsize(4)
    #                     +reserved[4](16)+hver(4)+cmdline(1536) = 1580
    #   boot_img_hdr_v4 = v3 + signature_size(4)                 = 1584
    # 所以 signature_size 在 offset 1580，不是 offset 24（那是 reserved[0]）
    sigsize = struct.unpack_from('<I', buf, 1580)[0] if hver >= 4 and len(buf) >= 1584 else 0

    # ── ramdisk 偏移 ──
    # v3/v4 的页大小固定 4096；v0~v2 从 header 里读 page_size
    if hver >= 3:
        page = PAGE
    else:
        page = struct.unpack_from('<I', buf, 36)[0] if len(buf) >= 40 else PAGE
        if page == 0 or (page & (page - 1)) != 0:
            page = PAGE

    roff = page + align(ksize, page)

    if rsize == 0:
        raise ValueError(
            "这个镜像里 ramdisk_size = 0，没有 ramdisk。\n"
            "  可能原因：\n"
            "    ① 这是纯 kernel 镜像（某些设备的 boot.img 不含 ramdisk）\n"
            "    ② 这个设备把 ramdisk 放在 init_boot.img 里（Android 13+ GKI）\n"
            "  处理办法：\n"
            "    · 如果设备有 init_boot 分区，请提供 init_boot.img\n"
            "    · 官方 OTA 包里的 payload.bin 可以提取出来\n"
            f"  当前：kernel_size={ksize:,}  header_version={hver}  page={page}  "
            f"ramdisk_offset=0x{roff:x}"
        )

    if roff + rsize > len(buf):
        raise ValueError(f"ramdisk 越界 {roff}+{rsize} > {len(buf)}")

    # signature 段在 ramdisk 之后
    sig_off = align(roff + rsize, page)
    has_sig = sigsize > 0 and sig_off + sigsize <= len(buf)

    return {
        'buf': buf, 'hver': hver, 'ksize': ksize, 'rsize': rsize,
        'hsize': hsize, 'sigsize': sigsize, 'has_sig': has_sig,
        'page': page, 'roff': roff,
        'rd': buf[roff:roff + rsize],
        'rend': roff + rsize,
        'sig_off': sig_off,
        'sig': buf[sig_off:sig_off + sigsize] if has_sig else None,
        'pad_start': align(sig_off + sigsize if has_sig else roff + rsize, page),
    }


def detect_format(b):
    if b[:4] == b'\x02\x21\x4c\x18': return 'lz4-legacy'
    if b[:4] == b'\x04\x22\x4d\x18': return 'lz4-frame'
    if b[:2] == b'\x1f\x8b': return 'gzip'
    if b[:4] == b'\x28\xb5\x2f\xfd': return 'zstd'
    if b[:4] == b'\xfd7zX': return 'xz'
    if b[:6] in (b'070701', b'070702'): return 'cpio'
    return 'unknown'


def decompress_rd(rd):
    fmt = detect_format(rd)
    if fmt == 'gzip':
        return gzip.decompress(rd), fmt
    if fmt in ('cpio',):
        return rd, fmt
    if fmt in ('lz4-legacy', 'lz4-frame'):
        args = ['lz4', '-d'] + (['-l'] if fmt == 'lz4-legacy' else []) + ['-c']
        r = subprocess.run(args, input=rd, capture_output=True)
        if r.returncode == 0:
            return r.stdout, fmt
        raise RuntimeError(f"lz4 解压失败: {r.stderr[:200]}")
    if fmt == 'zstd':
        r = subprocess.run(['zstd', '-d', '-c'], input=rd, capture_output=True)
        if r.returncode == 0:
            return r.stdout, fmt
        raise RuntimeError("zstd 解压失败")
    if fmt == 'xz':
        r = subprocess.run(['xz', '-d', '-c'], input=rd, capture_output=True)
        if r.returncode == 0:
            return r.stdout, fmt
        raise RuntimeError("xz 解压失败")
    raise RuntimeError(f"未知压缩格式 {fmt}")


# ══════════════════════════════════════════════
# cpio 层
# ══════════════════════════════════════════════

def parse_cpio(d):
    entries = []
    pos = 0
    trailer = None
    while pos + HDR <= len(d):
        if d[pos:pos + 6] not in (b'070701', b'070702'):
            raise ValueError(f"@{pos} magic 不是 070701/070702: {d[pos:pos+8]!r}")
        f = []
        for k in range(13):
            s = d[pos + 6 + k * 8: pos + 6 + (k + 1) * 8]
            try:
                f.append(int(s, 16))
            except ValueError:
                raise ValueError(f"@{pos} 字段 {k} 不是十六进制: {s!r}")
        (ino, mode, uid, gid, nlink, mtime, size,
         dmaj, dmin, rmaj, rmin, namesize, check) = f
        name = d[pos + HDR:pos + HDR + namesize - 1].decode('utf-8', 'replace')
        ds = align4(pos + HDR + namesize)
        de = align4(ds + size)
        if de > len(d):
            raise ValueError(f"@{pos} {name} 数据越界")
        if name == 'TRAILER!!!':
            trailer = {'pos': pos, 'end': align4(pos + HDR + namesize),
                       'namesize': namesize, 'fields': f}
            break
        entries.append({
            'name': name, 'mode': mode, 'uid': uid, 'gid': gid, 'nlink': nlink,
            'mtime': mtime, 'dmaj': dmaj, 'dmin': dmin, 'rmaj': rmaj, 'rmin': rmin,
            'data': d[ds:ds + size],
        })
        pos = de
    if trailer is None:
        raise ValueError("没有 TRAILER!!!")
    if trailer['end'] != len(d):
        raise ValueError(f"TRAILER 后多余 {len(d) - trailer['end']} 字节")
    return entries, trailer


def build_cpio(entries, start_ino=300000):
    out = bytearray()
    ino = start_ino
    for e in entries:
        nb = e['name'].encode() + b'\0'
        h = b'070701'
        for v in (ino, e['mode'], e['uid'], e['gid'], e['nlink'], e['mtime'],
                  len(e['data']), e['dmaj'], e['dmin'], e['rmaj'], e['rmin'],
                  len(nb), 0):
            h += format(v, 'x').rjust(8, '0')[-8:].encode()
        ino += 1
        out += h + nb
        while len(out) % 4: out += b'\0'
        if e['data']:
            out += e['data']
            while len(out) % 4: out += b'\0'
    tn = b'TRAILER!!!\0'
    t = b'070701'
    for v in (ino, 0o755, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(tn), 0):
        t += format(v, 'x').rjust(8, '0')[-8:].encode()
    out += t + tn
    while len(out) % 4: out += b'\0'
    return bytes(out)


# ══════════════════════════════════════════════
# 探测
# ══════════════════════════════════════════════

def is_elf(b):
    return len(b) >= 4 and b[:4] == b'\x7fELF'


def probe(img_path):
    buf = open(img_path, 'rb').read()
    img = parse_image(buf)
    cpio, fmt = decompress_rd(img['rd'])
    entries, trailer = parse_cpio(cpio)
    names = {e['name'] for e in entries}

    rep = {
        'image': {
            'path': img_path,
            'size': len(buf),
            'md5': hashlib.md5(buf).hexdigest(),
            'header_version': img['hver'],
            'header_size': img['hsize'],
            'kernel_size': img['ksize'],
            'ramdisk_size': img['rsize'],
            'ramdisk_offset': img['roff'],
            'rd_format': fmt,
        },
        'cpio': {
            'size': len(cpio),
            'entries': len(entries),
            'trailer_namesize': trailer['namesize'],
            'trailer_tail_bytes': len(cpio) - trailer['end'],
        },
        'init': None,
        'init_variants': [],
        'third_party': [],
        'devices': {},
        'missing_devices': [],
        'build_prop': None,
        'rename_plan': None,
        'all_entries': [],
    }

    # ── 列出所有条目 ──
    for e in entries:
        kind = 'dir' if (e['mode'] & 0o170000) == 0o040000 else \
               'chr' if (e['mode'] & 0o170000) == 0o020000 else \
               'blk' if (e['mode'] & 0o170000) == 0o060000 else \
               'lnk' if (e['mode'] & 0o170000) == 0o120000 else 'file'
        rep['all_entries'].append({
            'name': e['name'], 'kind': kind, 'size': len(e['data']),
            'mode': oct(e['mode']),
            'exec': bool(e['mode'] & 0o111),
            'elf': is_elf(e['data']),
            'rdev': f"{e['rmaj']}:{e['rmin']}" if kind in ('chr', 'blk') else None,
        })

    # ── 找 first-stage init ──
    # 判据：名字是 init，或者任何名为 init* 的可执行 ELF
    init_e = None
    for e in entries:
        if e['name'] == 'init':
            init_e = e
            break
    if init_e is None:
        # 退化：找最小的可执行 ELF 且名字带 init
        cands = [e for e in entries
                 if e['name'].startswith('init') and is_elf(e['data']) and (e['mode'] & 0o111)]
        if cands:
            init_e = min(cands, key=lambda x: len(x['data']))

    if init_e:
        rep['init'] = {
            'name': init_e['name'],
            'size': len(init_e['data']),
            'mode': oct(init_e['mode']),
            'is_elf': is_elf(init_e['data']),
            'contains_ksu': b'KernelSU' in init_e['data'],
            'contains_magisk': b'magisk' in init_e['data'].lower(),
        }

    # ── 已有的 init.* 变体 ──
    for e in entries:
        n = e['name']
        if n == 'init' or n.startswith('init.'):
            if n != 'init':
                rep['init_variants'].append({
                    'name': n, 'size': len(e['data']),
                    'exec': bool(e['mode'] & 0o111), 'elf': is_elf(e['data']),
                })

    # ── 第三方组件 ──
    for e in entries:
        base = e['name'].split('/')[-1]
        if base in THIRD_PARTY:
            rep['third_party'].append({
                'name': e['name'], 'size': len(e['data']),
                'desc': THIRD_PARTY[base],
            })
        elif e['name'] in THIRD_PARTY:
            rep['third_party'].append({
                'name': e['name'], 'size': len(e['data']),
                'desc': THIRD_PARTY[e['name']],
            })

    # ── 设备节点 ──
    for e in entries:
        if (e['mode'] & 0o170000) == 0o020000:  # 字符设备
            rep['devices'][e['name']] = f"{e['rmaj']}:{e['rmin']}"
    for name, (perm, ma, mi, required) in DEVICE_TABLE.items():
        if name not in rep['devices']:
            rep['missing_devices'].append({
                'name': name, 'rdev': f"{ma}:{mi}", 'required': required,
            })

    # ── build.prop ──
    bp = None
    for e in entries:
        if e['name'].endswith('build.prop') and len(e['data']) < 8192:
            bp = e['data'].decode('utf-8', 'replace')
            break
    if bp:
        info = {}
        for line in bp.split('\n'):
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                k, v = line.split('=', 1)
                if any(x in k for x in ('fingerprint', 'build.date', 'device', 'model', 'release')):
                    info[k] = v
        rep['build_prop'] = info

    # ── 改名计划 ──
    existing = {e['name'] for e in entries}
    chosen = None
    for cand in RENAME_CANDIDATES:
        if cand not in existing:
            chosen = cand
            break
    rep['rename_plan'] = {
        'chosen': chosen,
        'candidates': RENAME_CANDIDATES,
        'conflicts': [c for c in RENAME_CANDIDATES if c in existing],
        'ok': chosen is not None,
    }

    return rep


# ══════════════════════════════════════════════
# 修补
# ══════════════════════════════════════════════

def patch(img_path, init_path, ko_path, out_path, with_module=True):
    print("═" * 70)
    print(" 自适应修补")
    print("═" * 70)

    # 1. 探测
    print("\n[1] 探测原厂镜像")
    p = probe(img_path)
    print(f"  镜像   {p['image']['size']:,} 字节  header v{p['image']['header_version']}")
    print(f"  ramdisk {p['image']['rd_format']} {p['image']['ramdisk_size']:,} → cpio {p['cpio']['size']:,}")
    print(f"  条目   {p['cpio']['entries']}")

    if p['init']:
        i = p['init']
        print(f"\n  first-stage init:")
        print(f"    {i['name']}  {i['size']:,} 字节  mode={i['mode']}")
        print(f"    ELF={i['is_elf']}  含KernelSU={i['contains_ksu']}  含Magisk={i['contains_magisk']}")
    else:
        print("\n  ⚠ 找不到 first-stage init")

    if p['init_variants']:
        print(f"\n  已有 init.* 变体 {len(p['init_variants'])} 个:")
        for v in p['init_variants']:
            print(f"    {v['name']:<22} {v['size']:>9,} 字节  exec={v['exec']} elf={v['elf']}")

    if p['third_party']:
        print(f"\n  第三方组件 {len(p['third_party'])} 个:")
        for t in p['third_party']:
            print(f"    {t['name']:<22} {t['size']:>9,} 字节  {t['desc']}")
    else:
        print("\n  没有第三方组件（干净）")

    print(f"\n  设备节点 {len(p['devices'])} 个: {', '.join(sorted(p['devices']))}")
    if p['missing_devices']:
        print(f"  缺失 {len(p['missing_devices'])} 个:")
        for d in p['missing_devices']:
            mark = '必需' if d['required'] else '建议'
            print(f"    {d['name']:<16} rdev={d['rdev']}  [{mark}]")

    if p['build_prop']:
        print(f"\n  系统信息:")
        for k, v in p['build_prop'].items():
            print(f"    {k} = {v}")

    rp = p['rename_plan']
    print(f"\n  改名计划: {rp['chosen']}  (冲突: {rp['conflicts'] or '无'})")
    if not rp['ok']:
        print("  ❌ 所有候选名都被占用，无法改名")
        return False

    # 2. 读我们的组件
    print("\n[2] 读取注入组件")
    sk_init = open(init_path, 'rb').read()
    sk_ko = open(ko_path, 'rb').read() if with_module else None
    print(f"  sk_init    {len(sk_init):,} 字节")
    if sk_ko:
        print(f"  sk_hello.ko {len(sk_ko):,} 字节")
    else:
        print(f"  （不注入模块）")

    # 3. 执行修改
    print("\n[3] 修改 ramdisk")
    buf = open(img_path, 'rb').read()
    img = parse_image(buf)
    cpio, fmt = decompress_rd(img['rd'])
    entries, trailer = parse_cpio(cpio)

    # 3.1 清理第三方
    before = len(entries)
    entries = [e for e in entries
               if e['name'].split('/')[-1] not in THIRD_PARTY
               and e['name'] not in THIRD_PARTY]
    dropped = before - len(entries)
    print(f"  清理第三方组件: {dropped} 个")

    # 3.2 改名（先删掉可能重复的候选名）
    target_name = rp['chosen']
    src_e = next((e for e in entries if e['name'] == 'init'), None)
    if src_e:
        entries = [e for e in entries if e['name'] != 'init']
        src_e['name'] = target_name
        entries.append(src_e)
        print(f"  改名 init → {target_name}（{len(src_e['data']):,} 字节）")
    else:
        print(f"  ⚠ 没有 /init 可改名")

    # 3.3 补设备节点
    have = {e['name'] for e in entries}
    added_dev = 0
    for name, (perm, ma, mi, required) in DEVICE_TABLE.items():
        if name not in have:
            entries.append({
                'name': name, 'mode': perm | 0o020000, 'uid': 0, 'gid': 0, 'nlink': 1,
                'mtime': 0, 'dmaj': 0, 'dmin': 0, 'rmaj': ma, 'rmin': mi, 'data': b'',
            })
            added_dev += 1
            print(f"  + {name:<16} rdev={ma}:{mi}")
    if added_dev == 0:
        print(f"  设备节点已齐全")

    # 3.4 注入
    entries = [e for e in entries if e['name'] not in ('init', 'sk_hello.ko')]
    entries.append({
        'name': 'init', 'mode': 0o100755, 'uid': 0, 'gid': 0, 'nlink': 1,
        'mtime': 0, 'dmaj': 0, 'dmin': 0, 'rmaj': 0, 'rmin': 0, 'data': sk_init,
    })
    print(f"  + init（我们的包装器）{len(sk_init):,} 字节")
    if sk_ko:
        entries.append({
            'name': 'sk_hello.ko', 'mode': 0o100644, 'uid': 0, 'gid': 0, 'nlink': 1,
            'mtime': 0, 'dmaj': 0, 'dmin': 0, 'rmaj': 0, 'rmin': 0, 'data': sk_ko,
        })
        print(f"  + sk_hello.ko {len(sk_ko):,} 字节")

    print(f"  最终 {len(entries)} 条目")

    # 4. 重打包
    print("\n[4] 重打包")
    new_cpio = build_cpio(entries)
    new_rd = gzip.compress(new_cpio, 9)
    print(f"  cpio   {len(new_cpio):,}")
    print(f"  gzip   {len(new_rd):,}")

    out = bytearray()
    page = img['page']
    hdr = bytearray(buf[:img['hsize']])
    struct.pack_into('<I', hdr, 12 if img['hver'] >= 3 else 16, len(new_rd))
    out += hdr
    while len(out) < page: out.append(0)

    # kernel
    if img['ksize']:
        out += buf[page:page + img['ksize']]
        while len(out) % page: out.append(0)

    # ramdisk（新）
    out += new_rd
    while len(out) % page: out.append(0)

    # boot signature（v4 特有，ramdisk 之后）
    if img['has_sig']:
        out += img['sig']
        while len(out) % page: out.append(0)
        print(f"  boot signature 保留（{img['sigsize']:,} 字节 @ {img['sig_off']:,}）")

    # ── 保留 ramdisk 之后的尾部数据 ──
    #
    # 尾部可能有两类东西，性质完全不同：
    #
    #   AVB vbmeta（magic "AVB0"）
    #     · 必须在固定位置（4K 对齐，bootloader 按偏移找）
    #     · 被新 ramdisk 顶掉就无解，只能报告
    #
    #   bootconfig（Android 12+）
    #     · 定义是「附着在文件末尾」：[data][size:4][magic:4]
    #     · 位置可以变，只要还在末尾
    #     · 即使 AVB 被顶掉，bootconfig 依然可以救回来
    #
    # 另有厂商私有数据：保守起见整段原样保留。

    avb = find_avb(buf, img['pad_start'])
    bc = find_bootconfig(buf)
    bc_blob = buf[bc[0]:] if bc else None

    # 先尝试整体保留（AVB 位置够用的话，bootconfig 自然跟着过来）
    if avb > 0 and avb >= len(out):
        while len(out) < avb: out.append(0)
        out += buf[avb:]
        print(f"  尾部数据整体保留 @ {avb:,}（{len(buf)-avb:,} 字节）")
        if avb:
            print(f"    含 AVB@ {avb:,}" + (f" + bootconfig@{bc[0]:,}" if bc else ""))
    else:
        # AVB 保不住（或者本来就没有）。至少把 bootconfig 救回来。
        keep_until = len(buf) - (len(bc_blob) if bc_blob else 0)

        if len(out) > keep_until:
            # 连 bootconfig 都放不下了
            print(f"  ❌ 新 ramdisk({len(out):,}) 已超出可用空间({keep_until:,})")
            print(f"     尾部数据无法保留：AVB={avb if avb>0 else '无'}  bootconfig={'有' if bc else '无'}")
            print(f"     这会丢失 bootloader 校验信息和内核启动参数")
            while len(out) < len(buf): out.append(0)
        else:
            while len(out) < keep_until: out.append(0)
            if bc_blob:
                out += bc_blob
                print(f"  ⚠ AVB 位置 {avb:,} 被顶掉（无解，需重新签名）")
                print(f"     ✅ bootconfig 已重新附着到末尾（{bc[1]:,} 字节）")
            else:
                if avb > 0:
                    print(f"  ⚠ AVB 位置 {avb:,} 被顶掉")
                while len(out) < len(buf): out.append(0)

    while len(out) < len(buf): out.append(0)
    result = bytes(out)

    open(out_path, 'wb').write(result)
    print(f"  产物 {out_path}  {len(result):,} 字节  md5={hashlib.md5(result).hexdigest()}")

    # 5. 自验
    print("\n[5] 自验")
    ok = True
    chk = parse_image(result)
    cpio2, _ = decompress_rd(chk['rd'])
    e2, t2 = parse_cpio(cpio2)
    print(f"  cpio round-trip: ", end='')
    if build_cpio(e2) == cpio2:
        print("✅ 逐字节一致")
    else:
        print("❌ 不一致"); ok = False

    names2 = {e['name'] for e in e2}
    print(f"  改名生效: {'✅' if target_name in names2 else '❌'}")
    print(f"  /init 存在: {'✅' if 'init' in names2 else '❌'}")
    devs2 = {e['name']: f"{e['rmaj']}:{e['rmin']}" for e in e2 if (e['mode'] & 0o170000) == 0o020000}
    bad_dev = [n for n in DEVICE_TABLE if n in devs2 and devs2[n] == '0:0']
    print(f"  设备节点 rdev: {'✅ 全部非 0' if not bad_dev else '❌ ' + str(bad_dev)}")
    print(f"  TRAILER 尾部: {'✅ 0 字节' if len(cpio2) - t2['end'] == 0 else '❌'}")
    print(f"  文件大小: {'✅ 与原镜像相同' if len(result) == len(buf) else '❌ 不同'}")

    return ok


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]
    try:
        if cmd == 'probe':
            if len(sys.argv) < 3:
                print("用法: probe <镜像>")
                return
            rep = probe(sys.argv[2])
            print(json.dumps(rep, indent=2, ensure_ascii=False))
        elif cmd == 'patch':
            if len(sys.argv) < 6:
                print("用法: patch <镜像> <sk_init> <sk_hello.ko> <输出> [--no-module]")
                return
            with_module = '--no-module' not in sys.argv
            ok = patch(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], with_module)
            sys.exit(0 if ok else 1)
        else:
            print(__doc__)
    except ValueError as e:
        # 结构性问题：友好输出，不打印 traceback
        print()
        print("═" * 70)
        print(" ❌ 无法修补这个镜像")
        print("═" * 70)
        print()
        for line in str(e).split('\n'):
            print("  " + line)
        print()
        print("═" * 70)
        sys.exit(2)
    except FileNotFoundError as e:
        print(f"\n❌ 文件不存在: {e.filename}\n")
        sys.exit(2)
    except RuntimeError as e:
        print(f"\n❌ 处理失败: {e}\n")
        sys.exit(2)


if __name__ == '__main__':
    main()
