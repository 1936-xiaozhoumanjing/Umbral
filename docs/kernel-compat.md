# 内核兼容性更新说明（V1.3）

本文记录影核内核模块在「跨内核版本 / 跨厂商」上的全部改动与实测结论。

---

## 1. 结论摘要

| 项目 | 状态 |
|---|---|
| 支持的 KMI 目录 | 11 个（5.4 / 5.10 / 5.15 / 6.1 / 6.6，含 Android 15/16 别名） |
| 真 CRC（`__versions` 非空） | 5.4 / 5.10 / 5.15 / 6.1 / 6.6 **全部具备** |
| 双变体 | 每个 KMI 都提供 `umbral.ko`（带 CRC）与 `umbral_nomv.ko`（无 CRC） |
| vermagic 自动改写 | 打包时按目标机 `uname -r` 改写 `.modinfo` |
| 加载回退 | 4 级（finit_module → IGNORE 标志 → init_module → nomv 变体） |
| 门禁 | `tools/check_kmi_assets.py`，exit 0 视为通过 |

---

## 2. KMI 目录矩阵

```
android11-5.4      android12-5.10     android13-5.10
android13-5.15     android14-6.1      android15-5.15
android15-6.1      android15-6.6      android16-5.15
android16-6.1      android16-6.6
```

**为什么有 `android16-5.15` 这种组合：** 部分厂商把旧内核（5.15）搬上新系统（Android 16）。
GKI 官方并没有 `android16-5.15` 这个 KMI 世代（KernelSU 的清单里也没有），
所以这类机器只能「目录别名 + 自行编模块」，属于尽力支持。

---

## 3. 真 CRC：这次最实质的改动

### 问题
`CONFIG_MODVERSIONS=y` 的内核会校验模块里每个导入符号的 CRC。我们之前的模块
`__versions` 段是**空的**（大小为 0），却仍在 vermagic 里写着 `modversions` ——
这是自相矛盾状态：既不提供版本信息，又声称自己带版本信息。

### 根因
`modpost` 只对 `Module.symvers` 里有 CRC 记录的符号生成 `__versions`。
我们的四个内核树（5.4 / 5.10 / 5.15 / 6.1）从来没有**完整构建**过，
所以树里没有 `Module.symvers` → 段为空。

### 修法
对每棵树做一次完整构建，拿到 `Module.symvers`，再用它重编模块：

```bash
cd /root/k5xx
./scripts/config --file .config -e MODVERSIONS
make ARCH=arm64 LLVM=1 syncconfig && make ARCH=arm64 LLVM=1 olddefconfig \
  && make ARCH=arm64 LLVM=1 syncconfig
# 断言：.config 是 not set 之外的 y，且 auto.conf 同步
grep -c '^CONFIG_MODVERSIONS=y' include/config/auto.conf   # 必须 1
make ARCH=arm64 LLVM=1 -j$(nproc)          # ← 关键：完整构建，生成 Module.symvers
make -C $TREE M=$SRC ... modules           # 用这份 symvers 编我们的模块
```

### 实测结果

| 树 | Module.symvers | `__versions` | vermagic |
|---|---|---|---|
| 5.15 | 15,476 行 | 5,568 B | 含 modversions |
| 6.1 | 15,785 行 | 5,632 B | 含 modversions |
| 5.10 | 14,695 行 | 5,568 B | 含 modversions |
| 5.4 | 11,889 行 | 4,544 B | 含 modversions |
| 6.6 | 已有 | 4,736 B | 含 modversions |

**意义：GKI 在同一 KMI 世代内冻结导出符号 ABI，所以用该世代源码算出的 CRC
与同世代所有设备一致 —— 这是 KernelSU 的做法，模块「天生对得上」，不需要绕过任何检查。**

---

## 4. 老内核 + 新 clang 的两个编译障碍

完整构建 5.4 / 5.10 时暴露出的问题（与我们的代码无关，是内核本身对新编译器的兼容性）：

### ① `arch/arm64/include/asm/kgdb.h`

```c
asm ("brk %0" : : "I" (KGDB_COMPILED_DBG_BRK_IMM));   /* 1025 超出 clang-18 的 'I' 约束 */
```
修法（语义不变，换编码形式）：

```c
asm (".inst 0xd4208020");    /* brk #0x401：0xD4200000 | (0x401 << 5) */
```
原文件备份为 `kgdb.h.bak_clang18`。

### ② `arch/arm64/include/asm/vdso/gettimeofday.h`

```
error: unknown register name 'x1' in asm
```
修法：完整构建改用 GNU as（`-fno-integrated-as`）。
只影响内核本身；我们的模块仍然用集成汇编器编译。

**为什么不能只关 `CONFIG_KGDB`：** 该头仍会被 `asm-offsets` 间接包含，所以必须改源码。

---

## 5. vermagic 适配

`.ko` 里 `.modinfo` 段的 `vermagic=` 必须与目标机 `uname -r` 完全一致，否则 insmod 报
`version magic 'X' should be 'Y'`。

### 工具
```
tools/vermagic.py   --print / --set / --from-adb
```

改写策略：
- 新串更短 → 原地覆盖 + 零填充（段大小不变）
- 新串更长 → 重建 `.modinfo` 并追加到文件尾部（改段头，不动代码段）

### App 侧
`io.umbral.sk.Vermagic` 在打包前调用 `patchFile()`，读 `System.getProperty("os.version")`，
失败只记录日志、不阻断流程。

### 已实测的 vermagic 样本

```
nubia NX769J  6.6.30-android15-8-g54dcbfbef792-ab12368803-4k SMP preempt mod_unload modversions aarch64
vivo V2254A   5.15.197-gfddbe50ead86-dirty SMP preempt mod_unload modversions aarch64
我们的 5.15    5.15.194-ge6654bf2f6c2 SMP preempt mod_unload modversions aarch64
我们的 6.1     6.1.155-g498f91c17b08 SMP preempt mod_unload modversions aarch64
```

---

## 6. 双变体与四级加载

### 无 CRC 变体
```
tools/strip_versions.py --strip umbral.ko
```
把 `__versions` 的 `sh_type` 置 NULL、`sh_size` 置 0，并从 vermagic 删掉 `modversions`。
等价于 `CONFIG_MODVERSIONS=n` 构建，但不需要重跑内核树（单个模块约 1 秒）。

### init 的加载顺序（4 级回退）

```c
finit_module(fd, "", 0)                                     /* 正常路径 */
→ finit_module(fd, "", MODULE_INIT_IGNORE_MODVERSIONS
                       | MODULE_INIT_IGNORE_VERMAGIC)       /* 需目标机 CONFIG_MODULE_FORCE_LOAD=y */
→ init_module(buf, sz, "")                                  /* 兼容旧内核 */
→ load_module("/umbral_nomv.ko")                            /* 无 __versions 变体再来一遍 */
```

第 2 级若被目标机拒绝（GKI 默认 `MODULE_FORCE_LOAD` 未启用），自动落回第 3 级，
行为与改动前一致，不会更糟。

---

## 7. 打包与门禁

- `BootPatch` 在按 KMI 取模块的同时取 `umbral_nomv.ko`，**两份都写进 ramdisk**
  （`sk_root.ko` + `umbral_nomv.ko`，普通与 vendor_boot 两条路径各一处）
- 门禁脚本检查：每个 KMI 目录两套变体是否自洽（`__versions` 与 vermagic 是否矛盾）、
  注入点数量、init 内是否含两个关键字符串

```
python tools/check_kmi_assets.py    →  exit 0 = PASS
```

---

## 8. 已知限制（不承诺）

```
· 厂商公开的 GPL 源码 ≠ 该机正在运行的内核（样本机内核带 -dirty）
  没有「同源 + 同 .config」就拿不到一致的 CRC，这类机器只能先试 nomv + IGNORE
· android16-5.15 这类非 GKI 组合属尽力支持，不保证
· 模块仍要求目标机允许加载未签名模块（CONFIG_MODULE_SIG_FORCE 未启用）
· 以上全部为电脑侧验证（编译 / ELF 段落 / 打包内容 / 门禁），
  vivo V2254A 为首个待真机验证样本
```

---

## 9. 变更记录

| 模块版本 | 变更 |
|---|---|
| 1.42.0 | CAP_SYS_MODULE 对已授权 uid 放行 |
| 1.43.0 | 周期扫描认领管理器 uid（只打印，未授权 —— 有缺陷） |
| 1.43.1 | 周期扫描**真正写入授权表**；KMI 别名目录扩展 |
| V1.3（APK） | 五棵内核树全部算对 CRC；双变体；vermagic 自动适配；4 级加载回退 |
