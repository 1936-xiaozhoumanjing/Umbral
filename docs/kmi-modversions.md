# MODVERSIONS（符号 CRC）适配说明

## 一、两种 insmod 失败必须先分清

| 现象 | 含义 | 处理 |
|---|---|---|
| `version magic 'X' should be 'Y'` | vermagic 不一致 | `tools/vermagic.py --set`（已接线到打包流程） |
| `disagrees about version of symbol X` | 符号 CRC 不一致 | 换「无 __versions」变体 + IGNORE 标志加载 |
| `no symbol version for X` | 模块无版本信息而内核要求 | 同上 |
| `module verification failed` / `Key was rejected` | 模块签名强制 | 无签名则无解，如实告知 |
| `Unknown symbol X` | 符号不存在（跨分支） | 必须用该机型内核源码重编 |
| `Operation not permitted` / `avc: denied` | 权限/SELinux | 不是模块问题，查授权 |

分类器实现：`io/umbral/sk/LoadDiag.java`，`classify()` 返回 0~7/99，10 条真实报错用例全部通过。

## 二、构建两套变体

### 带 CRC（正常构建）
需要内核树里有完整构建产物（`Module.symvers`），modpost 才会写入符号 CRC。

### 无 CRC（后处理，1 秒/个）
```bash
python tools/strip_versions.py --strip umbral.ko
```
把 `__versions` 的 `sh_type` 置 NULL、`sh_size` 置 0，并从 vermagic 删掉 `modversions`。
等价于 `CONFIG_MODVERSIONS=n` 构建，但不需要重跑内核树。

### 改内核树时的陷阱（踩过两次）
```
scripts/config -d MODVERSIONS 只改 .config
make 实际编译读的是 include/config/auto.conf
不跑 make syncconfig，auto.conf 不更新 → 产物仍带 modversions，且尺寸一字不差
正确顺序：syncconfig → olddefconfig → syncconfig → prepare → modules_prepare → modules
```

## 三、实测状态（11 个 KMI 目录）

| KMI | main `__versions` | main vermagic | nomv `__versions` |
|---|---|---|---|
| android11-5.4 | 0 | 无 modversions | 0 |
| android12-5.10 | 0 | 无 modversions | 0 |
| android13-5.10 | 0 | 无 modversions | 0 |
| android13-5.15 | 0 | 无 modversions | 0 |
| android14-6.1 | 0 | 无 modversions | 0 |
| android15-5.15 | 0 | 无 modversions | 0 |
| android15-6.1 | 0 | 无 modversions | 0 |
| **android15-6.6** | **4736** | **含 modversions** | 0 |
| android16-5.15 | 0 | 无 modversions | 0 |
| android16-6.1 | 0 | 无 modversions | 0 |
| **android16-6.6** | **4736** | **含 modversions** | 0 |

**结论性事实：只有 6.6 分支的内核树有 `Module.symvers`，因此只有它能产出真正的 CRC 数据；
其余四个分支（5.4/5.10/5.15/6.1）从来没有过 CRC 信息 —— 之前的空 `__versions`
却仍宣称 `modversions`，属自相矛盾状态，现已统一成「自洽的无 CRC 形态」。**

门禁工具（随时复跑，exit 0 即通过）：
```bash
python tools/check_kmi_assets.py
```

## 四、加载侧（init，四级回退）

```
finit_module(fd, "", 0)
  → finit_module(fd, "", MODULE_INIT_IGNORE_MODVERSIONS|IGNORE_VERMAGIC)
  → init_module(buf, sz, "")
  → load_module("/umbral_nomv.ko")   ← 无 __versions 变体再走一遍上述三级
```

第 2 级依赖目标内核 `CONFIG_MODULE_FORCE_LOAD=y`；未开启时返回 EINVAL/EPERM，
自然落到第 3 级，行为与改动前一致。

## 五、打包侧

`io/umbral/flash/BootPatch.java`：按 KMI 取模块的同时取 `umbral_nomv.ko`，
两份都写入 ramdisk（`sk_root.ko` + `umbral_nomv.ko`），共 2 处注入点（普通 / vendor_boot）。

## 六、绕不过去的部分（不承诺）

```
厂商公开的 GPL 源码 ≠ 该机正在运行的内核（样本机内核带 -dirty，是自编译过的）
没有「同源 + 同 .config」就拿不到一致的 CRC
→ 这类机型只能：先试 nomv + IGNORE，仍失败则无解，如实告知用户
```

## 七、未验证项

- 全部结论均为电脑侧验证（编译 / ELF 段落 / 字符串 / 打包内容 / 门禁）
- **没有任何真实设备跑过**；vivo V2254A（Android16 / 5.15.197-dirty）为首个待验证样本