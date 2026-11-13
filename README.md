# 影核 / Umbral

**一套自研的 Android 内核级权限框架** —— 用自编译 LKM 代替 Magisk / KernelSU 的 su 二进制与授权数据库，
把 root 能力放进进程自己的 cred 里，并逐层收口可检测面。

> 仅用于自有设备的安全研究与逆向工程。请勿在非本人设备上使用。

---

## 特性

| 能力 | 说明 |
|---|---|
| 影子提权 | 进程 uid 不变、cred 提升为 root（全 caps + LSM 放行），`ps` 无异常 |
| 传统 su | 同时保留 su 通道（`su -c`，支持 `-s` / `-l` / `--`） |
| 五条判定点 | ①打开文件 ②文件属性 ③目录列表 ④文件内容 ⑤进程可见性 |
| 三道防线 | S1 虚拟文件系统白名单 / S2 保护 uid / S3 回读校验 |
| 代码段 hook | `jmp`(16B 绝对跳转) / `jmpb`(4B B 指令) / `jmpundo` / `ptr`(GOT) |
| 模块系统 | 兼容 KernelSU 的目录布局、两阶段执行、Zygisk 无关 |
| 隐蔽性 | 模块链表摘除、sysfs 摘除、`/proc` 名字过滤、`stat` 返回 ENOENT |
| 兼容性 | 多 KMI（5.4 / 5.10 / 5.15 / 6.1 / 6.6），BTF 现场解析偏移 |
| 诊断 | `/proc/umbral/diag` 输出能力状态（OK / DISABLED + 原因） |

---

## 目录结构

```
umbral/
├── README.md
├── LICENSE
├── .gitignore
├── docs/                              设计与验收文档
│   ├── systemless-mount-design.md     systemless 挂载设计（阶段 1 已实现）
│   ├── antidetect-capeff-tracerpid-design.md  CapEff / TracerPid 设计
│   └── um-omnipotence-6.md            五条判定点定义
│
├── kernel/                            内核模块
│   ├── Makefile                       obj-m := umbral.o
│   └── src/
│       ├── umbral.c                   主模块（提权 / 判定 / hook）
│       └── btf.c                      BTF 偏移解析（并入 umbral.c）
│
├── kernel-kmem/                       【仅本地，不发布】
│   ├── Makefile                       obj-m := kvm_guest.o
│   └── src/
│       ├── kvm_guest.c                → #include "umbral_kmem.c"
│       ├── umbral_kmem.c              内存原语主文件
│       ├── kmem_syms.inc              ELF 符号解析
│       ├── kmem_watch.inc             写监控
│       ├── kmem_scan.inc              内核内特征扫描
│       └── kmem_stream.inc            共享内存环采样
│
├── init/                              init 包装器
│   └── sk_init_log.c                  开机加载 .ko + 起守护进程
│
├── daemon/                            root 守护进程
│   └── umbrald.c                      属性注入 / 后台维护
│
├── su/                                su 实现
│   └── su.c                           提权 + 参数解析 + 最小环境
│
├── manager/                           管理器 APK（io.umbral）
│   ├── build.ps1                      构建脚本（aapt2/d8/apksigner）
│   ├── AndroidManifest.xml
│   ├── java/io/umbral/                源码
│   ├── res/                           资源
│   ├── jni/                           NDK 源码
│   └── assets/                        打包资产
│       ├── arm64-v8a/
│       │   ├── umbral_init
│       │   ├── android15-6.6/umbral.ko
│       │   ├── android14-6.1/umbral.ko
│       │   ├── android13-5.15/umbral.ko
│       │   ├── android13-5.10/umbral.ko
│       │   └── android12-5.10/umbral.ko
│       ├── bin/{su,umbrald}
│       └── lib/arm64-v8a/libumbral_xz.so
│
└── tools/
    └── bootpatch/                     镜像修补工具（PC 侧）
```

---

## 构建

### 内核模块

```bash
# 需要对应 KMI 的内核源码树
export KDIR=/path/to/kernel
make -C $KDIR M=$PWD/kernel ARCH=arm64 LLVM=1 modules
```

多 KMI 需要各自的内核树；产物按 `android<ver>-<kmi>/umbral.ko` 放置。

### su / init / daemon

```bash
$NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android30-clang \
    -O2 -fPIE -pie -s -o su su/su.c
```

### 管理器

```powershell
pwsh manager/build.ps1 -Clean
# 产物 manager/umbral-0.90.apk（需 android-sdk build-tools + JDK）
```

---

## 使用

```bash
# 1. 刷入（自行用 fastboot 刷 init_boot，或用 App 内修补）
fastboot flash init_boot init_boot_patched.img

# 2. 提权
su -c 'id -u'                      # → 0

# 3. 内核状态
cat /proc/umbral/version
cat /proc/umbral/diag              # 能力状态表

# 4. 规则（判定点）
echo "<uid> <dev> <ino> hide" > /proc/umbral/um
echo "dry <uid> <dev> <ino> hide" > /proc/umbral/um   # 先预演
echo "clear" > /proc/umbral/um

# 5. 代码 hook
echo "jmp <pid> <from_hex> <to_hex>" > /proc/umbral/procmem
echo "jmpundo <pid>"                 > /proc/umbral/procmem
```

---

## 节点一览

| 节点 | 权限 | 用途 |
|---|---|---|
| `/proc/umbral/version` | 0444 | 版本 |
| `/proc/umbral/diag` | 0444 | **能力状态表（换设备先看这个）** |
| `/proc/umbral/btf` | 0444 | BTF 解析出的结构偏移 |
| `/proc/umbral/escape` | 0666 | 提权入口 |
| `/proc/umbral/grant` / `grants` | 0222 / 0444 | 授权 |
| `/proc/umbral/um` | 0666 | 判定点规则（支持 `dry` 预演） |
| `/proc/umbral/umstat` | 0666 | 属性伪造 |
| `/proc/umbral/procmem` | 0600 | 代码段 hook / 读写 |
| `/proc/umbral/mnt` | 0600 | systemless 计划表（阶段 1：只存不挂） |

---

## 项目状态

| 模块 | 版本 | 状态 |
|---|---|---|
| `umbral.ko` | 1.41.0-mntplan | 编译通过、结构自校验通过；**未上机验证** |
| `kvm_guest.ko` | 1.9.0-torn | 同上；**不随本仓库发布** |
| 管理器 APK | 0.90 | 正式签名（CN=Umbral），已装机 |

### 未完成

- CapEff / CapTracerPid 伪装（设计见 `docs/antidetect-capeff-tracerpid-design.md`）
- systemless 挂载阶段 2/3（`apply <pid>` 与自动建 ns，设计见 `docs/systemless-mount-design.md`）
- 全部内核功能均未上机验证

---

## 免责声明

本项目仅供**自有设备**的安全研究、逆向工程学习与个人使用。
使用者需自行承担设备变砖、数据丢失、违反当地法律法规的一切后果。
作者不对任何滥用行为负责。

---

## 许可

见 `LICENSE`。
