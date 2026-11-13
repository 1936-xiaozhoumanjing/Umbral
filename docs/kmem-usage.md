# kvm_guest 内存内核工具 —— 正确用法

> 模块名 `kvm_guest`（源码 `umbral_kmem.c`，对外中性命名）。
> 本文件只写经过源码核对或实测确认的内容；未验证的部分会明确标「待验证」。

---

## 0. 前提与调用约定

### 节点

| 节点 | 权限 | 用途 |
|---|---|---|
| `/proc/umbral_kmem/call` | 0666（受 `km_caller_visible()` 门控） | 写=下命令，读=取结果 |
| `/proc/umbral_kmem/ring` | 0666 | `mmap` 用的采样环形缓冲，**不是文本命令** |

### 三条硬规则

```bash
# ① 只能用 echo 重定向写，不能用 > 覆盖写文件的方式（proc 拒绝 O_TRUNC）
echo "stat" > /proc/umbral_kmem/call      # ✅
# > /proc/umbral_kmem/call                 # ❌ 会失败

# ② 下完命令再单独读结果
echo "stat" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call

# ③ 读不到内容时会打印「用法」而不是空 —— 这最容易误判成"命令不存在"
#    0 条事件时现在会明确输出 "ev: 0 events ..."，不再伪装成用法
```

### 门控（决定你能不能写/读）

```
km_caller_visible()：uid 0 / 管理器 uid / grants.conf 里的 uid / comm 为 io.umbral
不满足时 open() 直接返回 -ENOENT（表现为"文件不存在"，不是权限不足）
```

---

## 1. 命令总表（按源码 dispatch 顺序）

| 命令 | 参数 | 作用 |
|---|---|---|
| `phymap` | `<pid> <0xVA>` | VA → PA，并显示页表 flags |
| `phyread` | `<pid> <0xVA> <len>` | 走物理直读（只支持 direct map，最大 16384） |
| `bread` | `<pid> <0xADDR>:<len> [...]` | 最常用：读目标进程内存（≤64 组，每组 ≤256B） |
| `watchoff` | `<pid>` | 摘掉该 pid 的 PTE 监控 |
| `watch` | `<pid> <0xA[:len]> [更多地址…]` | PTE 写监控（**已不推荐**，见第 6 节） |
| `ev` | 无 | 取事件环形缓冲（硬件断点 / PTE 命中都写这里） |
| `pageinfo` | `<pid> <0xVA>` | 一句话排错：huge/level/PTE 值/AP2/CONT |
| `tids` | `<pid>` | 列线程 tid |
| `regs` | `<tid>` 或 `<pid> <tid>` | 取线程用户态寄存器（PC/SP/LR/X0-X8 + state） |
| `streamstop` | 无 | 停止采样（未启动时返回 -EINVAL，不会崩） |
| `stream` | `<pid> <0xADDR:len> <Hz>` | 定时采样写环形缓冲，配合 `ring` mmap |
| `bpadd` | `<pid> <0xADDR> [len] [r\|w\|rw]` | **硬件断点**，len 默认 8，模式默认 w |
| `bpdel` | 无 | 摘掉全部硬件断点 |
| `bps` | 无 | 已注册硬件断点数量（上限 4） |
| `diag` | 无 | 自检：门控状态、符号解析、统计 |
| `stat` | 无 | 计数器（watches/active/hits/faults/calls/last_errno） |
| `scan` | `<pid> <start> <end> <pattern…>` | 进程内搜索（≤256MB/区段，≤64 命中） |
| `syms` | `[pid] [lib] [filter]` | 符号表；pid 可省略（全局按名字过滤） |
| `vma` | `<pid>` | 内存段布局 |

**空参数命令不需要额外空格**：`ev`、`stat`、`bps`、`bpdel`、`diag`、`streamstop`。

---

## 2. 读内存类

### 2.1 `bread` —— 主力读取

```bash
# 单点：读 16 字节
echo "bread 21211 0x62fe3a8000:16" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call

# 多点：一次读多块（上限 64 组，每组 ≤256 字节）
echo "bread 21211 0x62fe3a8000:32 0x62fe3a8100:64" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call
```

- 返回形如 `DATA <len> <hex…>`
- 未落页的页按**零**返回（不会中断整个读取）

### 2.2 `phyread` —— 物理路径

```bash
echo "phyread 21211 0x62fe3a8000 4096" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call
```

限制：
- 只支持 **direct map**（`__va` 可达的物理页），设备/pfn 映射不支持
- 单次 ≤ 16384 字节
- 与 `bread` 的区别：`phyread` 走 `km_walk` 取 PA 再 `__va`，**不会触发缺页**；`bread` 走 `access_process_vm`，会触发缺页

### 2.3 `phymap` —— 看页表

```bash
echo "phymap 21211 0x62fe3a8000" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call
```

### 2.4 `pageinfo` —— 排错首选

```bash
echo "pageinfo 21211 0x62fe3a8000" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call
```

输出包含 `huge=`、`level=`、`PTE=0x…`、`AP2=`、`CONT=`。
**注意：`huge=0 level=1` 只表示页表层级，不代表 CONT 位为 0** —— 开了 `CONFIG_ARM64_CONTPTE` 的机器，绝大部分页的 CONT 都是 1。

---

## 3. 硬件断点（推荐方式：抓"谁读/写了这个地址"）

### 3.1 为什么用它

```
ARM64 有 4 个硬件观察点（DBGBVR0-3 / DBGBCR0-3）。
它由 CPU 触发，完全不改页表 —— 不需要动 AP[2]、不碰 contpte、不刷 TLB。
命中时直接给出触发指令的 PC。
```

### 3.2 用法

```bash
echo "bps" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call
#   bps=0 max=4

# 抓「读」——坐标类数据读多写少，先挂读
echo "bpadd 21211 0x62fe3a8000 8 r"  > /proc/umbral_kmem/call; echo rc=$?
# 抓「写」
echo "bpadd 21211 0x62fe3a8000 8 w"  > /proc/umbral_kmem/call; echo rc=$?
# 读写都抓
echo "bpadd 21211 0x62fe3a8000 8 rw" > /proc/umbral_kmem/call; echo rc=$?

echo "bps" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call

# 让目标跑一会儿，取事件
echo "ev" > /proc/umbral_kmem/call && head -8 /proc/umbral_kmem/call
#   EV <addr> <pc> <tid> <seq> …
```

### 3.3 返回码含义

| rc | 含义 | 处理 |
|---|---|---|
| 0 | 挂上了 | 继续 |
| `-38` (-ENOSYS) | `register_user_hw_breakpoint` 符号没解析到 | 该内核没这个符号或 kallsyms 受限 |
| `-16` (-EBUSY) | 4 个观察点已满 | 先 `bpdel` |
| `-3` (-ESRCH) | pid 找不到 | 检查 pid |
| `-22` (-EINVAL) | 参数/任务无效（无 mm 等） | 检查 pid 是否线程、地址是否用户态 |
| `-1` (-EPERM) | perf 权限受限 | 少见，通常是内核策略 |

### 3.4 限制

```
· 只有 4 个（硬件决定）
· 只对指定 task 生效（线程级），不是全进程广播
· bp_len 建议 8（对齐）或 4；2 也支持
· 命中记录写进 `ev` 环形缓冲，容量固定，取完不自动清空
```

---

## 4. 进程与寄存器

```bash
echo "tids 21211" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call
# 列线程

echo "regs 21211 21300" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call
# regs <pid> <tid>：带 tgid 归属校验，tid 不属于该 pid 时返回 -ESRCH
# regs <tid>：只给 tid

echo "vma 21211" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call
# 段布局：起始/结束/权限/rss 名字
```

`regs` 输出包含 `state=`（R/S/I/?）、`PC SP LR`、`X0..X8`，以及 `CTX_PC/CTX_SP`（内核上下文，非用户态）。

---

## 5. 搜索与符号

```bash
# 在某个区间搜字节/模式（≤256MB，≤64 命中）
echo "scan 21211 0x6200000000 0x6300000000 0000803f" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call

# 符号：可省略 pid
echo "syms"            > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call
echo "syms libc"       > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call
echo "syms 21211"      > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call
echo "syms 21211 libUE4" > /proc/umbral_kmem/call && cat /proc/umbral_kmem/call
# 输出：S <addr> <size> <type> <name>（type=U 表示未定义符号）
```

---

## 6. `watch`（PTE 写监控）—— 已不推荐

**为什么不推荐：** 6.6 GKI 开了 `CONFIG_ARM64_CONTPTE=y`，几乎全部映射都是 16 页连续块。
改单个 PTE 需要 contpte 展开 + pte 表锁；调用约定任何一处不对就是 panic。
实测两次不同实现都在挂载瞬间崩，代价是整机重启。

**保留它只是为了「没有 contpte 的老内核」**：

```bash
insmod kvm_guest.ko watch=1          # 默认关闭
echo "watch <pid> <0xA[:len]>" > /proc/umbral_kmem/call
echo "watchoff <pid>" > /proc/umbral_kmem/call
```

行为与限制：
```
· CONT=1 的页直接返回 -EINVAL（不碰）
· 大页（1G/2M）返回 -EINVAL
· 已只读（AP[2]=1）返回 -EINVAL
· 上述拒绝都不会崩
```

**抓"谁读写了某地址"请优先用 `bpadd`。**

---

## 7. 采样（stream）

```bash
echo "stream 21211 0x62fe3a8000:64 200" > /proc/umbral_kmem/call
# 200Hz 采样 64 字节，写入 ring 环形缓冲

# ring 通过 mmap 读取（不是文本命令）
# 格式：128B 头 + 96B × 8192 槽

echo "streamstop" > /proc/umbral_kmem/call
# 未启动时返回 -EINVAL（已判空，不会崩）
```

`stream` 与 `watch` 的区别：`stream` 只**采样值**，不拦截写入者；`watch`/`bpadd` 才给 PC。

---

## 8. 故障对照表

| 现象 | 原因 | 处理 |
|---|---|---|
| 返回 `-38` | 命令门控未开 / 符号没解析到 | `diag` 看 `watch_enable`、`watch_ok`、符号指针 |
| 返回 `-22` | 参数格式错 / 页不满足条件 | 检查参数个数与地址；`pageinfo` 看页状态 |
| 返回 `-14` | 地址未映射 / 页不存在 | 先 `bread` 或 `pageinfo` 确认 |
| 返回 `-16` | 硬件观察点用满 | `bpdel` |
| 读节点直接打印「用法」 | 上一条命令没有任何输出 | 用具体命令；`ev` 现在会明确报 0 events |
| `open` 返回 ENOENT | 门控（`km_caller_visible()`）不通过 | 用 root / 管理器 uid |
| 命令"像不存在" | 多半是空输出被显示成用法 | 同上 |

---

## 9. 典型工作流

### 9.1 找「谁读了这个坐标」

```bash
echo "scan <pid> <start> <end> 0000803f"  > …/call && cat …/call   # 定位候选地址
echo "pageinfo <pid> 0x候选"               > …/call && cat …/call   # 确认已落页
echo "bpadd <pid> 0x候选 8 r"              > …/call; echo rc=$?     # 挂读断点
echo "bps"                                 > …/call && cat …/call
echo "ev"                                  > …/call && head          # 拿到 pc
```

### 9.2 找「谁改了这个值」

```bash
echo "bpadd <pid> 0x候选 8 w" > …/call; echo rc=$?
echo "ev"                     > …/call
```

### 9.3 读结构体

```bash
echo "bread <pid> 0x基址:256" > …/call && cat …/call
```

---

## 10. 版本与变更（内存模块）

| 版本 | 变更 |
|---|---|
| 2.5.1 | 修 dispatch 断链（watch/ev/watchoff/ring 掉出主链） |
| 2.5.2 | `syms` 支持省略 pid；新增 `diag` |
| 2.5.3 | 改用真实符号 `contpte_wrprotect_ptes`（原来找的 `contpte_ptep_set_wrprotect` 不存在） |
| 2.6.0 | 路线 A：检测 CONT 位，连续块直接拒（不崩） |
| 2.7.0 | 路线 B：`__pte_offset_map_lock` 加 pte 锁 —— 实测仍崩，PTE 路线停止 |
| 2.8.0 | **改用硬件断点**：`bpadd` / `bpdel` / `bps` |
| 2.8.1 | `ev` 空结果明确输出（不再伪装成用法） |
| 2.9.0 | `bpadd` 支持 `r` / `w` / `rw` |
| 2.9.1 | `streamstop` 未启动时判空返回 -EINVAL |

**当前版本：2.9.1**
