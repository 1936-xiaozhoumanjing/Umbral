# 反检测补口 · CapEff / TracerPid 设计（影核）

> 目标：让未授权 App 观察 `/proc/<pid>/status` 时，看不到「进程有全 caps」也看不到「被 ptrace 调试」。
> 现状：**未实现**。本文件是设计稿。

---

## 1. 要改的两行

```
/proc/<pid>/status 里：
    CapInh: / CapPrm: / CapEff: / CapBnd: / CapAmb:   5 个十六进制 64 位掩码
    TracerPid: <ptrace 我们的进程 pid>，未被跟踪时为 0
```

**检测逻辑（对手会这么写）：**
```
读 /proc/self/status
  CapEff 非 0        → 我这个 App 居然有 caps → 有 root
  CapBnd 全 f        → 同上
  TracerPid != 0     → 有人在调我 → 反调试告警
```

## 2. 实现思路（两条路，推荐 A）

### A. 在 read 上做文本改写（推荐）

```
钩 vfs_read（已有该钩子，复用）
  命中 /proc/<pid>/status 时：
    ① 把读到的 buffer 当文本，逐行找前缀 "CapPrm:" / "CapEff:" / "CapBnd:" 等
    ② 把后面的十六进制值替换成"看起来正常"的值
    ③ 找 "TracerPid:" 行，把数字替换成 0
```

**难点与对策：**

| 难点 | 对策 |
|---|---|
| 值的长度会变（`0000000000000000` vs `0000003fffffffff`） | **必须用定长十六进制输出**（16 位零填充），替换后长度不变，原地改 |
| 可能跨 read 边界 | 只处理「本行完整落在本 buffer 内」的情况；跨界的交给下一次 read（接受偶发漏改） |
| `/proc/self/status` 被 mmap？ | status 不支持 mmap，只能 read，所以 read 过滤是完整覆盖 |
| 多进程读自己 | 只对「未授权 uid」生效；授权 uid 读到真值 |

**"看起来正常"的值怎么定：**
```
普通三方 App 的典型值：
  CapInh 0000000000000000
  CapPrm 0000000000000000
  CapEff 0000000000000000
  CapBnd 0000000000000000   （Android App 常见为 0，部分机型给 0000000000000000）
  CapAmb 0000000000000000
TracerPid 0
```
> 保守做法：一律写 0。若某机型原生 Bnd 非 0，可后续按机型采样后配置。

### B. 在内核里改 seq_file 的输出源（不推荐）

```
改 proc_pid_status() 的数据源 —— 需要拿到 symbols 并 patch 函数体，
风险远高于改写 read buffer，收益相同。
```

## 3. 与现有代码的关系

```
· 复用判定点④（vfs_read）的钩子，不新增 kprobe
· 复用 hide/可见性闸门（只对未授权 uid 生效）
· 与 UM 规则表解耦：这是硬编码的安全能力，不走规则（避免误配把自己锁死）
· diag 增加两行：cap_capeff / cap_tracerpid 的 OK/DISABLED 状态
```

## 4. 落地顺序

```
第 1 步  TracerPid 归零（最简单：单行、值定长、总是 0）
第 2 步  CapEff / CapPrm / CapBnd / CapInh / CapAmb 五行置零（定长十六进制）
第 3 步  按机型配置 Bnd 值（可选）
```

## 5. 已验证的前提

```
/proc/<pid>/status 的 file_operations 没有 .mmap   → read 过滤是完整覆盖
vfs_read 钩子已在用（判定点④），复用不增加新风险
```
