# systemless 挂载 · 设计（影核）

> 目标：让 UM 模块能"替换" `/system` `/vendor` `/product` 里的文件，但不写只读分区，
> 且**只对授权进程可见** —— 未授权进程看到的仍是原厂视图。

---

## 1. 为什么不能简单 bind mount

```
如果对所有进程都挂一层 overlay：
   任何 App 只要 stat("/system/app/Foo/Foo.apk") 发现 size/mtime 与原厂不符
   → 一眼看出系统被改过 → 反检测直接破功
所以必须按进程隔离挂载视图。
```

## 2. 分层设计

```
用户空间（管理器 / umbrald）
  · 解析 UM 模块的 system/ vendor/ product/ 目录树
  · 组装 upperdir（模块目录）与 workdir（/data/adb/umbral/work/）
  · 通过 /proc/umbral/mnt 把「挂载计划」交给内核

内核（umbral.ko）
  · 维护一张挂载计划表：{ target_dev, target_ino, overlay_lower, overlay_upper, overlay_work }
  · 在进程「第一次将要访问被替换路径」时，为它建立私有 mount namespace
  · 在私有 ns 里对目标挂载点做 overlay 叠加
  · 未授权进程永不触发 → 视图保持原厂
```

## 3. 内核里具体要做什么

| 步骤 | 内核接口 | 说明 |
|---|---|---|
| ① 建私有 ns | `copy_mnt_ns(CLONE_NEWNS, ...)` 或 `unshare_nsproxy_namespaces` | 只对目标 mm 做，不影响别的进程 |
| ② 叠加 | `vfs_clone_file_range`/`do_mount` 走 overlayfs，或自己构造 `struct vfsmount` | 首选：调用 `do_mount("overlay", ...)` 在目标 ns 里挂 |
| ③ 判定时机 | 钩 `do_filp_open` / `path_openat`，检查路径是否命中挂载计划 | 首次命中才建 ns，后续复用 |
| ④ 撤销 | 进程退出时 ns 自动释放；`/proc/umbral/mnt clear` 清计划 | 避免泄漏 |

**关键技术选择：不自研 overlay，直接复用内核 overlayfs** —— 自己写一套 VFS 层叠加是几个月的工程且极易崩。

## 4. 与现有能力的耦合

```
· 与判定点①（打开文件）：同一处钩子，先判挂载计划，再判 UM 规则
· 与 hide：挂载计划表本身不能出现在 /proc/umbral 之外的地方；
            未授权进程连 /proc/umbral/mnt 都打不开（已有 getattr 拦截）
· 与 kCFI：do_mount / copy_mnt_ns 都是间接调用，走 kallsyms 解析；
            原型必须与内核头一致，否则强制 CFI 下直接 panic
```

## 5. 最小可用骨架（分三步落地，每步可独立验证）

```
第 1 步（只读，不改任何东西）
  /proc/umbral/mnt 节点：接受 "plan <target> <upper> <work>"
  内核只做校验与存表，/proc/umbral/diag 里显示 "mnt_plans=N"
  → 可验证：计划能存、能读、进程退出不残留

第 2 步（对单个指定 pid 生效）
  "apply <pid>" → 给该进程 copy_mnt_ns + overlay 叠加指定的一个目标
  → 可验证：cat /proc/<pid>/mounts 能看到 overlay；别的进程看不到

第 3 步（自动）
  在 do_filp_open 钩子里命中计划就自动建 ns
  → 可验证：模块目录里的文件真的替代了 /system 下的同名文件
```

## 6. 风险与对策

| 风险 | 对策 |
|---|---|
| 给错误进程建 ns → 系统服务异常 | 只对「已授权 uid」生效；白名单外一律不动 |
| overlay 挂载失败 → 进程看到半成品 | 失败即放弃该进程的 ns，退回原厂视图并打日志 |
| mount namespace 泄漏 | 进程退出时内核自动回收；表项用 mm 作 key，mm 释放即清理 |
| CFI 下间接调用 panic | 所有解析出来的内核函数原型必须与头文件逐一核对（已在 kCFI 核查里确认 7 个，本节新增 do_mount/copy_mnt_ns 需再核） |
| 与厂商 SELinux 策略冲突 | 挂载操作在 uid 0 上下文执行；失败只影响该进程，不全局 |

## 7. 现状

```
未实现。当前代码里没有任何 mount 相关逻辑。
本文件是设计稿，供下阶段按「第 1 步 → 第 2 步 → 第 3 步」逐步落地。
```
