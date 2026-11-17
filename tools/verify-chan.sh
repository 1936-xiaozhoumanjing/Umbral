#!/system/bin/sh
# 劫持通道自检（umbral 1.65.0-chan 及以后）
#
# 用法：sh verify-chan.sh
#
# 判定：
#   · 逐个候选写 0xEF 0xBE + "ver"，能读回含 "." 的内容 ⇒ 通道命中
#   · 同时报告 /proc/umbral 是否存在（SK_NO_PROCDIR=0 时应存在，=1 时应不存在）

MAGIC=$(printf '\357\276')
HIT=""
VER=""

scan_dir() {
  for f in $1/*; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in
      stat|meminfo|cpuinfo|vmstat|loadavg|uptime|version|modules|filesystems|\
      ns_last_pid|tainted|randomize_va_space|core_pattern|modprobe|hostname|\
      domainname|osrelease|ostype|panic*|printk*|sched_*|watchdog*|hung_task*|\
      perf_*|drop_caches|swappiness|overcommit*|max_map_count|min_free_kbytes|\
      dirty_*|vfs_cache_pressure|mmap_*)
        continue ;;
    esac
    printf '%sver' "$MAGIC" > "$f" 2>/dev/null || continue
    out=$(cat "$f" 2>/dev/null)
    case "$out" in
      *.*)
        HIT="$f"
        VER="$out"
        return 0 ;;
    esac
  done
  return 1
}

echo "== 1. 探测劫持通道 =="
scan_dir /proc/sys/vm || scan_dir /proc/sys/kernel

if [ -n "$HIT" ]; then
  echo "   ✅ 通道命中：$HIT"
  echo "   读回内容：$VER"
else
  echo "   ❌ 没有命中任何通道（模块可能不是 1.65.0-chan，或通道安装失败）"
fi

echo
echo "== 2. /proc/umbral 可见性 =="
if [ -e /proc/umbral/version ]; then
  echo "   存在：$(cat /proc/umbral/version 2>/dev/null)   （SK_NO_PROCDIR=0 的正常状态）"
else
  echo "   不存在：已切到 SK_NO_PROCDIR=1（彻底隐藏）"
fi
echo "   ls /proc | grep -c umbral = $(ls /proc 2>/dev/null | grep -c '^umbral$')"

echo
echo "== 3. 模块自身可见性 =="
echo "   lsmod 里 umbral = $(lsmod 2>/dev/null | grep -c '^umbral')"
echo "   /sys/module 里 umbral = $(ls /sys/module 2>/dev/null | grep -c '^umbral')"
echo "   /proc/modules 里 umbral = $(grep -c '^umbral' /proc/modules 2>/dev/null)"
echo "   tainted = $(cat /proc/sys/kernel/tainted 2>/dev/null)"

echo
echo "== 4. 结论 =="
if [ -n "$HIT" ] && [ ! -e /proc/umbral/version ]; then
  echo "   ✅ 彻底隐藏已达成（只有通道，没有任何 proc 目录）"
elif [ -n "$HIT" ]; then
  echo "   🟡 通道可用，但 /proc/umbral 仍在（可把 SK_NO_PROCDIR 置 1）"
else
  echo "   ⬜ 通道未就绪，先确认设备加载的是 1.65.0-chan"
fi
