#!/bin/bash
D=$(ls -d /root/ab/android_bootimg-* | head -1)

echo "════════ patcher.rs 的 patch() 完整实现（第 83-200 行）════════"
sed -n '83,200p' "$D/android-bootimg/src/patcher.rs" | sed 's/^/  /'