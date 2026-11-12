#!/bin/bash
D=$(ls -d /root/ab/android_bootimg-* | head -1)

echo "════════ patcher.rs 尾部（第 200-320 行）════════"
sed -n '200,320p' "$D/android-bootimg/src/patcher.rs" | sed 's/^/  /'