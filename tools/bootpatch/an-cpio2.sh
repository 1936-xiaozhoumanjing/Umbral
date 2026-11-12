#!/bin/bash
D=$(ls -d /root/ab/android_bootimg-* | head -1)

echo "════════ cpio.rs 85-165 行（TRAILER + dump）════════"
sed -n '85,165p' "$D/android-bootimg/src/cpio.rs" | sed 's/^/  /'

echo ""
echo "════════ is_magisk_patched（第 227-245 行）════════"
sed -n '227,250p' "$D/android-bootimg/src/cpio.rs" | sed 's/^/  /'

echo ""
echo "════════ char() 造设备节点（第 323-340 行）════════"
sed -n '323,345p' "$D/android-bootimg/src/cpio.rs" | sed 's/^/  /'