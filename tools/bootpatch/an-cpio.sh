#!/bin/bash
D=$(ls -d /root/ab/android_bootimg-* | head -1)

echo "════════ android_bootimg/src/cpio.rs 结构 ════════"
grep -nE "^(pub )?(struct|enum|fn|impl|const|static)|^    pub fn|^    fn" "$D/android-bootimg/src/cpio.rs" | head -40 | sed 's/^/  /'

echo ""
echo "════════ cpio 关键常量/魔数 ════════"
grep -nE "070701|070702|MAGIC|TRAILER|newc|crc" "$D/android-bootimg/src/cpio.rs" | head -20 | sed 's/^/  /'

echo ""
echo "════════ cpio 头字段处理 ════════"
sed -n '1,80p' "$D/android-bootimg/src/cpio.rs" | sed 's/^/  /'