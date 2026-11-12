# SK-Root 内核模块
#
# 编译：
#   make -C /root/gki-src/kernel M=/mnt/e/sk-root/src/sk ARCH=arm64 LLVM=1 modules
#
# 重要：必须用 ACK 源码 + Clang，不能用 upstream kernel.org + GCC。
#   用错源码  → .this_module 段大小对不上（1280 vs 1536）→ 拒绝加载
#   用错编译器 → 没有 kCFI type hash → CFI failure → panic

obj-m := umbral.o

KDIR    ?= /root/gki-src/kernel
PWD     := $(shell pwd)
ARCH    ?= arm64

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) LLVM=1 modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) LLVM=1 clean

info:
	@echo "KDIR          : $(KDIR)"
	@echo "target vermagic: 6.6.30-android15-8-g54dcbfbef792-ab12368803-4k SMP preempt mod_unload modversions aarch64"

.PHONY: all clean info
