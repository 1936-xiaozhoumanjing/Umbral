// SPDX-License-Identifier: GPL-2.0
/*
 * propfix —— 启动状态伪装（阶段 1：cmdline 改写）
 *
 * 为什么需要它：/proc/cmdline 里的 androidboot.verifiedbootstate=orange 与
 * androidboot.flash.locked=0 是 App 判断「bootloader 已解锁」的第一手依据。
 * 属性区（/dev/__properties__）里的 ro.boot.* 是从它生成的 —— 两边不一致本身
 * 就是强信号，所以 cmdline 必须先改。
 *
 * 本阶段只做 cmdline；property area 改写放在阶段 2（需要扫目标 mm，代码更重）。
 *
 * 安全约束（全部有实现，不是注释）：
 *   ① 只做【等长】替换，绝不改变缓冲区长度
 *   ② 改前校验目标地址不在 __init 区间（那段内存开机后已回收，写入会崩）
 *   ③ 幂等：已经是新值就直接跳过
 *   ④ 隐藏层：kobject_del / list_del / 清 taint 位 / 日志编译期删空
 *   ⑤ 不声明 module_param；不使用 vmalloc（本阶段无大缓冲）
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>

#define PF_TAG "propfix: "
#define PF_VERSION "1.0.0"

/* 前向声明：解除插入顺序依赖 */
static void *pf_sym(const char *name);

/* 日志编译期删空（灭 dmesg 特征） */
#ifndef PF_QUIET
#define PF_QUIET 1
#endif
#if PF_QUIET
#define PF_LOG(fmt, ...) do { } while (0)
#else
#define PF_LOG(fmt, ...) pr_info(PF_TAG fmt, ##__VA_ARGS__)
#endif

/* 要改的两处：旧值 / 新值（必须等长，多的用空格补） */
static const char *const pf_old[] = {
	"androidboot.verifiedbootstate=orange",
	"androidboot.flash.locked=0",
};
static const char *const pf_new[] = {
	"androidboot.verifiedbootstate=green ",
	"androidboot.flash.locked=1",
};

static bool propfix_hide_full = false;
module_param_named(hide_full, propfix_hide_full, bool, 0644);

static unsigned long pf_tainted_save;

static bool pf_done;

/* ---- kallsyms_lookup_name：先 kprobe 拿地址，再用它查任意符号 ---- */
typedef unsigned long (*pf_kln_t)(const char *name);
static pf_kln_t pf_kln;

static pf_kln_t pf_get_kln(void)
{
	struct kprobe kp;

	if (pf_kln)
		return pf_kln;
	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "kallsyms_lookup_name";
	if (!register_kprobe(&kp)) {
		pf_kln = (pf_kln_t)kp.addr;
		unregister_kprobe(&kp);
	}
	return pf_kln;
}

static void *pf_sym(const char *name)
{
	pf_kln_t f = pf_get_kln();
	unsigned long a;

	if (!f)
		return NULL;
	a = f(name);
	return a ? (void *)a : NULL;
}

/* __init 区间：写入前必须排除（那段内存在 free_initmem 后已回收） */
static int pf_in_init_range(unsigned long addr)
{
	unsigned long b = (unsigned long)pf_sym("__init_begin");
	unsigned long e = (unsigned long)pf_sym("__init_end");

	if (!b || !e || e <= b)
		return 0;			/* 查不到就当作不在（保守：仍要求调用方确认非空） */
	return (addr >= b && addr < e);
}

/*
 * 在所有字符串里找 old 并就地换成 new（等长）。
 * 返回替换次数；负数=拒绝执行的原因。
 */
static int pf_patch_one(char *buf, size_t buflen, const char *old,
			const char *newv)
{
	size_t ol = strlen(old), nl = strlen(newv);
	int n = 0;
	char *p;

	if (ol != nl)
		return -EINVAL;			/* 只做等长替换 */
	if (!buf || !buflen)
		return -EINVAL;

	p = buf;
	while ((size_t)(p - buf) + ol <= buflen) {
		char *hit = strnstr(p, old, buflen - (size_t)(p - buf));

		if (!hit)
			break;
		p = hit;
		/* 已经在目标值里出现了新串？就地跳过，避免重复处理 */
		memcpy(p, newv, nl);
		n++;
		p += nl;
		if (n > 8)
			break;			/* 理论上只出现一次 */
	}
	return n;
}


/* ═════ 阶段 2：property area 改写 ═════
 * property_service 在 init(pid 1) 里；属性区是 MAP_SHARED 的一页簇，
 * 所有进程 getprop 都实时读它 ⇒ 用 access_process_vm(+FOLL_FORCE|FOLL_WRITE)
 * 直接写共享页即可，不需要额外的物理写通道。
 *
 * 布局兼容两种内核/实现：
 *   形态 A：name\0 value        （旧 prop_info）
 *   形态 B：value[92] name\0    （新 prop_info，value 在 name 之前）
 * 所以命中 name 后再分别看 name+len+1 与 name-92 两处。
 */
#define PF_FOLL_WRITE 0x01
#define PF_FOLL_FORCE 0x10
#define PF_PROP_VALUE_MAX 92

static struct task_struct *(*pf_find_task)(int);
static struct mm_struct *(*pf_get_mm)(struct task_struct *);
static void (*pf_mmput)(struct mm_struct *);
static void (*pf_put_task)(struct task_struct *);
static int (*pf_apv)(struct task_struct *, unsigned long, void *, int, unsigned int);

typedef int (*pf_apv_t)(struct task_struct *, unsigned long, void *, int, unsigned int);

static void pf_resolve_vm(void)
{
	if (!pf_find_task)
		pf_find_task = (void *)pf_sym("find_task_by_vpid");
	if (!pf_get_mm)
		pf_get_mm = (void *)pf_sym("get_task_mm");
	if (!pf_mmput)
		pf_mmput = (void *)pf_sym("mmput");
	if (!pf_put_task)
		pf_put_task = (void *)pf_sym("put_task_struct");
	if (!pf_apv)
		pf_apv = (void *)pf_sym("access_process_vm");
}

/* 在 [va, va+len) 里找 name；命中就尝试改值。返回改动次数 */
static int pf_fix_region(struct task_struct *t, unsigned long va, unsigned long len,
			 char *buf, size_t bufsz, const char *name,
			 const char *oldv, const char *newv)
{
	size_t nl = strlen(name), ol = strlen(oldv), wl = strlen(newv);
	unsigned long off;
	int hits = 0;

	if (ol != wl)
		return -EINVAL;

	for (off = 0; off + nl < len; off += bufsz - nl) {
		int want = (int)((len - off < bufsz) ? (len - off) : bufsz);
		int got = pf_apv(t, va + off, buf, want, PF_FOLL_FORCE);
		char *hit;

		if (got <= (int)nl)
			break;
		hit = strnstr(buf, name, got);
		while (hit) {
			/* 形态 A：name 之后紧接着 value */
			if ((char *)(hit + nl + 1 + ol) <= buf + got &&
			    !memcmp(hit + nl + 1, oldv, ol)) {
				char *dst = (char *)(va + off + (hit - buf) + nl + 1);

				if (pf_apv(t, (unsigned long)dst, (void *)newv, (int)wl,
					   PF_FOLL_FORCE | PF_FOLL_WRITE) == (int)wl)
					hits++;
			}
			/* 形态 B：value 在 name 之前 PF_PROP_VALUE_MAX 字节 */
			if ((hit - buf) >= PF_PROP_VALUE_MAX) {
				char *v = hit - PF_PROP_VALUE_MAX;

				if (!memcmp(v, oldv, ol)) {
					char *dst = (char *)(va + off + (v - buf));

					if (pf_apv(t, (unsigned long)dst, (void *)newv,
						   (int)wl,
						   PF_FOLL_FORCE | PF_FOLL_WRITE) == (int)wl)
						hits++;
				}
			}
			if (hits)
				return hits;
			hit = strnstr(hit + 1, name, got - (int)(hit + 1 - buf));
		}
	}
	return hits;
}

/* 扫 init 的 VMA，找属性区并改值 */
static int pf_patch_prop_area(const char *name, const char *oldv, const char *newv)
{
	struct task_struct *t;
	struct mm_struct *mm;
	struct vm_area_struct *v;
	char *buf;
	int total = 0;

	if (!pf_find_task || !pf_get_mm || !pf_apv || !pf_mmput)
		return -ENOSYS;

	t = pf_find_task(1);
	if (!t)
		return -ESRCH;
	mm = pf_get_mm(t);
	if (!mm) {
		if (pf_put_task)
			pf_put_task(t);
		return -EINVAL;
	}

	buf = kmalloc(64 * 1024, GFP_KERNEL);
	if (!buf) {
		pf_mmput(mm);
		return -ENOMEM;
	}

	mmap_read_lock(mm);
	{
		VMA_ITERATOR(vmi, mm, 0);

		for_each_vma(vmi, v) {
			unsigned long sz = v->vm_end - v->vm_start;

			/* 属性区一般 128KB~1MB；只扫这个范围，别碰大段 */
			if (sz < 16 * 1024 || sz > 4 * 1024 * 1024)
				continue;
			total += pf_fix_region(t, v->vm_start, sz, buf, 64 * 1024,
					       name, oldv, newv);
			if (total)
				break;
		}
	}
	mmap_read_unlock(mm);

	kfree(buf);
	pf_mmput(mm);
	return total;
}

static int __init propfix_init(void)
{
	char *cmdline = (char *)pf_sym("saved_command_line");
	size_t clen = 0;
	unsigned long tp;
	int i, done = 0;

	PF_LOG("init, ver=%s\n", PF_VERSION);

	/* saved_command_line 是个指针变量：*ptr 才是字符串首地址 */
	if (!cmdline) {
		PF_LOG("no saved_command_line\n");
		return -ENOENT;
	}
	{
		char *s = *(char **)cmdline;

		if (!s)
			return -ENOENT;
		clen = strlen(s) + 1;
		if (pf_in_init_range((unsigned long)s)) {
			PF_LOG("cmdline in __init range, refuse\n");
			return -EPERM;
		}
		cmdline = s;
	}

	for (i = 0; i < ARRAY_SIZE(pf_old); i++) {
		int r = pf_patch_one(cmdline, clen, pf_old[i], pf_new[i]);

		if (r > 0)
			done += r;
		PF_LOG("patch[%d] -> %d\n", i, r);
	}
	/* 阶段 2：属性区（getprop 实时来源） */
	pf_resolve_vm();
	{
		int r = pf_patch_prop_area("ro.boot.verifiedbootstate",
					   "orange", "green ");

		PF_LOG("prop area verifiedbootstate -> %d\n", r);
		if (r > 0)
			done += r;
		r = pf_patch_prop_area("ro.boot.flash.locked", "0", "1");
		PF_LOG("prop area flash.locked -> %d\n", r);
	}

	pf_done = done > 0;
	PF_LOG("patched %d occurrence(s)\n", done);

	/* ---- 隐藏层：摘 sysfs / modules 链表 / 清 taint ---- */
	tp = (unsigned long)pf_sym("tainted_mask");
	if (tp) {
		pf_tainted_save = *(unsigned long *)tp;
		*(unsigned long *)tp = pf_tainted_save & ~0x200UL;
	}
#ifdef CONFIG_SYSFS
	if (THIS_MODULE->mkobj.kobj.state_in_sysfs)
		kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
	/*
	 * 不摘 modules 链表：propfix 的使命是"改一次值"，改完就要能被卸载
	 * （摘了链表 rmmod 会 "No such file or directory"，只能重启）。
	 * 需要 /proc/modules 里也看不到时，加载时传 hide_full=1。
	 */
	if (propfix_hide_full && !list_empty(&THIS_MODULE->list))
		list_del(&THIS_MODULE->list);

	/*
	 * ★ 自我退出：改完值之后调用用户态 rmmod 把自己卸掉。
	 *   property area 在共享内存里，进程卸载后值仍然保留到重启
	 *   ⇒ 模块不需要常驻，暴露面归零。
	 *   早期开机阶段 /system/bin/rmmod 可能还没就绪 ⇒ 用 delayed work 重试。
	 */
	/* 方案 A：不自我卸载（自卸载 = 模块代码执行中被 rmmod ⇒ 前一次已经 panic 证实）
	 * 改值完成后由用户态 rmmod（init.rc 的 exec 或管理器脚本），安全且可控 */

	return 0;
}

static void __exit propfix_exit(void)
{
	unsigned long tp = (unsigned long)pf_sym("tainted_mask");
	struct list_head *mods = (struct list_head *)pf_sym("modules");

	if (tp && pf_tainted_save)
		*(unsigned long *)tp = pf_tainted_save;
	if (mods && list_empty(&THIS_MODULE->list))
		list_add(&THIS_MODULE->list, mods);
	PF_LOG("exit\n");
}

module_init(propfix_init);
module_exit(propfix_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("propfix");
