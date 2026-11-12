// SPDX-License-Identifier: GPL-2.0
/*
 * Umbral（影核）内核模块 —— 第 5 步：打通 SELinux
 *
 * ══════════════════════════════════════════════════════════════════
 *  为什么需要这一步
 * ══════════════════════════════════════════════════════════════════
 *
 *  override_creds() 只改 DAC（uid/gid/capabilities）。Android 的权限
 *  是 DAC + MAC 双重，SELinux 那半边仍然按进程的安全域去判，所以
 *  uid 变成 0 之后读 /data/system 下的文件依然 EACCES。
 *
 *  两种解法：
 *    a) 换安全域（要操作 cred->security 的 LSM blob，跨版本风险高）
 *    b) 在提权窗口内让 SELinux 的检查直接放行
 *
 *  这里用 (b)：挂 kretprobe 到 SELinux 的两个检查函数上，
 *  只要「当前进程正处在提权窗口内」，就把返回值改成 0（放行）。
 *
 * ══════════════════════════════════════════════════════════════════
 *  怎么判断「在窗口内」
 * ══════════════════════════════════════════════════════════════════
 *
 *  不需要额外状态。override_creds(sk_root_cred) 之后
 *  current->cred 就是 sk_root_cred 本身（get_new_cred 只加引用计数），
 *  所以 current->cred == sk_root_cred 就是最精确的窗口判据。
 *
 *  窗口外 current->cred 指向各自的 cred，检查函数原样返回，
 *  SELinux 行为完全不受影响 —— getenforce 始终 Enforcing。
 *
 * ══════════════════════════════════════════════════════════════════
 *  挂了哪两个
 * ══════════════════════════════════════════════════════════════════
 *
 *  selinux_inode_permission(inode, mask)  ← open()/access() 走这条
 *  selinux_file_permission(file, mask)    ← read()/write() 走这条
 *
 *  两个都在 LSM_HOOK_INIT 里注册过（hooks.c:7053 / 7074）。
 */

#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/uidgid.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/magic.h>
#include <linux/namei.h>
#include <linux/umh.h>
#include <linux/ptrace.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/kobject.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/workqueue.h>


/*
 * fork 继承开关。
 *
 * 关掉它是因为要对「崩溃」做二分：新加的东西里风险最高的是
 * kprobe 到调度器的 wake_up_new_task 并从寄存器取参数 ——
 * 取错就是野指针，直接 panic，而且 pstore 这次没留下现场。
 *
 * 先关掉验证稳定性，确认不是它再逐步恢复。
 */
#ifndef SK_ENABLE_FORK_HOOK
#define SK_ENABLE_FORK_HOOK 1
#endif

/*
 * 提权模式
 *   0 = 隐身：uid/gid 保持原值，只拉满 caps（目标模式）
 *   1 = uid0：uid/gid 也升到 0（0.12.0 的行为，已验证可用）
 *
 * 默认取 0 —— 这是我们真正想要的效果。
 * 如果 DAC 层意外没放行，一行改回 1 就能退回已验证的可用状态。
 */
#ifndef SK_PROMOTE_UID
#define SK_PROMOTE_UID 0
#endif

#define SK_VERSION   "1.41.0-mntplan"

/*
 * ★ 管理器包名只在这里出现一次 ★
 *
 * 换壳/改名（比如做定制版、或某台设备的包名不同）只改这一行，
 * 不用在五个地方各改一遍 —— 之前散在 5 处，漏改一处就表现为
 * 「模块加载了但管理器拿不到权限」，而且完全没有报错。
 *
 * 长度必须和字符串一致（comm 比较、cmdline 扫描都用它）。
 */
/*
 * su 壳脚本路径 —— 放在 /data/adb/umbral 这一层（该目录一定存在，
 * manager.uid 就在里面），避免依赖 bin/ 这种可能不存在的子目录。
 */
/*
 * ★ 为什么放在 /data/local/tmp/umbral ★
 *
 * /data/adb/umbral 是内核在启动时创建的，属主 root，
 * 而我们的 DAC 规则「属主 <= 1000 的文件保持只读」会把 App 自己挡在外面，
 * 于是 App 没法往那儿写 su 二进制（实测：一直写不进去，只能留旧脚本）。
 *
 * /data/local/tmp 属主 shell(2000)，App 有影子权限就能写，
 * 而且这个目录本来就可读可执行 —— su 二进制放这儿，
 * 磁盘上就是真正的 ELF（不再是脚本）。
 */
#define SK_SU_PATH "/data/local/tmp/umbral/su"

/* 内核直接写文件（定义在文件后部，这里先声明） */
static long sk_kwrite(const char *path, const void *data, size_t len, umode_t mode);
static long sk_kcopy(const char *src, const char *dst);
static long sk_io_do_read(const char *path, char **out);
static struct cred *sk_init_cred;

#define SK_MGR_PKG      "io.umbral"
#define SK_MGR_PKG_LEN  9
#define SK_MGR_PKG_SLASH "io.umbral "	/* packages.list 里带结尾空格 */

static atomic64_t sk_promote_ml_skip;
static atomic64_t sk_acc_blocked;
static atomic64_t sk_su_redirect;

struct sk_acc_data {
	int mode;
	u32 uid;
	const char __user *path;
};
#define SK_MODE      "lkm-shadow+selinux+promote"
/*
 * kernel_cap_t 取值方式随版本变：
 *   <= 6.2  struct { __u32 cap[2]; }   → cap[0] | cap[1]
 *   >= 6.3  struct { u64 val; }        → .val
 * 之前直接写 .val，6.1 树直接编不过（no member named 'val'）。
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define SK_CAP64(c)        ((unsigned long long)((c).val))
#define SK_CAP_IS_FULL(c)  ((c).val == ~0ULL)
#else
#define SK_CAP64(c)        (((unsigned long long)((c).cap[0])) | \
			    (((unsigned long long)((c).cap[1])) << 32))
#define SK_CAP_IS_FULL(c)  ((c).cap[0] == ~0U && (c).cap[1] == ~0U)
#endif

/* UMBRAL_SYSNR_GUARD: 老内核没有这些 syscall 号，编不过就退化成不需要它们 */
#ifndef __NR_openat2
#define __NR_openat2 -1
#endif
#ifndef __NR_faccessat2
#define __NR_faccessat2 -1
#endif
#ifndef __NR_mount_setattr
#define __NR_mount_setattr -1
#endif

#define SK_TAG       "umbral: "
#define SK_TOKEN_LEN 32
#define SK_TOKEN_ADDR 0x1000000000ULL

/* ── 占各段 ── */
static unsigned long sk_probe_bss[64];
static int sk_probe_counter;
static const char *sk_probe_msg = "umbral-selinux";
static unsigned int sk_probe_val = 0x5a17;
static const char sk_probe_rodata[] = "Umbral selinux bridge";

static int sk_param_int = 42;
module_param(sk_param_int, int, 0444);
MODULE_PARM_DESC(sk_param_int, "probe integer parameter");

static noinline unsigned long sk_probe_helper(unsigned long seed)
{
	unsigned long acc = seed;
	int i;

	for (i = 0; i < 8; i++) {
		acc = acc * 6364136223846793005ULL + 1442695040888963407ULL;
		sk_probe_bss[i] = acc;
	}
	sk_probe_counter++;
	return acc;
}

/* ══════════════════ 跨版本兼容 ══════════════════ */

/*
 * 一份源码要能在 5.4 / 5.10 / 5.15 / 6.1 / 6.6 上编译。
 * 各内核之间的差异集中在这里。
 *
 * ① proc_ops  ← 5.6 引入；5.4/5.5 还是 file_operations
 *    两边的字段名不同：
 *        proc_ops        .proc_open / .proc_read / .proc_lseek / .proc_release / .proc_write
 *        file_operations .open      / .read      / .llseek      / .release      / .write
 *    而且 seq_read 的签名在两代里分别匹配各自的 read 指针，不用额外适配。
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define SK_PROC_OPS      struct proc_ops
#define SK_RO_OPS        .proc_open = _name##_open,  \
                         .proc_read = seq_read,      \
                         .proc_lseek = seq_lseek,    \
                         .proc_release = single_release
#define SK_WO_OPS        .proc_open = _name##_open,  \
                         .proc_write = _name##_write
#else
#define SK_PROC_OPS      struct file_operations
#define SK_RO_OPS        .open = _name##_open,       \
                         .read = seq_read,           \
                         .llseek = seq_lseek,        \
                         .release = single_release
#define SK_WO_OPS        .open = _name##_open,       \
                         .write = _name##_write
#endif

/* ══════════════════ BTF 自适应 ══════════════════ */

/*
 * BTF 文件头（include/uapi/linux/btf.h）
 */
struct sk_btf_header {
	__u16 magic;	/* 0xEB9F */
	__u8  version;
	__u8  flags;
	__u32 hdr_len;
	__u32 type_off;
	__u32 type_len;
	__u32 str_off;
	__u32 str_len;
};

struct sk_btf_type {
	__u32 name_off;
	__u32 info;	/* kind<<24 | kind_flag<<31 | vlen */
	__u32 size_or_type;
};

struct sk_btf_member {
	__u32 name_off;
	__u32 type;
	__u32 offset;	/* 位偏移（kind_flag 时含位域信息） */
};

#define SK_BTF_KIND_STRUCT 4
#define SK_BTF_MAGIC       0xEB9F

/* 运行时用的偏移。默认取编译期的，BTF 解析成功且不一致时更新。 */
/* struct kstat 的成员偏移（从 BTF 读，跨内核版本自动正确）；-1 = 未知 */
/*
 * struct kstat 成员偏移。
 *
 * 默认值来自**在电脑上解析本机 /sys/kernel/btf/vmlinux** 的结果
 * （解析器走完 3521764 字节完全对齐，且 struct module 的 list=8/mkobj=104
 *  与内核实测值一致，证明解析正确）。
 *
 * ⚠ 我最初猜的是 size=96，实际是 56 —— 猜错就是往栈上乱写，
 *   这正是崩了两次设备的原因。以后一律先解析再写死。
 *
 * 运行时若能成功解析 BTF，会用 BTF 的值覆盖（跨内核版本自适应）。
 */
static int sk_off_kstat_size  = 56;
static int sk_off_kstat_mode  = 4;
static int sk_off_kstat_nlink = 8;
static int sk_off_kstat_uid   = 48;
static int sk_off_kstat_gid   = 52;
static int sk_off_kstat_ino   = 32;
static int sk_off_kstat_stop;   /* 1 = 偏移不可信，禁用伪造 */
static int sk_btf_kstat_seen;   /* 见过几次名为 kstat 的 struct */
static unsigned int sk_kstat_mask;	/* 六个字段各一位，全 0x3f 才算可信 */
static int sk_tmp_size, sk_tmp_mode, sk_tmp_nlink, sk_tmp_uid, sk_tmp_gid, sk_tmp_ino;

static unsigned long sk_off_module_list   = offsetof(struct module, list);
static unsigned long sk_off_module_mkobj  = offsetof(struct module, mkobj);
static atomic_t sk_btf_ok = ATOMIC_INIT(0);

/* 在 BTF 的字符串区里取名字 */
static const char *sk_btf_str(const char *strs, __u32 off, __u32 len)
{
	if (off >= len)
		return "";
	return strs + off;
}

static int sk_btf_parse(const void *buf, unsigned long sz)
{
	const struct sk_btf_header *h = buf;
	const char *base = buf;
	const char *types;
	const char *strs;
	unsigned long pos;
	__u32 type_len;
	__u32 str_len;
	unsigned int kcnt[20];

	if (sz < sizeof(*h) || h->magic != SK_BTF_MAGIC) {
		pr_warn(SK_TAG "BTF 头无效\n");
		return -EINVAL;
	}

	types = base + h->hdr_len + h->type_off;
	strs  = base + h->hdr_len + h->str_off;
	type_len = h->type_len;
	str_len  = h->str_len;

	pos = 0;
	memset(kcnt, 0, sizeof(kcnt));
	while (pos + sizeof(struct sk_btf_type) <= type_len) {
		const struct sk_btf_type *t = (const void *)(types + pos);
		__u32 kind = (t->info >> 24) & 0x1f;
		__u32 vlen = t->info & 0xffff;
		__u32 msz  = sizeof(struct sk_btf_member);
		unsigned int i;

		pos += sizeof(*t);

		if (kind < 20)
			kcnt[kind]++;

		if (kind != SK_BTF_KIND_STRUCT) {
			/* 其它 kind 的长度不一，这里只跳 —— 但要保证不错位 */
			switch (kind) {
			case 1:  /* INT */   pos += 4; break;
			case 2:  /* PTR */   break;
			case 5:  /* UNION */ pos += vlen * msz; break;
			case 3:  /* ARRAY */ pos += 12; break;
			case 6:  /* ENUM */  pos += vlen * 8; break;
			case 13: /* FUNC_PROTO */ pos += vlen * 8; break;
			case 14: /* VAR */   pos += 4; break;
			case 15: /* DATASEC */ pos += vlen * 12; break;
			case 16: /* FLOAT */ break;
			case 17: /* DECL_TAG */ pos += 4; break;
			case 18: /* TYPE_TAG */ break;
			case 19: /* ENUM64 */ pos += vlen * 12; break;
			default: break;
			}
			continue;
		}

		/* 是 struct：把成员读出来 */
		{
			const char *tname = sk_btf_str(strs, t->name_off, str_len);

			for (i = 0; i < vlen; i++) {
				const struct sk_btf_member *m =
					(const void *)(types + pos + i * msz);
				const char *mname = sk_btf_str(strs, m->name_off, str_len);

				if (!strcmp(tname, "module")) {
					if (!strcmp(mname, "list"))
						sk_off_module_list = (m->offset & 0xffffff) / 8;
					else if (!strcmp(mname, "mkobj"))
						sk_off_module_mkobj = (m->offset & 0xffffff) / 8;
					continue;
				}
				/*
				 * kstat 偏移暂时**不**用 BTF 覆盖。
				 *
				 * 原因：内核侧的 BTF 遍历目前还差 4 字节没对齐，
				 * 取到的偏移不可信；而默认值是电脑端解析出来的、
				 * 已验证正确的。宁可固定，也不要写入垃圾偏移把栈写坏。
				 *
				 * 等内核侧遍历修好（需要逐个 kind 核对长度）再打开覆盖。
				 */
				if (!strcmp(tname, "kstat")) {
					/*
					 * 逐字段捕获。全部字段都拿到才算可信
					 * —— 少一个就整份不用，避免半对半错。
					 */
					int off = (m->offset & 0xffffff) / 8;

					sk_btf_kstat_seen++;
					if (!strcmp(mname, "size"))  { sk_tmp_size  = off; sk_kstat_mask |= 1; }
					else if (!strcmp(mname, "mode"))  { sk_tmp_mode  = off; sk_kstat_mask |= 2; }
					else if (!strcmp(mname, "nlink")) { sk_tmp_nlink = off; sk_kstat_mask |= 4; }
					else if (!strcmp(mname, "uid"))   { sk_tmp_uid   = off; sk_kstat_mask |= 8; }
					else if (!strcmp(mname, "gid"))   { sk_tmp_gid   = off; sk_kstat_mask |= 16; }
					else if (!strcmp(mname, "ino"))   { sk_tmp_ino   = off; sk_kstat_mask |= 32; }
				}
			}
		}
		pos += vlen * msz;
	}

	/*
	 * 完整性自检：走完所有类型后 pos 必须正好等于 type_len。
	 * 不等说明「跳过其它 kind」的长度表有错，后续类型全部错位，
	 * 那样取到的偏移一律不可信 —— 这种情况下宁可关掉功能。
	 */
	pr_info(SK_TAG "BTF: walked %lu / %u %s (kstat seen %d)\n", pos, type_len,
		(pos == type_len) ? "OK" : "MISALIGNED", sk_btf_kstat_seen);
	{
		int zi;
		char kb[160];
		int kl = 0;

		for (zi = 0; zi < 20; zi++) {
			if (kcnt[zi])
				kl += snprintf(kb + kl, sizeof(kb) - kl, "%d:%u ",
					       zi, kcnt[zi]);
			if (kl >= (int)sizeof(kb) - 16)
				break;
		}
		pr_info(SK_TAG "BTF kinds: %s\n", kb);
	}
	pr_info(SK_TAG "BTF: kstat.size=%d mode=%d nlink=%d uid=%d gid=%d ino=%d\n",
		sk_off_kstat_size, sk_off_kstat_mode, sk_off_kstat_nlink,
		sk_off_kstat_uid, sk_off_kstat_gid, sk_off_kstat_ino);

	/*
	 * 只有「明显走不完」才算错位。
	 * 实测本机 BTF 尾部有 4 字节对齐填充（walked 3521760 / 3521764），
	 * 这是正常的，不能因此把功能关掉。
	 */
	/*
	 * ── kstat 偏移的最终裁决 ──
	 *
	 * 优先级：
	 *   ① BTF 遍历干净（没明显错位）且六个字段全拿到 → 用 BTF 值（全机型自适应）
	 *   ② 否则：只有 6.6 才敢用实测默认值（那是从 6.6 的真实 BTF 里量出来的）
	 *   ③ 其它 KMI（5.4/5.10/5.15/6.1）+ BTF 不可信 → 直接禁用属性伪造
	 *
	 * 为什么这么保守：struct kstat 的布局在各 KMI 之间并不一致，
	 * 用错偏移写进去是**写坏内核栈**，不是返回错误 —— 会 panic。
	 * 宁可少一个功能，也不能让某台设备一用就崩。
	 */
	if (pos + 16 >= type_len && sk_kstat_mask == 0x3f) {
		sk_off_kstat_size  = sk_tmp_size;
		sk_off_kstat_mode  = sk_tmp_mode;
		sk_off_kstat_nlink = sk_tmp_nlink;
		sk_off_kstat_uid   = sk_tmp_uid;
		sk_off_kstat_gid   = sk_tmp_gid;
		sk_off_kstat_ino   = sk_tmp_ino;
		pr_info(SK_TAG "kstat 偏移取自 BTF（自适应）\n");
	} else if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
		   && LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)) {
		pr_info(SK_TAG "BTF 不可信，使用 6.6 实测默认偏移 mask=0x%x\n",
			sk_kstat_mask);
	} else {
		sk_off_kstat_stop = 1;
		pr_warn(SK_TAG "BTF 不可信且非 6.6（kmi=%u.%u），属性伪造已禁用\n",
			LINUX_VERSION_CODE >> 16,
			(LINUX_VERSION_CODE >> 8) & 0xff);
	}

	if (pos + 16 < type_len)
		sk_off_kstat_stop = 1;

	atomic_set(&sk_btf_ok, 1);
	return 0;
}

/* GKI 也没导出 filp_open / kernel_read / filp_close —— 同样用 kprobe 取址 */
static struct file *(*sk_filp_open)(const char *, int, umode_t);
static ssize_t (*sk_kernel_read)(struct file *, void *, size_t, loff_t *);
static ssize_t (*sk_kernel_write)(struct file *, const void *, size_t, loff_t *);
static int (*sk_filp_close)(struct file *, fl_owner_t);

static void *sk_sym(const char *name)
{
	struct kprobe kp;
	void *addr;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = name;
	if (register_kprobe(&kp))
		return NULL;
	addr = (void *)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

static bool sk_resolve_file_api(void)
{
	sk_filp_open   = sk_sym("filp_open");
	sk_kernel_read = sk_sym("kernel_read");
	sk_kernel_write = sk_sym("kernel_write");
	sk_filp_close  = sk_sym("filp_close");
	return sk_filp_open && sk_kernel_read && sk_filp_close;
}

static void sk_btf_init(void)
{
	struct file *f;
	void *buf = NULL;
	loff_t pos = 0;
	ssize_t n;

	if (!sk_resolve_file_api()) {
		pr_warn(SK_TAG "文件 API 取址失败（沿用编译期偏移）\n");
		return;
	}

	f = sk_filp_open("/sys/kernel/btf/vmlinux", O_RDONLY, 0);
	if (IS_ERR(f)) {
		pr_warn(SK_TAG "BTF 打不开（沿用编译期偏移）\n");
		return;
	}

	/* vmalloc 而不是 kmalloc —— 6MB 连续物理页在 init 时几乎必然失败 */
	buf = vzalloc(7 * 1024 * 1024);
	if (!buf) {
		pr_warn(SK_TAG "BTF: vzalloc 失败（沿用编译期偏移）\n");
		sk_filp_close(f, NULL);
		return;
	}

	n = sk_kernel_read(f, buf, 7 * 1024 * 1024 - 1, &pos);
	if (n <= 0)
		pr_warn(SK_TAG "BTF: kernel_read 返回 %zd\n", n);
	sk_filp_close(f, NULL);

	if (n > 0)
		sk_btf_parse(buf, (unsigned long)n);
	vfree(buf);

	pr_info(SK_TAG "BTF: module.list=%lu (编译期 %lu), module.mkobj=%lu (编译期 %lu)\n",
		sk_off_module_list, (unsigned long)offsetof(struct module, list),
		sk_off_module_mkobj, (unsigned long)offsetof(struct module, mkobj));
}



static bool sk_uid_privileged(uid_t uid);

static int (*sk_commit_creds)(struct cred *c);

/* ══════════════════ 零1：system/ 目录覆盖（路径改写，不用 overlay）══════════════════ */

#define SK_MAP_FILE "/data/local/tmp/umbral/systemmap.txt"
#define SK_MAP_MAX  512

/*
 * 映射表：target（如 /system/bin/xxx）→ real（模块里的真实路径）
 *
 * 为什么由 App 生成这张表而不是内核自己扫目录：
 *   内核里遍历目录要自己写 iterate_dir 回调，代码量大且易错；
 *   App 有读权限、有目录 API，扫一遍生成文本最快也最好排查。
 *   内核只负责「读文本 → 建表 → 在 open 时改写路径」。
 */
struct sk_map_ent {
	char target[192];
	char real[192];
};
static struct sk_map_ent *sk_map;
static int sk_map_n;
static bool sk_map_ready;

static void sk_map_load(void)
{
	struct file *f;
	loff_t pos = 0;
	ssize_t n;
	char *buf;

	if (sk_map_ready)
		return;
	sk_map_ready = true;

	if (!sk_filp_open || !sk_kernel_read || !sk_filp_close) {
		pr_warn(SK_TAG "映射表：缺文件 API，跳过\n");
		return;
	}
	f = sk_filp_open(SK_MAP_FILE, O_RDONLY, 0);
	if (IS_ERR(f)) {
		pr_info(SK_TAG "映射表：%s 不存在（未启用 system 覆盖）\n", SK_MAP_FILE);
		return;
	}
	buf = vzalloc(64 * 1024);
	if (!buf) {
		sk_filp_close(f, NULL);
		return;
	}
	n = sk_kernel_read(f, buf, 64 * 1024 - 1, &pos);
	sk_filp_close(f, NULL);
	if (n <= 0) {
		vfree(buf);
		return;
	}
	buf[n] = 0;

	sk_map = vzalloc(sizeof(*sk_map) * SK_MAP_MAX);
	if (!sk_map) {
		vfree(buf);
		return;
	}

	/* 逐行解析 "target real" */
	{
		char *p = buf;
		int cnt = 0;

		while (p && *p && cnt < SK_MAP_MAX) {
			char *e = strchr(p, '\n');
			char *sp;

			if (e)
				*e = 0;
			sp = strchr(p, ' ');
			if (sp) {
				size_t tl, rl;

				*sp = 0;
				tl = strlen(p);
				rl = strlen(sp + 1);
				if (tl > 0 && tl < sizeof(sk_map[0].target) &&
				    rl > 0 && rl < sizeof(sk_map[0].real)) {
					memcpy(sk_map[cnt].target, p, tl + 1);
					memcpy(sk_map[cnt].real, sp + 1, rl + 1);
					cnt++;
				}
			}
			if (!e)
				break;
			p = e + 1;
		}
		sk_map_n = cnt;
	}
	vfree(buf);
	pr_info(SK_TAG "映射表已载入：%d 条\n", sk_map_n);
}

/* 查表：命中返回真实路径，否则 NULL */
static const char *sk_map_lookup(const char *path)
{
	int i;

	if (!sk_map_n || !path)
		return NULL;
	for (i = 0; i < sk_map_n; i++) {
		if (!strcmp(sk_map[i].target, path))
			return sk_map[i].real;
	}
	return NULL;
}

static int sk_open_entry(struct kprobe *p, struct pt_regs *regs)
{
	struct filename *fn;
	const char *hit;
	char *dup;

	if (!sk_map_n)
		return 0;
	/* do_filp_open(dfd, struct filename *pathname, ...) */
	fn = (struct filename *)regs_get_kernel_argument(regs, 1);
	if (!fn || !fn->name)
		return 0;

	hit = sk_map_lookup(fn->name);
	if (!hit)
		return 0;

	/*
	 * 必须堆分配 —— 直接把静态字符串赋给 filename->name，
	 * 后面 VFS 会 kfree，会把 .rodata 释放掉（这个坑踩过）。
	 */
	dup = kmemdup_nul(hit, strlen(hit), GFP_ATOMIC);
	if (!dup)
		return 0;
	fn->name = dup;
	atomic64_inc(&sk_su_redirect);
	pr_info(SK_TAG "system 覆盖：%s\n", hit);
	return 0;
}

/* ══════════════════ 真正的 su 提权：照抄 KSU 的 escape_with_root_profile ══════════════════ */

/*
 * 为什么不在 execve 钩子里提权（v1.10~v1.15 的错）：
 *   钩子跑在 kprobe 的原子上下文，不能用 prepare_creds()（会睡眠），
 *   所以只能 commit_creds 一份「缓存好的 cred」—— 那份 cred 缺
 *   cred->user / cred->ucounts / groups / SELinux 域 的正确处理，
 *   结果就是 exec 被 SELinux 拒（退出码 255、零输出）。
 *
 * KSU 是在 **系统调用上下文** 里调 prepare_creds() 的。
 * 我们照抄它的做法：开一个 /proc/sk/escape 节点，
 * su 二进制启动后第一件事写这个文件 —— 那时是进程上下文，可以睡眠。
 *
 * 步骤逐条对应 KSU kernel/policy/app_profile.c: escape_with_root_profile()
 */
static void *sk_alloc_uid_ptr;   /* struct user_struct *(*)(kuid_t) */
static void (*sk_free_uid_ptr)(struct user_struct *);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
static int (*sk_set_cred_ucounts_ptr)(struct cred *);
#endif

static bool sk_escape_syms_ready;

static void sk_escape_resolve_syms(void)
{
	if (sk_escape_syms_ready)
		return;
	sk_escape_syms_ready = true;
	sk_alloc_uid_ptr = sk_sym("alloc_uid");
	sk_free_uid_ptr  = sk_sym("free_uid");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	sk_set_cred_ucounts_ptr = sk_sym("set_cred_ucounts");
#endif
	pr_info(SK_TAG "escape 符号：alloc_uid=%d free_uid=%d uc=%d\n",
		!!sk_alloc_uid_ptr, !!sk_free_uid_ptr,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
		!!sk_set_cred_ucounts_ptr
#else
		0
#endif
	);
}

/* 把当前进程提成 uid 0（必须是进程上下文） */
static void sk_set_cred_domain(struct cred *c);

static int sk_escape_to_root(void)
{
	struct cred *cred;
	int i;

	if (__kuid_val(current_uid()) == 0)
		return 0;			/* 已经是 root */

	sk_escape_resolve_syms();

	cred = prepare_creds();			/* 可睡眠，所以只能在 syscall 上下文 */
	if (!cred) {
		pr_warn(SK_TAG "escape: prepare_creds 失败\n");
		return -ENOMEM;
	}

	/* ① uid / gid 全套改成 root（KSU 也是四个一起改） */
	cred->uid   = GLOBAL_ROOT_UID;
	cred->suid  = GLOBAL_ROOT_UID;
	cred->euid  = GLOBAL_ROOT_UID;
	cred->fsuid = GLOBAL_ROOT_UID;
	cred->gid   = GLOBAL_ROOT_GID;
	cred->egid  = GLOBAL_ROOT_GID;
	cred->sgid  = GLOBAL_ROOT_GID;
	cred->fsgid = GLOBAL_ROOT_GID;
	cred->securebits = 0;

	/* ② cred->user 跟着换（KSU 特别强调漏这步会留下旧的 RLIMIT_NPROC 记账） */
	if (sk_alloc_uid_ptr && sk_free_uid_ptr) {
		struct user_struct *(*fn_au)(kuid_t) = sk_alloc_uid_ptr;
		struct user_struct *nu = fn_au(GLOBAL_ROOT_UID);

		if (nu) {
			sk_free_uid_ptr(cred->user);
			cred->user = nu;
		}
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	/* ③ ucounts 必须跟着刷新，否则 uid 变了但计数还挂在旧 uid 上 */
	if (sk_set_cred_ucounts_ptr && sk_set_cred_ucounts_ptr(cred)) {
		pr_warn(SK_TAG "escape: set_cred_ucounts 失败\n");
		put_cred(cred);
		return -ENOMEM;
	}
#endif

	/* ④ capability 拉满 */
	for (i = 0; i < sizeof(kernel_cap_t); i++)
		((u8 *)&cred->cap_effective)[i] = 0xff;
	memcpy(&cred->cap_permitted, &cred->cap_effective, sizeof(kernel_cap_t));
	memcpy(&cred->cap_bset,      &cred->cap_effective, sizeof(kernel_cap_t));

	/* ⑤ SELinux 域保持原值（域切换在 execve 路径上单独控制） */

	/*
	 * ★ 域也换成传统 su 域 ★
	 * 只把 uid 变成 0 不够：域还是 untrusted_app 的话，
	 * 读 /data/adb、写模块目录都会被 SELinux 拒
	 *（实测：uid=0 但 ls /data/adb/ksu → Permission denied）。
	 */
	sk_set_cred_domain(cred);

	sk_commit_creds(cred);
	pr_info(SK_TAG "escape 成功：pid=%d uid=0\n", current->pid);
	return 0;
}

static ssize_t sk_escape_write(struct file *f, const char __user *ubuf,
			       size_t len, loff_t *off)
{
	int rc;

	(void)ubuf;
	(void)len;

	if (!sk_uid_privileged(__kuid_val(current_uid()))) {
		pr_warn(SK_TAG "escape 拒绝：uid %u 不在授权表\n",
			__kuid_val(current_uid()));
		return -EPERM;
	}
	rc = sk_escape_to_root();
	if (rc)
		return rc;
	return len ? len : 1;
}

static int sk_escape_show(struct seq_file *m, void *v)
{
	seq_printf(m, "uid %u\n", __kuid_val(current_uid()));
	return 0;
}

/* ══════════════════ ④ 管理器签名校验 ══════════════════ */

#define SK_SIG_FILE "/data/local/tmp/umbral/signature.txt"

/*
 * 管理器签名摘要（App 用 GET_SIGNING_CERTIFICATES 算的 SHA-256，64 位 hex）。
 *
 * 对齐 KSU 的 signature 机制：它的 allowlist 记 (uid, 包名, 签名)，
 * 不只是 uid —— 因为 uid 可以冒用，签名不行。
 *
 * 做法：
 *   · 开机时（工作队列里，可睡眠）读一次 SK_SIG_FILE，存进内核
 *   · execve 赋权前，只有 sig_required 打开且摘要非空才继续
 *   · 摘要为空（文件被删/换）→ 拒绝提权，并写 /proc/sk/deny
 *
 * 默认关闭（sig_required=0），因为摘要还没跟授权表绑死，
 * 打开前要先确认 App 每次启动都会刷新这个文件。
 */
static int sk_sig_required;
module_param_named(sig_required, sk_sig_required, int, 0644);
MODULE_PARM_DESC(sig_required, "1 = execve 赋权前要求管理器签名摘要非空");

static char sk_sig_expect[65];
static bool sk_sig_loaded;

/*
 * 开机读一次摘要。
 * kernel_read 会睡眠 → 只能在延迟工作里调，不能在钩子里。
 */
static void sk_load_signature(void)
{
	struct file *f;
	loff_t pos = 0;
	ssize_t n;

	if (!sk_filp_open || !sk_kernel_read || !sk_filp_close) {
		pr_warn(SK_TAG "签名校验：缺 filp_open/kernel_read，跳过\n");
		return;
	}

	f = sk_filp_open(SK_SIG_FILE, O_RDONLY, 0);
	if (IS_ERR(f)) {
		pr_warn(SK_TAG "签名校验：打不开 %s\n", SK_SIG_FILE);
		return;
	}
	memset(sk_sig_expect, 0, sizeof(sk_sig_expect));
	n = sk_kernel_read(f, sk_sig_expect, 64, &pos);
	sk_filp_close(f, NULL);

	if (n <= 0) {
		pr_warn(SK_TAG "签名校验：读取返回 %zd\n", n);
		return;
	}
	/* 只保留 hex 字符，兼容后面还有包名行的情况 */
	{
		int i, j = 0;

		for (i = 0; i < n && j < 64; i++) {
			char c = sk_sig_expect[i];

			if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
			    (c >= 'A' && c <= 'F'))
				sk_sig_expect[j++] = c;
			else
				break;
		}
		sk_sig_expect[j] = 0;
		sk_sig_loaded = (j == 64);
	}
	pr_info(SK_TAG "签名摘要已载入（%d 位）：%s\n",
		(int)strlen(sk_sig_expect), sk_sig_expect);
}

/* ══════════════════ 管理器 uid 自举文件 ══════════════════ */

#define SK_MGR_UID_FILE "/data/adb/umbral/manager.uid"

/*
 * 管理器包名的数据目录。内核 stat 它的属主就能拿到 uid ——
 * 这样新设备上不需要任何前置条件（不需要 su、不需要 manager.uid 文件）。
 */
/* 1 = 这个 uid 是自动发现的管理器，直接给超级用户模式（永久 SU） */
static int sk_mgr_uid_found;

/*
 * 延迟发现：init 阶段 /data 还没挂载，stat 它必然失败。
 * 所以用 delayed work 在系统起来之后重试，直到拿到管理器 uid。
 */
static struct delayed_work sk_late_work;
static int sk_late_tries;

#define SK_LATE_MAX_TRIES 300
#define SK_LATE_DELAY_MS  2000

static const char *sk_mgr_dirs[] __attribute__((unused)) = {
	"/data/data/" SK_MGR_PKG,
	"/data/user/0/" SK_MGR_PKG,
};

/*
 * 直接读 /data/data/<pkg> 的属主 uid。
 * init 上下文可睡眠，filp_open 打开目录是安全的（只读，不解引用 inode 内容）。
 */
/* ══════════════════ 零2：sepolicy.rule → bypass 表 ══════════════════ */

/*
 * 不加载真实策略（security_load_policy 会整份替换，风险极高），
 * 而是把模块 sepolicy.rule 里的 allow 规则解析成一张 (ssid,tsid) 表，
 * 命中就走我们现有的 avc 钩子放行。
 *
 * 粒度说明（如实记录）：
 *   KSU 能按 tclass/perm 精确放行；我们这版只按 (源域, 目标域) 放行，
 *   即「这两个域之间的操作一律允许」。对模块自用规模够，但不是最小权限。
 *
 * 域名 → sid 的解析会睡眠，所以只在工作队列里做。
 */
#define SK_SP_FILE "/data/local/tmp/umbral/sepolicy.txt"
#define SK_SP_MAX  256

struct sk_sp_ent {
	u32 ssid;
	u32 tsid;
};
static struct sk_sp_ent *sk_sp;
static int sk_sp_n;
static bool sk_sp_ready;

static void sk_sp_load(void)
{
	struct file *f;
	loff_t pos = 0;
	ssize_t n;
	char *buf;
	int (*secctx2sid)(const char *secdata, u32 seclen, u32 *secid) = NULL;
	struct kprobe kp;

	if (sk_sp_ready)
		return;
	sk_sp_ready = true;

	if (!sk_filp_open || !sk_kernel_read || !sk_filp_close)
		return;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "security_secctx_to_secid";
	if (!register_kprobe(&kp)) {
		secctx2sid = (void *)kp.addr;
		unregister_kprobe(&kp);
	}
	if (!secctx2sid) {
		pr_warn(SK_TAG "sepolicy: 取不到 secctx_to_secid\n");
		return;
	}

	f = sk_filp_open(SK_SP_FILE, O_RDONLY, 0);
	if (IS_ERR(f)) {
		pr_info(SK_TAG "sepolicy: %s 不存在（未启用）\n", SK_SP_FILE);
		return;
	}
	buf = vzalloc(64 * 1024);
	if (!buf) {
		sk_filp_close(f, NULL);
		return;
	}
	n = sk_kernel_read(f, buf, 64 * 1024 - 1, &pos);
	sk_filp_close(f, NULL);
	if (n <= 0) {
		vfree(buf);
		return;
	}
	buf[n] = 0;

	sk_sp = vzalloc(sizeof(*sk_sp) * SK_SP_MAX);
	if (!sk_sp) {
		vfree(buf);
		return;
	}

	{
		char *line = buf;
		int cnt = 0;

		while (line && *line && cnt < SK_SP_MAX) {
			char *e = strchr(line, '\n');
			char *tok[4];
			int nt = 0;
			char *sv;

			if (e)
				*e = 0;
			/* 按空格切 */
			sv = line;
			while (sv && *sv && nt < 4) {
				char *sp = strchr(sv, ' ');

				if (sp)
					*sp = 0;
				tok[nt++] = sv;
				sv = sp ? sp + 1 : NULL;
				while (sv && *sv == ' ')
					sv++;
			}
			/* 期望四段：scontext tcontext tclass perms（App 已把 allow 去掉） */
			if (nt >= 2) {
				u32 s1 = 0, s2 = 0;

				if (secctx2sid(tok[0], strlen(tok[0]), &s1) == 0 && s1 &&
				    secctx2sid(tok[1], strlen(tok[1]), &s2) == 0 && s2) {
					sk_sp[cnt].ssid = s1;
					sk_sp[cnt].tsid = s2;
					cnt++;
				}
			}
			if (!e)
				break;
			line = e + 1;
		}
		sk_sp_n = cnt;
	}
	vfree(buf);
	pr_info(SK_TAG "sepolicy bypass 表：%d 条\n", sk_sp_n);
}

/* 给 avc 钩子用：这对域是否命中模块规则 */
static bool __maybe_unused sk_sp_match(u32 ssid, u32 tsid)
{
	int i;

	if (!sk_sp_n)
		return false;
	for (i = 0; i < sk_sp_n; i++) {
		if (sk_sp[i].ssid == ssid && sk_sp[i].tsid == tsid)
			return true;
	}
	return false;
}

static void sk_grants_restore(void);
static void sk_prot_init(void);
static void sk_open_register(void);
static void sk_open_unregister(void);

/**
 * Parse one line of grants.conf: uid <N> shadow|super  (whitespace tolerant).
 * Returns 0 when a grant was added, negative otherwise.
 */
static void sk_late_fn(struct work_struct *w);
static int sk_discover_manager_uid(void)
{
	/* 零1：载入 system 覆盖映射表 */
	sk_map_load();

	/* 零2：载入 sepolicy bypass 表 */
	sk_sp_load();

	/* S1/S2：受保护文件系统 dev 白名单 */
	sk_prot_init();
	sk_grants_restore();


	/* ④ 载入管理器签名摘要（在工作队列里，可睡眠）*/
	sk_load_signature();

	struct file *f;
	char *buf;
	ssize_t n;
	loff_t pos = 0;
	char *line, *next;
	int uid = -1;

	if (!sk_filp_open || !sk_kernel_read)
		return -1;

	/*
	 * ★ 优先读 /data/system/packages.list ★
	 *
	 * 为什么不 stat("/data/data/io.umbral")：
	 *   内核（kernel_t）去访问 app_data_file 会被 SELinux 拦，
	 *   即使文件存在也拿不到。
	 *   packages.list 是 system:system 0644，内核读它不会被拦。
	 *
	 * 格式（每行）：
	 *   <包名> <uid> <debuggable 0/1> <数据目录> <seinfo> ...
	 * 例：
	 *   io.umbral 10234 0 /data/user/0/io.umbral default:targetSdkVersion:35
	 */
	f = sk_filp_open("/data/system/packages.list", O_RDONLY, 0);
	if (IS_ERR(f)) {
		pr_info(SK_TAG "packages.list 打不开: %ld\n", PTR_ERR(f));
		return -1;
	}

	buf = vzalloc(256 * 1024);
	if (!buf) {
		sk_filp_close(f, NULL);
		return -1;
	}
	n = sk_kernel_read(f, buf, 256 * 1024 - 1, &pos);
	sk_filp_close(f, NULL);
	if (n <= 0) {
		vfree(buf);
		return -1;
	}
	buf[n] = 0;

	for (line = buf; line && *line; line = next) {
		next = strchr(line, '\n');
		if (next)
			*next++ = 0;

		if (!strncmp(line, SK_MGR_PKG_SLASH, SK_MGR_PKG_LEN + 1)) {
			char *sp = strchr(line, ' ');

			if (sp && sscanf(sp + 1, "%d", &uid) == 1 && uid > 0) {
				pr_info(SK_TAG "从 packages.list 找到管理器 uid=%d\n",
					uid);
				sk_mgr_uid_found = 1;
				break;
			}
		}
	}

	vfree(buf);
	return uid;
}




/*
 * 读 /data/adb/umbral/manager.uid，返回里面的 uid；读不到返回 -1。
 * 必须在 init（可睡眠上下文）调用。
 */
static int sk_read_manager_uid(void)
{
	struct file *f;
	char buf[32];
	loff_t pos = 0;
	ssize_t n;
	long v = -1;

	if (!sk_resolve_file_api())
		return -1;

	f = sk_filp_open(SK_MGR_UID_FILE, O_RDONLY, 0);
	if (IS_ERR(f))
		return -1;

	memset(buf, 0, sizeof(buf));
	n = sk_kernel_read(f, buf, sizeof(buf) - 1, &pos);
	sk_filp_close(f, NULL);

	if (n <= 0)
		return -1;

	if (kstrtol(buf, 10, &v) || v <= 0)
		return -1;

	return (int)v;
}

/*
 * 把管理器 uid 落到 /data/adb/umbral/manager.uid。
 *
 * 为什么必须由模块来写：
 *   管理器被授权后 DAC 大部分绕过，但「属主 <= 1000 的文件保持只读」
 *   这条规则是为了救 ART（否则 Writable dex file 拒绝加载 APK），
 *   而 /data/adb 属主正是 root(0) —— 所以管理器自己写不进去。
 *   su 也不行（App 不在 KSU 允许列表）。
 *   模块在内核态是 root 身份，不受那条规则约束。
 */
static void sk_write_manager_uid(int uid)
{
	struct file *f;
	char buf[16];
	int n;

	if (uid <= 0 || !sk_kernel_write || !sk_filp_open)
		return;

	n = snprintf(buf, sizeof(buf), "%d\n", uid);

	f = sk_filp_open(SK_MGR_UID_FILE,
			 O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(f)) {
		pr_warn(SK_TAG "写 manager.uid 打不开文件: %ld\n", PTR_ERR(f));
		return;
	}

	{
		loff_t pos = 0;
		ssize_t w = sk_kernel_write(f, buf, (size_t)n, &pos);
		sk_filp_close(f, NULL);
		if (w == n)
			pr_info(SK_TAG "manager.uid 已写入 %d\n", uid);
		else
			pr_warn(SK_TAG "写 manager.uid 只写了 %zd/%d\n", w, n);
	}
}

/* ══════════════════ 自隐藏 ══════════════════ */

/*
 * hide=0  可见、可 rmmod（开发迭代默认）
 * hide=1  从模块链表和 sysfs 摘掉 → lsmod / /proc/modules / /sys/module 都看不到
 *
 * ★ 后果必须记住：hide=1 之后 rmmod 也会失效（模块不在链表里），
 *   想卸载只能重启。所以默认 0，只在最终验证时开。
 *
 * 两处痕迹：
 *   ① 模块链表  THIS_MODULE->list    → lsmod、/proc/modules 都遍历它
 *   ② sysfs     THIS_MODULE->mkobj   → /sys/module/sk_root
 *
 * 还有第三处（sysfs 下的 sections 目录）在去掉 mkobj 后一并消失。
 */
/*
 * 启动时自动授权的 uid。
 *
 * 为什么需要：管理器要在没有 su 的情况下管理模块，就必须先有权限。
 * 而给它权限的正是我们自己的模块 —— 这就是自举闭环：
 *
 *     刷机 / KSU 模块脚本 insmod 时带上 grant_uid=<管理器 uid>
 *       → 模块启动即把该 uid 加进授权表
 *         → 管理器第一次跑 syscall 就被提权
 *           → 它能读 /data/adb/modules、能 exec ksud
 *             → 整个管理器不依赖任何 su
 *
 * grant_mode: 0 = 影子（uid 不变），1 = 超级用户（uid→0）
 */
static int sk_grant_uid = -1;
module_param_named(grant_uid, sk_grant_uid, int, 0444);
MODULE_PARM_DESC(grant_uid, "uid to auto-authorize at load time");

static int sk_grant_mode = 0;
module_param_named(grant_mode, sk_grant_mode, int, 0444);
MODULE_PARM_DESC(grant_mode, "0 = shadow, 1 = superuser");

/*
 * 是否钩 avc_has_perm / avc_has_perm_noaudit。
 *
 * 默认 0（不钩）—— 这是用一次崩溃换来的结论：
 *
 *   avc_has_perm 是 SELinux 的**通用**判据，不只服务文件访问，
 *   binder 事务、socket、shm、msg 全都走它。给一个 binder 密集的
 *   App（也就是管理器自己）授权后，我们把这些检查全部强行放行，
 *   binder 驱动在不该通过的状态下继续跑 → 不变量被破坏 → panic。
 *
 *   文件访问其实不需要它：selinux_inode_permission / file_permission /
 *   file_open 三个专用钩子已经覆盖了。能力检查由 selinux_capable 覆盖。
 *   通用判据保持原样，系统就还是系统。
 */
/*
 * LSM 钩子位掩码。
 *   bit0 inode_permission / bit1 file_permission / bit2 file_open
 *   bit3 selinux_capable  / bit4 avc_has_perm    / bit5 avc_has_perm_noaudit
 *
 * 默认 15 —— 前四个。通用 avc 默认不挂（会把 binder 的判据一起放行）。
 */
#define SK_HOOKBIT_INODE   1
#define SK_HOOKBIT_FILE    2
#define SK_HOOKBIT_OPEN    4
#define SK_HOOKBIT_CAP     8
#define SK_HOOKBIT_AVC     16
#define SK_HOOKBIT_AVC_NA  32
#define SK_HOOKBIT_CAPFN   64	/* cap_capable        → 满 caps */
#define SK_HOOKBIT_GENPERM 128	/* generic_permission → DAC 放行 */

/* 二分用：1 = 关掉提权（只保留钩子，不碰 cred） */
static int sk_nopromote;
module_param_named(nopromote, sk_nopromote, int, 0444);
MODULE_PARM_DESC(nopromote, "1 = disable promotion entirely (bisect)");

/*
 * fork 继承钩子 —— **默认关**。
 *
 * 这是二分出来的结论，也是设计上的必然：
 *
 *   老的「按 pid 授权」年代，子进程需要被单独写进授权表，
 *   所以要在 wake_up_new_task 上钩一把。
 *
 *   现在授权按 **uid** —— 子进程的 uid 和父进程一样，
 *   sk_grant_mode_task() 天然就命中同一条记录，根本不需要继承。
 *
 *   而这个钩子挂在 wake_up_new_task 上，那是在 rq->lock 持有、
 *   中断关闭的极敏感位置，往里塞 kzalloc + 哈希插入，
 *   给一个几十线程的 App 授权时就可能把调度器捅坏 —— 实测会 panic。
 *
 * 只有需要按 pid 临时授权（测试用）时才把它打开。
 */
static int sk_forkoff = 1;
module_param_named(fork, sk_forkoff, int, 0444);
MODULE_PARM_DESC(fork, "1 = disable fork inheritance (default 1; uid grants make it unnecessary)");

/*
 * 默认：LSM 四个专用钩子(15) + cap_capable(64) + generic_permission(128)。
 *
 * generic_permission 现在带了 O_RDWR 例外（见 sk_perm_return），
 * 所以不会再触发 "Writable dex file" 那个 SecurityException。
 */
/*
 * ★ v0.98 诊断版：只留 DAC，SELinux 钩子全关 ★
 *
 * 目的：二分定位「一开管理器就崩」到底在不在 SELinux 路径上。
 *
 *   128 = GENPERM  generic_permission（DAC 判定）
 *   64  = CAPFN    cap_capable
 *   （1 INODE / 2 FILE / 4 OPEN / 8 CAP 全部关掉）
 *
 * 如果这版 App 能正常打开 → 崩溃在 SELinux 钩子里
 * 如果这版还崩          → 崩溃在 DAC 或 syscall 钩子里
 */
/*
 * ★ v0.99 零拦截对照版 ★
 *
 * 把**所有**拦截钩子关掉，只保留：
 *   · /proc/sk 节点（能读状态）
 *   · 延迟工作（抄日志）
 *
 * 目的：回答「崩溃到底是不是我们拦出来的」。
 *
 *   这版 App 完全没有影子权限 → 它会显示「未刷入」
 *   如果这版 App 能正常打开  → 崩溃确实来自我们的拦截逻辑
 *   如果这版 App 还是崩/重启 → 崩溃跟内核拦截无关，是 App 自己或别的因素
 *
 * 这是从 0 往上二分的第一步（你说得对：从多往少减没意义）。
 */
/*
 * ★ 把 AVC 层的两个钩子打开 ★
 *
 * 之前默认 mask = 15|64|128，只挂了
 *   inode_permission / file_permission / file_open / selinux_capable
 *   + cap_capable + generic_permission
 *
 * 但 SELinux 的拒绝不止从这四处出来 —— 很多对象类（目录搜索、
 * 套接字、binder 传输、xattr 等）直接走 avc_has_perm /
 * avc_has_perm_noaudit。那两条没挂，就等于「有一部分目录怎么都读不了」。
 *
 * 现在加上 bit16(AVC) + bit32(AVC_NA)。
 * 代价：MAC 放行的面变宽了，异常信号也变多 —— 但先让它能干活，
 *       之后再用 /proc/sk/deny 看实际被拦在哪一层，逐步收窄。
 */
static int sk_hookmask = 15 | 16 | 32 | 64 | 128;
module_param_named(hooks, sk_hookmask, int, 0444);
MODULE_PARM_DESC(hooks, "LSM hook bitmask (default 15 = inode|file|open|capable)");

static int sk_hide;
/*
 * 用 module_param_named 让参数名就叫 hide —— module_param(sk_hide,...)
 * 生成的是 sk_hide=，而 insmod 时写 hide=1 会被当成未知参数静默忽略，
 * 现象是「传了但没生效」，这个坑踩过一次。
 */
module_param_named(hide, sk_hide, int, 0444);
MODULE_PARM_DESC(hide, "1 = hide this module from lsmod and sysfs");

static atomic_t sk_hidden = ATOMIC_INIT(0);

static void sk_hide_self(void)
{
	if (!sk_hide)
		return;
	if (atomic_xchg(&sk_hidden, 1))
		return;		/* 只做一次，重复摘链表会崩 */

	/*
	 * 用运行时偏移而不是编译期 &THIS_MODULE->list ——
	 * 如果编译时的 struct module 布局和设备内核不一致，
	 * 取编译期地址会摘错节点，直接把模块链表捅坏（这就是崩溃 #1 的形态）。
	 * BTF 解析出来的偏移才可信。
	 */
	{
		unsigned long base = (unsigned long)THIS_MODULE;

		/* ① 从模块链表摘掉 —— lsmod 和 /proc/modules 立刻看不到 */
		list_del_init((struct list_head *)(base + sk_off_module_list));

		/* ② 从 sysfs 摘掉 —— /sys/module/sk_root 消失 */
		kobject_del((struct kobject *)(base + sk_off_module_mkobj
					       + offsetof(struct module_kobject, kobj)));
	}

	/* 注意：这里不能再 pr_info 之外的任何操作依赖 THIS_MODULE 的链表位置 */
	pr_info(SK_TAG "module hidden (lsmod / sysfs cleared)\n");
}

/* ══════════════════ 状态 ══════════════════ */

static struct proc_dir_entry *sk_dir;

static atomic64_t sk_seen       = ATOMIC64_INIT(0);
static atomic64_t sk_elevated   = ATOMIC64_INIT(0);
static atomic64_t sk_reverted   = ATOMIC64_INIT(0);
static atomic64_t sk_denied     = ATOMIC64_INIT(0);
static atomic64_t sk_lsm_seen   = ATOMIC64_INIT(0);
static atomic64_t sk_lsm_bypass = ATOMIC64_INIT(0);
/* 诊断用：无条件计数，用来确认 hook 到底被调用了几次 */
static atomic64_t sk_lsm_e_called = ATOMIC64_INIT(0);
static atomic64_t sk_lsm_r_called = ATOMIC64_INIT(0);
/* 窗口期间 cred 被别人换掉的次数（这些会泄漏一个 cred 引用，属已知取舍）*/
static atomic64_t sk_off_orphan   = ATOMIC64_INIT(0);
/* 调试：前 N 次提权把 syscall 号打进 dmesg，用来定位崩溃前在做什么 */
static atomic64_t sk_dbg_elev     = ATOMIC64_INIT(0);
static int        sk_dbg_limit    __maybe_unused = 300;
static atomic_t   sk_err        = ATOMIC_INIT(0);

static struct cred *sk_root_cred;
/* ══════════════════ 按 task 授权（影子通道核心） ══════════════════ */

/*
 * 为什么需要这张表
 * ─────────────────────────────────────────────────────────
 * 内存令牌（SK_TOKEN_ADDR 那 32 字节）挂在 mm 上。
 * execve 会把 mm 整个换掉 → 令牌没了。
 * 而跑任何脚本都必然 fork + exec，所以现状是：
 *     影子权限只对「App 自己的进程」有效，对脚本一律无效。
 *
 * 这张表按 (pid, start_time) 定位一个 task：
 *     进程号         pid
 *     创建时刻       start_time（单调，同一 pid 复用时必然不同）
 *
 * 于是：
 *     execve  → task_struct 不换 → 授权活下来
 *     fork    → 在 wake_up_new_task 里继承给子进程
 *     pid 复用 → start_time 不同 → 不会误授权
 *
 * 因为 (pid,start_time) 本身就不会误匹配，进程退出时**不需要**清理表项，
 * 代价只是占一个槽位。槽位有上限，满了拒绝新授权。
 */
/* 授权模式 */
#define SK_GRANT_SHADOW   0	/* 只拉 caps，uid 不变（隐身） */
#define SK_GRANT_SUPER    1	/* caps + uid→0（真 root，看得出） */
#define SK_GRANT_FULL     2	/* 完全影子：只绕 DAC，不碰 MAC */

struct sk_grant {
	struct hlist_node node;
	struct rcu_head rcu;
	pid_t pid;
	u64 start_time;
	u8  mode;
};

#define SK_GRANT_BITS 7
#define SK_GRANT_MAX  256

static DEFINE_SPINLOCK(sk_grant_lock);

/* ── 按 uid 授权（持久，管理器用这个）── */
struct sk_ugrant {
	struct hlist_node node;
	struct rcu_head rcu;
	u32 uid;
	u8  mode;
};

static DEFINE_HASHTABLE(sk_ugrants, SK_GRANT_BITS);
static atomic_t sk_ugrant_n = ATOMIC_INIT(0);

/* 按 uid 查模式。-1 无授权 */
static int sk_grant_mode_uid(u32 uid)
{
	struct sk_ugrant *g;
	int mode = -1;

	if (atomic_read(&sk_ugrant_n) == 0)
		return -1;

	rcu_read_lock();
	hlist_for_each_entry_rcu(g, &sk_ugrants[hash_min(uid, SK_GRANT_BITS)], node) {
		if (g->uid == uid) {
			mode = (int)g->mode;
			break;
		}
	}
	rcu_read_unlock();
	return mode;
}

/* 这个 uid 是否已在授权表里（复用 sk_grant_mode_uid，避免重复实现） */
static bool sk_ugrant_has(u32 uid)
{
	return sk_grant_mode_uid(uid) >= 0;
}

static void sk_ugrant_del(u32 uid);

static int sk_ugrant_add(u32 uid, u8 mode)
{
	/*
	 * ★ 先清掉这个 uid 的所有旧条目，再加新的 ★
	 *
	 * 之前是"有就改模式"，但只要有任何一条路径绕过它（proc 写入、
	 * 自举、从 grants.conf 恢复），就可能留下两条记录：
	 *     uid 10560 shadow
	 *     uid 10560 super
	 * 之后查模式时随机命中一条 —— 表现为「两个权限同时在」，
	 * 目标应用行为错乱甚至卡死。
	 *
	 * 现在保证：一个 uid 永远只有一条记录。
	 */
	sk_ugrant_del(uid);

	struct sk_ugrant *g;

	/*
	 * ★ 管理器自己永远不给超级用户模式 ★
	 *   超级用户模式会 commit_creds 把进程变成 uid 0，
	 *   ActivityManager 发现进程 uid 变了会直接杀掉 —— App 打不开。
	 *   管理器要真 root 时走子进程（Shell.root），本体只用影子。
	 */
	/*
	 * ★ 已存在就更新模式，不能再直接返回 ★
	 *   原来这里 return 0 表示"已经有了"，结果从影子切到超级用户时
	 *   新模式写不进去，管理器界面以为成功、内核还是旧模式 ——
	 *   表现为「两个权限同时在」，App 卡死。
	 */
	{
		int cur = sk_grant_mode_uid(uid);

		if (cur >= 0) {
			if (cur == (int)mode)
				return 0;
			/* 已有的那条改模式 */
			{
				struct sk_ugrant *g2;
				bool done = false;

				rcu_read_lock();
				hlist_for_each_entry_rcu(g2,
						&sk_ugrants[hash_min(uid, SK_GRANT_BITS)], node) {
					if (g2->uid == uid) {
						WRITE_ONCE(g2->mode, mode);
						done = true;
						break;
					}
				}
				rcu_read_unlock();
				if (done)
					return 0;
			}
		}
	}

	g = kzalloc(sizeof(*g), GFP_ATOMIC);
	if (!g)
		return -ENOMEM;

	g->uid  = uid;
	g->mode = mode;

	spin_lock(&sk_grant_lock);
	hlist_add_head_rcu(&g->node, &sk_ugrants[hash_min(uid, SK_GRANT_BITS)]);
	spin_unlock(&sk_grant_lock);
	atomic_inc(&sk_ugrant_n);
	return 0;
}

static void sk_ugrant_del(u32 uid)
{
	struct sk_ugrant *g;
	struct hlist_node *tmp;
	struct sk_ugrant *victim = NULL;
	unsigned int bkt;

	spin_lock(&sk_grant_lock);
	hash_for_each_safe(sk_ugrants, bkt, tmp, g, node) {
		if (g->uid == uid) {
			hlist_del_rcu(&g->node);
			victim = g;
			break;
		}
	}
	spin_unlock(&sk_grant_lock);

	if (victim) {
		atomic_dec(&sk_ugrant_n);
		kfree_rcu(victim, rcu);
	}
}


static DEFINE_HASHTABLE(sk_grants, SK_GRANT_BITS);
static atomic_t  sk_grant_n     = ATOMIC_INIT(0);
static atomic_t  sk_inherited   = ATOMIC_INIT(0);
static atomic64_t sk_grant_hits = ATOMIC64_INIT(0);
static atomic64_t sk_grant_miss = ATOMIC64_INIT(0);

/* 允许写 /proc/sk/grant 的 uid。默认 -1 = 只允许 root 自己写。
 * insmod 时指定：insmod umbral.ko sk_allow_uid=10563 */
static int sk_allow_uid = -1;
module_param(sk_allow_uid, int, 0444);
MODULE_PARM_DESC(sk_allow_uid, "uid allowed to write /proc/sk/grant");

/* 查一个 task 是否有授权（RCU 读，不睡眠） */
/* -1 无授权 / SK_GRANT_SHADOW / SK_GRANT_SUPER */
/*
 * 只看 pid 表的授权模式（不回落查 uid）。
 *
 * ★ 为什么必须有这个区分 ★
 *
 *   uid 级 SUPER  = 该 uid 的**所有**进程都算超级用户
 *                   → App fork 出来的 :remote / WebView 沙箱等子进程
 *                     也会被 commit_creds 成 uid 0
 *                   → ASM 发现 App 的进程 uid 变了 → 杀进程 / 系统不稳
 *                   → 实测就是「一授超级用户就崩」
 *
 *   pid 级 SUPER  = 只有明确登记过的那一个进程提权
 *                   → 就是 su 的做法：App 本体不变，专门 fork 一个子进程
 *                     让它自己写 /proc/sk/grant 登记 pid，然后那个进程变 uid 0
 *                   → App 和它的其它子进程完全不受影响
 *
 * 所以：uid 级 SUPER 只当影子用（放行但不换 uid），pid 级才真提权。
 */
static int sk_pid_grant_mode(struct task_struct *t)
{
	struct sk_grant *g;
	pid_t pid;
	u64 st;
	int mode = -1;

	if (!t || t->pid <= 0)
		return -1;
	if (atomic_read(&sk_grant_n) == 0)
		return -1;

	pid = t->pid;
	st  = t->start_time;
	(void)st;

	rcu_read_lock();
	hlist_for_each_entry_rcu(g, &sk_grants[hash_min(pid, SK_GRANT_BITS)], node) {
		/*
		 * ★ 只按 pid 匹配，不再要求 start_time 完全相等 ★
		 *
		 * 原来要求 g->start_time == t->start_time。
		 * 但登记发生在 fork 之后极短时间内，两个来源的 start_time
		 * 精度/取值不一定一致（实测：写 grant 成功、count 却一直是 0，
		 * 表现就是「提权不生效」）。
		 *
		 * 放宽为只比 pid 的风险：pid 复用。但这条授权的生命周期很短
		 * （子进程跑完就退出，条目也随 sk_grant_del 清掉），
		 * 而 pid 复用需要同一个 pid 值在授权存活期内被重新分配 —— 极不可能。
		 */
		if (g->pid == pid) {
			mode = (int)g->mode;
			break;
		}
	}
	rcu_read_unlock();
	return mode;
}

static int sk_grant_mode_task(struct task_struct *t)
{
	struct sk_grant *g;
	pid_t pid;
	u64 st;
	int mode = -1;

	if (!t || t->pid <= 0)
		return -1;
	/*
	 * 快速短路：两张表都空才直接返回。
	 * 只判 pid 表会漏掉「只按 uid 授权」的情况 —— 这个 bug 踩过一次，
	 * 症状是 uid_count 有值但完全不生效。
	 */
	if (atomic_read(&sk_grant_n) == 0 && atomic_read(&sk_ugrant_n) == 0)
		return -1;

	pid = t->pid;
	st  = t->start_time;

	rcu_read_lock();
	hlist_for_each_entry_rcu(g, &sk_grants[hash_min(pid, SK_GRANT_BITS)], node) {
		/* 只按 pid 匹配（start_time 在 fallback 登记时是 0，比了必失配）*/
		if (g->pid == pid) {
			mode = (int)g->mode;
			break;
		}
	}
	rcu_read_unlock();

	if (mode >= 0)
		return mode;

	/*
	 * 没按 task 授权就看 uid。
	 * 注意用 real_cred->uid —— override_creds 只改 cred，
	 * real_cred 始终是原始 uid，所以超级用户模式提权后也能稳定命中。
	 */
	return sk_grant_mode_uid(__kuid_val(__task_cred(t)->uid));
}

static bool sk_granted_task(struct task_struct *t)
{
	bool r = (sk_grant_mode_task(t) >= 0);

	if (r)
		atomic64_inc(&sk_grant_hits);
	else
		atomic64_inc(&sk_grant_miss);
	return r;
}

static inline bool sk_is_granted(void)
{
	bool r = sk_granted_task(current);

	if (r)
		atomic64_inc(&sk_grant_hits);
	else
		atomic64_inc(&sk_grant_miss);
	return r;
}

/*
 * 加授权。
 * 用 GFP_ATOMIC —— 因为 fork 继承是在 kprobe 上下文里调的，
 * 那里 preempt 已关，不能睡。
 */
static int sk_grant_add(struct task_struct *t, u8 mode)
{
	struct sk_grant *g;

	if (!t || t->pid <= 0)
		return -EINVAL;
	if (sk_grant_mode_task(t) >= 0)
		return 0;			/* 已有，幂等 */
	if (atomic_read(&sk_grant_n) >= SK_GRANT_MAX)
		return -ENOSPC;

	g = kzalloc(sizeof(*g), GFP_ATOMIC);
	if (!g)
		return -ENOMEM;

	g->pid        = t->pid;
	g->start_time = t->start_time;
	g->mode       = mode;

	spin_lock(&sk_grant_lock);
	hlist_add_head_rcu(&g->node, &sk_grants[hash_min(g->pid, SK_GRANT_BITS)]);
	spin_unlock(&sk_grant_lock);

	atomic_inc(&sk_grant_n);
	return 0;
}

static void sk_grant_del(pid_t pid)
{
	struct sk_grant *g;
	struct hlist_node *tmp;
	struct sk_grant *victim = NULL;
	unsigned int bkt;

	spin_lock(&sk_grant_lock);
	hash_for_each_safe(sk_grants, bkt, tmp, g, node) {
		if (g->pid == pid) {
			hlist_del_rcu(&g->node);
			victim = g;
			break;
		}
	}
	spin_unlock(&sk_grant_lock);

	if (victim) {
		atomic_dec(&sk_grant_n);
		kfree_rcu(victim, rcu);
	}
}

static void sk_grant_clear(void)
{
	struct sk_grant *g;
	struct sk_ugrant *ug;
	struct hlist_node *tmp;
	unsigned int bkt;

	spin_lock(&sk_grant_lock);
	hash_for_each_safe(sk_grants, bkt, tmp, g, node) {
		hlist_del_rcu(&g->node);
		kfree_rcu(g, rcu);
	}
	/*
	 * 这里不用 hash_for_each_safe —— 它在这个内核上展开成对
	 * hlist_entry_safe 的调用，clang 报 "assigning to ... from void"。
	 * 显式遍历桶更稳，也不依赖宏的内部形状。
	 */
	{
		unsigned int i;

		for (i = 0; i < HASH_SIZE(sk_ugrants); i++) {
			while (!hlist_empty(&sk_ugrants[i])) {
				ug = hlist_entry(sk_ugrants[i].first,
						 struct sk_ugrant, node);
				hlist_del_rcu(&ug->node);
				kfree_rcu(ug, rcu);
			}
		}
	}
	spin_unlock(&sk_grant_lock);

	atomic_set(&sk_grant_n, 0);
	atomic_set(&sk_ugrant_n, 0);
}

/*
 * 按 pid 找 task。
 *
 * 本来该用 find_get_task_by_vpid()，但 GKI 没把它导出（modpost 会报 undefined），
 * 所以自己遍历进程表。这只在「授予授权」时走一次，不在系统调用热路径上，
 * O(进程数) 完全可以接受。
 */
static struct task_struct *sk_find_task(pid_t pid)
{
	struct task_struct *t, *found = NULL;

	rcu_read_lock();
	for_each_process(t) {
		if (t->pid == pid) {
			get_task_struct(t);
			found = t;
			break;
		}
	}
	rcu_read_unlock();
	return found;
}

/* 写 /proc/sk/grant 的资格：root 自己，或 insmod 指定的 uid */
static bool sk_writer_allowed(void)
{
	u32 uid = __kuid_val(current_uid());

	if (uid == 0)
		return true;
	if (sk_allow_uid >= 0 && uid == (u32)sk_allow_uid)
		return true;
	/*
	 * 自举授权的那一方也算合法写入者。
	 * 影子模式下 uid 不变，所以「被授权的管理器」就是 sk_grant_uid 本身，
	 * 它要能给自己之外的应用授权，就得有写权限。
	 */
	if (sk_grant_uid > 0 && uid == (u32)sk_grant_uid)
		return true;

	/*
	 * ★ 授权表里的 uid 也有写资格 ★
	 *
	 * 之前只认「真 root / 参数指定 / grant_uid」，于是：
	 *   · 加载器不传参时 sk_grant_uid = -1
	 *   · 管理器自己在授权表里，却写不进 /proc/sk/grant
	 *   · 结果界面点了授权没反应、UM 规则下发不了
	 *
	 * 授权表里的是用户明确批准过的 uid，让它管理规则是合理的。
	 */
	if (sk_grant_mode_uid(uid) >= 0)
		return true;

	return false;
}


static const char *sk_backend = "none";

/* 记录哪些 hook 真的注册成功了（撤未注册的 kretprobe 会 panic） */
#define SK_HOOK_SYSCALL   BIT(0)
#define SK_HOOK_SYSCALL_B BIT(1)
#define SK_HOOK_INODE     BIT(2)
#define SK_HOOK_FILE      BIT(3)
#define SK_HOOK_OPEN      BIT(4)
#define SK_HOOK_AVC       BIT(5)
#define SK_HOOK_AVC_NA    BIT(6)
#define SK_HOOK_CAPFN  (1 << 12)
#define SK_HOOK_GENPERM (1 << 13)
#define SK_HOOK_CAPABLE   BIT(7)
#define SK_HOOK_FORK      BIT(8)
static unsigned int sk_hooks;

/* ══════════════════ token ══════════════════ */

static const u8 sk_secret[SK_TOKEN_LEN] = {
	0x9e, 0x3b, 0x71, 0xc5, 0x28, 0xd4, 0x66, 0x0a,
	0xb7, 0x52, 0x8c, 0x1f, 0xe3, 0x45, 0xda, 0x7c,
	0x11, 0xa9, 0x6e, 0xf8, 0x34, 0xcb, 0x93, 0x5d,
	0x07, 0xbe, 0x40, 0x82, 0xd9, 0x2a, 0x67, 0xf1,
};

static void sk_derive_token(u32 uid, u8 out[SK_TOKEN_LEN])
{
	u64 h = 0xcbf29ce484222325ULL ^ (u64)uid;
	int i;

	for (i = 0; i < SK_TOKEN_LEN; i++) {
		h ^= sk_secret[i];
		h *= 0x100000001b3ULL;
		h ^= h >> 33;
		h *= 0xff51afd7ed558ccdULL;
		h ^= h >> 29;
		out[i] = (u8)(h >> ((i & 7) * 8));
	}
}

extern unsigned long __arch_copy_from_user(void *to, const void __user *from,
					   unsigned long n);

static noinline __attribute__((used))
long sk_copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
	unsigned long left;

	if (!access_ok(src, size))
		return -EFAULT;

	pagefault_disable();
	left = __arch_copy_from_user(dst, src, size);
	pagefault_enable();

	return left ? -EFAULT : 0;
}

static noinline __attribute__((used))
bool sk_has_token(void)
{
	u8 expect[SK_TOKEN_LEN];
	u8 got[SK_TOKEN_LEN];

	if (!current->mm)
		return false;

	sk_derive_token(__kuid_val(current_uid()), expect);

	if (sk_copy_from_user_nofault(got, (const void __user *)SK_TOKEN_ADDR,
				      SK_TOKEN_LEN) != 0)
		return false;

	return memcmp(expect, got, SK_TOKEN_LEN) == 0;
}

/* ══════════════════ 敏感 syscall ══════════════════ */

static const u16 __maybe_unused sk_sensitive[96] = {
	/*
	 * execve / execveat 特意**不在**这里。
	 *
	 * 原因：execve 会把 current->cred 换成 bprm->cred，
	 * 让窗口内提权 + 事后撤销这套机制失去配对（见 sk_off 的注释）。
	 * 而且 exec 后授权本来该由「按 task 授权表」接管（task_struct 不换），
	 * 不需要 exec 本身被提权。
	 */
	__NR_ptrace,
	__NR_kill, __NR_tkill, __NR_tgkill,
	__NR_rt_sigqueueinfo, __NR_rt_tgsigqueueinfo,
	__NR_ioctl,
	__NR_openat, __NR_openat2,
	__NR_unlinkat, __NR_renameat, __NR_renameat2,
	__NR_mkdirat, __NR_mknodat,
	__NR_symlinkat, __NR_linkat,
	__NR_mount, __NR_umount2, __NR_mount_setattr,
	__NR_fchmodat, __NR_fchmod,
	__NR_fchownat, __NR_fchown,
	/*
	 * setuid / setgid / setreuid / setresuid / setfsuid / capset
	 * 特意**不在**这里。
	 *
	 * 原因和 execve 一样但更严重：这些调用在窗口内成功执行后，
	 * 内部会 commit_creds(new)，而 commit_creds 会 put 掉
	 * 当前 cred（也就是我们的 sk_root_cred）。
	 * 随后 return handler 再撤一次 → double-free → panic。
	 *
	 * 而且从语义上讲，影子权限本来就不该让脚本真的改掉自己的 uid
	 * ——「uid 保持不变」是这个方案的全部卖点。
	 */
	__NR_process_vm_readv, __NR_process_vm_writev,
	__NR_init_module, __NR_finit_module, __NR_delete_module,
	__NR_kexec_load, __NR_reboot,
	__NR_settimeofday, __NR_clock_settime,
	__NR_sethostname, __NR_setdomainname
};

static bool __maybe_unused sk_is_sensitive(u32 nr)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sk_sensitive); i++) {
		if (sk_sensitive[i] == nr)
			return true;
	}
	return false;
}
/*
 * 扩容名单：只对**已授权 task** 生效。
 *
 * 原来的 sk_sensitive[]（45 条）保留「授权或内存令牌」两条路；
 * 这张表只走授权这一条 —— 因为要在 read/write 这种高频调用上
 * 逐次读用户内存去比对令牌，代价太大（实测全局 7000 万次调用）。
 */
static const u16 __maybe_unused sk_broad[96] = {
	/*
	 * read / write 必须在里面 —— 这是实测出来的，不是猜的。
	 *
	 * 一开始把它们去掉了，理由是「open 成功后的 fd 读写不再过 DAC」。
	 * 但实测证明这条不成立：文件以 root 身份 open 后，
	 * file_security_struct.sid 记的是 root 的 sid；
	 * 随后 read 用真实 creds 进入 selinux_file_permission，
	 * sid 和 fsec->sid 对不上 → 走 inode_has_perm 重新校验 → 被拒。
	 * 症状就是动态链接器报：
	 *     CANNOT LINK EXECUTABLE "id":
	 *     can't read file "/system/lib64/libcutils.so": Permission denied
	 *
	 * 现在敢把高频调用放回来，是因为 sk_off() 已经加了
	 * 「cred 被换掉就不硬撤」的防护，撤销不会再打坏引用计数。
	 */
#ifdef __NR_read
	__NR_read,
#endif
#ifdef __NR_write
	__NR_write,
#endif
	__NR_pread64, __NR_readv, __NR_preadv, __NR_preadv2,
	__NR_pwrite64, __NR_writev, __NR_pwritev, __NR_pwritev2,
	__NR_readlinkat, __NR_getdents64,
	__NR_truncate, __NR_ftruncate, __NR_fallocate,
	__NR_newfstatat, __NR_fstat, __NR_statx,
	__NR_faccessat, __NR_faccessat2,
	__NR_utimensat,
	__NR_getxattr, __NR_setxattr, __NR_listxattr, __NR_removexattr,
	__NR_fgetxattr, __NR_fsetxattr, __NR_flistxattr, __NR_fremovexattr,
#ifdef __NR_rmdir
	__NR_rmdir,
#endif
	__NR_chdir, __NR_fchdir,
#ifdef __NR_creat
	__NR_creat,
#endif
#ifdef __NR_open
	__NR_open,
#endif
	__NR_fcntl, __NR_flock,
	__NR_prlimit64, __NR_setpriority,
	__NR_sched_setaffinity, __NR_sched_setscheduler,
	__NR_setpgid, __NR_setsid, __NR_setgroups,
	__NR_unshare, __NR_setns,
	__NR_add_key, __NR_keyctl, __NR_request_key,
	__NR_bpf, __NR_perf_event_open,
	__NR_setsockopt, __NR_bind,
	__NR_name_to_handle_at, __NR_open_by_handle_at,
	__NR_fanotify_init,
	__NR_migrate_pages, __NR_set_mempolicy
};

static bool __maybe_unused sk_is_broad(u32 nr)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sk_broad); i++) {
		if (sk_broad[i] == nr)
			return true;
	}
	return false;
}


/* ══════════════════ 提权窗口 ══════════════════ */

/* 当前进程的 caps 是否已经拉满（模式 0 用来判断「提过了」） */
static inline bool cap_capable_current_full(void)
{
	/*
	 * 内核 6.6 把 kernel_cap_t 从 u32 数组改成了单个 u64 val，
	 * 所以这里直接比 val，不能再用 .cap[i]。
	 */
	return SK_CAP_IS_FULL(current_cred()->cap_effective);
}

static noinline __attribute__((used))
bool sk_can_elevate(void)
{
	struct task_struct *tsk = current;

	if (tsk->flags & PF_KTHREAD)
		return false;
	if (!tsk->mm)
		return false;
	if (!sk_root_cred)
		return false;
#if SK_PROMOTE_UID
	/* 模式 1：uid 已经是 0 就不用再提 */
	if (__kuid_val(current_uid()) == 0)
		return false;
#else
	/* 模式 0：uid 不变，用 caps 是否已满来判断「提过了」 */
	if (cap_capable_current_full())
		return false;
#endif
	return true;
}

static noinline __attribute__((used))
const struct cred *sk_on(void)
{
	const struct cred *old;

	/*
	 * 已经在窗口内就别再套一层。
	 * 嵌套 override 会让 return handler 的配对关系错位，
	 * 最后 revert 次数和 override 次数对不上 → 同样泄漏。
	 */
	if (sk_root_cred && current->cred == sk_root_cred)
		return NULL;

	old = override_creds(sk_root_cred);

	atomic64_inc(&sk_elevated);

	/* 诊断：只在第一次提权时打印一次，确认 cred 真的变成 root 了 */
	{
		static bool once;
		if (!once) {
			once = true;
			pr_info(SK_TAG "PROBE root_cred uid=%u euid=%u fsuid=%u "
				"cap_eff=%016llx  cur uid=%u fsuid=%u cap_eff=%016llx\n",
				__kuid_val(sk_root_cred->uid),
				__kuid_val(sk_root_cred->euid),
				__kuid_val(sk_root_cred->fsuid),
				SK_CAP64(sk_root_cred->cap_effective),
				__kuid_val(current_cred()->uid),
				__kuid_val(current_cred()->fsuid),
				SK_CAP64(current_cred()->cap_effective));
		}
	}

	return old;
}

/*
 * 撤销提权。
 *
 * ★★★ 这里踩过一个大坑，直接导致设备 panic ★★★
 *
 * override_creds() 之后，窗口期间如果有 syscall 自己换了 cred
 * （execve 就是典型：它会把 current->cred 换成 bprm->cred），
 * 那么到 return handler 执行 revert_creds(old) 时：
 *
 *     revert_creds 内部是
 *         override = current->cred;      // 此时已经不是我俩的 sk_root_cred
 *         rcu_assign_pointer(current->cred, old);
 *         put_cred(override);            // 把别人的 cred 引用计数减 1
 *
 * 引用计数被多减一次 → cred 提前释放 → 别处还在用 → use-after-free → panic。
 * 这和「列表里有没有 execve」没关系，只要窗口内有任何东西换 cred 就会中招。
 *
 * 正确做法：撤销前先确认 current->cred 仍然是我们覆盖进去的那份。
 *     是  → 正常 revert，引用计数自然平衡
 *     不是 → 覆盖已经无处可撤，只把 override_creds 拿走的那份引用还回去
 */
static noinline __attribute__((used, unused))
void sk_off(const struct cred *old)
{
	if (!old)
		return;

	if (sk_root_cred && current->cred == sk_root_cred) {
		revert_creds(old);
	} else {
		/*
		 * 窗口期间 cred 被换掉了（commit_creds 等）。
		 *
		 * ★ 这里**绝对不能** put_cred(sk_root_cred) ★
		 *
		 * 因为 commit_creds(new) 内部已经做过
		 *     put_cred(current->cred);      // 此时的 current->cred 就是我们的 sk_root_cred
		 * 我们再 put 一次就是 double-free → use-after-free → 直接 panic。
		 * 这正是 0.10.0 把设备搞崩的原因，我上一版「补一个 put 保持平衡」
		 * 恰好补成了第二次 put。
		 *
		 * 正确取舍：泄漏一个 cred 引用（约 200 字节，且只在极少数路径发生），
		 * 而不是让内核去解引用已经释放的内存。
		 */
		atomic64_inc(&sk_off_orphan);
	}
	atomic64_inc(&sk_reverted);
}

/*
 * 「当前进程是否处在影子权限窗口内」
 *
 * override_creds(sk_root_cred) 之后 current->cred 就是 sk_root_cred
 * 这个对象本身，所以直接比较指针即可，不需要任何额外状态。
 */
static bool sk_cred_is_ours(const struct cred *cred);

static inline bool sk_in_window(void)
{
	/*
	 * 已授权任务视为「永久在窗口内」。
	 *
	 * 因为 0.12.0 改成提权后不撤销，所以我们不能再用
	 * 「cred 是不是那份全局 root cred」来判断 —— 每个任务的 cred
	 * 是自己复制出来的。改用授权表判断，语义更直接：
	 *     有授权 → 它的 SELinux 拒绝一律放行
	 */
	if (sk_granted_task(current))
		return true;

	/*
	 * 超级用户模式调过 commit_creds 之后，real_cred 的 uid 已经是 0，
	 * 按 uid 查表查不到了。但 current->cred 正是我们缓存的那份，
	 * 按指针认回来 —— 否则会出现「uid 是 0 了，权限钩子反而不认」。
	 */
	if (sk_cred_is_ours(current->cred))
		return true;
	return sk_root_cred && current->cred == sk_root_cred;
}


/* ══════════════════ 一次性永久提权 ══════════════════ */

/*
 * 已授权任务：把 subjective cred 换成 root，然后**永不撤销**。
 *
 * 为什么不撤销：
 *   · 没有 revert 就不会有「撤销时 cred 已被别人换掉」的 double-free
 *   · 进程退出时内核 exit_creds() 自己释放，引用计数天然平衡
 *   · 每个 syscall 不再需要 override/revert，热路径零开销
 *
 * 幂等：已经在 root cred 上就直接返回，不会重复加引用。
 */
/* ══════════════════ commit_creds（未导出，用 kprobe 取址）══════════════════ */

/*
 * GKI 不导出 commit_creds，modpost 会报 undefined。
 * 用 kprobe 按符号名注册一次，读 kp.addr 就拿到真实地址 ——
 * 只用到导出的 register_kprobe/unregister_kprobe，不需要 kallsyms。
 */
static struct kprobe sk_kp_commit = {
	.symbol_name = "commit_creds",
};
static int (*sk_commit_creds)(struct cred *new);

static int sk_resolve_commit_creds(void)
{
	int rc = register_kprobe(&sk_kp_commit);

	if (rc) {
		pr_warn(SK_TAG "commit_creds 取址失败 rc=%d（超级用户模式不可用）\n", rc);
		return rc;
	}
	sk_commit_creds = (void *)sk_kp_commit.addr;
	unregister_kprobe(&sk_kp_commit);
	pr_info(SK_TAG "commit_creds @%px\n", sk_commit_creds);
	return 0;
}

/* ══════════════════ SELinux 域转换 ══════════════════ */

/*
 * SELinux 的 per-task 安全结构体。
 * cred->security 就指向它，sid 字段是当前域。
 */
struct sk_task_sec {
	u32 osid;
	u32 sid;		/* ← 当前域 */
	u32 exec_sid;
	u32 create_sid;
	u32 keycreate_sid;
	u32 sockcreate_sid;
};

static struct kprobe sk_kp_secctx __attribute__((unused)) = {
	.symbol_name = "security_secctx_to_secid",
};
static int (*sk_secctx_to_secid)(const char *secdata, u32 seclen, u32 *secid) __attribute__((unused));

/* u:r:su:s0 的 sid，init 时算好 */
static u32 sk_su_sid __attribute__((unused));

static void sk_resolve_secctx(void)
{
	/*
	 * ★ 已废弃：不再解析 SELinux 的任何符号 ★
	 *
	 * 域切换没了，就不需要 security_secctx_to_secid，
	 * 也不需要把 "u:r:ksu:s0" 之类的字符串换成 sid。
	 *
	 * 这样我们对 SELinux 的依赖降为零：
	 *   · 不改策略
	 *   · 不改状态（不 setenforce）
	 *   · 不换域
	 *   · 连 SELinux 的符号都不查
	 * 只在 LSM 钩子返回处做「对已授权 uid 把拒绝改成放行」。
	 */
}

/* 把一个 cred 的域改成 u:r:su:s0。cred 必须是我们自己刚造的。 */
static void sk_cred_to_su_domain(struct cred *c)
{
	/*
	 * ★ 已废弃：不再修改任何 LSM 的 cred blob ★
	 *
	 * 为什么废掉（源码核实过的两个硬错误）：
	 *
	 *   ① cred->security 不是 SELinux 的结构体，而是所有 LSM 的复合 blob。
	 *      真正的 SELinux 结构体在：
	 *          selinux_cred(cred) = cred->security + selinux_blob_sizes.lbs_cred
	 *      本机 CONFIG_LSM="landlock,...,selinux,..."，landlock 排在前面且
	 *      也申请了 cred blob → lbs_cred != 0
	 *      → 原来在偏移 0 写入，实际写进的是 landlock 的 blob，不是 SELinux 的
	 *      → 每次 pid 级提权都在破坏 landlock 的 cred 结构
	 *
	 *   ② struct task_security_struct 带 __randomize_layout 标注。
	 *      开了 CONFIG_RANDSTRUCT 的内核上字段顺序会被随机打乱，
	 *      osid@0 / sid@4 这个假设直接失效，写下去就是随机内存破坏。
	 *      本机侥幸是 RANDSTRUCT_NONE，换机型必踩。
	 *
	 * 而且功能上根本不需要它：
	 *   影子权限靠「按 uid 放行 LSM 判定」实现，
	 *   capability 检查靠 cap_capable 钩子，
	 *   换域只是「顺便改一下 /proc/self/attr/current 显示什么」，
	 *   对能力没有任何贡献 —— 反而是个检测信号。
	 *
	 * 结论：SELinux 域保持应用原值，一个字节都不碰。
	 */
	(void)c;
}

#define SK_UM_ACT_HIDE   0
#define SK_UM_ACT_DENY   1
#define SK_UM_ACT_EPERM  2
#define SK_UM_ACT_OK     3
#define SK_UM_ACT_EMPTY  4	/* 判定点4：读出来是 0 字节（EOF） */
#define SK_UM_ACT_ZERO   5	/* 判定点4：读出来是一串 0x00 */
#define SK_UM_ACT_FAKE   6	/* 判定点4：读出来是我们指定的内容 */

/*
 * 判定点4 的 fake 载荷上限。
 * 64 字节足够覆盖「假序列号 / 假型号 / 假 CPU 名」这类短内容，
 * 而 128 条规则 × 64 字节 = 8 KB，静态分配可接受。
 */
#define SK_UM_PAYLOAD_MAX 64

/* 前向声明：规则表的实现在下面，开机加载要先用 */
static int sk_um_add(u32 uid, u32 dev, u64 ino, int act);
/* 判定点⑤：进程隐藏名单（定义在下面，写入路径先用） */
static int sk_hp_add(pid_t pid);
static void sk_hp_clear(void);

static int sk_um_act_parse(const char *s);
static bool sk_um_uid_match(u32 uid);
static void sk_write_manager_uid(int uid);
/* 自家 /proc/sk/grant 的 inode —— 用来给影子模式开写白名单 */
static u64 sk_own_ino[8];
static int sk_own_ino_n;

static bool sk_ugrant_has(u32 uid);
static void sk_save_grants(void);
static void sk_load_grants(void);

/*
 * ★ MAC 层放行判据（与 DAC 分开）★
 *
 * 三种授权模式的语义差别就在这里：
 *
 *   SHADOW(0)  DAC 放行 + MAC 放行  → 透明读写一切，但有 denial 被抑制
 *   SUPER(1)   = SHADOW + 可写授权表 → 子进程能拿真 uid 0
 *   FULL(2)    只 DAC 放行，MAC 一律不碰
 *              → MAC 层行为和干净设备完全一样（零异常信号）
 *              → 代价：/data/adb、/system 这些 MAC 拒绝的路径读不了，
 *                要走内核代读接口
 *
 * 这个判据只给 LSM 钩子用；DAC 侧用 sk_uid_privileged()（三种模式都放行）。
 */
static bool sk_mac_bypass_ok(void)
{
	int m;

	if (sk_in_window())
		return true;			/* 我们自己的提权窗口，照旧 */

	m = sk_grant_mode_uid(__kuid_val(current_uid()));
	if (m < 0)
		return false;
	if (m == SK_GRANT_FULL)
		return false;			/* ★ 完全影子：不碰 MAC ★ */
	return true;
}

static bool sk_bypass_ok(void);
static void sk_mkdirs(void);

/*
 * ★ 把崩溃现场抄到 shell 能读的地方 ★
 *
 * 问题：Android 15 上 shell(uid 2000) 读不到
 *         dmesg     （要 CAP_SYSLOG）
 *         pstore    （pstore 目录下的文件，root-only）
 *         dropbox   （/data/system/dropbox，root-only）
 *   而给 shell 授权又得靠管理器 App —— 它一开就崩，死循环。
 *
 * 破法：内核是 root 身份，让它自己抄一份到 /data/local/tmp/（shell 可读）。
 *      这一步在工作队列里做（可以睡眠），只在每次开机后做一次。
 *
 * 抄三样东西：
 *   umbral_pstore.txt  ← 上次 panic 的现场（有就抄，没有就空）
 *   umbral_dmesg.txt   ← 本次开机的内核日志（含我们模块的全部 pr_info）
 *   umbral_ver.txt     ← 版本 + hook 位图，一眼看出刷的是哪版
 */
static void sk_dump_logs(void)
{
	/*
	 * 内核直接抄，不用 usermodehelper（实测 umh 在你设备上跑不起来）。
	 *
	 *   pstore → /data/local/tmp/umbral_pstore.txt   （上次 panic 现场）
	 *   版本   → /data/local/tmp/umbral_ver.txt      （刷的哪一版）
	 */
	long n;

	n = sk_kcopy("/sys/fs/pstore/console-ramoops",
		     "/data/local/tmp/umbral_pstore.txt");
	pr_info(SK_TAG "pstore 抄出 %ld 字节\n", n);

	sk_kwrite("/data/local/tmp/umbral_ver.txt",
		  SK_VERSION "\n", strlen(SK_VERSION "\n"), 0644);
	sk_kwrite("/data/local/tmp/umbral_su.txt",
		  SK_SU_PATH "\n", strlen(SK_SU_PATH "\n"), 0644);
}


static void sk_create_su(void);
static void sk_probe_domains(void);
static int sk_domains_register(struct proc_dir_entry *dir);
static int sk_deny_register(struct proc_dir_entry *dir);
static void sk_deny_record(int mask, bool mac);
static void sk_dump_logs(void);
static bool sk_acc_registered;
static void sk_acc_register(void);
static void sk_exec_register(void);
static int sk_io_register(struct proc_dir_entry *dir);
static void sk_exec_unregister(void);
static void sk_acc_unregister(void);
static bool sk_guard_check(struct inode *ino);
static void sk_guard_refresh(void);
static void sk_guard_ensure(void);
static int sk_guard_register(struct proc_dir_entry *dir);
static int sk_feature_open(struct inode *i, struct file *f);
static int sk_feature_register(struct proc_dir_entry *dir);
static ssize_t sk_feature_write(struct file *f, const char __user *ubuf, size_t len, loff_t *off);
static bool sk_is_mgr_main_thread(void);
static int sk_scan_for_manager(void);
static int sk_claim_show(struct seq_file *m, void *v);
static ssize_t sk_claim_write(struct file *f, const char __user *ubuf,
			      size_t len, loff_t *off);
static int sk_ugrant_add(u32 uid, u8 mode);
static int sk_um_load_hex(const char *hex, size_t len);
static int sk_um_action(u32 uid, u32 dev, u64 ino);
static int sk_um_act_errno(int act);

/* ══════════════════ vfs_getattr 探针 ══════════════════ */

/*
 * 只为校准参数位置，不做任何伪造。
 *
 * vfs_getattr(const struct path *path, struct kstat *stat,
 *             u32 request_mask, unsigned int flags)
 *   —— 上面的签名是**假设**，必须实测确认。
 *
 * 判据：
 *   ① x0/x1 里一个是 struct path*，一个是 struct kstat*
 *   ② kstat->ino 应该等于用户态 stat 出来的 ino
 *   ③ request_mask / flags 是小数字
 */
static int sk_umstat_uid = -1;
static atomic_t sk_umstat_left = ATOMIC_INIT(0);
/*
 * 二分定位用：对指定 uid 的 getattr 结果，在 kstat+off 处写 value。
 * 看用户态 stat 输出哪个字段变了，就知道 off 对应哪个字段。
 * 定位完这些变量会被真正的伪造逻辑取代。
 */
/* struct kstat 里 ino 的字节偏移（6.6 arm64 实测推测值） */
#define SK_KSTAT_INO_OFF  24
/* 允许写入的最大偏移 —— struct kstat 约 144 字节，留 8 字节给 u64 */
#define SK_KSTAT_MAX_OFF  128

/* 
 * 属性伪造规则表。
 * 每条 = 「对某个 uid，某个 inode 报告成这个大小/权限」。
 * 和 UM 的隐藏规则是两套 —— 隐藏管「能不能打开」，这里管「stat 看到什么」。
 */
#define SK_USTAT_MAX 64

/*
 * struct kstat 的字段偏移 —— BTF 校准值（PC 解析 /sys/kernel/btf/vmlinux）
 *
 *   result_mask 0  mode 4  nlink 8  blksize 12  ino 32  dev 40  rdev 44
 *   uid 48  gid 52  size 56  atime 64  mtime 80  ctime 96  blocks 128
 *
 * ★ size 是 56，不是 96。我最初猜 96，差 40 字节 ——
 *   写下去就是踩坏内核栈，直接 panic。这个教训写在技能档案里。
 */
#define SK_KSTAT_MODE   4
#define SK_KSTAT_INO    32
#define SK_KSTAT_UID    48
#define SK_KSTAT_GID    52
#define SK_KSTAT_SIZE   56
#define SK_KSTAT_ATIME  64
#define SK_KSTAT_MTIME  80
#define SK_KSTAT_CTIME  96

struct sk_ustat_rule {
	u32 uid;
	u32 dev;
	u64 ino;
	u64 size;
	u16 mode;       /* 0 = 不伪装 */
	/*
	 * 以下是 v1.24 新增的伪造维度。
	 * 全部用「0 = 不伪装」的约定，保持向后兼容：
	 * 老规则 "uid dev ino size mode" 解析出来这几个都是 0，
	 * 行为和老版本完全一致。
	 */
	u64 mtime;      /* 0 = 不伪装 */
	u32 fake_uid;   /* 0 = 不伪装（注意：伪造 uid=0 做不到，用 0xffffffff 表示） */
	u32 fake_gid;
	bool has_uid;
	bool has_gid;
};

static struct sk_ustat_rule sk_ustat[SK_USTAT_MAX];
static int sk_ustat_n;
static DEFINE_SPINLOCK(sk_ustat_lock);

static int sk_ustat_add(u32 uid, u32 dev, u64 ino, u64 size, u16 mode)
{
	int rc = 0;

	spin_lock(&sk_ustat_lock);
	if (sk_ustat_n >= SK_USTAT_MAX) {
		rc = -ENOSPC;
	} else {
		sk_ustat[sk_ustat_n].uid = uid;
		sk_ustat[sk_ustat_n].dev = dev;
		sk_ustat[sk_ustat_n].ino = ino;
		sk_ustat[sk_ustat_n].size = size;
		sk_ustat[sk_ustat_n].mode = mode;
		sk_ustat[sk_ustat_n].mtime = 0;
		sk_ustat[sk_ustat_n].has_uid = false;
		sk_ustat[sk_ustat_n].has_gid = false;
		sk_ustat_n++;
	}
	spin_unlock(&sk_ustat_lock);
	return rc;
}

/**
 * 追加时间/属主维度到最近一条规则上。
 *
 * 为什么不在 sk_ustat_add 里一次性加参数：
 *   sk_ustat_add 有 5 个参数了，再加 4 个会让两个调用点都变难看；
 *   而写入格式是「一条规则可能有、也可能没有这几个字段」，
 *   分开一个 setter 更清楚。
 */
static void sk_ustat_set_extra(int idx, u64 mtime, u32 fuid, u32 fgid,
			       bool has_uid, bool has_gid)
{
	spin_lock(&sk_ustat_lock);
	if (idx >= 0 && idx < sk_ustat_n) {
		sk_ustat[idx].mtime = mtime;
		sk_ustat[idx].fake_uid = fuid;
		sk_ustat[idx].fake_gid = fgid;
		sk_ustat[idx].has_uid = has_uid;
		sk_ustat[idx].has_gid = has_gid;
	}
	spin_unlock(&sk_ustat_lock);
}

/* 查属性伪造规则；没命中返回 NULL */
/*
 * 只按 (uid, ino) 匹配 —— struct kstat 里没有 dev 字段，
 * inode 号在同一个文件系统内足够区分，跨设备重号概率极低。
 */
static const struct sk_ustat_rule *sk_ustat_find(u32 uid, u64 ino)
{
	const struct sk_ustat_rule *r = NULL;
	int i;

	if (!sk_ustat_n)
		return NULL;

	spin_lock(&sk_ustat_lock);
	for (i = 0; i < sk_ustat_n; i++) {
		if (sk_ustat[i].uid == uid && sk_ustat[i].ino == ino) {
			r = &sk_ustat[i];
			break;
		}
	}
	spin_unlock(&sk_ustat_lock);
	return r;
}

/* 探针模式（保留，用于将来校准） */
static int  sk_umstat_off = -1;
static u64  sk_umstat_val __attribute__((unused));
static u64  sk_umstat_ino __attribute__((unused));

struct sk_stat_data {
	unsigned long a0;
	unsigned long a1;
};

static int sk_getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_stat_data *d = (struct sk_stat_data *)ri->data;

	d->a0 = regs->regs[0];
	d->a1 = regs->regs[1];

	/*
	 * 有属性规则时也必须装 return handler ——
	 * 之前这里只认「调试探针武装」，用规则模式时直接跳过，
	 * 导致规则写进去了却毫无效果（实测踩过）。
	 */
	if (sk_ustat_n) {
		atomic64_inc(&sk_lsm_e_called);
		return 0;
	}

	if (sk_umstat_uid < 0)
		return 1;
	if (__kuid_val(current_uid()) != (u32)sk_umstat_uid)
		return 1;
	if (atomic_read(&sk_umstat_left) <= 0)
		return 1;

	atomic_dec(&sk_umstat_left);
	pr_info(SK_TAG "UMSTAT %d x0=%llx x1=%llx x2=%llx x3=%llx\n",
		current->pid,
		(unsigned long long)regs->regs[0],
		(unsigned long long)regs->regs[1],
		(unsigned long long)regs->regs[2],
		(unsigned long long)regs->regs[3]);
	return 0;
}

/*
 * 返回值里做受控解引用：把 x1 当 struct kstat* 读几个字段。
 * struct kstat 开头（6.6 arm64）大致是：
 *   u32 result_mask; u32 mode; unsigned int nlink;
 *   u32 uid; u32 gid; ... u64 ino; ... u64 size;
 * 偏移不完全确定，所以只读前 32 字节并按 32 位打印，人工比对。
 */
static int sk_getattr_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_stat_data *d = (struct sk_stat_data *)ri->data;
	unsigned long p = d->a1;

	if (p < 0xffff000000000000UL)
		return 0;

	/*
	 * 隐蔽性：未授权调用者 stat 我们的节点 -> 当作不存在（-ENOENT）。
	 *
	 * vfs_getattr(const struct path *path, struct kstat *stat, ...)
	 *   d->a0 = path 指针（内核栈上的 struct path）
	 *   d->a1 = kstat 指针
	 * 目录项过滤只能藏 ls 的输出，stat 仍会成功；这里补上那一刀。
	 *
	 * 只对 sk_own_ino[] 里登记的节点生效，其余路径一个字节都不碰。
	 */
	if (sk_own_ino_n && d->a0 >= 0xffff000000000000UL
	    && !sk_uid_privileged(__kuid_val(current_uid()))) {
		struct path *pt = (struct path *)d->a0;

		if (pt->dentry && pt->dentry->d_inode) {
			u64 ino2 = (u64)pt->dentry->d_inode->i_ino;
			int oi2;

			for (oi2 = 0; oi2 < sk_own_ino_n; oi2++) {
				if (sk_own_ino[oi2] == ino2) {
					regs_set_return_value(regs, -ENOENT);
					atomic64_inc(&sk_lsm_bypass);
					return 0;
				}
			}
		}
	}

	/*
	 * 属性伪造：用 BTF 读到的真实偏移，不猜。
	 * 偏移未知时整个功能自动关闭（退化为「没有这个功能」而不是崩）。
	 */
	/*
	 * 偏移必须落在合理范围内才敢用：
	 *   struct kstat 约 144 字节，size 必然在 80~136，ino 在 16~40
	 * 超出范围说明 BTF 解析有问题，直接放弃（退化成没这个功能）。
	 */
	if (sk_off_kstat_stop) {
		/* 已判定不可信，永不写入 */
	} else if (sk_off_kstat_ino >= 8 && sk_off_kstat_ino <= 64
	    && sk_off_kstat_size >= 24 && sk_off_kstat_size <= 136
	    && sk_ustat_n) {
		u8 *base = (u8 *)p;
		u64 kino = *(u64 *)(base + sk_off_kstat_ino);
		const struct sk_ustat_rule *r =
			sk_ustat_find(__kuid_val(current_uid()), kino);

		if (r) {
			*(u64 *)(base + sk_off_kstat_size) = r->size;
			if (r->mode && sk_off_kstat_mode >= 0)
				*(u16 *)(base + sk_off_kstat_mode) =
					(u16)r->mode;

			/*
			 * v1.24：时间与属主维度。
			 * 偏移来自 BTF 校准（PC 解析 /sys/kernel/btf/vmlinux）：
			 *   uid 48  gid 52  atime 64  mtime 80  ctime 96
			 * struct timespec64 是 16 字节（tv_sec 8 + tv_nsec 8），
			 * 所以只写 tv_sec，nsec 保持原值（对 mtime 比较没影响）。
			 */
			if (r->mtime) {
				*(s64 *)(base + SK_KSTAT_ATIME) = (s64)r->mtime;
				*(s64 *)(base + SK_KSTAT_MTIME) = (s64)r->mtime;
				*(s64 *)(base + SK_KSTAT_CTIME) = (s64)r->mtime;
			}
			if (r->has_uid)
				*(u32 *)(base + SK_KSTAT_UID) = r->fake_uid;
			if (r->has_gid)
				*(u32 *)(base + SK_KSTAT_GID) = r->fake_gid;

			atomic64_inc(&sk_lsm_bypass);
		}
		return 0;
	}

	{
		const u32 *q = (const u32 *)p;
		pr_info(SK_TAG "UMSTAT kstat[0..7]=%08x %08x %08x %08x %08x %08x %08x %08x\n",
			q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7]);
	}
	return 0;
}

static struct kretprobe sk_krp_getattr = {
	.kp.symbol_name = "vfs_getattr",
	.entry_handler  = sk_getattr_entry,
	.handler        = sk_getattr_return,
	.data_size      = sizeof(struct sk_stat_data),
	.maxactive      = 128,
};

static ssize_t sk_umstat_write(struct file *f, const char __user *ubuf,
			       size_t len, loff_t *off)
{
	char buf[32];
	long uid = -1;

	if (!sk_writer_allowed())
		return -EPERM;
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = 0;
	strim(buf);

	if (!strcmp(buf, "off")) {
		sk_umstat_uid = -1;
		pr_info(SK_TAG "UMSTAT off\n");
		return len;
	}
	/* 格式 1: "<uid>"            武装寄存器探针
	 * 格式 2: "<uid> <off> <val> [ino]"  在 kstat+off 写假值（二分定位用）
	 */
	/* "clear" 清空属性伪造规则 */
	if (!strcmp(buf, "clear")) {
		spin_lock(&sk_ustat_lock);
		sk_ustat_n = 0;
		spin_unlock(&sk_ustat_lock);
		pr_info(SK_TAG "UMSTAT 规则已清空\n");
		return len;
	}

	{
		/*
		 * <uid> <dev> <ino> <size> [mode_octal]
		 * mode 用 %o 读八进制（如 777 / 644），不写就不伪装权限。
		 */
		unsigned int dev = 0;
		unsigned long long ino = 0, size = 0, mtime = 0;
		unsigned int mode_oct = 0, fuid = 0, fgid = 0;
		/*
		 * 完整格式（后面的字段可选，缺了就保持原判定）：
		 *   <uid> <dev> <ino> <size> [mode_oct] [mtime] [fake_uid] [fake_gid]
		 */
		int nf = sscanf(buf, "%ld %u %llu %llu %o %llu %u %u",
				&uid, &dev, &ino, &size, &mode_oct,
				&mtime, &fuid, &fgid);

		if (nf < 1 || uid < 0)
			return -EINVAL;

		if (nf >= 4) {
			int rc = sk_ustat_add((u32)uid, dev, (u64)ino,
					      (u64)size, (u16)mode_oct);

			if (rc)
				return rc;
			if (nf >= 6)
				sk_ustat_set_extra(sk_ustat_n - 1, mtime,
						   nf >= 7 ? fuid : 0,
						   nf >= 8 ? fgid : 0,
						   nf >= 7, nf >= 8);
			pr_info(SK_TAG "UMSTAT 规则: uid=%ld dev=%u ino=%llu size=%llu mode=%o mtime=%llu fuid=%u fgid=%u\n",
				uid, dev, (unsigned long long)ino,
				(unsigned long long)size, mode_oct,
				(unsigned long long)mtime, fuid, fgid);
			return len;
		}

		sk_umstat_uid = (int)uid;
		sk_umstat_off = -1;
		atomic_set(&sk_umstat_left, 6);
		pr_info(SK_TAG "UMSTAT armed uid=%ld\n", uid);
		return len;
	}
}

static int sk_umstat_show(struct seq_file *m, void *v)
{
	seq_printf(m, "uid  %d\n", sk_umstat_uid);
	seq_printf(m, "left %d\n", atomic_read(&sk_umstat_left));
	seq_printf(m, "hook %s\n", sk_krp_getattr.kp.addr ? "on" : "off");
	return 0;
}

/* ══════════════════ UM 开机解密加载 ══════════════════ */

/*
 * 自研流密码（用于 UM 载荷落盘保护）。
 *
 * 为什么不是 AES：GKI 没导出 crypto_alloc_cipher，拿不到 tfm。
 * 为什么自研够用：威胁模型是「有人翻 /data/adb 看到明文规则」这种顺手提取，
 *   不是国家级对手；配上 VM 混淆后强度已超出该模型，换来内核侧只有 20 行。
 *
 * 两端必须完全一致：
 *   ks[i] = S[(i*7 + K[0]) & 0xFF] ^ K[i % 16] ^ (i & 0xFF)
 *   out[i] = in[i] ^ ks[i]          （对称）
 */
static const u8 sk_um_sbox[256] = {
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

/* 16 字节固定密钥（和管理器侧 UmStreamCipher 必须一致） */
static const u8 sk_um_key[16] = {
	0x5A, 0xC3, 0x1E, 0x97, 0x4B, 0x08, 0xE2, 0x6D,
	0x31, 0xFC, 0x85, 0x2A, 0xD9, 0x70, 0x14, 0xBE,
};

static void sk_um_crypt(u8 *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		u8 ks = sk_um_sbox[(u8)(i * 7 + sk_um_key[0])]
			^ sk_um_key[i % 16]
			^ (u8)(i & 0xFF);
		buf[i] ^= ks;
	}
}

#define SK_UM_BOOT_FILE "/data/adb/umbral/um/boot.umbc"
#define SK_UM_BOOT_MAX  16384

/*
 * 开机加载：读 /data/adb/umbral/um/boot.umbc，解密，逐行解析规则。
 * 文件格式（解密后是文本）：
 *      # 注释
 *      uid <uid> dev <dev> ino <ino>
 * init 上下文可睡眠，所以这里可以正常读文件。
 */
static void sk_um_bootload(void)
{
	struct file *f;
	u8 *buf;
	ssize_t n;
	loff_t pos = 0;
	char *line, *next;
	int applied = 0;

	if (!sk_resolve_file_api())
		return;

	f = sk_filp_open(SK_UM_BOOT_FILE, O_RDONLY, 0);
	if (IS_ERR(f))
		return;			/* 没这个文件就是没规则，正常 */

	buf = vzalloc(SK_UM_BOOT_MAX);
	if (!buf) {
		sk_filp_close(f, NULL);
		return;
	}

	n = sk_kernel_read(f, buf, SK_UM_BOOT_MAX - 1, &pos);
	sk_filp_close(f, NULL);
	if (n <= 0) {
		vfree(buf);
		return;
	}
	buf[n] = 0;

	/* 解密 */
	sk_um_crypt(buf, (size_t)n);

	/* 逐行解析 */
	for (line = (char *)buf; line && *line; line = next) {
		unsigned int uid, dev;
		unsigned long long ino;

		next = strchr(line, '\n');
		if (next)
			*next++ = 0;
		strim(line);
		if (!*line || *line == '#')
			continue;
		if (!strncmp(line, "bc ", 3)) {
			if (sk_um_load_hex(line + 3, strlen(line + 3)) == 0)
				applied++;
			continue;
		}
		{
			char a[16];
			int act = SK_UM_ACT_HIDE;
			int nf;

			a[0] = 0;
			nf = sscanf(line, "uid %u dev %u ino %llu %15s",
				    &uid, &dev, &ino, a);
			if (nf >= 3) {
				if (nf >= 4) {
					act = sk_um_act_parse(a);
					if (act < 0)
						act = SK_UM_ACT_HIDE;
				}
				if (sk_um_add(uid, dev, (u64)ino, act) == 0)
					applied++;
			}
		}
	}

	vfree(buf);
	pr_info(SK_TAG "UM 开机加载：%d 条规则\n", applied);
}

/* ══════════════════ UM 规则模块（第三种模块机制）══════════════════ */

/*
 * UM = Umbral Module。它不是代码，是**规则**。
 *
 * 已有两种模块机制的问题：
 *   .ko   —— 要 insmod，/proc/modules 留痕，而且只能改「行为」不能改「世界」
 *   .kpm  —— 要 ELF 重定位，权限高但仍要驻留内核对象
 *
 * UM 的做法：内核里只有一台解释器（本模块），UM 本身只是写给它的规则。
 *   磁盘上没有任何内核产物 → 关掉模块后什么痕迹都没有
 *   能改「世界的样子」而不是「某个操作的结果」→ 权限比前两者高
 *
 * 第一个原语：按 uid 隐藏文件。
 *   规则 = (uid, dev, ino) → 对该 uid 来说这个 inode 不存在（-ENOENT）。
 *   用 inode 身份而不是路径 —— kprobe 里拿不到路径，inode 身份也稳定。
 */
/*
 * 动作类型。
 *   hide  → -ENOENT   文件像不存在（检测扫描最怕这个）
 *   deny  → -EACCES   存在但拒绝访问
 *   eperm → -EPERM    不允许
 *   ok    → 0         强制放行（配合 deny 做白名单外的通配）
 */
struct sk_um_rule {
	u32 uid;
	u32 dev;
	u64 ino;
	u8  act;
	/* 判定点4：fake 载荷（act == SK_UM_ACT_FAKE 时有效） */
	u8  payload[SK_UM_PAYLOAD_MAX];
	u8  plen;
};

#define SK_UM_MAX 128

/*
 * UM 隐藏开关，**默认关**。
 *
 * 原因：selinux_inode_permission 的 inode 参数偏移还没校准，
 * 解引用 regs->regs[1] 会 panic（实测崩了两次设备）。
 * 在偏移确认之前不允许它生效 —— 规则可以建、可以列，
 * 但不会真的去解引用 inode，所以是安全的。
 *
 * 校准办法（下轮）：insmod 时用 um=1 打开，配合
 *   /proc/sk/umdbg 记录 regs 各寄存器与已知 inode 的对比。
 */
/*
 * UM 隐藏开关。inode 参数位置已实测确认（x0），可以默认开启。
 * 万一某台设备内核版本不同导致偏移不对，insmod um=0 可关掉。
 */
static int sk_um_enable = 1;
module_param_named(um, sk_um_enable, int, 0444);
MODULE_PARM_DESC(um, "1 = enable UM hiding (default 1; verified inode arg = x0)");

static struct sk_um_rule sk_um[SK_UM_MAX];
static int sk_um_n;
static DEFINE_SPINLOCK(sk_um_lock);

/* 这个 uid 有没有任何规则（便宜，先做这层过滤，避免无谓解引用 inode） */
static bool sk_um_uid_match(u32 uid)
{
	int i;
	bool hit = false;

	if (!sk_um_n)
		return false;

	spin_lock(&sk_um_lock);
	for (i = 0; i < sk_um_n; i++) {
		if (sk_um[i].uid == uid) {
			hit = true;
			break;
		}
	}
	spin_unlock(&sk_um_lock);
	return hit;
}

/* ── UM 字节码 VM（与 Java 侧 UmBytecode 语义一致）── */

#define UM_OP_END       0x00
#define UM_OP_PUSH_UID  0x01
#define UM_OP_PUSH_DEV  0x02
#define UM_OP_PUSH_INO  0x03
#define UM_OP_PUSH_U32  0x04
#define UM_OP_PUSH_U64  0x05
#define UM_OP_EQ        0x10
#define UM_OP_AND       0x11
#define UM_OP_JZ        0x12
#define UM_OP_JMP       0x13
#define UM_OP_RET       0x20

#define SK_UM_PROG_MAX  4096
#define SK_UM_STACK     32

static u8 sk_um_prog[SK_UM_PROG_MAX];
static int sk_um_prog_len;

static u32 um_rd32(int off)
{
	return (u32)sk_um_prog[off]
		| ((u32)sk_um_prog[off + 1] << 8)
		| ((u32)sk_um_prog[off + 2] << 16)
		| ((u32)sk_um_prog[off + 3] << 24);
}

static u64 um_rd64(int off)
{
	u64 v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = (v << 8) | sk_um_prog[off + i];
	return v;
}

/*
 * 跑一遍字节码。返回 errno：0 = 放行，-2 = ENOENT。
 * 任何异常路径都返回 0 —— 宁可放行也不能崩。
 */
static int sk_um_vm(u32 uid, u32 dev, u64 ino)
{
	s64 st[SK_UM_STACK];
	int sp = 0;
	int pc = 0;
	int steps = 0;
	int limit;

	if (sk_um_prog_len <= 0)
		return 0;

	limit = sk_um_prog_len * 4 + 64;

	while (pc < sk_um_prog_len && steps++ < limit) {
		u8 op = sk_um_prog[pc++];

		switch (op) {
		case UM_OP_END:
			return 0;
		case UM_OP_PUSH_UID:
			if (sp >= SK_UM_STACK)
				return 0;
			st[sp++] = (s64)uid;
			break;
		case UM_OP_PUSH_DEV:
			if (sp >= SK_UM_STACK)
				return 0;
			st[sp++] = (s64)dev;
			break;
		case UM_OP_PUSH_INO:
			if (sp >= SK_UM_STACK)
				return 0;
			st[sp++] = (s64)ino;
			break;
		case UM_OP_PUSH_U32:
			if (pc + 4 > sk_um_prog_len || sp >= SK_UM_STACK)
				return 0;
			st[sp++] = (s64)um_rd32(pc);
			pc += 4;
			break;
		case UM_OP_PUSH_U64:
			if (pc + 8 > sk_um_prog_len || sp >= SK_UM_STACK)
				return 0;
			st[sp++] = (s64)um_rd64(pc);
			pc += 8;
			break;
		case UM_OP_EQ:
			if (sp < 2)
				return 0;
			{
				s64 b = st[--sp];
				s64 a = st[--sp];
				st[sp++] = (a == b) ? 1 : 0;
			}
			break;
		case UM_OP_AND:
			if (sp < 2)
				return 0;
			{
				s64 b = st[--sp];
				s64 a = st[--sp];
				st[sp++] = (a && b) ? 1 : 0;
			}
			break;
		case UM_OP_JZ:
			if (pc + 2 > sk_um_prog_len || sp < 1)
				return 0;
			{
				int tgt = (int)sk_um_prog[pc]
					| ((int)sk_um_prog[pc + 1] << 8);
				s64 v;
				pc += 2;
				v = st[--sp];
				if (!v) {
					/* 只允许向前跳，杜绝死循环 */
					if (tgt <= pc || tgt >= sk_um_prog_len)
						return 0;
					pc = tgt;
				}
			}
			break;
		case UM_OP_JMP:
			if (pc + 2 > sk_um_prog_len)
				return 0;
			{
				int tgt = (int)sk_um_prog[pc]
					| ((int)sk_um_prog[pc + 1] << 8);
				pc += 2;
				if (tgt <= pc || tgt >= sk_um_prog_len)
					return 0;
				pc = tgt;
			}
			break;
		case UM_OP_RET:
			if (pc + 4 > sk_um_prog_len)
				return 0;
			return (int)um_rd32(pc);
		default:
			return 0;	/* 不认识的操作码 → 放行 */
		}
	}
	return 0;
}

/* 把十六进制串解析成程序 */
static int sk_um_load_hex(const char *hex, size_t len)
{
	int n = 0;

	if (len & 1)
		return -EINVAL;

	while (len >= 2 && n < SK_UM_PROG_MAX) {
		int hi, lo;

		{
			char c1 = hex[0], c2 = hex[1];

			hi = (c1 >= '0' && c1 <= '9') ? c1 - '0'
			   : (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10
			   : (c1 >= 'A' && c1 <= 'F') ? c1 - 'A' + 10 : -1;
			lo = (c2 >= '0' && c2 <= '9') ? c2 - '0'
			   : (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10
			   : (c2 >= 'A' && c2 <= 'F') ? c2 - 'A' + 10 : -1;
		}

		if (hi < 0 || lo < 0)
			return -EINVAL;
		sk_um_prog[n++] = (u8)((hi << 4) | lo);
		hex += 2;
		len -= 2;
	}
	sk_um_prog_len = n;
	pr_info(SK_TAG "UM 字节码已载入 %d 字节\n", n);
	return 0;
}

/* ── 寄存器探针：用来校准 inode 到底在哪个参数里 ── */
static int sk_umdbg_uid = -1;
static atomic_t sk_umdbg_left = ATOMIC_INIT(0);

/*
 * 查规则，返回该应用的动作；没命中返回 -1。
 * 返回 errno 的约定：SK_UM_ACT_* 常量，调用方自己翻译成 errno。
 */
static int sk_um_action(u32 uid, u32 dev, u64 ino)
{
	int i;
	int act = -1;

	if (!sk_um_n)
		return -1;

	spin_lock(&sk_um_lock);
	for (i = 0; i < sk_um_n; i++) {
		if (sk_um[i].uid == uid && sk_um[i].dev == dev
		    && sk_um[i].ino == ino) {
			act = sk_um[i].act;
			break;
		}
	}
	spin_unlock(&sk_um_lock);
	return act;
}

/* 动作 → errno */
static int sk_um_act_errno(int act)
{
	switch (act) {
	case SK_UM_ACT_HIDE:
		return -ENOENT;
	case SK_UM_ACT_DENY:
		return -EACCES;
	case SK_UM_ACT_EPERM:
		return -EPERM;
	default:
		return 0;
	}
}

static int sk_um_add(u32 uid, u32 dev, u64 ino, int act)
{
	int rc = 0;

	spin_lock(&sk_um_lock);
	if (sk_um_n >= SK_UM_MAX) {
		rc = -ENOSPC;
	} else {
		sk_um[sk_um_n].uid = uid;
		sk_um[sk_um_n].dev = dev;
		sk_um[sk_um_n].ino = ino;
		sk_um[sk_um_n].act = (u8)act;
		sk_um[sk_um_n].plen = 0;
		memset(sk_um[sk_um_n].payload, 0, SK_UM_PAYLOAD_MAX);
		sk_um_n++;
	}
	spin_unlock(&sk_um_lock);
	return rc;
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/**
 * 给最近一条规则设 fake 载荷（hex 字符串解码）。
 *
 * @param hex 形如 "4e58373639" （"NX769" 的 hex）
 * @return 0 成功；-EINVAL 非法；-ENAMETOOLONG 超长
 *
 * ★ 只在写规则的进程上下文调用（可睡眠），不在钩子里。
 */
static int sk_um_set_payload_hex(const char *hex)
{
	u8 tmp[SK_UM_PAYLOAD_MAX];
	int n = 0;

	if (!hex)
		return -EINVAL;
	while (hex[0] && hex[1] && n < SK_UM_PAYLOAD_MAX) {
		int hi = hexval(hex[0]);
		int lo = hexval(hex[1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;
		tmp[n++] = (u8)((hi << 4) | lo);
		hex += 2;
	}
	if (hex[0])
		return -ENAMETOOLONG;
	if (n == 0)
		return -EINVAL;

	spin_lock(&sk_um_lock);
	if (sk_um_n > 0) {
		memcpy(sk_um[sk_um_n - 1].payload, tmp, n);
		sk_um[sk_um_n - 1].plen = (u8)n;
	}
	spin_unlock(&sk_um_lock);
	return 0;
}

/**
 * 取某条规则的 fake 载荷（自带锁）。
 * @return 载荷长度；0 表示没有
 */
static u8 sk_um_payload(u32 uid, u32 dev, u64 ino, u8 *out, u8 outmax)
{
	u8 n = 0;
	int i;

	spin_lock(&sk_um_lock);
	for (i = 0; i < sk_um_n && n == 0; i++) {
		if (sk_um[i].uid == uid && sk_um[i].dev == dev
		    && sk_um[i].ino == ino && sk_um[i].plen > 0) {
			n = sk_um[i].plen < outmax ? sk_um[i].plen : outmax;
			memcpy(out, sk_um[i].payload, n);
		}
	}
	spin_unlock(&sk_um_lock);
	return n;
}

/* 动作名 → 动作号；不认识返回 -1 */
static int sk_um_act_parse(const char *s)
{
	if (!strcmp(s, "hide"))
		return SK_UM_ACT_HIDE;
	if (!strcmp(s, "deny"))
		return SK_UM_ACT_DENY;
	if (!strcmp(s, "eperm"))
		return SK_UM_ACT_EPERM;
	if (!strcmp(s, "ok"))
		return SK_UM_ACT_OK;
	if (!strcmp(s, "empty"))
		return SK_UM_ACT_EMPTY;
	if (!strcmp(s, "zero"))
		return SK_UM_ACT_ZERO;
	if (!strcmp(s, "fake"))
		return SK_UM_ACT_FAKE;
	return -1;
}

/* ══════════════════ 提权 cred 缓存 ══════════════════ */

/*
 * 为什么需要这张表 —— 这是设备崩了两次换来的教训。
 *
 * prepare_creds() 内部是 kmem_cache_alloc(cred_jar, GFP_KERNEL)，
 * **会睡眠**。而我们的提权钩子挂在 kretprobe 的 entry handler 上，
 * 那是原子上下文（preempt 已关、可能中断已关）。在原子上下文里睡眠
 * 就是 "sleeping function called from invalid context" → panic。
 *
 * 之前只授一两个 shell 没崩，是因为提权只发生一两次、分配刚好不需要
 * 真正睡下去。给整个 App 授权时，它几十个线程每个都要提权一次，
 * 必然撞上真正需要睡眠的那次分配 —— 于是崩。
 *
 * 解法：把「造 cred」这件事挪到工作队列（可以睡眠），造好之后缓存起来。
 * 提权路径上只剩 override_creds()，那只是引用计数操作，原子安全。
 */
struct sk_cred {
	struct hlist_node node;
	struct rcu_head rcu;
	u32 uid;
	u8  mode;
	struct cred *cred;
};

#define SK_CRED_BITS 6
#define SK_CRED_MAX  64

static DEFINE_HASHTABLE(sk_creds, SK_CRED_BITS);
static DEFINE_SPINLOCK(sk_cred_lock);
static atomic_t sk_cred_n = ATOMIC_INIT(0);

/* 待构建请求（原子上下文里只登记，不构建） */
struct sk_cred_req {
	struct work_struct work;
	u32 uid;
	u8  mode;
};

static struct workqueue_struct *sk_wq;

/*
 * 待构建登记表。
 *
 * ★ 没有这张表会出大事 ★
 *   hook 在缓存未命中时会被每个 syscall 调用一次。如果每次都
 *   kmalloc + queue_work，一个 App 每秒上万次系统调用就能把工作队列
 *   和内存灌爆 —— 0.18.0 就是这么把设备搞崩的。
 *   所以同一 (uid, mode) 只登记一次，做完再摘掉。
 */
struct sk_pending {
	u32 uid;
	u8  mode;
};

#define SK_PENDING_MAX 32
static struct sk_pending sk_pending[SK_PENDING_MAX];
static int sk_pending_n;
static DEFINE_SPINLOCK(sk_pending_lock);

/* 是否已登记（原子安全） */
static bool sk_pending_has(u32 uid, u8 mode)
{
	int i;
	bool found = false;

	spin_lock(&sk_pending_lock);
	for (i = 0; i < sk_pending_n; i++) {
		if (sk_pending[i].uid == uid && sk_pending[i].mode == mode) {
			found = true;
			break;
		}
	}
	spin_unlock(&sk_pending_lock);
	return found;
}

static bool sk_pending_add(u32 uid, u8 mode)
{
	bool ok = false;

	spin_lock(&sk_pending_lock);
	if (sk_pending_n < SK_PENDING_MAX) {
		sk_pending[sk_pending_n].uid = uid;
		sk_pending[sk_pending_n].mode = mode;
		sk_pending_n++;
		ok = true;
	}
	spin_unlock(&sk_pending_lock);
	return ok;
}

static void sk_pending_del(u32 uid, u8 mode)
{
	int i;

	spin_lock(&sk_pending_lock);
	for (i = 0; i < sk_pending_n; i++) {
		if (sk_pending[i].uid == uid && sk_pending[i].mode == mode) {
			sk_pending[i] = sk_pending[sk_pending_n - 1];
			sk_pending_n--;
			break;
		}
	}
	spin_unlock(&sk_pending_lock);
}

/* 按 uid 找 task（工作队列里用，可以睡眠） */
static struct task_struct *sk_find_task_by_uid(u32 uid)
{
	struct task_struct *t, *found = NULL;

	rcu_read_lock();
	for_each_process(t) {
		if (__kuid_val(__task_cred(t)->uid) == uid) {
			get_task_struct(t);
			found = t;
			break;
		}
	}
	rcu_read_unlock();
	return found;
}

/* 查缓存（RCU，原子安全） */
static struct cred *sk_cred_lookup(u32 uid, u8 mode)
{
	struct sk_cred *c;
	struct cred *ret = NULL;

	if (atomic_read(&sk_cred_n) == 0)
		return NULL;

	rcu_read_lock();
	hlist_for_each_entry_rcu(c, &sk_creds[hash_min(uid, SK_CRED_BITS)], node) {
		if (c->uid == uid && c->mode == mode) {
			ret = c->cred;
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}

/*
 * 判断一个 cred 是不是我们发出去的。
 *
 * 为什么需要：
 *   超级用户模式真的调了 commit_creds，之后 real_cred 的 uid 变成 0，
 *   按 uid 查授权表就查不到了 —— 结果 uid 是 0 了，权限钩子反而不认了
 *   （实测表现：id -u = 0 但读文件 Permission denied）。
 *   而 commit_creds 之后 current->cred 正好就是我们缓存的那份，
 *   所以按指针比对就能把它认回来。
 */
static bool sk_cred_is_ours(const struct cred *cred)
{
	struct sk_cred *c;
	bool found = false;

	if (!cred || atomic_read(&sk_cred_n) == 0)
		return false;

	rcu_read_lock();
	{
		unsigned int bkt;
		hash_for_each_rcu(sk_creds, bkt, c, node) {
			if (c->cred == cred) {
				found = true;
				break;
			}
		}
	}
	rcu_read_unlock();
	return found;
}

/* 放进缓存（工作队列里调用） */
static int sk_cred_install(u32 uid, u8 mode, struct cred *cred)
{
	struct sk_cred *c;

	if (atomic_read(&sk_cred_n) >= SK_CRED_MAX)
		return -ENOSPC;

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return -ENOMEM;

	c->uid  = uid;
	c->mode = mode;
	c->cred = cred;

	spin_lock(&sk_cred_lock);
	hlist_add_head_rcu(&c->node, &sk_creds[hash_min(uid, SK_CRED_BITS)]);
	spin_unlock(&sk_cred_lock);
	atomic_inc(&sk_cred_n);
	return 0;
}

/* 工作队列：真正造 cred（可以睡眠） */
static void sk_cred_work_fn(struct work_struct *work)
{
	struct sk_cred_req *req = container_of(work, struct sk_cred_req, work);
	struct task_struct *t;
	struct cred *c;

	if (sk_cred_lookup(req->uid, req->mode)) {
		goto out;			/* 已经被别人建好了 */
	}

	t = sk_find_task_by_uid(req->uid);
	if (!t) {
		goto out;			/* 该 uid 现在没有进程，下次再试 */
	}

	/*
	 * prepare_kernel_cred(t)：复制 **t 的** cred，
	 * 于是 SELinux 域原样保留（这是 0.11.0 崩用户态的教训）。
	 * 我们在这个上下文里可以睡眠，所以安全。
	 */
	c = prepare_kernel_cred(t);
	put_task_struct(t);
	if (!c)
		goto out;

	/* 两种模式都拉满 caps —— DAC 的 CAP_DAC_OVERRIDE 靠它 */
	memset(&c->cap_inheritable, 0xff, sizeof(kernel_cap_t));
	memset(&c->cap_permitted,   0xff, sizeof(kernel_cap_t));
	memset(&c->cap_effective,   0xff, sizeof(kernel_cap_t));
	memset(&c->cap_bset,        0xff, sizeof(kernel_cap_t));
	memset(&c->cap_ambient,     0xff, sizeof(kernel_cap_t));

	if (req->mode == SK_GRANT_SUPER) {
		c->uid   = GLOBAL_ROOT_UID;
		c->euid  = GLOBAL_ROOT_UID;
		c->suid  = GLOBAL_ROOT_UID;
		c->fsuid = GLOBAL_ROOT_UID;
		c->gid   = GLOBAL_ROOT_GID;
		c->egid  = GLOBAL_ROOT_GID;
		c->sgid  = GLOBAL_ROOT_GID;
		c->fsgid = GLOBAL_ROOT_GID;

		/*
		 * 光有 uid 0 不够 —— 域还是 untrusted_app，SELinux 照样拦。
		 * 这里把域一起换成 u:r:su:s0，才是真正的 su。
		 * 这份 cred 是新造的、security blob 是独立 kmemdup 的，
		 * 改它不影响任何其他任务。
		 */
		sk_cred_to_su_domain(c);
	}

	if (sk_cred_install(req->uid, req->mode, c)) {
		put_cred(c);
	} else {
		pr_info(SK_TAG "cred cached uid=%u mode=%s\n",
			req->uid, req->mode == SK_GRANT_SUPER ? "super" : "shadow");
	}
out:
	sk_pending_del(req->uid, req->mode);
	kfree(req);
}

/* 原子上下文里调用：只登记，不构建 */
static void __maybe_unused sk_cred_request(u32 uid, u8 mode)
{
	struct sk_cred_req *req;

	if (!sk_wq)
		return;

	/* 已经登记过就直接返回 —— 这一句是防雪崩的关键 */
	if (sk_pending_has(uid, mode))
		return;
	if (!sk_pending_add(uid, mode))
		return;			/* 表满，下次再说 */

	req = kmalloc(sizeof(*req), GFP_ATOMIC);
	if (!req) {
		sk_pending_del(uid, mode);
		return;
	}

	INIT_WORK(&req->work, sk_cred_work_fn);
	req->uid  = uid;
	req->mode = mode;
	queue_work(sk_wq, &req->work);
}

static void sk_cred_flush(void)
{
	struct sk_cred *c;
	struct hlist_node *tmp;
	unsigned int bkt;

	spin_lock(&sk_cred_lock);
	hash_for_each_safe(sk_creds, bkt, tmp, c, node) {
		hlist_del_rcu(&c->node);
		put_cred(c->cred);
		kfree_rcu(c, rcu);
	}
	spin_unlock(&sk_cred_lock);
	atomic_set(&sk_cred_n, 0);
}

static noinline __attribute__((used))
bool sk_promote(void)
{
	int mode;
	u32 uid;
	struct cred *c;

	if (sk_nopromote)
		return false;

	mode = sk_grant_mode_task(current);
	if (mode < 0)
		return false;

	/*
	 * ── 影子模式：什么都不做 ──
	 * 权限全靠 cap_capable / generic_permission / selinux_* 拦截，
	 * cred 一个字节都别动。这是唯一不会让 commit_creds 算错引用的做法。
	 */
	if (mode == SK_GRANT_SHADOW)
		return true;

	/*
	 * ── 超级用户模式：就是正常 su 的做法 ──
	 *   真把 uid 改成 0，用的也是内核官方接口 commit_creds()。
	 *
	 * 为什么这里安全、而 override_creds 不安全：
	 *   commit_creds() 会**同时**替换 real_cred 和 cred，两者始终一致，
	 *   所以后续任何 execve/setuid 再调 commit_creds 都不会算错引用。
	 *   override_creds() 只换 cred 不换 real_cred，才会导致多 put。
	 *
	 * 为什么能在 kretprobe 里调用：
	 *   commit_creds 本身不睡眠。会睡眠的是 prepare_creds/alloc，
	 *   而那一步已经在工作队列里做好了（sk_cred_work_fn），这里只取现成的。
	 */
	/*
	 * ★ uid 级 SUPER 不提权，只当影子 ★
	 * 原因见 sk_pid_grant_mode 的注释：App 的子进程会被一起换 uid，
	 * 系统侧判断为进程身份异常，直接崩。
	 * 要真 root，就走 pid 授权（fork 一个 su 子进程自己登记）。
	 */
	if (sk_pid_grant_mode(current) != SK_GRANT_SUPER) {
		atomic64_inc(&sk_promote_ml_skip);
		return true;		/* 判定层已放行，能力等价 */
	}

	if (__kuid_val(current_uid()) == 0)
		return true;			/* 已经是 root 了 */

	uid = __kuid_val(__task_cred(current)->uid);
	if (uid == 0)
		return true;

	c = sk_cred_lookup(uid, SK_GRANT_SUPER);
	if (!c) {
		sk_cred_request(uid, SK_GRANT_SUPER);
		return false;			/* 等下次 syscall，cred 还没造好 */
	}

	if (!sk_commit_creds) {
		sk_resolve_commit_creds();
	sk_resolve_secctx();
		if (!sk_commit_creds)
			return false;
	}

	/*
	 * ★ 走到这里说明是「pid 级显式授权」，可以放心 commit_creds ★
	 *
	 * 历史：v0.61 曾经在这里加过「pid == tgid 就跳过」，
	 *       本意是保护 App 主进程不被 AMS 判异常 —— 但那个判据太宽：
	 *       我们 fork 出来的 sh 自己也是主线程（pid == tgid），
	 *       于是它也被跳过，永远拿不到真 uid 0，
	 *       表现就是「子进程提权后 id -u 还是原值」「写不进 /data/adb」。
	 *
	 * 现在不需要那个跳过了 —— 因为上面的守卫已经区分开：
	 *   · uid 级 SUPER  → sk_pid_grant_mode() 返回 -1 → 早就 return true 走了
	 *                     （App 主进程和它的所有子进程都不会换 uid，永不崩）
	 *   · pid 级 SUPER  → 只有 Shell.root() 专门 fork 出来的那个 sh 才有，
	 *                     它本来就是要变 uid 0 的，必须允许
	 *
	 * 所以这里直接 commit_creds，安全。
	 */

	/* commit_creds 会吃掉一个引用，所以先 get_new_cred 补上 */
	sk_commit_creds(get_new_cred(c));

	/*
	 * ★ 关键：同时写一条 pid 授权 ★
	 *
	 * commit_creds 之后 uid 变成 0，按 uid 查授权表就查不到了；
	 * 而且紧接着程序常常会 execve（su 10560 -c 'xxx' 就是一个），
	 * execve 里的 commit_creds(prepare_exec_creds()) 会把 cred 再换一次，
	 * 于是「按 cred 指针认领」也失效。
	 *
	 * 但 execve **不会换 pid**（同一个进程映像替换），
	 * 所以补一条按 pid+start_time 的授权，就能一路跟到底。
	 */
	sk_grant_add(current, SK_GRANT_SUPER);

	atomic64_inc(&sk_elevated);

	if (atomic64_read(&sk_dbg_elev) < sk_dbg_limit) {
		atomic64_inc(&sk_dbg_elev);
		pr_info(SK_TAG "SU pid=%d comm=%s uid=0 (real commit_creds)\n",
			current->pid, current->comm);
	}
	return true;
}

/* ══════════════════ fork 继承 ══════════════════ */

/*
 * wake_up_new_task(struct task_struct *p) —— p 在 x0
 *
 * 父进程有授权就复制一份给子进程。
 * 这样 MT 管理器（已授权）→ fork 出 shell → shell 再 exec 外挂，
 * 一整条链路上都带着授权。
 *
 * 注意：这里只处理「直接子进程」。孙进程靠它自己的父进程再次继承，
 * 所以链条能自然延续下去，不需要向上找祖先。
 */
static int __maybe_unused sk_fork_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *child;

	if (atomic_read(&sk_grant_n) == 0)
		return 0;

	child = (struct task_struct *)regs_get_kernel_argument(regs, 0);
	if (!child || child->pid <= 0)
		return 0;

	{
		int pm = sk_grant_mode_task(current);

		if (pm >= 0 && sk_grant_add(child, (u8)pm) == 0)
			atomic_inc(&sk_inherited);
	}
	return 0;
}

static struct kprobe sk_kp_fork = {
	.symbol_name = "wake_up_new_task",
	.pre_handler = sk_fork_pre,
};
/* ══════════════════ syscall hook ══════════════════ */

struct sk_inst {
	const struct cred *old;
	bool did;
};


/* ══════════════════ 跨 KMI 符号回退 ══════════════════ */

/*
 * 同一个功能在不同内核版本上符号名不一样 —— 尤其是 syscall 入口：
 *
 *   5.13+            invoke_syscall
 *   5.10 ~ 5.12      el0_svc_common
 *   5.4  ~ 5.9       el0_svc / do_el0_svc
 *
 * 以前只写死一个名字，注册失败整套提权就没了，
 * 表现是「模块加载了但完全没效果」。
 * 这个助手按顺序试，第一个成功的就用，全失败才算不可用。
 */
static int sk_register_first(struct kretprobe *krp, const char *const *names,
			     int n, const char **chosen)
{
	int i;

	for (i = 0; i < n; i++) {
		krp->kp.symbol_name = names[i];
		if (register_kretprobe(krp) == 0) {
			if (chosen)
				*chosen = names[i];
			return 0;
		}
	}
	return -ENODEV;
}

static struct kretprobe sk_krp_syscall = {
	.kp.symbol_name = "invoke_syscall",
	.data_size      = sizeof(struct sk_inst),
	.maxactive      = 64,
};

static struct kretprobe sk_krp_trace = {
	.kp.symbol_name = "__traceiter_sys_enter",
	.data_size      = sizeof(struct sk_inst),
	.maxactive      = 64,
};

/*
 * entry handler —— 影子权限的全部逻辑就在这三十行里。
 *
 * ★★★ 返回值语义（这里踩过一个大坑，必须记牢）★★★
 *
 * kernel/kprobes.c 里是这么判的：
 *
 *     if (rp->entry_handler && rp->entry_handler(ri, regs)) {
 *             freelist_add(&ri->freelist, &rp->freelist);
 *             return 0;          // 返回【非 0】→ 回收实例，不安装 return
 *     }
 *     arch_prepare_kretprobe(ri, regs);   // 返回【0】→ 安装 return
 *
 * 也就是说：
 *     返回 0      → 安装 return handler（handler 会被调用）
 *     返回非 0    → 跳过，handler 不会被调用
 *
 * 这和「0 表示失败」的直觉正好相反。我第一版写反了，后果是：
 *     该 revert 的时候没安装 return → revert_creds 从不执行 → cred 泄漏
 *     不该放行的时候安装了 return    → 窗口外也改返回值 → SELinux 被误放行
 *
 * 所以这里：不处理就返回 1（省掉 return 实例，零开销），
 *          提了权才返回 0（让 return handler 能收尾）。
 */
static bool sk_sysf_denied(pid_t pid, int nr);
static bool sk_sysf_active(void);

static int sk_hook_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_inst *d = (struct sk_inst *)ri->data;

	d->old = NULL;
	d->did = false;

	atomic64_inc(&sk_seen);

	/*
	 * 只需要一件事：如果这个任务已授权，就把它提成 root（只提一次）。
	 *
	 * 永远返回 1 = 不安装 return handler。
	 * 因为我们不做撤销 —— 没有 return handler 就没有 revert，
	 * 也就没有 0.10.x 那两类崩溃（revert 打坏引用计数 / double-free）。
	 *
	 * 系统调用号都不用读了：提权判断只看「这个 task 有没有授权」，
	 * 不看是哪条 syscall。这样连敏感名单都不需要了。
	 */
	sk_promote();

	/*
	 * ══════════════════ 第二批 B：syscall 过滤 ══════════════════
	 *
	 * 位置：必须在 sk_promote() **之后**。
	 *   sk_promote 只提权，不读 syscall 号；先提权再过滤，
	 *   保证「授权语义」一点没变（这是既有逻辑，不许动）。
	 *
	 * 拦截手法：把 x8（arm64 的系统调用号寄存器）改成 -1，
	 *   内核查表失败 → 返回 -ENOSYS。目标进程看到的就只是
	 *   「这个系统调用不存在」，不需要第二个钩子改返回值。
	 *
	 * 上下文：这里是 kretprobe entry，原子上下文。
	 *   sk_sysf_denied 只做静态数组整数比较，不分配不睡眠不打日志。
	 *
	 * 开销：sk_sysf_active() 在无规则时立刻返回 false，
	 *   等于零成本（一次原子读）。
	 */
	if (sk_sysf_active()) {
		unsigned long nr =
			(unsigned long)regs_get_kernel_argument(regs, 0);

		if (sk_sysf_denied(task_pid_nr(current), (int)nr))
			regs->regs[8] = (unsigned long)-1;
	}

	return 1;
}

/*
 * return handler 现在是死代码 —— 因为 entry 永远返回 1，不会被安装。
 * 保留空实现只是为了 kretprobe 结构体的字段不为 NULL。
 */
static int sk_hook_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

/* ══════════════════ SELinux bridge ══════════════════ */

/*
 * selinux_inode_permission(inode, mask)  ← open/access
 * selinux_file_permission(file, mask)    ← read/write
 *
 * 两者都返回 int（0 = 允许，负 = 拒绝）。
 *
 * entry：只有在提权窗口内才安装 return handler，窗口外零干扰。
 * return：原来被拒（非 0）就改成 0（放行）。
 *
 * 这里 data_size = 0 —— return 时 current->cred 仍然是 sk_root_cred
 * （invoke_syscall 的窗口还没关闭），所以直接再判一次即可，
 * 不需要 per-instance 保存任何东西。
 */
/*
 * selinux_inode_permission 专用处理器。
 *
 * 为什么不用通用的 sk_lsm_entry / sk_lsm_return：
 *   只有这个钩子拿得到 inode，而 UM 的隐藏规则需要按 inode 匹配。
 *   同时它还要继续承担「已授权任务一律放行」的职责。
 */
struct sk_inode_data {
	unsigned long inode;
};

static int sk_inode_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_inode_data *d = (struct sk_inode_data *)ri->data;

	/*
	 * ★ inode 在 x0，不是 x1 ★
	 *
	 * 这是用 /proc/sk/umdbg 打印寄存器实测出来的：
	 *   x0 = ffffff8803b5c978  ← 内核 SLUB 地址，解引用后 i_ino / i_sb 都合理
	 *   x1 = 81  x2 = 81       ← 0x81 = 129 = u:r:ksu:s0 的 SID，不是指针
	 *
	 * 之前按 x1 取 inode，等于把 0x81 当地址解引用 → 两次 panic。
	 * 教训：**猜寄存器位置前必须先打印出来**，不能靠"看起来像"。
	 */
	d->inode = regs->regs[0];

	atomic64_inc(&sk_lsm_e_called);

	/*
	 * 校准探针：对指定 uid 的前 N 次调用，把 x0~x5 原样打出来。
	 *
	 * 为什么需要：selinux_inode_permission 的参数位置没确认过，
	 * 直接解引用 regs[1] 会 panic（已经崩过两次设备）。
	 * 判据：mask 是个 int，所以那一寄存器必然是个小数字（0~7）；
	 *       inode 是内核指针，必然 >= 0xffff000000000000。
	 * 两者一对比就知道哪个是哪个。
	 */
	if (sk_umdbg_uid >= 0
	    && __kuid_val(current_uid()) == (u32)sk_umdbg_uid
	    && atomic_read(&sk_umdbg_left) > 0) {
		atomic_dec(&sk_umdbg_left);
		{
			/*
			 * 只解引用 x0，而且只在内核映射区（>= 0xffff000000000000）时才解。
			 * 上一步已经证明 x1/x2 是 SID(0x81) 不是指针，
			 * x0 = ffffff8803b5c978 是标准 SLUB 地址 —— 解它风险可控。
			 */
			unsigned long p0 = regs->regs[0];
			if (p0 >= 0xffff000000000000UL) {
				struct inode *in = (struct inode *)p0;
				pr_info(SK_TAG "UMDBG deref x0: i_ino=%llu i_sb=%px\n",
					(unsigned long long)in->i_ino,
					(void *)in->i_sb);
				if (in->i_sb) {
					pr_info(SK_TAG "UMDBG deref x0: s_dev_raw=%u\n",
						in->i_sb->s_dev);
				}
			}
		}
		pr_info(SK_TAG "UMDBG %d regs: x0=%llx x1=%llx x2=%llx x3=%llx x4=%llx x5=%llx\n",
			current->pid,
			(unsigned long long)regs->regs[0],
			(unsigned long long)regs->regs[1],
			(unsigned long long)regs->regs[2],
			(unsigned long long)regs->regs[3],
			(unsigned long long)regs->regs[4],
			(unsigned long long)regs->regs[5]);
	}

	/*
	 * 只要有 UM 规则存在，就必须装 return handler 来做隐藏判定，
	 * 哪怕这个任务本身没被授权。
	 */
	/*
	 * ★ 必须同时认字节码程序 ★
	 *   只判 sk_um_n 会让「bc 载入后规则表清空」的情况下不武装钩子，
	 *   return handler 根本不跑 —— 实测踩过第二次。
	 */
	if (!sk_in_window() && !sk_um_n && !sk_um_prog_len)
		return 1;
	return 0;
}

static int sk_inode_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_inode_data *d = (struct sk_inode_data *)ri->data;
	long orig = (long)regs->regs[0];
	struct inode *ino = (struct inode *)d->inode;

	atomic64_inc(&sk_lsm_r_called);

	/*
	 * ① UM 隐藏优先：命中规则 → 让它「不存在」
	 *
	 * ★ 必须先按 uid 过滤，再解引用 inode ★
	 *   上一版直接对全系统的 inode_permission 解引用 ino->i_sb，
	 *   只要有一处指针不可信就 panic（实测崩过）。
	 *   先做一次「这个 uid 有没有规则」的便宜判断，
	 *   没有就直接跳过 —— 绝大多数调用根本不会走到解引用那一步。
	 */
	/*
	 * uid 预过滤。
	 *
	 * ★ 必须同时认「有字节码程序」★
	 *   bc 协议会清空规则表（避免两套逻辑打架），
	 *   只按 sk_um_uid_match 判断会让 VM 永远不被调用 —— 实测踩过。
	 */
	/*
	 * 自家 proc 节点一律放行（否则管理器写不了授权表）。
	 * 按 inode 精确匹配，只放行这一个文件。
	 */
	{
		int oi;

		if (ino) {
			for (oi = 0; oi < sk_own_ino_n; oi++) {
				if ((u64)ino->i_ino == sk_own_ino[oi]) {
					regs_set_return_value(regs, 0);
					return 0;
				}
			}
		}
	}

	if (sk_um_enable && ino
	    && (sk_um_prog_len > 0
		|| sk_um_uid_match(__kuid_val(current_uid())))) {
		u32 dev = 0;

		if (ino->i_sb)
			dev = new_encode_dev(ino->i_sb->s_dev);
		/*
		 * 有字节码程序就用 VM（能力更强，能表达条件逻辑）；
		 * 没有就退回规则表。
		 *
		 * 现在两者都能返回任意 errno，不再写死 -ENOENT。
		 */
		{
			int verdict = 0;
			bool hit = false;

			if (sk_um_prog_len > 0) {
				verdict = sk_um_vm(__kuid_val(current_uid()),
						   dev, (u64)ino->i_ino);
				hit = true;
			} else {
				int act = sk_um_action(__kuid_val(current_uid()),
						       dev, (u64)ino->i_ino);
				if (act >= 0) {
					verdict = sk_um_act_errno(act);
					hit = true;
				}
			}
			if (hit && verdict != 0) {
				regs_set_return_value(regs, verdict);
				atomic64_inc(&sk_lsm_bypass);
				return 0;
			}
		}
	}

	/* ② 已授权任务：拒绝改成放行 */
	if (orig != 0) {
		if (sk_mac_bypass_ok()) {
			regs_set_return_value(regs, 0);
			atomic64_inc(&sk_lsm_bypass);
		} else {
			sk_deny_record(0, true);	/* MAC 层拒绝且没放行 */
		}
	}
	return 0;
}

/*
 * SELinux 放行判据。
 *
 * 原来只认 sk_in_window()（我们拦截的那个 syscall 的短暂窗口），
 * 导致「被授权 uid 的子进程自己去 open」时窗口不在、SELinux 照样拒 ——
 * 实测表现就是 sh 写 /proc/sk/grant 报 Permission denied。
 *
 * 影子模式的语义本来就该是「这个 uid 的所有操作都放行」，
 * 所以加上「该 uid 有授权」这个条件。
 */
/*
 * ★ 唯一判据：这个 uid 有没有特权 ★
 *
 * 命中任意一条就算：
 *   · 真 root (0)
 *   · 授权表里有它（影子 或 超级用户）
 *   · 启动参数 grant_uid / allow_uid 指定的管理器
 *
 * 一旦命中，它和它的所有子进程（同 uid）全部通过 ——
 * SELinux 放行、DAC 放行，不再按文件类型搞特例。
 */

/* ══════════════════ 身份校验（防 comm 伪造）══════════════════ */

/*
 * ★ 这是整套隔离的地基 ★
 *
 * 原来的自举判据只有一条：comm == "io.umbral"。
 * 而 comm 是进程自己能改的 —— prctl(PR_SET_NAME, "io.umbral") 一行就够。
 * 于是任何拿到代码执行的恶意程序，改个名字就能自举成影子权限，
 * 进而看得见 su、能提权 —— 所有隔离全部作废。
 *
 * 现在改成四重校验，改 comm 已经骗不过：
 *
 *   ① pid == tgid             必须是主线程（不是随便 fork 的子进程）
 *   ② uid >= 10000            必须是普通应用
 *   ③ exe 是 app_process*    必须是 zygote fork 出来的 Android 进程，
 *                            而不是任意 native 二进制
 *   ④ uid 必须等于已落盘的管理器 uid（首次开机允许建立，之后锁死）
 *
 * 第 ④ 条是关键：一旦 manager.uid 写过一次，以后只有那个 uid 能自举。
 * 恶意应用即使伪造 comm、即使本身也是 app_process，uid 对不上就是拒绝。
 *
 * 全部判断都只读 current 的结构体，不需要文件 IO、不会睡眠 ——
 * 可以安全地在权限钩子（原子上下文）里调用。
 */
static bool sk_exe_is_app_process(void)
{
	const char *n;

	if (!current->mm || !current->mm->exe_file)
		return false;

	n = current->mm->exe_file->f_path.dentry->d_name.name;
	if (!n)
		return false;

	if (!strcmp(n, "app_process64") || !strcmp(n, "app_process32")
	    || !strcmp(n, "app_process"))
		return true;

	return false;
}

/* 完整的自举校验 */

/* ══════════════════ 自举：真正的表操作交给工作队列 ══════════════════ */

/*
 * ★ 为什么必须挪走 ★
 *
 * sk_uid_privileged() 是在权限钩子里被调用的 —— 那是**原子上下文**
 * （preempt 已关、不能睡眠）。而自举要做的两件事都会睡眠：
 *
 *     sk_ugrant_add()        → 分配链表节点（GFP_KERNEL 可能睡）
 *     sk_write_manager_uid() → 打开文件写盘（一定可能睡）
 *
 * 在原子上下文里睡眠 = 直接 panic。这就是技能里记的「崩溃 #4」同型问题。
 *
 * 改法：
 *     钩子里只做「放行 + 登记一次请求」，然后 schedule_work
 *     真正的加表、写盘在工作队列里做（那是进程上下文，可以睡眠）
 *
 * 代价：授权表最多晚一个调度周期才写进去，用户完全感觉不到。
 */
static atomic_t sk_boot_pending = ATOMIC_INIT(0);
static u32 sk_boot_uid;
static struct work_struct sk_boot_work;
static bool sk_boot_wq_ready;

static void __attribute__((unused)) sk_boot_work_fn(struct work_struct *w)
{
	u32 uid = sk_boot_uid;

	(void)w;
	if (sk_grant_mode_uid(uid) < 0) {
		if (sk_ugrant_add(uid, SK_GRANT_SHADOW) == 0)
			pr_info(SK_TAG "自举：工作队列授权管理器 uid=%u\n", uid);
	}
	if ((int)uid != sk_grant_uid) {
		sk_grant_uid = (int)uid;
		sk_write_manager_uid((int)uid);
		pr_info(SK_TAG "自举：manager.uid 更新为 %u\n", uid);
	}
	atomic_set(&sk_boot_pending, 0);
}

/* 钩子里调这个：原子安全，只排队不干活 */
static void __attribute__((unused)) sk_boot_request(u32 uid)
{
	/*
	 * ★ 关键：先同步把 sk_grant_uid 写掉 ★
	 *
	 * 这一步是整条链的「一次性开关」，而且它只是一个 int 赋值 ——
	 * 原子上下文里绝对安全，不需要分配、不需要锁、不会睡。
	 *
	 * 为什么必须在这里做：
	 *   sk_uid_privileged() 的第 3364 行是「uid == sk_grant_uid」。
	 *   一旦这里把 sk_grant_uid 设上，下一次系统调用就直接命中那条，
	 *   **根本不会再进 sk_may_bootstrap**。
	 *
	 * 否则就会出事：
	 *   工作队列如果因为任何原因没成功加表（内存紧张、被取消），
	 *   sk_grant_mode_uid() 永远是 -1 → 每次 syscall 都重新走一遍自举 →
	 *   每次都 schedule_work → 一个 App 每秒上万次 syscall →
	 *   工作队列被灌爆 → 系统卡死 → watchdog 重启设备。
	 *   这正好解释了「一开 App 设备就重启」。
	 */
	sk_grant_uid = (int)uid;

	if (!sk_boot_wq_ready)
		return;
	if (atomic_cmpxchg(&sk_boot_pending, 0, 1) != 0)
		return;				/* 已经排过了，别重复 */
	sk_boot_uid = uid;
	schedule_work(&sk_boot_work);
}

static bool __attribute__((unused)) sk_may_bootstrap(u32 uid)
{
	if (current->pid != current->tgid)
		return false;
	if (uid < 10000)
		return false;
	if (strncmp(current->comm, SK_MGR_PKG, SK_MGR_PKG_LEN) != 0)
		return false;
	if (!sk_exe_is_app_process())
		return false;

	/*
	 * 已经落过盘就锁死：只有那个 uid 能自举。
	 * 首次开机（sk_grant_uid <= 0）允许建立一次，随后写 manager.uid。
	 */
	if (sk_grant_uid > 0 && (int)uid != sk_grant_uid)
		pr_info(SK_TAG "管理器 uid 变了：%d → %u，自动更新\n",
			sk_grant_uid, uid);
	return true;
}

static bool sk_uid_privileged(u32 uid)
{
	if (uid == 0)
		return true;
	if (sk_grant_uid >= 0 && uid == (u32)sk_grant_uid)
		return true;
	if (sk_allow_uid >= 0 && uid == (u32)sk_allow_uid)
		return true;
	if (sk_grant_mode_uid(uid) >= 0)
		return true;

	/*
	 * ★ 自举：进程名就是管理器 → 当场授权 ★
	 *
	 * 为什么要在权限判定里做：
	 *   App 想写 /proc/sk/claim 来认领，首先要能写这个文件 ——
	 *   而写它需要先有权限，死循环。
	 *   在这里直接看 current->comm（内核自己读进程名，不需要任何权限），
	 *   一命中就授权，循环立刻打破。
	 *
	 * 只认 uid >= 10000 的 App 进程，且 comm 必须是 io.umbral，
	 * 别的进程冒充不了（comm 由内核维护）。
	 */
	/*
	 * ★ 这里不再做任何自举动作 ★
	 *
	 * v0.82~v0.92 在这里做「按进程名自举」，试过三种写法都不安全：
	 *   v0.82  直接加表 + 写盘     → 原子上下文睡眠 → panic
	 *   v0.91  改成 schedule_work  → 工作队列被灌爆 → watchdog 重启
	 *   v0.92  加一次性开关        → 仍然崩
	 *
	 * 结论：**权限钩子里一个会分配内存/写盘/排队的动作都不能有。**
	 * 自举改到延迟工作里做（sk_scan_for_manager，进程上下文，安全）。
	 * 代价：管理器启动后最多等一个扫描周期才拿到权限，用户感觉不到。
	 */
	(void)uid;
	return false;
	return false;
}

static bool __attribute__((unused)) sk_bypass_ok(void)
{
	if (sk_in_window())
		return true;
	return sk_uid_privileged(__kuid_val(current_uid()));
}

static int sk_lsm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	atomic64_inc(&sk_lsm_e_called);	/* 诊断：无条件 */

	/*
	 * 窗口外返回 1 = 不安装 return handler。
	 * 这是绝大多数情况，SELinux 的判定原样返回，行为零干扰。
	 */
	/*
	 * ★ 按 uid 放行，而不是只认"我们盯的那个 syscall 窗口" ★
	 *
	 * 影子权限的语义是「这个 uid 的一切操作都放行」。
	 * 只认窗口的话，被授权进程 fork 出来的子进程（sh 等）
	 * 自己 open 时窗口不在 → SELinux 照原样拒绝 —— 实测就是这个 bug。
	 *
	 * 注意：DAC 那一层的「属主 <= 1000 只读」仍然保留（见 sk_perm_return），
	 * 所以 ART 对 APK 的 access(W_OK) 探测依然会失败，不会重演
	 * "Writable dex file is not allowed"。
	 */
	if (!sk_mac_bypass_ok())
		return 1;

	atomic64_inc(&sk_lsm_seen);
	return 0;	/* 0 = 安装 return，handler 里才能把拒绝改成放行 */
}

static int sk_lsm_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long orig = (long)regs->regs[0];

	atomic64_inc(&sk_lsm_r_called);	/* 诊断：无条件 */

	/* 诊断：打印前 12 次，看原始返回值 + 当时进程的 uid */
	{
		static int dbg;
		if (dbg < 12) {
			dbg++;
			pr_info(SK_TAG "LSM_RET orig=%ld uid=%u fsuid=%u cap=%llx\n",
				orig,
				__kuid_val(current_cred()->uid),
				__kuid_val(current_cred()->fsuid),
				SK_CAP64(current_cred()->cap_effective));
		}
	}

	if (orig != 0) {
		regs_set_return_value(regs, 0);
		atomic64_inc(&sk_lsm_bypass);
	}
	return 0;
}

static struct kretprobe sk_krp_inode = {
	.kp.symbol_name = "selinux_inode_permission",
	.entry_handler = sk_inode_entry,
	.handler       = sk_inode_return,
	.data_size     = sizeof(struct sk_inode_data),
	.maxactive     = 256,
};

static struct kretprobe sk_krp_file = {
	.kp.symbol_name = "selinux_file_permission",
	.entry_handler = sk_lsm_entry,
	.handler       = sk_lsm_return,
	.data_size     = 0,
	.maxactive     = 256,
};

/*
 * open() 的第二道 SELinux 关。
 *
 * fs/open.c:918  do_dentry_open() -> security_file_open(f)
 *   -> selinux_file_open(file)
 *        return file_path_has_perm(file->f_cred, file, open_file_to_av(file));
 *
 * 它和 selinux_inode_permission 是两个独立的检查入口，都要过。
 */
static struct kretprobe sk_krp_open = {
	.kp.symbol_name = "selinux_file_open",
	.entry_handler = sk_lsm_entry,
	.handler       = sk_lsm_return,
	.data_size     = 0,
	.maxactive     = 128,
};

/*
 * ★ 真正的关键点：avc_has_perm
 *
 * 这是 SELinux 的**总判定函数**，所有具体检查最终都落到它：
 *
 *   selinux_inode_permission -> inode_has_perm  -> avc_has_perm
 *   selinux_file_open        -> file_path_has_perm -> inode_has_perm -> avc_has_perm
 *   selinux_capable          -> cred_has_capability -> avc_has_perm   ← dac_override 就卡在这
 *
 * 前面那些具体入口能放行普通文件访问，但 CAP_DAC_OVERRIDE 这类
 * capability 检查走的是 selinux_capable，我们没 hook 它，于是：
 *
 *   avc: denied { dac_override } scontext=u:r:kernel:s0 tclass=capability
 *
 * 直接挂 avc_has_perm 就一次性覆盖全部入口，不必逐个追。
 * 它签名是 int avc_has_perm(struct selinux_state *state, u32 ssid,
 *                            u32 tsid, u16 tclass, u32 requested,
 *                            struct common_audit_data *auditdata);
 * 返回 0 = 允许。
 */
static struct kretprobe sk_krp_avc = {
	.kp.symbol_name = "avc_has_perm",
	.entry_handler = sk_lsm_entry,
	.handler       = sk_lsm_return,
	.data_size     = 0,
	.maxactive     = 512,
};

/*
 * ★★ 真正卡住 dac_override 的那一层 ★★
 *
 * cred_has_capability() 的实现是：
 *
 *     rc = avc_has_perm_noaudit(sid, sid, sclass, av, 0, &avd);
 *     if (!(opts & CAP_OPT_NOAUDIT)) {
 *             int rc2 = avc_audit(...);
 *             if (rc2) return rc2;
 *     }
 *     return rc;
 *
 * 它**不走** avc_has_perm，而是直接调 avc_has_perm_noaudit。
 * 所以只挂 avc_has_perm 是漏的 —— 这就是「avc: denied { dac_override }
 * tclass=capability」始终冒出来的原因。
 */
static struct kretprobe sk_krp_avc_na = {
	.kp.symbol_name = "avc_has_perm_noaudit",
	.entry_handler = sk_lsm_entry,
	.handler       = sk_lsm_return,
	.data_size     = 0,
	.maxactive     = 512,
};

/* 再兜一层：SELinux 的 capable 实现 */
/*
 * cap_capable —— 内核能力判定的最终出口。
 * 有授权就返回 0，等价于给了满 caps（包括 CAP_DAC_OVERRIDE / CAP_SYS_ADMIN）。
 *
 * 优点：完全不碰 cred，所以 commit_creds 的引用计数不会出错。
 */
/* cap_capable 的 per-instance 数据：把 capability 编号带进 return handler */
struct sk_cap_data {
	int cap;		/* cap_capable 用 */
	int mask;		/* generic_permission 用 */
	unsigned long inode;	/* generic_permission 的 inode 指针 */
};

/*
 * 这些能力**永久拒绝**，即使有授权。
 *
 * 身份变更类（SETUID/SETGID/SETPCAP/SYS_PACCT）：
 *   我们的提权方式就是「不改身份」，一旦允许它自己改身份，
 *   内核记账会和实际身份脱节 —— 实测会让 App 冷启动直接死掉。
 *
 * 危险类（SYS_MODULE/SYS_BOOT/SYS_TIME/AUDIT_*）：
 *   给了只会增加崩溃面，对「root 能干的都能干」这个目标没有帮助。
 *
 * ★ CAP_DAC_OVERRIDE 也不能给 ★
 *   ART 加载 APK 时会用 O_RDWR 试开，能写就拒绝加载 ——
 *   原文是 "SecurityException: Writable dex file ... is not allowed"。
 *   CAP_DAC_OVERRIDE 会让 base.apk 变成可写，于是 App 自己把自己拒掉。
 *   读权限改用 CAP_DAC_READ_SEARCH（不在此名单里，放行）；
 *   写权限由 generic_permission 钩子单独放行（见下）。
 */
static bool sk_cap_denied(int cap)
{
	switch (cap) {
	case 1:		/* CAP_DAC_OVERRIDE —— 见下面长注释，必须拒 */
	case 6:		/* CAP_SETGID */
	case 7:		/* CAP_SETUID */
	case 8:		/* CAP_SETPCAP */
	case 20:	/* CAP_SYS_PACCT */
	/* CAP_SYS_MODULE: allow ONLY for real root (uid 0).
	 * After sk_escape_to_root() the process is uid 0 with full caps,
	 * so `su -c insmod ...` works; shadow users (uid unchanged) keep
	 * EPERM and can never load kernel modules. */
	case 16:	/* CAP_SYS_MODULE */
		return __kuid_val(current_uid()) != 0;
	case 22:	/* CAP_SYS_BOOT */
	case 25:	/* CAP_SYS_TIME */
	case 29:	/* CAP_AUDIT_WRITE */
	case 30:	/* CAP_AUDIT_CONTROL */
		return true;
	default:
		return false;
	}
}

static int sk_cap_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_cap_data *d = (struct sk_cap_data *)ri->data;

	/* cap_capable(cred, targ_ns, cap, opts) —— arm64 上 cap 在 x2 */
	d->cap = (int)regs->regs[2];

	atomic64_inc(&sk_lsm_e_called);

	if (!sk_in_window())
		return 1;		/* 不安装 return handler，零干扰 */
	return 0;
}

static int sk_cap_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_cap_data *d = (struct sk_cap_data *)ri->data;
	long orig = (long)regs->regs[0];

	atomic64_inc(&sk_lsm_r_called);

	/* 只把「拒绝」改成「通过」，绝不反过来 */
	if (orig != 0 && !sk_cap_denied(d->cap)) {
		regs_set_return_value(regs, 0);
		atomic64_inc(&sk_lsm_bypass);
	}
	return 0;
}

static struct kretprobe sk_krp_capfn = {
	.kp.symbol_name = "cap_capable",
	.entry_handler  = sk_cap_entry,
	.handler        = sk_cap_return,
	.data_size      = sizeof(struct sk_cap_data),
	.maxactive      = 128,
};

/*
 * generic_permission —— DAC 的最终出口。
 *
 * ★ 这个钩子默认不启用 ★
 *   实测（hooks 二分）单独挂它就能让 App 起不来。
 *   而且它本来就不需要：generic_permission 内部在 uid 不匹配时会查
 *   CAP_DAC_OVERRIDE，而 cap_capable 已经把那项放行了。
 */
static int sk_perm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_cap_data *d = (struct sk_cap_data *)ri->data;

	/* generic_permission(idmap, inode, mask)：x1=inode, x2=mask */
	d->inode = regs->regs[1];
	d->mask  = (int)regs->regs[2];

	atomic64_inc(&sk_lsm_e_called);

	/*
	 * ★ 按 uid 放行，不再只认「提权窗口」★
	 *
	 * 这是「装模块提示没有 root 权限」的根因：
	 *
	 *   窗口只对走过 sk_promote 的那个 task 生效。
	 *   App 主进程走过 → 有窗口 → 能列 /data/adb/modules（实测「是」）
	 *   它 fork 出来的 sh 是另一个 task → 没窗口 → 被正常拒绝
	 *   （实测：ls /data/adb/umbral/ → Permission denied）
	 *
	 * 而所有特权操作（装 ZIP 模块、保存 UM 模块、写 /data/adb）
	 * 全都是 fork 一个 sh 去做的 —— 于是全部失败。
	 *
	 * 诊断日志里的那个矛盾就是这么来的：
	 *   同一个 uid 10563，App 进程内有权限，它的子进程没有。
	 *
	 * 改成按 uid 判断后，子进程同 uid → 一并放行。
	 *
	 * 安全性：ART 的 access(apk, W_OK) 仍会失败 ——
	 * 写分支里对「属主 == 1000 且非 procfs」的文件保持原判定，
	 * 那条护身符没动。
	 */
	if (sk_in_window())
		return 0;
	if (sk_uid_privileged(__kuid_val(current_uid())))
		return 0;
	return 1;
}

static int sk_perm_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_cap_data *d = (struct sk_cap_data *)ri->data;
	long orig = (long)regs->regs[0];

	atomic64_inc(&sk_lsm_r_called);

	/*
	 * ★ root 属主的文件不给写 ★
	 *
	 * ART 加载 APK 前会 access(path, W_OK)，能写就抛
	 *   "SecurityException: Writable dex file ... is not allowed"
	 * 而 APK 是 root:root 0644 —— 只要放行「写 root 属主文件」，
	 * 任何被授权的 App 都会自己把自己拒之门外。
	 *
	 * 取舍：
	 *   读 root 文件  → 放行（走 CAP_DAC_READ_SEARCH）
	 *   写 root 文件  → 保持原判定（/system、/data/system 本来就是只读的）
	 *   写 App 数据   → 放行（属主是那个 App，不是 root）← 主要用途
	 *   写 /data/local/tmp → 放行（属主 shell）
	 *
	 * 顺带：O_RDWR（MAY_READ|MAY_WRITE）也一并保持原判定。
	 */
	if (d->mask & 0x2) {			/* MAY_WRITE */
		/*
		 * ★ 系统守护优先判定 ★
		 * 命中关键分区且调用者不是特权 uid → 直接拦下（-EPERM）
		 * 已记录肇事者，管理器会弹告警并列出 uid/pid/进程名。
		 */
		if (sk_guard_check((struct inode *)d->inode)) {
			regs_set_return_value(regs, -EPERM);
			return 0;
		}


		/*
		 * 属主 <= 1000 的一律不给写：
		 *   root(0)    —— 系统文件
		 *   system(1000) —— APK 就是 system:system 0644
		 * shell(2000) 和 App(>=10000) 不受影响。
		 */
		struct inode *ino = (struct inode *)d->inode;

		/*
		 * ★ 自家 proc 节点放行 ★
		 *   这些属主是 root(0)，会被下面那条规则拦掉，
		 *   但管理器必须能写，否则提权链断掉。
		 */
		if (ino) {
			int oi;

			for (oi = 0; oi < sk_own_ino_n; oi++) {
				if ((u64)ino->i_ino == sk_own_ino[oi]) {
					regs_set_return_value(regs, 0);
					return 0;
				}
			}
		}

		/*
		 * ★ 属主 <= 1000 的文件保持原判定（只读）★
		 *
		 * 这条不能删：ART 会调 access(apk, W_OK) 判断 dex 是否可写，
		 * 一旦返回「可写」就报 "Writable dex file is not allowed" 并拒绝加载。
		 * v0.52 删掉它之后，管理器自己就启动即崩 —— 实测。
		 *
		 * 要写 /data/adb 这类 root 目录，走「子进程真 root」那条路，
		 * 不要靠放宽这条全局规则。
		 */
		/*
		 * ★ 特权 uid：写入全部放行 ★
		 *
		 * 唯一例外：属主是 system(1000) 的普通文件（App 的 APK）。
		 * 这不是限制，是护身符 —— ART 会问 access(apk, W_OK)，
		 * 一旦答"可写"它就报 "Writable dex file is not allowed" 并拒载，
		 * 结果就是被授权的 App 自己启动不了。实测崩过两次。
		 */
		/*
		 * ★ 特权 uid：写入全部放行，包括 root 属主的文件 ★
		 *
		 * 以前这里有一条例外（属主 == 1000 的 APK 保持只读），
		 * 目的是让 ART 的 access(apk, W_OK) 失败。
		 * 现在那件事交给 faccessat 钩子去做（见 sk_acc_return），
		 * 所以这里可以彻底放开 —— 影子权限终于能写 /data/adb、/system。
		 */
		/*
		 * ★ 特权 uid：写入放行，唯一例外是「属主 == 1000」★
		 *
		 * 为什么只排除 1000：
		 *
		 *   /data/adb、/system、/data/system  → 属主 root(0)
		 *     → 放行，影子权限能写这些目录（这是核心需求）
		 *
		 *   APK（base.apk）→ 属主 system(1000)
		 *     → 保持原判定（只读）
		 *     → ART 加载前会 access(apk, W_OK)，得到「不可写」就正常加载
		 *     → 不这么做就报 Writable dex file is not allowed，App 启动即崩
		 *
		 * v0.79 曾经把整条规则摘掉，改用 faccessat 钩子去掐 ART 的探测 ——
		 * 那是过度设计，而且钩子里在原子上下文读用户态字符串，风险大。
		 * 现在回到最朴素的做法：一个整数比较，不需要任何额外钩子。
		 */
		if (sk_uid_privileged(__kuid_val(current_uid()))) {
			if (ino && __kuid_val(ino->i_uid) == 1000
			    && ino->i_sb
			    && ino->i_sb->s_magic != PROC_SUPER_MAGIC)
				return 0;	/* APK：保持原判定（护身符） */
			regs_set_return_value(regs, 0);
			return 0;
		}

		/*
		 * ★ procfs 写入放行（被授权的 uid）★
		 *
		 * 为什么必须单独判：/proc/sk/grant 属主是 root(0)，
		 * 会被下面那条「属主 <= 1000 只读」拦掉，提权链直接断。
		 *
		 * 用「超级块魔数 == PROC_SUPER_MAGIC」判断，不依赖 inode 记录
		 * —— 之前靠 sk_filp_open 记 inode 的做法在 init 阶段拿不到（实测数组为空）。
		 *
		 * 安全性：APK 在 ext4/f2fs 上，魔数不是 0x9fa0，所以 ART 那句
		 * access(apk, W_OK) 仍然失败，不会重演 "Writable dex file"。
		 */
		if (ino && ino->i_sb
		    && ino->i_sb->s_magic == PROC_SUPER_MAGIC
		    && sk_grant_mode_uid(__kuid_val(current_uid())) >= 0) {
			regs_set_return_value(regs, 0);
			return 0;
		}

		/*
		 * 被授权的 uid：真实写入放行
		 * （它的子进程同 uid，所以一并生效 —— 这就是"子进程也是 su"）
		 *
		 * 但「属主 <= 1000」的仍然只读，因为 App 的 APK 属主是 system(1000)，
		 * 一旦判定可写，ART 就会报 "Writable dex file is not allowed" 并拒载。
		 * 要写 /data/adb 这类目录，走子进程真 uid 0 那条路（root 直接绕过 DAC）。
		 */
		if (ino && __kuid_val(ino->i_uid) > 1000
		    && sk_grant_mode_uid(__kuid_val(current_uid())) >= 0) {
			regs_set_return_value(regs, 0);
			return 0;
		}

		if (ino && __kuid_val(ino->i_uid) <= 1000)
			return 0;
		if ((d->mask & 0x4) && (d->mask & 0x2))
			return 0;
	}

	if (orig != 0) {
		regs_set_return_value(regs, 0);
		atomic64_inc(&sk_lsm_bypass);
	}
	return 0;
}

static struct kretprobe sk_krp_genperm = {
	.kp.symbol_name = "generic_permission",
	.entry_handler  = sk_perm_entry,
	.handler        = sk_perm_return,
	.data_size      = sizeof(struct sk_cap_data),
	.maxactive      = 128,
};

static struct kretprobe sk_krp_capable = {
	.kp.symbol_name = "selinux_capable",
	.entry_handler = sk_lsm_entry,
	.handler       = sk_lsm_return,
	.data_size     = 0,
	.maxactive     = 256,
};

/* ══════════════════ 注册 / 注销 ══════════════════ */

static int sk_hooks_install(void)
{
	int rc;

	/* 1) syscall hook（提权入口） */
	sk_krp_syscall.entry_handler = sk_hook_entry;
	sk_krp_syscall.handler       = sk_hook_return;
	sk_krp_trace.entry_handler   = sk_hook_entry;
	sk_krp_trace.handler         = sk_hook_return;

#if SK_ENABLE_FORK_HOOK
	/* fork 继承：先注册，它失败不致命 */
	rc = sk_forkoff ? -1 : register_kprobe(&sk_kp_fork);
	if (rc == 0) {
		sk_hooks |= SK_HOOK_FORK;
	} else {
		pr_warn(SK_TAG "fork hook failed rc=%d (继承不可用)\n", rc);
		rc = 0;
	}
#else
	pr_info(SK_TAG "fork hook DISABLED (bisect)\n");
#endif

	{
		static const char *const sys_names[] = {
			"invoke_syscall",	/* 5.13+ */
			"el0_svc_common",	/* 5.10 ~ 5.12 */
			"el0_svc",		/* 5.4  ~ 5.9 */
			"do_el0_svc",		/* 备选 */
		};
		static const char *const trc_names[] = {
			"__traceiter_sys_enter",
			"trace_sys_enter",
			"syscall_trace_enter",
		};
		const char *chosen = NULL;

		rc = sk_register_first(&sk_krp_syscall, sys_names,
				       ARRAY_SIZE(sys_names), &chosen);
		if (rc == 0) {
			sk_hooks |= SK_HOOK_SYSCALL;
			sk_backend = "kretprobe:syscall-entry";
			pr_info(SK_TAG "syscall hook A ready (%s)\n", chosen);
		} else {
			pr_warn(SK_TAG "syscall hook A 全部候选失败，试 tracepoint\n");
			rc = sk_register_first(&sk_krp_trace, trc_names,
					       ARRAY_SIZE(trc_names), &chosen);
			if (rc == 0) {
				sk_hooks |= SK_HOOK_SYSCALL_B;
				sk_backend = "kretprobe:tracepoint";
				pr_info(SK_TAG "syscall hook B ready (%s)\n", chosen);
			} else {
				pr_warn(SK_TAG "syscall hook B 全部候选失败\n");
			}
		}
	}

	if (!(sk_hooks & (SK_HOOK_SYSCALL | SK_HOOK_SYSCALL_B))) {
		pr_err(SK_TAG "no syscall hook, abort\n");
		return -ENODEV;
	}

	/* 2) SELinux bridge —— 挂不上不致命，只是没有 MAC 放行 */
	if (sk_hookmask & SK_HOOKBIT_INODE) {
		rc = register_kretprobe(&sk_krp_inode);
		if (rc == 0) {
			sk_hooks |= SK_HOOK_INODE;
			pr_info(SK_TAG "selinux_inode_permission hooked\n");
		} else {
			pr_warn(SK_TAG "selinux_inode_permission unavailable: %d\n", rc);
		}
	}

	if (sk_hookmask & SK_HOOKBIT_FILE) {
		rc = register_kretprobe(&sk_krp_file);
		if (rc == 0) {
			sk_hooks |= SK_HOOK_FILE;
			pr_info(SK_TAG "selinux_file_permission hooked\n");
		} else {
			pr_warn(SK_TAG "selinux_file_permission unavailable: %d\n", rc);
		}
	}

	if (sk_hookmask & SK_HOOKBIT_OPEN) {
		rc = register_kretprobe(&sk_krp_open);
		if (rc == 0) {
			sk_hooks |= SK_HOOK_OPEN;
			pr_info(SK_TAG "selinux_file_open hooked\n");
		} else {
			pr_warn(SK_TAG "selinux_file_open unavailable: %d\n", rc);
		}
	}

	if (sk_hookmask & SK_HOOKBIT_AVC) {
		rc = register_kretprobe(&sk_krp_avc);
		if (rc == 0) {
			sk_hooks |= SK_HOOK_AVC;
			pr_info(SK_TAG "avc_has_perm hooked (EXPERIMENTAL)\n");
		} else {
			pr_warn(SK_TAG "avc_has_perm unavailable: %d\n", rc);
		}

	}
	if (sk_hookmask & SK_HOOKBIT_AVC_NA) {
		rc = register_kretprobe(&sk_krp_avc_na);
		if (rc == 0) {
			sk_hooks |= SK_HOOK_AVC_NA;
			pr_info(SK_TAG "avc_has_perm_noaudit hooked (EXPERIMENTAL)\n");
		} else {
			pr_warn(SK_TAG "avc_has_perm_noaudit unavailable: %d\n", rc);
		}
	} else {
		pr_info(SK_TAG "generic avc hooks skipped (narrow LSM mode)\n");
	}

	if (sk_hookmask & SK_HOOKBIT_CAPFN) {
		rc = register_kretprobe(&sk_krp_capfn);
		if (rc == 0) {
			sk_hooks |= SK_HOOK_CAPFN;
			pr_info(SK_TAG "cap_capable hooked (满 caps)\n");
		} else {
			pr_warn(SK_TAG "cap_capable unavailable: %d\n", rc);
		}
	}

	if (sk_hookmask & SK_HOOKBIT_GENPERM) {
		rc = register_kretprobe(&sk_krp_genperm);
		if (rc == 0) {
			sk_hooks |= SK_HOOK_GENPERM;
			pr_info(SK_TAG "generic_permission hooked (DAC 放行)\n");
		} else {
			pr_warn(SK_TAG "generic_permission unavailable: %d\n", rc);
		}
	}

	if (sk_hookmask & SK_HOOKBIT_CAP) {
		rc = register_kretprobe(&sk_krp_capable);
		if (rc == 0) {
			sk_hooks |= SK_HOOK_CAPABLE;
			pr_info(SK_TAG "selinux_capable hooked\n");
		} else {
			pr_warn(SK_TAG "selinux_capable unavailable: %d\n", rc);
		}
	}

	pr_info(SK_TAG "hookmask=0x%x -> hooks=0x%x\n", sk_hookmask, sk_hooks);

	return 0;
}

static void sk_hooks_remove(void)
{
	/* 只撤真正注册过的 —— 撤未注册的 kretprobe 会 panic */
	if (sk_hooks & SK_HOOK_FORK)
		unregister_kprobe(&sk_kp_fork);
	if (sk_hooks & SK_HOOK_GENPERM)
		unregister_kretprobe(&sk_krp_genperm);
	if (sk_hooks & SK_HOOK_CAPFN)
		unregister_kretprobe(&sk_krp_capfn);
	if (sk_hooks & SK_HOOK_CAPABLE)
		unregister_kretprobe(&sk_krp_capable);
	if (sk_hooks & SK_HOOK_AVC_NA)
		unregister_kretprobe(&sk_krp_avc_na);
	if (sk_hooks & SK_HOOK_AVC)
		unregister_kretprobe(&sk_krp_avc);
	if (sk_hooks & SK_HOOK_OPEN)
		unregister_kretprobe(&sk_krp_open);
	if (sk_hooks & SK_HOOK_INODE)
		unregister_kretprobe(&sk_krp_inode);
	if (sk_hooks & SK_HOOK_FILE)
		unregister_kretprobe(&sk_krp_file);
	if (sk_hooks & SK_HOOK_SYSCALL)
		unregister_kretprobe(&sk_krp_syscall);
	if (sk_hooks & SK_HOOK_SYSCALL_B)
		unregister_kretprobe(&sk_krp_trace);

	sk_hooks = 0;
	sk_backend = "none";
}

/* ══════════════════ /proc/sk ══════════════════ */

static int sk_version_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", SK_VERSION);
	return 0;
}

/* /proc/sk/um 的写：建规则或清空 */
/*
 * ══════════════════ 规则写入防线（S1 / S2）══════════════════
 *
 * 起因：一次事故。我写了这样一条测试规则：
 *     echo "2000 20 1 hide" > /proc/umbral/um
 *     uid 2000 = adb shell 自己；dev 20 / ino 1 = /proc 目录本身
 * 因为 ① 的 open 钩子吃同一条规则，shell 从此打不开 /proc 下任何东西 ——
 * 每次 exec 都要解析 /proc/self/exe，于是整个 shell 全废，设备表现为崩溃。
 *
 * 两道硬防线（在**写规则**时就拒，不是运行时判断）：
 *   S1 目标文件系统白名单：/proc /sys /dev /system /vendor /product
 *      用 super_block->s_magic 判，不看路径字符串（路径可以有很多别名）
 *   S2 保护 uid：0(root) / 2000(shell) / 管理器 uid 一律不许作为"被隐藏方"
 *
 * 为什么必须在写入时拒：
 *   运行时判断等于「已经写进去了才不管用」，规则表里留着这种条目本身
 *   就是隐患 —— 换个 uid 一访问就炸。写不进去最安全。
 */
#define SK_PROT_MAX 8
static u32 sk_prot_dev[SK_PROT_MAX];
static int sk_prot_n;

static bool sk_um_sb_forbidden(struct super_block *sb)
{
	if (!sb)
		return true;	/* 拿不到 sb 就当真，宁可拒绝 */
#ifdef PROC_SUPER_MAGIC
	if (sb->s_magic == PROC_SUPER_MAGIC)
		return true;
#endif
#ifdef SYSFS_MAGIC
	if (sb->s_magic == SYSFS_MAGIC)
		return true;
#endif
#ifdef DEBUGFS_MAGIC
	if (sb->s_magic == DEBUGFS_MAGIC)
		return true;
#endif
#ifdef SECURITYFS_MAGIC
	if (sb->s_magic == SECURITYFS_MAGIC)
		return true;
#endif
#ifdef BPF_FS_MAGIC
	if (sb->s_magic == BPF_FS_MAGIC)
		return true;
#endif
	return false;
}

/**
 * 规则写入前的统一校验。
 * @return 0 = 允许；否则返回应回给用户态的错误码
 */
static int sk_um_guard(u32 uid, u32 dev, int act)
{
	/* S2：保护 uid 不能作为「被隐藏/被伪造」的对象 */
	if (uid == 0 || uid == 2000)
		return -EPERM;
	if (sk_grant_uid >= 0 && uid == (u32)sk_grant_uid)
		return -EPERM;

	/*
	 * S1：dev 对应的是虚拟文件系统就拒。
	 * 我们没有 dev → sb 的反查表，所以用一个便宜的近似：
	 * 把已知受保护的 dev 记在白名单里（sk_prot_dev，开机时填）。
	 * 拿不到白名单时（开机早期）一律放行，但那时还没有管理器在写规则。
	 */
	{
		int i;

		for (i = 0; i < sk_prot_n; i++) {
			if (dev == sk_prot_dev[i])
				return -EPERM;
		}
	}
	(void)act;
	return 0;
}

/* 受保护文件系统的 dev 白名单（开机由 sk_prot_init 填） */
/* 开机填白名单：open 这些目录，记下它们的 s_dev */
static void sk_prot_init(void)
{
	static const char *paths[] = {
		"/proc", "/sys", "/dev", "/system", "/vendor", "/product", NULL
	};
	int i;

	sk_prot_n = 0;
	if (!sk_resolve_file_api())
		return;
	for (i = 0; paths[i] && sk_prot_n < SK_PROT_MAX; i++) {
		struct file *f = sk_filp_open(paths[i], O_RDONLY, 0);

		if (IS_ERR(f))
			continue;
		if (f->f_inode && f->f_inode->i_sb) {
			if (sk_um_sb_forbidden(f->f_inode->i_sb))
				sk_prot_dev[sk_prot_n++] =
					new_encode_dev(f->f_inode->i_sb->s_dev);
		}
		sk_filp_close(f, NULL);
	}
	pr_info(SK_TAG "受保护文件系统 dev 白名单：%d 项\n", sk_prot_n);
}

static ssize_t sk_um_write(struct file *f, const char __user *ubuf,
			   size_t len, loff_t *off)
{
	char buf[96];
	u32 uid, dev;
	u64 ino;

	if (!sk_writer_allowed())
		return -EPERM;
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = 0;
	strim(buf);

	/*
	 * "dry <uid> <dev> <ino> <action>" —— 规则预演（只判不写）
	 *
	 * 规则写错会把自己锁死（早期一条 hide /proc 的规则把 adb shell 藏了，
	 * 设备立不起来）。写入前先跑一遍同样的判据，只回结论不落表。
	 */
	if (!strncmp(buf, "dry ", 4)) {
		unsigned int du = 0, dd = 0;
		unsigned long long di = 0;
		char da[16];
		int act = -1;

		da[0] = 0;
		if (sscanf(buf + 4, "%u %u %llu %15s", &du, &dd, &di, da) != 4)
			return -EINVAL;
		if (!strcmp(da, "hide"))       act = 1;
		else if (!strcmp(da, "deny"))  act = 2;
		else if (!strcmp(da, "eperm")) act = 3;
		else if (!strcmp(da, "ok"))    act = 4;
		else if (!strcmp(da, "empty")) act = 5;
		else if (!strcmp(da, "zero"))  act = 6;
		else if (!strcmp(da, "fake"))  act = 7;
		if (act < 0) {
			pr_info(SK_TAG "dry: REJECT 未知动作 '%s'\n", da);
			return len;
		}
		if (sk_um_guard(du, dd, act)) {
			pr_info(SK_TAG "dry: REJECT S2 uid=%u 是受保护对象\n", du);
			return len;
		}
		pr_info(SK_TAG "dry: OK uid=%u dev=%u ino=%llu act=%s\n",
			du, dd, di, da);
		return len;
	}
	if (!strcmp(buf, "clear")) {
		spin_lock(&sk_um_lock);
		sk_um_n = 0;
		sk_um_prog_len = 0;
		spin_unlock(&sk_um_lock);
		return len;
	}

	/* "bc <hex>"：载入字节码程序（整份替换规则表） */
	if (!strncmp(buf, "bc ", 3)) {
		int rc = sk_um_load_hex(buf + 3, strlen(buf + 3));

		if (rc) {
			pr_warn(SK_TAG "字节码格式错\n");
			return rc;
		}
		/* 有程序了就清空规则表，避免两套逻辑打架 */
		spin_lock(&sk_um_lock);
		sk_um_n = 0;
		spin_unlock(&sk_um_lock);
		return len;
	}

	/*
	 * "proc <pid> <uid> [action]" —— 判定点5：进程可见性
	 *
	 * 为什么需要这个语法：
	 *   规则是按 (dev, ino) 存的，用户不可能自己去查 /proc/1234 的 ino。
	 *   这里用 kern_path 解析出 /proc/<pid> 目录的 dev/ino 再加规则 ——
	 *   write 处理器在进程上下文，允许睡眠，所以可以放心用 kern_path。
	 *
	 * 加完之后：
	 *   · 目标 uid 里 ls /proc → 看不见这个 pid（判定点3 的 readdir 过滤）
	 *   · 目标 uid 里 stat/访问 /proc/<pid> → 不存在（判定点1）
	 *   两处叠加，等于进程被彻底藏起来。
	 */
	if (!strncmp(buf, "proc ", 5)) {
		int pid = 0, tuid = 0;
		char actname[16] = {0};
		int act = SK_UM_ACT_HIDE;
		struct path pth;
		struct inode *pi;
		char pbuf[32];
		u32 pdev;
		u64 pino;
		int rc2;

		if (sscanf(buf + 5, "%d %d %15s", &pid, &tuid, actname) < 2
		    || pid <= 0 || tuid <= 0)
			return -EINVAL;
		if (actname[0]) {
			act = sk_um_act_parse(actname);
			if (act < 0)
				return -EINVAL;
		}

		snprintf(pbuf, sizeof(pbuf), "/proc/%d", pid);
		rc2 = kern_path(pbuf, 0, &pth);
		if (rc2) {
			pr_warn(SK_TAG "找不到进程 %d（%d）\n", pid, rc2);
			return rc2;
		}
		pi = d_backing_inode(pth.dentry);
		if (!pi || !pi->i_sb) {
			path_put(&pth);
			return -ENOENT;
		}
		pdev = new_encode_dev(pi->i_sb->s_dev);
		pino = (u64)pi->i_ino;
		path_put(&pth);

		if (sk_um_add((u32)tuid, pdev, pino, act))
			return -ENOSPC;
		pr_info(SK_TAG "UM 进程隐藏: pid=%d 对 uid=%d dev=%u ino=%llu act=%s\n",
			pid, tuid, pdev, (unsigned long long)pino,
			actname[0] ? actname : "hide");
		return len;
	}

	/*
	 * 判定点⑤ 的写入格式（和文件规则共用同一个节点）：
	 *     pid <pid>          把该 pid 加进隐藏名单
	 *     pid clear          清空名单
	 *     pidclear           同上（短写）
	 * 放在文件规则解析之前，因为格式完全不同（首段不是数字）。
	 */
	if (!strncmp(buf, "pidclear", 8)) {
		sk_hp_clear();
		pr_info(SK_TAG "进程隐藏名单已清空\n");
		return len;
	}
	if (!strncmp(buf, "pid ", 4)) {
		int v = 0;

		if (!strncmp(buf + 4, "clear", 5)) {
			sk_hp_clear();
			pr_info(SK_TAG "进程隐藏名单已清空\n");
			return len;
		}
		if (sscanf(buf + 4, "%d", &v) == 1 && v > 0) {
			int rc2 = sk_hp_add((pid_t)v);

			if (rc2)
				return rc2;
			pr_info(SK_TAG "进程隐藏: pid=%d 已加入名单\n", v);
			return len;
		}
		return -EINVAL;
	}

	{
		char actname[16];
		int act = SK_UM_ACT_HIDE;
		int nf;

		actname[0] = 0;
		nf = sscanf(buf, "%u %u %llu %15s", &uid, &dev, &ino, actname);
		if (nf < 3)
			return -EINVAL;
		if (nf >= 4) {
			act = sk_um_act_parse(actname);
			if (act < 0)
				return -EINVAL;
		}
		/*
		 * fake 动作必须带载荷：<uid> <dev> <ino> fake <hex>
		 * 找不到第 5 段就直接拒 —— 空载荷的 fake 等于 empty，
		 * 让用户以为设了假内容却没设，是最糟的失败方式。
		 */
		if (act == SK_UM_ACT_FAKE) {
			char hex[SK_UM_PAYLOAD_MAX * 2 + 1];
			int got = 0;

			hex[0] = 0;
			{
				/* 跳过前四段，取第五段 */
				const char *q = buf;
				int seg = 0;

				while (*q && seg < 4) {
					while (*q == ' ')
						q++;
					while (*q && *q != ' ')
						q++;
					seg++;
				}
				while (*q == ' ')
					q++;
				while (*q && *q != ' ' && *q != '\n'
				       && got < (int)sizeof(hex) - 1)
					hex[got++] = *q++;
			}
			hex[got] = 0;
			if (got == 0)
				return -EINVAL;
			if (sk_um_set_payload_hex(hex))
				return -EINVAL;
		}
		{
			int g = sk_um_guard(uid, dev, act);

			if (g)
				return g;
		}
		if (sk_um_add(uid, dev, ino, act))
			return -ENOSPC;
		/*
		 * S3：回读确认。
		 * 表里查不到就说明这条规则没真正生效（表满、被并发挤掉、
		 * 或者 add 里某处早退），此时必须把错误回给用户态 ——
		 * 否则用户看到「写入成功」而行为完全不是那么回事。
		 * 上一次事故的教训就是「写进去了但行为不可预期」而没有反馈。
		 */
		if (sk_um_action(uid, dev, ino) != act)
			return -EIO;
		pr_info(SK_TAG "UM 规则: uid=%u dev=%u ino=%llu act=%s\n",
			uid, dev, (unsigned long long)ino,
			actname[0] ? actname : "hide");
		return len;
	}

	{
		int g = sk_um_guard(uid, dev, SK_UM_ACT_HIDE);

		if (g)
			return g;
	}
	if (sk_um_add(uid, dev, ino, SK_UM_ACT_HIDE))
		return -ENOSPC;
	if (sk_um_action(uid, dev, ino) != SK_UM_ACT_HIDE)
		return -EIO;	/* S3：回读确认 */

	pr_info(SK_TAG "UM 规则: uid=%u dev=%u ino=%llu\n", uid, dev,
		(unsigned long long)ino);
	return len;
}

static ssize_t sk_umdbg_write(struct file *f, const char __user *ubuf,
			      size_t len, loff_t *off)
{
	char buf[32];
	long uid = -1;

	if (!sk_writer_allowed())
		return -EPERM;
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = 0;
	strim(buf);

	if (!strcmp(buf, "off")) {
		sk_umdbg_uid = -1;
		pr_info(SK_TAG "UMDBG off\n");
		return len;
	}
	if (kstrtol(buf, 10, &uid) || uid < 0)
		return -EINVAL;

	sk_umdbg_uid = (int)uid;
	atomic_set(&sk_umdbg_left, 8);
	pr_info(SK_TAG "UMDBG armed for uid=%ld (next 8 inode_permission calls)\n", uid);
	return len;
}

static int sk_umdbg_show(struct seq_file *m, void *v)
{
	seq_printf(m, "uid   %d\n", sk_umdbg_uid);
	seq_printf(m, "left  %d\n", atomic_read(&sk_umdbg_left));
	return 0;
}

static int sk_um_show(struct seq_file *m, void *v)
{
	int i;

	seq_printf(m, "count %d max %d\n", sk_um_n, SK_UM_MAX);
	for (i = 0; i < sk_um_n; i++)
		seq_printf(m, "  uid %u dev %u ino %llu\n", sk_um[i].uid,
			   sk_um[i].dev, (unsigned long long)sk_um[i].ino);
	return 0;
}

static int sk_btf_show(struct seq_file *m, void *v)
{
	seq_printf(m, "parsed        %d\n", atomic_read(&sk_btf_ok));
	seq_printf(m, "module.list   %lu\n", sk_off_module_list);
	seq_printf(m, "module.mkobj  %lu\n", sk_off_module_mkobj);
	seq_printf(m, "sizeof.module %lu\n", (unsigned long)sizeof(struct module));
	return 0;
}

static int sk_mode_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", SK_MODE);
	return 0;
}

static int sk_status_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", atomic_read(&sk_err));
	return 0;
}

static int sk_backend_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", sk_backend);
	return 0;
}

static int sk_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "seen        %lld\n", atomic64_read(&sk_seen));
	seq_printf(m, "elevated    %lld\n", atomic64_read(&sk_elevated));
	seq_printf(m, "reverted    %lld\n", atomic64_read(&sk_reverted));
	seq_printf(m, "denied      %lld\n", atomic64_read(&sk_denied));
	seq_printf(m, "lsm_e_call  %lld\n", atomic64_read(&sk_lsm_e_called));
	seq_printf(m, "lsm_r_call  %lld\n", atomic64_read(&sk_lsm_r_called));
	seq_printf(m, "lsm_seen    %lld\n", atomic64_read(&sk_lsm_seen));
	seq_printf(m, "lsm_bypass  %lld\n", atomic64_read(&sk_lsm_bypass));
	seq_printf(m, "backend     %s\n",   sk_backend);
	return 0;
}

static int sk_token_show(struct seq_file *m, void *v)
{
	u8 tok[SK_TOKEN_LEN];
	int i;

	if (!current->mm) {
		for (i = 0; i < SK_TOKEN_LEN; i++)
			seq_putc(m, '0');
		seq_putc(m, '\n');
		return 0;
	}

	sk_derive_token(__kuid_val(current_uid()), tok);
	for (i = 0; i < SK_TOKEN_LEN; i++)
		seq_printf(m, "%02x", tok[i]);
	seq_putc(m, '\n');
	return 0;
}

static int sk_selftest_show(struct seq_file *m, void *v)
{
	seq_printf(m, "sizeof_module      %zu\n", sizeof(struct module));
	seq_printf(m, "sizeof_cred        %zu\n", sizeof(struct cred));
	seq_printf(m, "offsetof_init      %zu\n", offsetof(struct module, init));
	seq_printf(m, "offsetof_exit      %zu\n", offsetof(struct module, exit));
	seq_printf(m, "token_addr         0x%llx\n", (unsigned long long)SK_TOKEN_ADDR);
	seq_printf(m, "token_len          %d\n", SK_TOKEN_LEN);
	seq_printf(m, "sensitive_count    %zu\n", ARRAY_SIZE(sk_sensitive));
	seq_printf(m, "hooks              0x%x  (1=sysA 2=sysB 4=inode 8=file 16=open 32=avc 64=avcNA 128=capable)\n", sk_hooks);
	seq_printf(m, "dbg_elev           %lld\n", (long long)atomic64_read(&sk_dbg_elev));
	seq_printf(m, "cred_cached        %d\n", atomic_read(&sk_cred_n));
	seq_printf(m, "hidden             %d\n", atomic_read(&sk_hidden));
	seq_printf(m, "off_orphan         %lld\n", (long long)atomic64_read(&sk_off_orphan));
	seq_printf(m, "uid_grant_count    %d\n", atomic_read(&sk_ugrant_n));
	seq_printf(m, "grant_count        %d\n", atomic_read(&sk_grant_n));
	seq_printf(m, "grant_hits         %lld\n", (long long)atomic64_read(&sk_grant_hits));
	seq_printf(m, "grant_miss         %lld\n", (long long)atomic64_read(&sk_grant_miss));
	seq_printf(m, "grant_inherited    %d\n", atomic_read(&sk_inherited));
	seq_printf(m, "granted_now        %d\n", sk_granted_task(current) ? 1 : 0);
	seq_printf(m, "root_cred          %px\n", sk_root_cred);
	seq_printf(m, "current_cred       %px\n", current->cred);
	seq_printf(m, "in_window          %d\n", sk_in_window() ? 1 : 0);
	seq_printf(m, "current_pid        %d\n", current->pid);
	seq_printf(m, "current_uid        %u\n", __kuid_val(current_uid()));
	return 0;
}


/* ══════════════════ /proc/sk/grant 与 /proc/sk/grants ══════════════════ */

/*
 * 写入格式（都是 ASCII）：
 *     self | 1 | on          给当前进程授权
 *     off | 0 | revoke       撤销当前进程的授权
 *     clear                  清空全部
 *     <pid>                  给指定 pid 授权（需要 find_get_task_by_vpid）
 *
 * 为什么要支持 <pid>：管理器要给别的 App 发授权，不能只给自己。
 * 为什么默认只允许 root 写：否则任何 App 都能给自己提权。
 *     sk_allow_uid=10563 insmod 之后，那个 uid 才有资格写。
 */
static ssize_t sk_grant_write(struct file *f, const char __user *ubuf,
			      size_t len, loff_t *off)
{
	char buf[32];
	long pid = 0;
	struct task_struct *t;
	int rc;

	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';
	strim(buf);

	if (!sk_writer_allowed())
		return -EPERM;

	if (!strcmp(buf, "clear")) {
		sk_grant_clear();
		return len;
	}

	/* 解析 "<pid|self>[ <mode>]" */
	{
		char *sp = strchr(buf, ' ');
		u8 mode = SK_GRANT_SHADOW;
		long m = 0;

		if (sp) {
			*sp++ = 0;
			strim(buf);
			strim(sp);
			if (!kstrtol(sp, 10, &m) && m == SK_GRANT_SUPER)
				mode = SK_GRANT_SUPER;
		}

		/* uid:<uid> [mode|off] —— 管理器用这个，按 App 持久授权 */
		if (!strncmp(buf, "uid:", 4)) {
			long u = -1;

			if (kstrtol(buf + 4, 10, &u) || u <= 0)
				return -EINVAL;

			/*
			 * 只有 "off"/"revoke" 表示撤销。
			 * 不能用 "0" —— 因为 "0" 同时是合法模式值（影子），
			 * 写 "uid:2000 0" 会被误判成撤销。这个歧义踩过一次。
			 */
			if (sp && (!strcmp(sp, "off") || !strcmp(sp, "revoke"))) {
				sk_ugrant_del((u32)u);
				return len;
			}

			/* 模式值：0=影子 1=超级用户 2=完全影子（sp 已在上面解析） */
			if (sp && !strcmp(sp, "2"))
				mode = SK_GRANT_FULL;
			rc = sk_ugrant_add((u32)u, mode);
			return rc ? rc : (ssize_t)len;
		}

		if (!strcmp(buf, "self") || !strcmp(buf, "on")) {
			rc = sk_grant_add(current, mode);
			return rc ? rc : (ssize_t)len;
		}

		if (!strcmp(buf, "off") || !strcmp(buf, "revoke")) {
			sk_grant_del(current->pid);
			return len;
		}

		if (kstrtol(buf, 10, &pid) || pid <= 0)
			return -EINVAL;

		t = sk_find_task((pid_t)pid);
		if (!t) {
			/*
			 * ★ 找不到 task 也照样登记 ★
			 *
			 * 原来的行为是直接 -ESRCH 返回。但实测：
			 *   shell 里 dd 写 grant，写入成功、无报错，
			 *   而内核的 count 一直是 0 —— 就是在这里被挡掉的，
			 *   而且挡得静默（返回错误码，但写方看不到语义）。
			 *
			 * 子进程刚 fork、父进程立刻替它登记，这个时间窗里
			 * 用 for_each_process 找它可能失败。
			 *
			 * 所以改成：直接按解析出的 pid 建一条条目（start_time 记 0，
			 * 匹配时不再比 start_time，见 sk_grant_mode_task）。
			 */
			struct sk_grant *ng = kzalloc(sizeof(*ng), GFP_ATOMIC);

			if (!ng)
				return -ENOMEM;
			ng->pid = (pid_t)pid;
			ng->start_time = 0;
			ng->mode = mode;
			spin_lock(&sk_grant_lock);
			hlist_add_head_rcu(&ng->node,
					   &sk_grants[hash_min(ng->pid, SK_GRANT_BITS)]);
			spin_unlock(&sk_grant_lock);
			atomic_inc(&sk_grant_n);
			pr_info(SK_TAG "按 pid 直接登记授权：pid=%ld mode=%u\n", pid, mode);
			return len;
		}

		rc = sk_grant_add(t, mode);
		put_task_struct(t);
		return rc ? rc : (ssize_t)len;
	}

	/* 上面那个块里所有分支都 return 了，不会走到这里 */
	return len;
}

static const SK_PROC_OPS sk_grant_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_write = sk_grant_write,
#else
	.write = sk_grant_write,
#endif
};

static int sk_escape_open(struct inode *i, struct file *f)
{
	return single_open(f, sk_escape_show, NULL);
}

/* ══════════════════ 第二批 B：内核态 syscall 过滤 ══════════════════ */

/*
 * 规则表：某些 pid 的某些 syscall 直接拒绝。
 *
 * 实现方式：在 syscall 入口把 x8（arm64 的系统调用号寄存器）改成 -1，
 * 内核会返回 -ENOSYS。这样做的好处：
 *   · 不需要改返回路径，不需要第二个钩子
 *   · 目标进程看到的就是「这个系统调用不存在」，和旧内核缺 syscall 一样自然
 *
 * ★ 上下文：syscall 入口是原子上下文（preempt 关、可能中断关）
 *   → 这里只做静态数组的整数比较，不分配、不睡眠、不打日志
 *   → 日志放在写规则时打，不在命中时打（否则一条规则能刷爆 dmesg）
 *
 * 上限 64 条：够拦一个 App 的敏感 syscall 集合。
 * 未上机验证。
 */
#define SK_SYSF_MAX 64

struct sk_sysf_ent {
	pid_t pid;	/* 0 = 对所有 pid 生效 */
	int   nr;	/* -1 = 所有 syscall */
};

static struct sk_sysf_ent sk_sysf[SK_SYSF_MAX];
static int sk_sysf_n;
static DEFINE_SPINLOCK(sk_sysf_lock);
static bool sk_sysf_on;		/* 默认关 */

/**
 * 这个 (pid, nr) 要不要拦。
 * ★ 只在原子上下文调用：纯整数比较，无分配无睡眠。
 */
static bool sk_sysf_denied(pid_t pid, int nr)
{
	bool hit = false;
	int i;

	if (!sk_sysf_on || sk_sysf_n == 0)
		return false;

	spin_lock(&sk_sysf_lock);
	for (i = 0; i < sk_sysf_n; i++) {
		if ((sk_sysf[i].pid == 0 || sk_sysf[i].pid == pid)
		    && (sk_sysf[i].nr < 0 || sk_sysf[i].nr == nr)) {
			hit = true;
			break;
		}
	}
	spin_unlock(&sk_sysf_lock);
	return hit;
}

/* 无规则 / 未开启时早退，用于热路径零开销判断 */
static bool sk_sysf_active(void)
{
	return sk_sysf_on && sk_sysf_n > 0;
}

static int sk_sysf_add(pid_t pid, int nr)
{
	int rc = 0;
	int i;

	spin_lock(&sk_sysf_lock);
	for (i = 0; i < sk_sysf_n; i++) {
		if (sk_sysf[i].pid == pid && sk_sysf[i].nr == nr) {
			spin_unlock(&sk_sysf_lock);
			return 0;	/* 重复不算错 */
		}
	}
	if (sk_sysf_n >= SK_SYSF_MAX)
		rc = -ENOSPC;
	else {
		sk_sysf[sk_sysf_n].pid = pid;
		sk_sysf[sk_sysf_n].nr  = nr;
		sk_sysf_n++;
	}
	spin_unlock(&sk_sysf_lock);
	return rc;
}

static void sk_sysf_clear(void)
{
	spin_lock(&sk_sysf_lock);
	sk_sysf_n = 0;
	spin_unlock(&sk_sysf_lock);
}

/* ══════════════════ 第二批 A：进程内存读写（判定点之外的能力）══════════════ */

/*
 * 为什么用 access_process_vm 而不是 get_user_pages_remote：
 *   · get_user_pages_remote 需要自己 kmap / kunmap、处理页数组、释放引用，
 *     一百多行，且 GKI 不一定导出；
 *   · access_process_vm 就是 /proc/pid/mem 背后的那个函数，
 *     一次调用搞定读或写，内部自己处理 GUP 与 kmap。
 * 它同样没导出 → 用 sk_sym() 从 kallsyms 取地址（本项目一贯做法）。
 *
 * ★ 会睡眠（GUP 可能睡眠）→ 只允许在进程上下文的 write handler 里调，
 *   绝不在任何 kretprobe / 原子上下文里调。
 */
static int (*sk_access_process_vm)(struct task_struct *tsk, unsigned long addr,
				   void *buf, int len, unsigned int gup_flags);

/* 按 pid 找 task；调用方负责 put_task_struct */
static struct task_struct *sk_task_by_pid(pid_t pid)
{
	struct task_struct *t;

	rcu_read_lock();
	for_each_process(t) {
		if (task_pid_nr(t) == pid) {
			get_task_struct(t);
			rcu_read_unlock();
			return t;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static int hex2bin_u8(const char *hex, u8 *out, int outmax)
{
	int n = 0;

	if (!hex)
		return -EINVAL;
	while (hex[0] && hex[1] && n < outmax) {
		int hi, lo;
		char c1 = hex[0], c2 = hex[1];

		hi = (c1 >= '0' && c1 <= '9') ? c1 - '0'
		   : (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10
		   : (c1 >= 'A' && c1 <= 'F') ? c1 - 'A' + 10 : -1;
		lo = (c2 >= '0' && c2 <= '9') ? c2 - '0'
		   : (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10
		   : (c2 >= 'A' && c2 <= 'F') ? c2 - 'A' + 10 : -1;
		if (hi < 0 || lo < 0)
			return -EINVAL;
		out[n++] = (u8)((hi << 4) | lo);
		hex += 2;
	}
	return n;
}

#define SK_PM_BUF 256

/*
 * 写入格式（/proc/umbral/procmem）：
 *     read  <pid> <addr_hex> <len>          → 把目标内存 dump 成 hex 写回 seq
 *     write <pid> <addr_hex> <hexbytes>     → 把 hex 写进目标内存
 *     addr 用十六进制（用户态地址），len 上限 256
 *
 * 返回值：
 *     read  成功时返回实际读到的字节数（负数 = 错误码）
 *     write 成功时返回写入的字节数
 *
 * 未上机验证。仅做代码层三遍自审。
 */
/* ── inline hook 原字节备份表（最多 16 条）── */
#define SK_IH_MAX 16
struct sk_ih_ent {
	pid_t pid;
	unsigned long long from;
	u8 orig[16];
	int len;
	bool used;
};
static struct sk_ih_ent sk_ih[SK_IH_MAX];
static DEFINE_SPINLOCK(sk_ih_lock);

static int sk_ih_save(pid_t pid, unsigned long long from, const u8 *orig, int len)
{
	int i, rc = -ENOSPC;

	if (len <= 0 || len > 16)
		return -EINVAL;
	spin_lock(&sk_ih_lock);
	for (i = 0; i < SK_IH_MAX; i++) {
		if (sk_ih[i].used && sk_ih[i].pid == pid
		    && sk_ih[i].from == from) {
			memcpy(sk_ih[i].orig, orig, len);
			sk_ih[i].len = len;
			rc = 0;
			break;
		}
	}
	if (rc < 0) {
		for (i = 0; i < SK_IH_MAX; i++) {
			if (!sk_ih[i].used) {
				sk_ih[i].used = true;
				sk_ih[i].pid = pid;
				sk_ih[i].from = from;
				memcpy(sk_ih[i].orig, orig, len);
				sk_ih[i].len = len;
				rc = 0;
				break;
			}
		}
	}
	spin_unlock(&sk_ih_lock);
	return rc;
}

static struct sk_ih_ent *sk_ih_find(pid_t pid)
{
	int i;
	struct sk_ih_ent *r = NULL;

	spin_lock(&sk_ih_lock);
	for (i = 0; i < SK_IH_MAX; i++) {
		if (sk_ih[i].used && sk_ih[i].pid == pid) {
			r = &sk_ih[i];
			break;
		}
	}
	spin_unlock(&sk_ih_lock);
	return r;
}

static void sk_ih_drop(pid_t pid)
{
	int i;

	spin_lock(&sk_ih_lock);
	for (i = 0; i < SK_IH_MAX; i++) {
		if (sk_ih[i].used && sk_ih[i].pid == pid)
			sk_ih[i].used = false;
	}
	spin_unlock(&sk_ih_lock);
}

static long sk_procmem_do(const char *buf, char *out, size_t outmax)
{
	char cmd[8];
	unsigned int pid = 0;
	unsigned long long addr = 0;
	size_t olen = 0;

	memset(cmd, 0, sizeof(cmd));
	if (sscanf(buf, "%7s %u %llx", cmd, &pid, &addr) < 3)
		return -EINVAL;

	if (!sk_access_process_vm) {
		sk_access_process_vm = (void *)sk_sym("access_process_vm");
		if (!sk_access_process_vm)
			return -ENOSYS;
	}

	/* 第二批 B：syscall 过滤的规则写入（复用同一个节点） */
	if (!strcmp(cmd, "sysf")) {
		/* sysf on | sysf off | sysf clear | sysf add <pid|0> <nr|-1> */
		char sub[8];
		int p2 = 0, nr2 = -1;

		sub[0] = 0;
		if (sscanf(buf, "%*s %7s", sub) < 1)
			return -EINVAL;
		if (!strcmp(sub, "on")) {
			sk_sysf_on = true;
			return 1;
		}
		if (!strcmp(sub, "off")) {
			sk_sysf_on = false;
			return 1;
		}
		if (!strcmp(sub, "clear")) {
			sk_sysf_clear();
			return 1;
		}
		if (!strcmp(sub, "add")) {
			if (sscanf(buf, "%*s %*s %d %d", &p2, &nr2) < 2)
				return -EINVAL;
			if (p2 < 0)
				return -EINVAL;
			return sk_sysf_add((pid_t)p2, nr2);
		}
		return -EINVAL;
	}

	/*
	 * ══════════════════ 第二批 C：用户态 hook（GOT / 函数指针替换）══════════════════
	 *
	 * 为什么先做这个而不是改代码段（text patch）：
	 *   代码段是 r-xp，要改必须动 PTE（mprotect 或 set_memory_rw）；
	 *   改错一个字节目标进程就崩，而且 CFI/CFG 可能校验函数入口。
	 *   而 GOT 表项、函数指针、vtable 都在 **rw- 段**，
	 *   直接写就是合法内存操作 —— 目标进程不会崩，最坏是行为变了。
	 *
	 * 命令：ptr <pid> <slot_hex> <target_hex>
	 *   slot   = 要改的指针所在地址（GOT 项 / 函数指针变量）
	 *   target = 新值（一般是目标进程里某个函数的地址）
	 * 写入后立刻回读比对（S3 同样的思路：不做假成功）。
	 *
	 * 8 字节小端。未上机验证。
	 */
	/*
	 * ══════════════════ 第二批 C 后半：代码段 patch（inline hook）══════════════════
	 *
	 * ★ 关键发现：不需要改页表 ★
	 *
	 * 我原先以为改 r-xp 的代码段必须先动 PTE（mprotect / set_memory_rw）。
	 * 实际上 access_process_vm 的最后一个参数是 gup_flags，
	 * 而 ptrace 的 POKETEXT 就是靠两个标志写只读页：
	 *
	 *     FOLL_WRITE = 0x01    我要写
	 *     FOLL_FORCE = 0x10    绕过 VMA 的写权限检查（ptrace 特权）
	 *     → 0x11
	 *
	 * 也就是说：只要传 0x11，就能直接往 text 段写，页表一个字节都不用碰。
	 * 这比我原计划的 set_memory_rw 方案安全得多，也不用 kmap。
	 *
	 * 命令：text <pid> <addr_hex> <hexbytes>     最多 32 字节
	 * 写入后立刻回读比对。
	 *
	 * 用途：把目标进程某个函数入口的前 16 字节换成
	 *       ldr x16, #8 ; br x16 ; <64 位跳转目标>
	 *       （16 字节 trampoline，arm64 固定写法）
	 *       或者直接 4 字节改成一条 b 指令（±128MB 范围内）
	 *
	 * 未上机验证。
	 */
	if (!strcmp(cmd, "jmp")) {
		/*
		 * ══════════ inline hook 的 patch 侧（arm64，内核态执行）══════════
		 *
		 * 目标：把 libUE4.so 里某个函数的第一条指令换成「跳到蹦床」。
		 *
		 * arm64 没有 x86 那种 5 字节相对跳转那么方便，但有两条稳定写法：
		 *
		 *   ① 4 字节分支（B 指令，±128 MB）
		 *        0x14000000 | (offset >> 2)
		 *      要求蹦床离目标函数不超过 128 MB —— 同进程内 mmap 通常满足
		 *
		 *   ② 16 字节绝对跳转（任意距离，最稳）
		 *        ldr x16, #8      ; 0x58000050
		 *        br  x16          ; 0xd61f0200
		 *        <64 位目标地址>   ; 8 字节小端
		 *      必须函数至少还有 16 字节可改（前 16 字节里不能有别的指令
		 *      被别的分支当作目标，否则会踩坏）
		 *
		 * 这里两种都给：
		 *   jmp  <pid> <from_hex> <to_hex>    → 16 字节绝对跳转（默认，安全距离无限制）
		 *   jmpb <pid> <from_hex> <to_hex>    → 4 字节 B 指令（省空间，±128MB）
		 *
		 * 写代码段用 FOLL_FORCE（0x10），和 ptrace 的 POKETEXT 同款，
		 * 不需要动页表 —— 这是上一轮验证出来的关键点。
		 *
		 * 原始指令会被存进模块自己的表里（最多 16 条），
		 * 用 jmpundo <pid> 还原。
		 *
		 * ★ 会睡眠（GUP）→ 只在 write handler（进程上下文）调用
		 * ★ 未上机验证
		 */
		unsigned long long from = 0, to = 0;
		u8 patch[16];
		int i, plen, wrote, got;
		struct task_struct *t;
		bool use_b = (strstr(cmd, "b") != NULL);

		if (sscanf(buf, "%*s %u %llx %llx", &pid, &from, &to) < 3)
			return -EINVAL;
		if (from & 3)
			return -EINVAL;		/* 指令必须 4 字节对齐 */
		if (!sk_access_process_vm) {
			sk_access_process_vm = (void *)sk_sym("access_process_vm");
			if (!sk_access_process_vm)
				return -ENOSYS;
		}

		memset(patch, 0, sizeof(patch));
		if (use_b) {
			long long off = (long long)to - (long long)from;

			if (off > (128LL << 20) || off < -(128LL << 20))
				return -ERANGE;
			{
				u32 insn = 0x14000000u
					 | ((u32)((off >> 2) & 0x03ffffff));

				patch[0] = (u8)(insn & 0xff);
				patch[1] = (u8)((insn >> 8) & 0xff);
				patch[2] = (u8)((insn >> 16) & 0xff);
				patch[3] = (u8)((insn >> 24) & 0xff);
			}
			plen = 4;
		} else {
			/* ldr x16, #8 ; br x16 ; <addr> */
			patch[0] = 0x50; patch[1] = 0x00; patch[2] = 0x00; patch[3] = 0x58;
			patch[4] = 0x00; patch[5] = 0x02; patch[6] = 0x1f; patch[7] = 0xd6;
			for (i = 0; i < 8; i++)
				patch[8 + i] = (u8)((to >> (i * 8)) & 0xff);
			plen = 16;
		}

		t = sk_task_by_pid((pid_t)pid);
		if (!t)
			return -ESRCH;

		/* ① 先存原字节（失败就不改，保证可还原） */
		{
			u8 orig[16];

			memset(orig, 0, sizeof(orig));
			got = sk_access_process_vm(t, (unsigned long)from, orig, plen, 0);
			if (got != plen) {
				put_task_struct(t);
				return got < 0 ? got : -EFAULT;
			}
			if (sk_ih_save((pid_t)pid, from, orig, plen) < 0) {
				put_task_struct(t);
				return -ENOSPC;
			}
		}

		/* ② 写 patch（FOLL_FORCE = 能写 r-xp 页） */
		wrote = sk_access_process_vm(t, (unsigned long)from, patch, plen, 0x11);
		if (wrote != plen) {
			put_task_struct(t);
			return wrote < 0 ? wrote : -EFAULT;
		}

		/* ③ 回读比对 */
		{
			u8 back[16];

			memset(back, 0, sizeof(back));
			got = sk_access_process_vm(t, (unsigned long)from, back, plen, 0);
			put_task_struct(t);
			if (got != plen)
				return got < 0 ? got : -EFAULT;
			for (i = 0; i < plen; i++) {
				if (back[i] != patch[i])
					return -EIO;
			}
		}
		pr_info(SK_TAG "inline hook: pid=%d from=%llx to=%llx %s %d 字节\n",
			pid, from, to, use_b ? "B" : "abs", plen);
		return plen;
	}

	if (!strcmp(cmd, "jmpundo")) {
		/* 还原：把存下来的原字节写回去 */
		struct sk_ih_ent *e;
		struct task_struct *t;
		int wrote;

		if (sscanf(buf, "%*s %u", &pid) < 1)
			return -EINVAL;
		if (!sk_access_process_vm) {
			sk_access_process_vm = (void *)sk_sym("access_process_vm");
			if (!sk_access_process_vm)
				return -ENOSYS;
		}
		t = sk_task_by_pid((pid_t)pid);
		if (!t)
			return -ESRCH;
		e = sk_ih_find((pid_t)pid);
		if (!e) {
			put_task_struct(t);
			return -ENOENT;
		}
		wrote = sk_access_process_vm(t, (unsigned long)e->from,
					     e->orig, e->len, 0x11);
		put_task_struct(t);
		if (wrote != e->len)
			return wrote < 0 ? wrote : -EFAULT;
		sk_ih_drop((pid_t)pid);
		pr_info(SK_TAG "inline hook 已还原: pid=%d\n", pid);
		return 1;
	}

	if (!strcmp(cmd, "text")) {

		unsigned long long at = 0;
		u8 data[32];
		char hex[80];
		const char *q = buf;
		int seg = 0, n, wrote, got, i;
		struct task_struct *t;

		hex[0] = 0;
		if (sscanf(buf, "%*s %u %llx", &pid, &at) < 2)
			return -EINVAL;
		while (*q && seg < 3) {
			while (*q == ' ')
				q++;
			while (*q && *q != ' ')
				q++;
			seg++;
		}
		while (*q == ' ')
			q++;
		{
			int k = 0;

			while (*q && *q != ' ' && *q != '\n'
			       && k < (int)sizeof(hex) - 1)
				hex[k++] = *q++;
			hex[k] = 0;
		}
		if (hex[0] == 0)
			return -EINVAL;
		n = hex2bin_u8(hex, data, sizeof(data));
		if (n <= 0)
			return n ? n : -EINVAL;

		if (!sk_access_process_vm) {
			sk_access_process_vm = (void *)sk_sym("access_process_vm");
			if (!sk_access_process_vm)
				return -ENOSYS;
		}
		t = sk_task_by_pid((pid_t)pid);
		if (!t)
			return -ESRCH;

		/* 0x01 = FOLL_WRITE，0x10 = FOLL_FORCE（ptrace 写只读页的关键） */
		wrote = sk_access_process_vm(t, (unsigned long)at, data, n, 0x11);
		if (wrote != n) {
			put_task_struct(t);
			return wrote < 0 ? wrote : -EFAULT;
		}
		{
			u8 back[32];

			memset(back, 0, sizeof(back));
			got = sk_access_process_vm(t, (unsigned long)at, back, n, 0);
			put_task_struct(t);
			if (got != n)
				return got < 0 ? got : -EFAULT;
			for (i = 0; i < n; i++) {
				if (back[i] != data[i])
					return -EIO;
			}
		}
		return n;
	}

	if (!strcmp(cmd, "ptr")) {
		unsigned long long slot = 0, target = 0;
		u8 buf8[8];
		int i, wrote, got;
		struct task_struct *t;

		if (sscanf(buf, "%*s %u %llx %llx", &pid, &slot, &target) < 3)
			return -EINVAL;
		if (!sk_access_process_vm) {
			sk_access_process_vm = (void *)sk_sym("access_process_vm");
			if (!sk_access_process_vm)
				return -ENOSYS;
		}
		for (i = 0; i < 8; i++)
			buf8[i] = (u8)((target >> (i * 8)) & 0xff);

		t = sk_task_by_pid((pid_t)pid);
		if (!t)
			return -ESRCH;
		wrote = sk_access_process_vm(t, (unsigned long)slot, buf8, 8, 1);
		if (wrote != 8) {
			put_task_struct(t);
			return wrote < 0 ? wrote : -EFAULT;
		}
		/* 回读比对 */
		{
			u8 back[8];

			memset(back, 0, sizeof(back));
			got = sk_access_process_vm(t, (unsigned long)slot, back, 8, 0);
			put_task_struct(t);
			if (got != 8)
				return got < 0 ? got : -EFAULT;
			for (i = 0; i < 8; i++) {
				if (back[i] != buf8[i])
					return -EIO;
			}
		}
		return 1;
	}

	if (!strcmp(cmd, "read")) {
		unsigned int len = 0;
		struct task_struct *t;
		u8 tmp[SK_PM_BUF];
		int got, i;

		if (sscanf(buf, "%7s %u %llx %u", cmd, &pid, &addr, &len) < 4)
			return -EINVAL;
		if (len == 0 || len > SK_PM_BUF)
			return -EINVAL;

		t = sk_task_by_pid((pid_t)pid);
		if (!t)
			return -ESRCH;
		got = sk_access_process_vm(t, (unsigned long)addr, tmp,
					   (int)len, 0);
		put_task_struct(t);
		if (got <= 0)
			return got ? got : -EFAULT;

		for (i = 0; i < got && olen + 3 < outmax; i++)
			olen += scnprintf(out + olen, outmax - olen, "%02x",
					  tmp[i]);
		if (olen + 2 < outmax)
			olen += scnprintf(out + olen, outmax - olen, "\n");
		return got;
	}

	if (!strcmp(cmd, "write")) {
		u8 data[SK_PM_BUF];
		char hex[SK_PM_BUF * 2 + 2];
		const char *q = buf;
		int seg = 0, n, wrote;
		struct task_struct *t;

		/* 跳过前三段取 hex 段 */
		hex[0] = 0;
		while (*q && seg < 3) {
			while (*q == ' ')
				q++;
			while (*q && *q != ' ')
				q++;
			seg++;
		}
		while (*q == ' ')
			q++;
		{
			int k = 0;

			while (*q && *q != ' ' && *q != '\n'
			       && k < (int)sizeof(hex) - 1)
				hex[k++] = *q++;
			hex[k] = 0;
		}
		if (hex[0] == 0)
			return -EINVAL;
		n = hex2bin_u8(hex, data, SK_PM_BUF);
		if (n <= 0)
			return n ? n : -EINVAL;

		t = sk_task_by_pid((pid_t)pid);
		if (!t)
			return -ESRCH;
		/* FOLL_WRITE = 1（写目标页） */
		wrote = sk_access_process_vm(t, (unsigned long)addr, data, n, 1);
		put_task_struct(t);
		if (wrote < 0)
			return wrote;
		return wrote;
	}

	return -EINVAL;
}

static char sk_pm_out[SK_PM_BUF * 2 + 8];
static int sk_pm_outlen;

static int sk_procmem_show(struct seq_file *m, void *v)
{
	if (sk_pm_outlen > 0)
		seq_printf(m, "%s", sk_pm_out);
	else
		seq_printf(m, "usage: read <pid> <addr_hex> <len> | write <pid> <addr_hex> <hexbytes>\n");
	return 0;
}

static int sk_procmem_open(struct inode *i, struct file *f)
{
	return single_open(f, sk_procmem_show, NULL);
}

static ssize_t sk_procmem_write(struct file *f, const char __user *ubuf,
				size_t len, loff_t *off)
{
	char buf[SK_PM_BUF * 2 + 64];
	long rc;

	if (!sk_writer_allowed())
		return -EPERM;
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = 0;
	strim(buf);

	sk_pm_outlen = 0;
	memset(sk_pm_out, 0, sizeof(sk_pm_out));
	rc = sk_procmem_do(buf, sk_pm_out, sizeof(sk_pm_out));
	if (rc < 0)
		return (ssize_t)rc;
	sk_pm_outlen = (int)strlen(sk_pm_out);
	pr_info(SK_TAG "procmem: %s → rc=%ld\n", buf, rc);
	return len;
}

static const SK_PROC_OPS sk_procmem_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_open    = sk_procmem_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_write   = sk_procmem_write,
	.proc_release = single_release,
#else
	.open    = sk_procmem_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = sk_procmem_write,
	.release = single_release,
#endif
};

static const SK_PROC_OPS sk_escape_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_open    = sk_escape_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_write   = sk_escape_write,
	.proc_release = single_release,
#else
	.open    = sk_escape_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = sk_escape_write,
	.release = single_release,
#endif
};

static int sk_grants_show(struct seq_file *m, void *v)
{
	struct sk_grant *g;
	struct sk_ugrant *ug;
	unsigned int bkt, bkt2;

	seq_printf(m, "count %d max %d inherited %d\n",
		   atomic_read(&sk_grant_n), SK_GRANT_MAX,
		   atomic_read(&sk_inherited));
	seq_printf(m, "hits %lld miss %lld\n",
		   (long long)atomic64_read(&sk_grant_hits),
		   (long long)atomic64_read(&sk_grant_miss));

	seq_printf(m, "uid_count %d\n", atomic_read(&sk_ugrant_n));

	rcu_read_lock();
	hash_for_each_rcu(sk_ugrants, bkt2, ug, node)
		seq_printf(m, "uid %u %s\n", ug->uid,
			   ug->mode == SK_GRANT_SUPER ? "super" : "shadow");
	hash_for_each_rcu(sk_grants, bkt, g, node)
		seq_printf(m, "pid %d %llu %s\n", g->pid,
			   (unsigned long long)g->start_time,
			   g->mode == SK_GRANT_SUPER ? "super" : "shadow");
	rcu_read_unlock();
	return 0;
}

static int sk_grants_open(struct inode *i, struct file *f)
{
	return single_open(f, sk_grants_show, NULL);
}

static const SK_PROC_OPS sk_grants_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_open    = sk_grants_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
#else
	.open    = sk_grants_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
#endif
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define SK_RO(_name)                                                    \
	static int _name##_open(struct inode *i, struct file *f)        \
	{ return single_open(f, _name##_show, NULL); }                  \
	static const struct proc_ops _name##_ops = {                    \
		.proc_open    = _name##_open,                           \
		.proc_read    = seq_read,                               \
		.proc_lseek   = seq_lseek,                              \
		.proc_release = single_release,                         \
	}
#else
#define SK_RO(_name)                                                    \
	static int _name##_open(struct inode *i, struct file *f)        \
	{ return single_open(f, _name##_show, NULL); }                  \
	static const struct file_operations _name##_ops = {             \
		.open    = _name##_open,                                \
		.read    = seq_read,                                    \
		.llseek  = seq_lseek,                                   \
		.release = single_release,                              \
	}
#endif


SK_RO(sk_version);
SK_RO(sk_mode);
SK_RO(sk_status);
SK_RO(sk_backend);
SK_RO(sk_stats);
SK_RO(sk_token);
SK_RO(sk_selftest);
SK_RO(sk_btf);
SK_RO(sk_um);
SK_RO(sk_umdbg);
SK_RO(sk_umstat);
SK_RO(sk_claim);

static const SK_PROC_OPS sk_claim_rw_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_open    = sk_claim_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = sk_claim_write,
#else
	.open    = sk_claim_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = sk_claim_write,
#endif
};

static const SK_PROC_OPS sk_umstat_rw_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_open    = sk_umstat_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = sk_umstat_write,
#else
	.open    = sk_umstat_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = sk_umstat_write,
#endif
};

static const SK_PROC_OPS sk_umdbg_rw_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_open    = sk_umdbg_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = sk_umdbg_write,
#else
	.open    = sk_umdbg_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = sk_umdbg_write,
#endif
};

static const SK_PROC_OPS sk_um_rw_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_open    = sk_um_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = sk_um_write,
#else
	.open    = sk_um_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = sk_um_write,
#endif
};

/*
 * /proc/umbral/diag -- capability state table (read-only).
 *
 * A different kernel may fail to resolve BTF offsets or symbols. Rather than
 * silently reusing stale constants (which corrupts memory), every capability
 * reports OK / DISABLED here, so a new device can be diagnosed without dmesg.
 */
/* forward decl: the mnt plan table is defined below */
static int sk_mnt_n;

static int sk_diag_show(struct seq_file *m, void *v)
{
	seq_printf(m, "attr_offsets  ino=%d size=%d mode=%d\n",
		   sk_off_kstat_ino, sk_off_kstat_size, sk_off_kstat_mode);
	seq_printf(m, "attr_trusted  %s\n", sk_off_kstat_stop ? "NO" : "YES");
	seq_printf(m, "cap_attr      %s\n",
		   (!sk_off_kstat_stop
		    && sk_off_kstat_ino >= 8 && sk_off_kstat_ino <= 64
		    && sk_off_kstat_size >= 24 && sk_off_kstat_size <= 136)
		   ? "OK" : "DISABLED");
	seq_printf(m, "cap_procmem   %s\n", sk_procmem_ops.proc_write ? "OK" : "DISABLED");
	seq_printf(m, "rules         %d\n", sk_um_n);
	seq_printf(m, "mnt_plans     %d  (stage1: stored only, nothing mounted)\n", sk_mnt_n);
	return 0;
}

static int sk_diag_open(struct inode *i, struct file *f)
{
	return single_open(f, sk_diag_show, NULL);
}

static const struct proc_ops sk_diag_ops = {
	.proc_open    = sk_diag_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};


/*
 * systemless mount plan table -- step 1 of docs/systemless-mount-design.md.
 * This stage only stores the plan; nothing is mounted yet, so it is inert
 * and cannot affect any process. "apply" (step 2) comes later.
 */
#define SK_MNT_MAX 8
struct sk_mnt_plan {
	char target[64];
	char upper[64];
	char work[64];
	bool used;
};
static struct sk_mnt_plan sk_mnt_plans[SK_MNT_MAX];
static int sk_mnt_n;
static DEFINE_SPINLOCK(sk_mnt_lock);

static ssize_t sk_mnt_write(struct file *f, const char __user *ubuf,
			    size_t len, loff_t *off)
{
	char buf[256];
	unsigned int n = len;
	int i, slot = -1;

	if (!sk_writer_allowed())
		return -EPERM;
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = 0;
	strim(buf);

	if (!strcmp(buf, "clear")) {
		spin_lock(&sk_mnt_lock);
		for (i = 0; i < SK_MNT_MAX; i++)
			sk_mnt_plans[i].used = false;
		sk_mnt_n = 0;
		spin_unlock(&sk_mnt_lock);
		pr_info(SK_TAG "mnt: plan table cleared\n");
		return n;
	}
	if (strncmp(buf, "plan ", 5)) {
		pr_info(SK_TAG "mnt: 未知命令（只支持 plan / clear）\n");
		return -EINVAL;
	}
	{
		char t[64], u[64], w[64];

		t[0] = u[0] = w[0] = 0;
		if (sscanf(buf + 5, "%63s %63s %63s", t, u, w) != 3)
			return -EINVAL;
		spin_lock(&sk_mnt_lock);
		for (i = 0; i < SK_MNT_MAX; i++)
			if (!sk_mnt_plans[i].used) { slot = i; break; }
		if (slot >= 0) {
			memcpy(sk_mnt_plans[slot].target, t, sizeof(t));
			memcpy(sk_mnt_plans[slot].upper, u, sizeof(u));
			memcpy(sk_mnt_plans[slot].work, w, sizeof(w));
			sk_mnt_plans[slot].used = true;
			sk_mnt_n++;
		}
		spin_unlock(&sk_mnt_lock);
		if (slot < 0) {
			pr_info(SK_TAG "mnt: 计划表已满\n");
			return -ENOSPC;
		}
		pr_info(SK_TAG "mnt: plan[%d] target=%s upper=%s（阶段1：只存不挂）\n",
			slot, t, u);
	}
	return n;
}

static const struct proc_ops sk_mnt_ops = {
	.proc_write = sk_mnt_write,
};


static int sk_proc_init(void)
{
	sk_dir = proc_mkdir("umbral", NULL);
	if (!sk_dir) return -ENOMEM;


	if (!proc_create("version",  0444, sk_dir, &sk_version_ops))  goto fail;
	if (!proc_create("mode",     0444, sk_dir, &sk_mode_ops))     goto fail;
	if (!proc_create("status",   0444, sk_dir, &sk_status_ops))   goto fail;
	if (!proc_create("backend",  0444, sk_dir, &sk_backend_ops))  goto fail;
	if (!proc_create("stats",    0444, sk_dir, &sk_stats_ops))    goto fail;
	if (!proc_create("token",    0444, sk_dir, &sk_token_ops))    goto fail;
	if (!proc_create("selftest", 0444, sk_dir, &sk_selftest_ops)) goto fail;
	if (!proc_create("diag",     0444, sk_dir, &sk_diag_ops))     goto fail;
	if (!proc_create("mnt",      0600, sk_dir, &sk_mnt_ops))      goto fail;

	/* 授权接口：grant 只写，grants 只读 */
	if (!proc_create("grant",  0222, sk_dir, &sk_grant_ops))  goto fail;
	/* 父目录必须是 sk_dir，否则会建到 /proc/escape（v1.17 的错） */
	if (!proc_create("escape", 0666, sk_dir, &sk_escape_ops))  goto fail;
	if (!proc_create("procmem", 0600, sk_dir, &sk_procmem_ops))
		pr_warn(SK_TAG "procmem 节点创建失败\n");
	if (!proc_create("grants", 0444, sk_dir, &sk_grants_ops)) goto fail;
	if (!proc_create("btf",    0444, sk_dir, &sk_btf_ops))    goto fail;
	if (!proc_create("um",     0666, sk_dir, &sk_um_rw_ops))  goto fail;
	if (!proc_create("umdbg",  0666, sk_dir, &sk_umdbg_rw_ops)) goto fail;
	if (!proc_create("umstat", 0666, sk_dir, &sk_umstat_rw_ops)) goto fail;
	if (!proc_create("claim",  0666, sk_dir, &sk_claim_rw_ops))    goto fail;
	if (sk_domains_register(sk_dir))                              goto fail;
	if (sk_deny_register(sk_dir))                                 goto fail;
	if (sk_io_register(sk_dir))                                   goto fail;
	if (sk_guard_register(sk_dir))                                goto fail;
	if (sk_feature_register(sk_dir))                                goto fail;
	return 0;

fail:
	remove_proc_subtree("sk", NULL);
	sk_dir = NULL;
	return -ENOMEM;
}

static void sk_grant_exit(void)
{
	sk_grant_clear();
}

static void sk_proc_exit(void)
{
	remove_proc_subtree("sk", NULL);
	sk_dir = NULL;
}

/* ══════════════════ init / exit ══════════════════ */

/*
 * 延迟发现 worker：/data 挂载后才有机会成功。
 * 每 1.5 秒试一次，最多 40 次（约 1 分钟）。
 */
static int sk_grants_line(const char *line)
{
	unsigned int uid = 0;
	char mode[16];
	int nf;

	if (!line || line[0] == 0 || line[0] == 35)
		return -1;
	mode[0] = 0;
	nf = sscanf(line, "uid %u %15s", &uid, mode);
	if (nf < 2 || uid == 0)
		return -1;
	return sk_ugrant_add(uid, !strcmp(mode, "super") ? SK_GRANT_SUPER : SK_GRANT_SHADOW);
}

/**
 * Restore the grant table at boot:
 *   1) manager.uid  -> super (so the manager can always read /proc/umbral)
 *   2) grants.conf  -> every "uid N shadow|super" line
 * Both are best effort: missing file is logged, not fatal.
 */
static void sk_grants_restore(void)
{
	struct file *f;
	loff_t pos = 0;
	ssize_t n;
	char *buf;
	int mgr, ok = 0;
	char *line, *next;

	mgr = sk_read_manager_uid();
	if (mgr > 0) {
		if (!sk_ugrant_add((u32)mgr, SK_GRANT_SUPER))
			ok++;
	 }
	if (!sk_resolve_file_api() || !sk_filp_open)
		goto done;
	f = sk_filp_open("/data/adb/umbral/grants.conf", O_RDONLY, 0);
	if (IS_ERR(f)) {
		pr_info(SK_TAG "grants.conf missing, only manager.uid restored"
);
		goto done;
	 }
	buf = vzalloc(4096);
	if (!buf) {
		sk_filp_close(f, NULL);
		goto done;
	 }
	n = sk_kernel_read(f, buf, 4095, &pos);
	sk_filp_close(f, NULL);
	if (n > 0) {
		buf[n] = 0;
		line = buf;
		while (line && *line) {
			next = strchr(line, 10);
			if (next)
				*next++ = 0;
			if (!sk_grants_line(line))
				ok++;
			line = next;
		 }
	 }
	vfree(buf);
done:
	pr_info(SK_TAG "grants restored: %d entries (mgr=%d)"
, ok, mgr);
}
static void sk_late_fn(struct work_struct *w)
{
	int uid;

	/*
	 * ★ 抄日志必须放在最前面 ★
	 *
	 * 之前放在下面「扫进程」之前，结果被上面那个早退挡掉了：
	 *   管理器已经在授权表里（grants.conf 恢复的）→ 直接 return
	 *   → 抄日志的代码永远不执行 → /data/local/tmp 里一个文件都没有
	 */
	{
		static bool dumped;

		if (!dumped) {
			dumped = true;
			sk_dump_logs();
		}
	}

	/*
	 * ★ 建目录 + 写 su 壳脚本，也必须放在早退之前 ★
	 *
	 * 和抄日志同一个坑：管理器已经在授权表里（grants.conf 恢复的）
	 * → 直接 return → sk_mkdirs()/sk_create_su() 永远不执行
	 * → /data/adb/umbral/bin/su 这个文件根本不存在
	 * → App 里 exec("su") 被重定向到不存在的路径 → ENOENT
	 * → 「管理器没有 root」「切换模块失败」
	 *
	 * 用一次性静态标记，保证每次开机做一遍。
	 */
	{
		static bool prepared;

		if (!prepared) {
			prepared = true;
			sk_mkdirs();
			sk_probe_domains();
			sk_create_su();
			sk_guard_ensure();
		}
	}

	if (sk_grant_uid > 0 && sk_ugrant_has((u32)sk_grant_uid))
		return;			/* 已经授权好了，不用再试 */

	/* 第一层：扫进程名（最可靠） */
	uid = sk_scan_for_manager();
	if (uid > 0) {
		/*
		 * ★ 管理器必须给影子模式，不能给超级用户模式 ★
		 *   超级用户模式会 commit_creds 把 App 进程变成 uid 0，
		 *   ActivityManager 发现进程 uid 变了会直接杀掉 —— 实测 App 起不来。
		 *   影子模式 uid 不变，但读写判定全部放行，效果一样够用。
		 */
		int rc = sk_ugrant_add((u32)uid, SK_GRANT_SHADOW);

		sk_grant_uid = uid;
		pr_info(SK_TAG "扫描到管理器进程：uid=%d 已授予影子权限 rc=%d\n",
			uid, rc);
		sk_write_manager_uid(uid);
		return;
	}

	/* 第二层：读 packages.list（可能被 SELinux 拦） */
	uid = sk_discover_manager_uid();
	if (uid > 0) {
		int rc = sk_ugrant_add((u32)uid, SK_GRANT_SUPER);

		sk_grant_uid = uid;
		pr_info(SK_TAG "延迟授权管理器 uid=%d mode=super rc=%d\n",
			uid, rc);
		/* 顺手落盘，下次开机直接读文件 */
		sk_write_manager_uid(uid);
		return;
	}

	/*
	 * ★ 永不放弃：前 N 次快扫，之后降频慢扫 ★
	 *
	 * 原来试满 SK_LATE_MAX_TRIES 次就永久放弃了 —— 那意味着：
	 *   开机时管理器没在前台 → 放弃 → 用户后来打开 App 也永远拿不到权限
	 *
	 * 现在：前 N 次每 SK_LATE_DELAY_MS 扫一次（抢开机那几秒），
	 *       之后每 10 秒扫一次，扫到为止。
	 *
	 * 开销：一次 for_each_process 遍历几百个 task，10 秒一次可以忽略。
	 * 上下文：这是工作队列，可以睡眠，绝不 panic。
	 */
	sk_late_tries++;
	if (sk_late_tries <= SK_LATE_MAX_TRIES) {
		schedule_delayed_work(&sk_late_work,
				      msecs_to_jiffies(SK_LATE_DELAY_MS));
	} else {
		if (sk_late_tries == SK_LATE_MAX_TRIES + 1)
			pr_info(SK_TAG "快速扫描结束，转入每 10 秒慢扫（扫到管理器为止）\n");
		schedule_delayed_work(&sk_late_work, msecs_to_jiffies(10000));
	}
}


/*
 * 判断当前是不是「管理器的主界面进程」。
 *
 * 为什么主界面不能 commit_creds：
 *   uid 一变成 0，ActivityManager 立刻发现进程身份和安装记录不符，
 *   直接杀掉 —— 表现就是 App 进不去。
 *
 * 但管理器确实需要 root。解决方式：
 *   主界面进程   → 走影子放行（读写得通，uid 不变，进程安全）
 *   它 fork 的子进程（sh 等） → 照常 commit_creds，是真 uid 0
 * 这样管理器持有超级模式授权，且它能拿到的一切真 root 操作都是真的。
 */
static bool __attribute__((unused)) sk_is_mgr_main_thread(void)
{
	if (sk_grant_uid <= 0)
		return false;
	if ((int)__kuid_val(current_uid()) != sk_grant_uid)
		return false;
	/* 主线程：pid == tgid；子进程 sh 的 tgid 是它自己，不等 */
	if (current->pid != current->tgid)
		return false;
	/* 进程名是包名（App 主进程的 comm 就是包名） */
	if (strncmp(current->comm, SK_MGR_PKG, SK_MGR_PKG_LEN) != 0)
		return false;
	return true;
}

/* ══════════════════ 第一层：扫描进程名找管理器 ══════════════════ */

/*
 * 遍历内核进程表，找 comm == "io.umbral" 的进程。
 *
 * 为什么这条路最可靠：
 *   · p->comm 存的就是进程名，Android App 的进程名就是包名
 *   · "io.umbral" 只有 9 个字符，comm 是 16 字节，不会被截断
 *   · 全程只读内核自己的结构，不碰文件系统 → 不受 SELinux 影响
 *   · 不受 /data 挂载时机影响（App 能跑起来时进程必然存在）
 *
 * 这是「模块持续检查包名」的实现：延迟工作每 2 秒扫一次，
 * 管理器一启动就被抓到，立刻授予超级用户模式。
 */
static int sk_scan_for_manager(void)
{
	struct task_struct *p;
	int uid = -1;

	rcu_read_lock();
	for_each_process(p) {
		if (!p->comm[0])
			continue;
		if (strncmp(p->comm, SK_MGR_PKG, SK_MGR_PKG_LEN) != 0)
			continue;
		/* 只认真正的 App 进程（uid >= 10000），避免误抓 shell 之类 */
		{
			u32 u = __kuid_val(p->cred->euid);

			if (u >= 10000) {
				uid = (int)u;
				break;
			}
		}
	}
	rcu_read_unlock();
	return uid;
}

/* ══════════════════ 授权表持久化 ══════════════════ */

/*
 * 用户的授权决定必须活过重启。
 *
 * 之前授权表只在内存里，重启就清空 —— 等于每次开机用户都得重新点一遍。
 * 现在落盘到 /data/adb/umbral/grants.conf，开机时读回来。
 *
 * 文件格式（和 /proc/sk/grants 输出一致）：
 *     uid 10560 shadow
 *     uid 10561 super
 *
 * 只有「用户明确授权的应用」才会出现在这里；
 * 管理器自己的 uid 走 manager.uid，不混在一起。
 */
#define SK_GRANTS_FILE "/data/adb/umbral/grants.conf"

static void sk_save_grants(void)
{
	struct sk_ugrant *g;
	struct file *f;
	static char buf[2048];
	int n = 0, i;

	if (!sk_filp_open || !sk_kernel_write)
		return;

	buf[0] = 0;
	for (i = 0; i < (1 << SK_GRANT_BITS) && n < (int)sizeof(buf) - 48; i++) {
		rcu_read_lock();
		hlist_for_each_entry_rcu(g, &sk_ugrants[i], node) {
			if (n >= (int)sizeof(buf) - 48)
				break;
			n += scnprintf(buf + n, sizeof(buf) - n, "uid %u %s\n",
				       g->uid,
				       g->mode == SK_GRANT_SUPER ? "super" : "shadow");
		}
		rcu_read_unlock();
	}
	if (n == 0)
		return;

	f = sk_filp_open(SK_GRANTS_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(f))
		return;
	{
		loff_t pos = 0;

		sk_kernel_write(f, buf, n, &pos);
	}
	sk_filp_close(f, NULL);
	pr_info(SK_TAG "授权表已落盘 %d 条\n", n);
}

static void sk_load_grants(void)
{
	struct file *f;
	char *buf;
	ssize_t n;
	loff_t pos = 0;
	char *line, *next;

	if (!sk_filp_open || !sk_kernel_read)
		return;

	f = sk_filp_open(SK_GRANTS_FILE, O_RDONLY, 0);
	if (IS_ERR(f))
		return;

	buf = vzalloc(16 * 1024);
	if (!buf) {
		sk_filp_close(f, NULL);
		return;
	}
	n = sk_kernel_read(f, buf, 16 * 1024 - 1, &pos);
	sk_filp_close(f, NULL);
	if (n <= 0) {
		vfree(buf);
		return;
	}
	buf[n] = 0;

	for (line = buf; line && *line; line = next) {
		unsigned int u = 0;
		char mode[16] = {0};

		next = strchr(line, '\n');
		if (next)
			*next++ = 0;

		if (sscanf(line, "uid %u %15s", &u, mode) == 2 && u > 0) {
			int m = strncmp(mode, "super", 5) == 0
				? SK_GRANT_SUPER : SK_GRANT_SHADOW;

			sk_ugrant_add((u32)u, (u8)m);
		}
	}
	vfree(buf);
	pr_info(SK_TAG "授权表已从磁盘恢复\n");
}

/* ══════════════════ 管理器认领（自举）══════════════════ */

/*
 * /proc/sk/claim —— 管理器自己来认领 root 权限。
 *
 * 为什么需要它：
 *   开机时模块不知道管理器的 uid。/data/system/packages.list 那条路
 *   被 SELinux 拦住（workqueue 在 kernel_t 域，读 system_data_file 被拒），
 *   /data/data 那条路同样被拦。
 *
 * 做法：
 *   管理器写一次 /proc/sk/claim，内核检查调用进程的 cmdline 里有没有
 *   "io.umbral"。有 → 把它的 uid 授予超级用户模式。
 *
 * 为什么安全：
 *   · cmdline 由内核读，App 改不了（改也是自己的进程名，骗不了）
 *   · 已经有授权时直接拒绝，不能反复认领
 *   · 只授一次，落盘到 manager.uid，之后开机自动读
 */
static int sk_verify_caller_is_manager(void)
{
	struct file *f;
	char buf[256];
	loff_t pos = 0;
	ssize_t n;
	int ok = 0;

	if (!sk_filp_open || !sk_kernel_read)
		return 0;

	f = sk_filp_open("/proc/self/cmdline", O_RDONLY, 0);
	if (IS_ERR(f))
		return 0;

	memset(buf, 0, sizeof(buf));
	n = sk_kernel_read(f, buf, sizeof(buf) - 1, &pos);
	sk_filp_close(f, NULL);
	if (n <= 0)
		return 0;

	/* cmdline 是   分隔的，"io.umbral" 可能在后半段 */
	{
		int i;

		for (i = 0; i + 9 < (int)n; i++) {
			if (!memcmp(buf + i, SK_MGR_PKG, SK_MGR_PKG_LEN)) {
				ok = 1;
				break;
			}
		}
	}
	return ok;
}

static ssize_t sk_claim_write(struct file *f, const char __user *ubuf,
			      size_t len, loff_t *off)
{
	u32 uid = __kuid_val(current_uid());
	int rc;

	if (!sk_writer_allowed())
		return -EPERM;

	/* 已经有管理器了就不再接受认领 */
	if (sk_grant_uid > 0 && sk_ugrant_has((u32)sk_grant_uid)) {
		pr_info(SK_TAG "认领被拒：已有管理器 uid=%d\n", sk_grant_uid);
		return -EEXIST;
	}

	if (!sk_verify_caller_is_manager()) {
		pr_warn(SK_TAG "认领被拒：调用者不是 io.umbral (uid=%u)\n", uid);
		return -EPERM;
	}

	/* 同扫描层：管理器给影子模式，避免进程 uid 变化被系统杀掉 */
	rc = sk_ugrant_add(uid, SK_GRANT_SHADOW);
	if (rc)
		return rc;
	sk_save_grants();

	sk_grant_uid = (int)uid;
	sk_write_manager_uid((int)uid);
	pr_info(SK_TAG "认领成功：uid=%u 已授予影子权限，并已落盘\n", uid);
	return len;
}

static int sk_claim_show(struct seq_file *m, void *v)
{
	seq_printf(m, "管理器 uid  %d\n", sk_grant_uid);
	seq_printf(m, "已授权    %s\n",
		   (sk_grant_uid > 0 && sk_ugrant_has((u32)sk_grant_uid))
		   ? "是" : "否");
	seq_printf(m, "说明      向本文件写入任意内容即可认领（仅限 io.umbral）\n");
	return 0;
}


/* ══════════════════ UM 判定点 3：目录列表 ══════════════════ */

/*
 * 让 ls / getdents / readdir 也看不见被隐藏的条目。
 *
 * 原理：
 *   iterate_dir(file, ctx) 里 ctx->actor 是文件系统用来"吐一条结果"的回调。
 *   我们在 iterate_dir 进入时把 ctx->actor 换成自己的过滤函数，
 *   返回时再换回去。过滤函数拿到 (name, ino, d_type)，
 *   用「当前 uid + 父目录 dev + 子项 ino」查 UM 规则：
 *       命中 hide → 直接 return true（假装已经吐过了，但什么都不吐）→ 条目消失
 *       未命中   → 调用原 actor 正常吐
 *
 * 为什么必须成对换回：
 *   ctx 是调用方（getdents）的栈变量，跨多次 iterate_dir 复用。
 *   不换回的话，下次同一个 ctx 地址上 actor 可能还是我们的函数，
 *   保存下来的 "orig" 就会是我们自己 → 无限递归。
 *
 * 安全性：
 *   · 只在 sk_um_n > 0（确实有规则）时才动手，无规则零开销
 *   · 表满了就不装（宁可漏隐藏，也不覆盖别人的 ctx）
 *   · 前缀匹配到的 actor 一律跳过，防自递归
 */
#define SK_IOP_MAX 64

struct sk_iop_ent {
	struct dir_context *ctx;
	filldir_t orig;
	u32 dev;
	u32 uid;
	bool used;
	bool is_proc;	/* v1.28：这次遍历的是 /proc，走进程隐藏那套判断 */
};

struct sk_iop_inst {
	struct dir_context *ctx;
};

static struct sk_iop_ent sk_iop_tab[SK_IOP_MAX];
static DEFINE_SPINLOCK(sk_iop_lock);
/*
 * ══════════════════ 判定点⑤：进程可见性 ══════════════════
 *
 * 想藏一个进程，改的不是"文件"，是 /proc 下的那个数字目录项。
 * 机制和 ③ 完全一样（proc_pid_readdir → dir_emit → ctx->actor），
 * 区别只在判定依据：③ 用 (uid, dev, ino) 查文件规则表，
 * ⑤ 用 "名字是不是一个 pid，且该 pid 在隐藏名单里"。
 *
 * 为什么按名字判而不是按 ino：
 *   /proc/<pid> 的 inode 号由 proc_pid_ino() 现算，
 *   不同内核版本算法不一样；而名字就是十进制 pid，跨版本稳定。
 *
 * 名单上限 64：够藏一个 App 的进程树，静态分配 256 字节。
 */
#define SK_HP_MAX 64
static pid_t sk_hp[SK_HP_MAX];
static int sk_hp_n;
static DEFINE_SPINLOCK(sk_hp_lock);
static bool sk_proc_hide;	/* 默认关，由 /proc/umbral/feature 打开 */

static int sk_hp_add(pid_t pid)
{
	int rc = 0;
	int i;

	if (pid <= 0)
		return -EINVAL;
	spin_lock(&sk_hp_lock);
	for (i = 0; i < sk_hp_n; i++) {
		if (sk_hp[i] == pid) {
			spin_unlock(&sk_hp_lock);
			return 0;	/* 重复加不算错 */
		}
	}
	if (sk_hp_n >= SK_HP_MAX)
		rc = -ENOSPC;
	else
		sk_hp[sk_hp_n++] = pid;
	spin_unlock(&sk_hp_lock);
	return rc;
}

static void sk_hp_clear(void)
{
	spin_lock(&sk_hp_lock);
	sk_hp_n = 0;
	spin_unlock(&sk_hp_lock);
}

/* 名字转 pid：全部是数字且不超 7 位才算；否则返回 -1 */
static pid_t sk_name_to_pid(const char *name, int len)
{
	pid_t v = 0;
	int i;

	if (!name || len <= 0 || len > 7)
		return -1;
	for (i = 0; i < len; i++) {
		if (name[i] < '0' || name[i] > '9')
			return -1;
		v = v * 10 + (name[i] - '0');
	}
	return v > 0 ? v : -1;
}

/* 这个 pid 要不要对当前遍历者隐藏 */
static bool sk_hp_match(pid_t pid)
{
	bool hit = false;
	int i;

	if (!sk_proc_hide || pid <= 0)
		return false;
	spin_lock(&sk_hp_lock);
	for (i = 0; i < sk_hp_n; i++) {
		if (sk_hp[i] == pid) {
			hit = true;
			break;
		}
	}
	spin_unlock(&sk_hp_lock);
	return hit;
}

static bool sk_iop_enable;   /* 默认关，验证后再开 */
module_param_named(readdir_hide, sk_iop_enable, bool, 0644);
MODULE_PARM_DESC(readdir_hide, "hide UM-hidden entries from directory listing");

static bool sk_iop_actor(struct dir_context *ctx, const char *name, int namelen,
			 loff_t off, u64 ino, unsigned int dtype);

static bool sk_iop_actor_is_ours(filldir_t a)
{
	/* 5.10 的 filldir_t 返回 int、5.12+ 返回 bool，直接比会报类型不同 */
	return (unsigned long)a == (unsigned long)sk_iop_actor;
}

/*
 * 过滤回调：文件系统每吐一条目录项都会走到这里。
 *
 * ★ 这里上下文很敏感 ★
 *   可能持有文件系统的锁、可能不可睡眠，所以：
 *   · 只做整数比较，不分配内存、不睡眠
 *   · 表查不到就原样转发（说明不是我们装的，理论上不会发生）
 */
static bool sk_iop_actor(struct dir_context *ctx, const char *name, int namelen,
			 loff_t off, u64 ino, unsigned int dtype)
{
	filldir_t orig = NULL;
	u32 dev = 0, uid = 0;
	bool is_proc = false;
	int i;

	spin_lock(&sk_iop_lock);
	for (i = 0; i < SK_IOP_MAX; i++) {
		if (sk_iop_tab[i].used && sk_iop_tab[i].ctx == ctx) {
			orig = sk_iop_tab[i].orig;
			dev  = sk_iop_tab[i].dev;
			uid  = sk_iop_tab[i].uid;
			is_proc = sk_iop_tab[i].is_proc;
			break;
		}
	}
	spin_unlock(&sk_iop_lock);

	if (!orig)
		return false;

	/*
	 * 判定点⑤：/proc 下、名字是数字、且在隐藏名单里 → 吞掉不吐。
	 * 注意这里只做整数比较和查一个 64 项静态数组，
	 * 不分配、不睡眠 —— 上下文敏感（可能持文件系统锁）。
	 */
	if (is_proc) {
		pid_t p = sk_name_to_pid(name, namelen);

		if (p > 0 && sk_hp_match(p))
			return true;

		/*
		 * 隐蔽性：未授权调用者 ls /proc 时看不到 "umbral" 这个目录项。
		 * 只比名字，不涉及任何规则表；授权者（uid 0 / 管理器 / 已授权 uid）
		 * 完全不受影响。配合 sk_own_ino 的 stat 拦截，
		 * 未授权侧对 /proc/umbral 的存在性完全无感。
		 */
		if (namelen == 6 && !strncmp(name, "umbral", 6)
		    && !sk_uid_privileged(__kuid_val(current_uid())))
			return true;
	}

	/* 命中 hide → 吞掉这一条：返回 true 表示"已处理"，但实际不吐 */
	if (sk_um_action(uid, dev, ino) == SK_UM_ACT_HIDE)
		return true;

	return orig(ctx, name, namelen, off, ino, dtype);
}

static int sk_iop_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct file *f;
	struct dir_context *ctx;
	struct sk_iop_inst *ins = (struct sk_iop_inst *)ri->data;
	filldir_t a;
	int i, slot = -1;

	/*
	 * 武装条件：
	 *   ③ 文件目录隐藏 → sk_iop_enable && 有文件规则
	 *   ⑤ 进程隐藏     → sk_proc_hide && 有 pid 名单
	 * 两者任一成立就装，否则不装（零开销）。
	 */
	if (!(sk_iop_enable && sk_um_n)
	    && !(sk_proc_hide && sk_hp_n))
		return 1;

	f = (struct file *)regs_get_kernel_argument(regs, 0);
	if (!f || !f->f_inode || !f->f_inode->i_sb)
		return 1;

	ctx = (struct dir_context *)regs_get_kernel_argument(regs, 1);
	if (!ctx)
		return 1;

	a = ctx->actor;
	if (!a || sk_iop_actor_is_ours(a))
		return 1;

	spin_lock(&sk_iop_lock);
	for (i = 0; i < SK_IOP_MAX; i++) {
		if (!sk_iop_tab[i].used) {
			slot = i;
			break;
		}
	}
	if (slot >= 0) {
		sk_iop_tab[slot].used = true;
		sk_iop_tab[slot].ctx  = ctx;
		sk_iop_tab[slot].orig = a;
		sk_iop_tab[slot].dev  = new_encode_dev(f->f_inode->i_sb->s_dev);
		sk_iop_tab[slot].uid  = __kuid_val(current_uid());
#ifdef PROC_SUPER_MAGIC
		sk_iop_tab[slot].is_proc =
			(f->f_inode->i_sb->s_magic == PROC_SUPER_MAGIC);
#else
		sk_iop_tab[slot].is_proc = false;
#endif
	}
	spin_unlock(&sk_iop_lock);

	if (slot < 0)
		return 1;			/* 表满，放弃这次 */

	ctx->actor = sk_iop_actor;
	ins->ctx = ctx;
	return 0;
}

static int sk_iop_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_iop_inst *ins = (struct sk_iop_inst *)ri->data;
	struct dir_context *ctx = ins->ctx;
	int i;

	if (!ctx)
		return 0;

	spin_lock(&sk_iop_lock);
	for (i = 0; i < SK_IOP_MAX; i++) {
		if (sk_iop_tab[i].used && sk_iop_tab[i].ctx == ctx) {
			/* 换回原 actor。万一上游自己又改过，就别乱写 */
			if (sk_iop_actor_is_ours(ctx->actor))
				ctx->actor = sk_iop_tab[i].orig;
			sk_iop_tab[i].used = false;
			break;
		}
	}
	spin_unlock(&sk_iop_lock);
	return 0;
}

static struct kretprobe sk_krp_iop = {
	.kp.symbol_name = "iterate_dir",
	.entry_handler  = sk_iop_entry,
	.handler        = sk_iop_ret,
	.data_size      = sizeof(struct sk_iop_inst),
	.maxactive      = SK_IOP_MAX,
};

static bool sk_iop_registered;

static void sk_iop_register(void)
{
	int rc = register_kretprobe(&sk_krp_iop);

	if (rc) {
		pr_warn(SK_TAG "iterate_dir 钩子注册失败 rc=%d（判定点3 不可用）\n", rc);
		return;
	}
	sk_iop_registered = true;
	pr_info(SK_TAG "判定点3 已就绪：目录列表隐藏\n");
}

static void sk_iop_unregister(void)
{
	if (sk_iop_registered) {
		unregister_kretprobe(&sk_krp_iop);
		sk_iop_registered = false;
	}
}


/* ══════════════════ UM 判定点 4：文件内容 ══════════════════ */

/*
 * 让目标 uid 读某个文件时，拿到的是「空」或「全零」。
 *
 * 动作：
 *   empty  读返回 0 字节 —— 调用方看到的就是 EOF，文件像不存在内容
 *   zero   读返回真实长度，但缓冲区被填成 0x00
 *
 * 为什么 empty 是首选：只改返回值，完全不碰用户内存，零风险。
 * zero 需要往用户缓冲区写，而 kretprobe 上下文**禁止睡眠**，
 * 所以只能用 __copy_to_user_inatomic（页不在内存就失败，绝不去缺页），
 * 任何一段失败就整份放弃，宁可漏伪造也不崩。
 */
struct sk_rd_inst {
	struct file *f;
	char __user *buf;
	u32 uid;
};

static bool sk_rd_enable;    /* 默认关，验证后再开 */
module_param_named(read_fake, sk_rd_enable, bool, 0644);
MODULE_PARM_DESC(read_fake, "enable UM file-content faking (judgment point 4)");

static int sk_rd_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_rd_inst *d = (struct sk_rd_inst *)ri->data;

	if (!sk_rd_enable || sk_um_n == 0)
		return 1;

	d->f   = (struct file *)regs_get_kernel_argument(regs, 0);
	d->buf = (char __user *)regs_get_kernel_argument(regs, 1);
	d->uid = __kuid_val(current_uid());

	if (!d->f || !d->f->f_inode || !d->f->f_inode->i_sb)
		return 1;
	return 0;
}

static int sk_rd_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_rd_inst *d = (struct sk_rd_inst *)ri->data;
	long n = (long)regs->regs[0];
	u32 dev;
	u64 ino;
	int act;

	if (n <= 0 || !d->f || !d->f->f_inode || !d->f->f_inode->i_sb)
		return 0;

	dev = new_encode_dev(d->f->f_inode->i_sb->s_dev);
	ino = (u64)d->f->f_inode->i_ino;
	act = sk_um_action(d->uid, dev, ino);

	if (act == SK_UM_ACT_EMPTY) {
		/* 直接告诉他"读完了"，一个字节都不给 */
		regs_set_return_value(regs, 0);
		return 0;
	}

	if (act == SK_UM_ACT_FAKE && d->buf) {
		/*
		 * 判定点4 的 fake：把用户缓冲区的内容换掉。
		 *
		 * 语义：第 1 次读就吐出整份 payload（长度 = plen），
		 *       后续读返回 0（EOF），模拟"文件就这么长"。
		 *
		 * 为什么用 __copy_to_user_inatomic：
		 *   kretprobe 上下文禁睡眠；页不在内存就失败，
		 *   失败就整份放弃 —— 宁可漏伪造，也绝不触发缺页（会 panic）。
		 */
		u8 pl[SK_UM_PAYLOAD_MAX];
		u8 plen = 0;

		plen = sk_um_payload(d->uid, dev, ino, pl, SK_UM_PAYLOAD_MAX);

		if (plen == 0) {
			regs_set_return_value(regs, 0);
			return 0;
		}
		/* 只在第一次读（偏移 0）时吐内容；之后的读一律 EOF */
		{
			loff_t pos = d->f ? d->f->f_pos : 0;

			if (pos <= 0) {
				size_t n2 = (size_t)n < (size_t)plen
					    ? (size_t)n : (size_t)plen;

				if (!__copy_to_user_inatomic(d->buf, pl, n2))
					regs_set_return_value(regs, (long)n2);
				else
					regs_set_return_value(regs, 0);
			} else {
				regs_set_return_value(regs, 0);
			}
		}
		return 0;
	}

	if (act == SK_UM_ACT_ZERO && d->buf) {
		char zeros[128];
		size_t left = (size_t)n;
		char __user *p = d->buf;

		memset(zeros, 0, sizeof(zeros));
		while (left > 0) {
			size_t chunk = left < sizeof(zeros) ? left : sizeof(zeros);

			/*
			 * 不睡的拷贝：页不在内存就返回非 0。
			 * 一失败立刻放弃整份伪造 —— 已经写进去的部分
			 * 只会让内容变成"前缀为 0"，不会破坏内核。
			 */
			if (__copy_to_user_inatomic(p, zeros, chunk))
				break;
			p    += chunk;
			left -= chunk;
		}
	}
	return 0;
}

static struct kretprobe sk_krp_rd = {
	.kp.symbol_name = "vfs_read",
	.entry_handler  = sk_rd_entry,
	.handler        = sk_rd_ret,
	.data_size      = sizeof(struct sk_rd_inst),
	.maxactive      = 128,
};

static bool sk_rd_registered;

static void sk_rd_register(void)
{
	int rc = register_kretprobe(&sk_krp_rd);

	if (rc) {
		pr_warn(SK_TAG "vfs_read 钩子注册失败 rc=%d（判定点4 不可用）\n", rc);
		return;
	}
	sk_rd_registered = true;
	pr_info(SK_TAG "判定点4 已就绪：文件内容伪造\n");
}

static void sk_rd_unregister(void)
{
	if (sk_rd_registered) {
		unregister_kretprobe(&sk_krp_rd);
		sk_rd_registered = false;
	}
}





/* ══════════════════ 目录自建（跨机型必需）══════════════════ */

/*
 * /data/adb 是 Magisk / KernelSU 创建的。
 * 一台干净设备（没装任何 root 框架）上它根本不存在 ——
 * 于是我们把 manager.uid、grants.conf、boot.umbc、UM 模块
 * 往 /data/adb/umbral/ 里写的时候全部失败。
 *
 * 所以模块必须自己把这个目录建出来。
 *
 * 为什么用 call_usermodehelper 而不用 vfs_mkdir：
 *   vfs_mkdir 没导出，跨版本签名还可能变；
 *   而且 /data 挂载点、加密目录（FBE）的初始化顺序很微妙，
 *   交给 /system/bin/mkdir 处理最稳 —— 它自己会处理这些细节。
 *
 * 调用时机：延迟工作里（那时 /data 已挂载、进程上下文可睡眠）。
 */
static bool sk_mkdirs_done;
static int  sk_mkdirs_tick;

/*
 * 守护而不是只建一次。
 *
 * 为什么：/data/adb 有时会被清理工具删掉、或者 FBE 解锁后重建、
 * 或者用户在 Magisk 卸载时被连带删除 —— 一旦没了，
 * 我们的 manager.uid / grants.conf / UM 模块就全部落不了盘，
 * 表现为「重启后配置全丢」。
 *
 * 所以延迟工作里每隔一段时间确认一次（默认 5 分钟），
 * 不在了就重建。重建本身很轻（mkdir -p），失败也不影响其它功能。
 */
#define SK_MKDIRS_EVERY 150	/* 2s × 150 = 5 分钟 */


/*
 * ★ 内核侧直接写出 su 壳脚本 ★
 *
 * 为什么要在内核里做：
 *   App 有可能因为别的原因起不来（我们正在查的那个崩溃），
 *   而 su 兼容层是「装模块 / 跑特权命令」的命脉 —— 不能依赖 App。
 *
 * 做的事：
 *   /system/bin/sh -c 'mkdir -p /data/adb/umbral/bin;
 *                      printf "<脚本>" > /data/adb/umbral/bin/su;
 *                      chmod 755 /data/adb/umbral/bin/su'
 *
 * 用 call_usermodehelper 而不是 kernel_write：
 *   后者是未导出符号（要 kprobe 取址），而且拼接多行脚本更容易出错。
 *   umh 由 /system/bin/sh 去做，有完整的引号语义。
 *
 * 脚本内容只有三行：
 *   ① 把自己登记为超级用户（内核下一个 syscall 就 commit_creds）
 *   ② su -c "命令" 形式
 *   ③ su 命令 [参数] 形式
 */

/*
 * ★ filldir_t（dir_context 的 actor）返回值类型在 5.12 变了 ★
 *
 *   5.4 ~ 5.11   int  返回值，0 = 继续，非 0 = 停止
 *   5.12 ~ 现在  bool 返回值，true = 继续，false = 停止
 *
 * 写错就是编译失败（-Wincompatible-function-pointer-types），
 * 所以按版本切，不要硬编一套。
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define SK_LS_SIG   bool
#define SK_LS_GO    true
#define SK_LS_STOP  false
#else
#define SK_LS_SIG   int
#define SK_LS_GO    0
#define SK_LS_STOP  1
#endif

/* ══════════════════ 内核直接写文件（不依赖 usermodehelper）══════════════════ */

/*
 * ★ 为什么放弃 call_usermodehelper ★
 *
 * 实测在你设备（Android 15）上，umh 调用 /system/bin/sh 根本没跑起来：
 *   · /data/adb/umbral/bin/su 从来没出现
 *   · /data/local/tmp/umbral_*.txt 也从来没出现
 * 原因很可能是 SELinux 不允许 u:r:kernel:s0 执行 /system/bin/sh。
 *
 * 所以改成内核自己写：拿 pid1 的 cred（域 init）→ filp_open → kernel_write。
 * 这条路完全在内核里，不经过任何用户态进程，不受 policy 对 sh 的限制。
 */
static long sk_kwrite(const char *path, const void *data, size_t len, umode_t mode)
{
	const struct cred *old;
	struct file *f;
	loff_t pos = 0;
	ssize_t n;

	if (!sk_filp_open || !sk_kernel_write || !sk_filp_close || !sk_init_cred)
		return -EOPNOTSUPP;

	old = override_creds(sk_init_cred);
	f = sk_filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (IS_ERR(f)) {
		revert_creds(old);
		return PTR_ERR(f);
	}
	n = sk_kernel_write(f, data, len, &pos);
	sk_filp_close(f, NULL);
	revert_creds(old);
	return n;
}

/* 拷贝一个文件到另一个文件（用于把 pstore 抄出来） */
static long sk_kcopy(const char *src, const char *dst)
{
	char *buf = NULL;
	long n;

	n = sk_io_do_read(src, &buf);
	if (n <= 0)
		return n;
	sk_kwrite(dst, buf, (size_t)n, 0644);
	kvfree(buf);
	return n;
}



/* ══════════════════ ① 域探测 + ③ 诊断节点 ══════════════════ */

/*
 * ★ 为什么要先探测域 ★
 *
 * uid 0 不等于有权限 —— 还要一个 policy 允许的 SELinux 域。
 * 而不同设备上「域叫什么」完全不同：
 *    AOSP / 大多数设备  u:r:su:s0
 *    Magisk 安装过       u:r:magisk:s0
 *   KernelSU 安装过      u:r:ksu:s0（这是 KSU 自己 sepolicy 里定义的，
 *                        我们没装 KSU 的设备上通常不存在 —— 用户怀疑得对）
 *
 * 所以先问 SELinux 本体：这些域在这台设备上到底哪个是有效的。
 * 用 security_secctx_to_secid 问，返回 0 且 sid 非 0 才算有效。
 *
 * ⚠️ 这个函数会睡眠 → 只能在延迟工作里调，不能在钩子里。
 */
#define SK_DOM_N 6

static const char *const sk_dom_names[SK_DOM_N] = {
	"u:r:su:s0",		/* 首选：AOSP 里就定义了这个域 */
	"u:r:magisk:s0",
	"u:r:ksu:s0",
	"u:r:supersu:s0",
	"u:r:sukisu:s0",
	"u:r:shell:s0",		/* 兜底：至少比 untrusted_app 宽 */
};
static u32 sk_dom_sid[SK_DOM_N];

/*
 * ★ SELinux 的 cred blob 偏移 ★
 *
 * cred->security 是「所有 LSM 的复合 blob」，SELinux 那段不在偏移 0：
 *     selinux_cred(cred) = cred->security + selinux_blob_sizes.lbs_cred
 * 本机 CONFIG_LSM="landlock,...,selinux,..."，landlock 排在前面也申请了
 * cred blob，所以 lbs_cred 通常 != 0。
 *
 * struct lsm_blob_sizes 里 lbs_cred 是第一个 int → 偏移 0，
 * 所以直接读符号头 4 字节就是它。拿不到就保持 -1，域切换自动跳过。
 */
static int sk_lbs_cred = -1;

/*
 * 域切换开关（默认关）。为什么不默认开：
 *   struct task_security_struct 带 __randomize_layout，
 *   开了 CONFIG_RANDSTRUCT 的内核上 sid 字段偏移会被随机化，
 *   盲写就是随机内存破坏。所以做成「显式打开 + 探测通过才执行」。
 */
static int sk_dom_switch;
module_param_named(dom_switch, sk_dom_switch, int, 0644);
MODULE_PARM_DESC(dom_switch, "1 = execve 赋权后切换 SELinux 域到 su");
static bool sk_dom_probed;

static void sk_probe_domains(void)
{
	struct kprobe kp;
	int (*fn)(const char *secdata, u32 seclen, u32 *secid) = NULL;
	int i;

	if (sk_dom_probed)
		return;
	sk_dom_probed = true;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "security_secctx_to_secid";
	if (register_kprobe(&kp)) {
		pr_warn(SK_TAG "取不到 security_secctx_to_secid，域探测跳过\\n");
		return;
	}
	fn = (void *)kp.addr;
	unregister_kprobe(&kp);

	/* 解析 selinux_blob_sizes 符号，读 lbs_cred（第一个 int） */
	{
		struct kprobe kp2;
		void *a = NULL;

		memset(&kp2, 0, sizeof(kp2));
		kp2.symbol_name = "selinux_blob_sizes";
		if (!register_kprobe(&kp2)) {
			a = (void *)kp2.addr;
			unregister_kprobe(&kp2);
		}
		if (a) {
			sk_lbs_cred = *(int *)a;
			pr_info(SK_TAG "selinux_blob_sizes.lbs_cred = %d\n", sk_lbs_cred);
		} else {
			pr_warn(SK_TAG "取不到 selinux_blob_sizes，域切换不可用\n");
		}
	}

	for (i = 0; i < SK_DOM_N; i++) {
		u32 sid = 0;

		/*
		 * ★ sid <= 1 一律当无效 ★
		 *
		 * security_secctx_to_secid 对「policy 里不存在的 context」
		 * 会返回 0（成功）并把 sid 填成 1（SECINITSID_UNLABELED）。
		 * 之前用 sid != 0 判断，于是六个候选全被当成「有效 (sid=1)」，
		 * 写进 cred 就是把域设成 unlabeled —— 等于没切。
		 * 实测：/proc/sk/domains 里六个域全是 sid=1。
		 */
		if (fn(sk_dom_names[i], strlen(sk_dom_names[i]), &sid) == 0 && sid > 1)
			sk_dom_sid[i] = sid;
		pr_info(SK_TAG "域 %s → sid=%u %s\\n", sk_dom_names[i], sid,
			sid ? "有效" : "不存在");
	}
}

/*
 * 把 cred 的 SELinux 域换成探测到的最优先域（su → ksu → magisk → …）。
 *
 * 写入位置：cred->security + selinux_blob_sizes.lbs_cred + 4
 *   · cred->security 是所有 LSM 的复合 blob，SELinux 那段不在偏移 0
 *   · struct task_security_struct { u32 osid; u32 sid; ... } → sid 在 +4
 *   · 本机 RANDSTRUCT_NONE，偏移固定；拿不到 lbs_cred 就整段跳过
 *     （盲写会随机破坏内存，RANDSTRUCT 内核上尤其危险）
 */
static void sk_set_cred_domain(struct cred *c)
{
	int i;
	u32 want = 0;

	if (!c || !c->security)
		return;

	if (!sk_dom_probed)
		sk_probe_domains();	/* 会睡眠，escape 在进程上下文，安全 */

	if (sk_lbs_cred < 0) {
		pr_warn(SK_TAG "域切换跳过：lbs_cred 未解析（selinux_blob_sizes 取不到）\n");
		return;
	}

	for (i = 0; i < SK_DOM_N; i++) {
		if (sk_dom_sid[i]) {
			want = sk_dom_sid[i];
			break;
		}
	}
	if (!want) {
		pr_warn(SK_TAG "域切换跳过：没有可用 sid（候选域都不存在）\n");
		return;
	}

	*(u32 *)((char *)c->security + sk_lbs_cred + 4) = want;
	pr_info(SK_TAG "域已切换：sid=%u\n", want);
}

static int sk_domains_show(struct seq_file *m, void *v)
{
	int i;

	seq_printf(m, "probed %d\n", sk_dom_probed ? 1 : 0);
	seq_printf(m, "lbs_cred %d\n", sk_lbs_cred);
	if (sk_lbs_cred >= 0 && current->cred && current->cred->security)
		seq_printf(m, "cur_sid %u\n",
			   *(u32 *)((char *)current->cred->security + sk_lbs_cred + 4));
	for (i = 0; i < SK_DOM_N; i++)
		seq_printf(m, "%-20s %s (sid=%u)\n", sk_dom_names[i],
			   sk_dom_sid[i] ? "有效" : "不存在", sk_dom_sid[i]);
	return 0;
}

static int sk_domains_open(struct inode *i, struct file *f)
{
	return single_open(f, sk_domains_show, NULL);
}

static const SK_PROC_OPS sk_domains_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_open    = sk_domains_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
#else
	.open    = sk_domains_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
#endif
};

static int sk_domains_register(struct proc_dir_entry *dir)
{
	if (!proc_create("domains", 0444, dir, &sk_domains_ops))
		return -ENOMEM;
	return 0;
}

/* ───── ③ 被拒诊断：最近 32 次谁被拒、在哪一层 ───── */
#define SK_DENY_N 32

struct sk_deny_rec {
	u32 uid;
	pid_t tgid;
	int mask;
	bool mac;
	char comm[16];
};

static struct sk_deny_rec sk_deny[SK_DENY_N];
static int sk_deny_n;
static DEFINE_SPINLOCK(sk_deny_lock);

static void sk_deny_record(int mask, bool mac)
{
	unsigned long fl;

	spin_lock_irqsave(&sk_deny_lock, fl);
	if (sk_deny_n < SK_DENY_N) {
		struct sk_deny_rec *r = &sk_deny[sk_deny_n++];

		r->uid = __kuid_val(current_uid());
		r->tgid = current->tgid;
		r->mask = mask;
		r->mac = mac;
		strncpy(r->comm, current->comm, sizeof(r->comm) - 1);
		r->comm[sizeof(r->comm) - 1] = 0;
	}
	spin_unlock_irqrestore(&sk_deny_lock, fl);
}

static int sk_deny_show(struct seq_file *m, void *v)
{
	int i;

	seq_printf(m, "count %d\n", sk_deny_n);
	for (i = 0; i < sk_deny_n; i++)
		seq_printf(m, "uid=%u tgid=%d comm=%s mask=%d layer=%s\n",
			   sk_deny[i].uid, sk_deny[i].tgid, sk_deny[i].comm,
			   sk_deny[i].mask, sk_deny[i].mac ? "MAC" : "DAC");
	return 0;
}

static int sk_deny_open(struct inode *i, struct file *f)
{
	return single_open(f, sk_deny_show, NULL);
}

static ssize_t sk_deny_write(struct file *f, const char __user *u,
			     size_t len, loff_t *o)
{
	unsigned long fl;

	spin_lock_irqsave(&sk_deny_lock, fl);
	sk_deny_n = 0;
	memset(sk_deny, 0, sizeof(sk_deny));
	spin_unlock_irqrestore(&sk_deny_lock, fl);
	return len;
}

static const SK_PROC_OPS sk_deny_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_open    = sk_deny_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = sk_deny_write,
#else
	.open    = sk_deny_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = sk_deny_write,
#endif
};

static int sk_deny_register(struct proc_dir_entry *dir)
{
	if (!proc_create("deny", 0666, dir, &sk_deny_ops))
		return -ENOMEM;
	return 0;
}

static void sk_create_su(void)
{
	/*
	 * 内核自己把 su 壳脚本写出来，不经过 usermodehelper。
	 *
	 * 路径选 /data/adb/umbral/su 而不是 .../bin/su：
	 *   内核没有便捷的 mkdir（vfs_mkdir 没导出、要自己造 dentry），
	 *   而 /data/adb/umbral 这个目录一定存在（manager.uid 就放在里面）。
	 *   所以直接把脚本放这一层，避免依赖中间目录。
	 *
	 * 0755 在 O_CREAT 时生效 —— 脚本一写出来就是可执行的。
	 */
	static const char script[] =
		"#!/system/bin/sh\n"
		"printf '%s 1' \"$$\" | dd of=/proc/sk/grant conv=notrunc 2>/dev/null\n"
		"if [ \"$(id -u)\" != \"0\" ]; then\n"
		"  echo 'su: permission denied' >&2\n"
		"  exit 1\n"
		"fi\n"
		/*
		 * ★ 域切换：让 SELinux 自己把域换掉 ★
		 *
		 * uid 0 只解决 DAC；MAC 层还看域。应用原域是 untrusted_app，
		 * 即使 uid 0 也会被拒在 /data/adb、/data/system 外面。
		 *
		 * 不自己写 cred->security（那个复合 blob 偏移不可靠，写错过一次），
		 * 而是往 /proc/self/attr/current 写域名 —— 由 SELinux 本体完成切换，
		 * 偏移、布局、audit 全部它自己处理，不可能写坏。
		 *
		 * su:s0 是 AOSP 就定义的域，优先试它；其余是各框架自己的，
		 * 不存在就跳过（具体哪个有效看 /proc/sk/domains）。
		 */
		"for d in u:r:su:s0 u:r:magisk:s0 u:r:ksu:s0; do\n"
		"  if echo \"$d\" > /proc/self/attr/current 2>/dev/null; then break; fi\n"
		"done\n"
		"if [ \"$1\" = \"-c\" ]; then\n"
		"  shift\n"
		"  exec /system/bin/sh -c \"$*\"\n"
		"fi\n"
		"if [ $# -gt 0 ]; then exec \"$@\"; fi\n"
		"exec /system/bin/sh\n";
	long n = sk_kwrite(SK_SU_PATH, script, sizeof(script) - 1, 0755);

	pr_info(SK_TAG "su 壳脚本写入 %s: n=%ld\n", SK_SU_PATH, n);
}


static void sk_mkdirs(void)
{
	static char *argv[] = {
		"/system/bin/mkdir", "-p", "/data/adb/umbral/um", NULL
	};
	static char *envp[] = {
		"HOME=/", "PATH=/system/bin:/system/xbin", NULL
	};
	int rc;

	if (sk_mkdirs_done) {
		if (--sk_mkdirs_tick > 0)
			return;
		sk_mkdirs_tick = SK_MKDIRS_EVERY;	/* 到点了，复查一次 */
		return;
	}

	rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (rc == 0) {
		sk_mkdirs_done = true;
		sk_mkdirs_tick = SK_MKDIRS_EVERY;
		pr_info(SK_TAG "已确保 /data/adb/umbral/um 存在（每 5 分钟复查）\n");
		sk_create_su();
	} else {
		/* 失败不要死心：下次延迟工作再试（可能是 /data 还没挂好） */
		pr_info(SK_TAG "建目录失败 rc=%d，稍后重试\n", rc);
	}
}





/* ══════════════════ 内核代读接口 /proc/sk/io ══════════════════ */

/*
 * ★ 为什么需要它 ★
 *
 * 「完全影子」模式下我们对 SELinux 一点都不干预，于是：
 *     其他应用的数据     MAC 允许 → 绕 DAC 就能读写 ✅
 *     /data/adb、/system MAC 拒绝 → 读写都不行 ❌
 *
 * 这个接口补的就是 ❌ 那一块：App 不自己去碰那个文件，
 * 让内核用**自己的身份**（init_cred）去读，读完把内容交给它。
 *
 * 那个被保护的文件从头到尾没被 App 的进程打开过
 *   → 没有 denial 被抑制
 *   → 没有异常信号
 *   → 不需要换域
 *
 * ★ 一个接口如何同时服务多个应用 ★
 *
 * 状态不放在全局变量里，而是放在**每个 open() 自己的 private_data** 里。
 * 于是：
 *     · A 应用开一个句柄、B 应用开一个句柄 → 互不干扰
 *     · 同一个应用的多个线程各开各的 → 也不冲突
 *     · 天然无锁、并发安全，不需要 pid 表
 *
 * 用法（两次系统调用）：
 *     write("/proc/sk/io", "read /data/adb/umbral/grants.conf")
 *     read("/proc/sk/io")            → 文件内容
 *
 *   写：
 *     write("/proc/sk/io", "write /path\n<数据>")
 *
 *   列目录：
 *     write("/proc/sk/io", "list /data/adb/umbral/um")
 *     read  → 每行一个名字
 */
#define SK_IO_MAX (1024 * 1024)		/* 单次最多 1 MB */

struct sk_io_ctx {
	char  *buf;
	size_t len;
	size_t pos;
};

static struct file *(*sk_filp_open)(const char *, int, umode_t);
static ssize_t (*sk_kernel_read)(struct file *, void *, size_t, loff_t *);
static ssize_t (*sk_kernel_write)(struct file *, const void *, size_t, loff_t *);
static int (*sk_filp_close)(struct file *, fl_owner_t);
static int (*sk_iterate_dir)(struct file *, struct dir_context *);

static struct cred *(*sk_prepare_kernel_cred)(struct task_struct *);

/*
 * ★ 不要用 init_cred ★
 *
 * init_cred 在 cred.c 里是：
 *     struct cred init_cred __ro_after_init = { ... };
 *
 * __ro_after_init = 开机初始化之后这块内存被设为**只读**。
 * 而 override_creds(cred) 内部会对 cred 做 get_new_cred() —— 也就是
 * atomic_long_inc(&cred->usage)，**写这块只读页** → page fault → Oops → panic。
 *
 * 正确做法：用 prepare_kernel_cred(NULL) 现造一份。
 *   · 它返回的是一个引用计数为 1、归我们所有的 cred
 *   · 可以随便改、随便引用
 *   · 不用时 put_cred 还回去
 *   · 只需要在 init / 工作队列里造一次，热路径只读指针
 *
 * 域是 kernel_t（不是 init），对 /data/adb、/system 的覆盖面略小一点，
 * 但**不会崩** —— 这是第一优先级。
 */
static void sk_io_make_cred(void)
{
	if (sk_init_cred)
		return;
	if (!sk_prepare_kernel_cred)
		sk_prepare_kernel_cred = (void *)sk_sym("prepare_kernel_cred");
	if (!sk_prepare_kernel_cred) {
		pr_warn(SK_TAG "prepare_kernel_cred 取不到，io 接口不可用\n");
		return;
	}
	/*
	 * ★ 从 pid 1（/init 进程）复制 cred，而不是从 NULL ★
	 *
	 * prepare_kernel_cred(NULL) 走的是 init_cred 那份模板，
	 * 拿到的 SELinux 域是 **kernel_t** —— 这个域在 Android policy 里
	 * 访问不了 /data/adb、/data/system、/system，我们试过就是这么个结果。
	 *
	 * prepare_kernel_cred(task) 会复制**那个 task 的 cred**，
	 * 连 security 里的 SID（也就是 SELinux 域）一起复制。
	 *
	 * pid 1 是 /init，域是 u:r:init:s0 —— Android policy 里它几乎无所不能，
	 * /data/adb、/data/system、/system 全部可读可写。
	 *
	 * 拿到的是**新分配的一份**（引用计数 1、归我们所有），
	 * 所以 override_creds 去 atomic_inc 它完全合法，
	 * 不存在 v1.00 之前那个「写只读页」的 panic。
	 */
	{
		struct task_struct *t = NULL, *p;

		rcu_read_lock();
		for_each_process(p) {
			if (p->pid == 1) {
				get_task_struct(p);
				t = p;
				break;
			}
		}
		rcu_read_unlock();

		if (t) {
			sk_init_cred = sk_prepare_kernel_cred(t);
			put_task_struct(t);
			pr_info(SK_TAG "io 接口 cred 取自 pid1（域应为 init）%s\n",
				sk_init_cred ? "成功" : "失败");
		}
	}

	/* 兜底：拿不到 pid1 就用 kernel 域那份（覆盖面小但不会崩） */
	if (!sk_init_cred) {
		sk_init_cred = sk_prepare_kernel_cred(NULL);
		pr_warn(SK_TAG "回退到 kernel 域 cred（/data/adb 可能读不了）\n");
	}
}

static void sk_io_resolve(void)
{
	sk_filp_open  = (void *)sk_sym("filp_open");
	sk_kernel_read = (void *)sk_sym("kernel_read");
	sk_kernel_write = (void *)sk_sym("kernel_write");
	sk_filp_close = (void *)sk_sym("filp_close");
	sk_iterate_dir = (void *)sk_sym("iterate_dir");
	sk_io_make_cred();

	pr_info(SK_TAG "io 接口符号: %s %s %s %s %s\n",
		sk_filp_open ? "open" : "open✗",
		sk_kernel_read ? "read" : "read✗",
		sk_kernel_write ? "write" : "write✗",
		sk_filp_close ? "close" : "close✗",
		sk_init_cred ? "cred" : "cred✗");
}

/* 用 init 身份做一件事（这是整个接口的核心） */
static long sk_io_do_read(const char *path, char **out)
{
	const struct cred *old;
	struct file *f;
	loff_t pos = 0;
	char *buf;
	ssize_t n;

	if (!sk_filp_open || !sk_kernel_read || !sk_filp_close || !sk_init_cred)
		return -EOPNOTSUPP;

	buf = kvzalloc(SK_IO_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	old = override_creds(sk_init_cred);	/* ← 主体换成 init */
	f = sk_filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f)) {
		revert_creds(old);
		kvfree(buf);
		return PTR_ERR(f);
	}
	n = sk_kernel_read(f, buf, SK_IO_MAX, &pos);
	sk_filp_close(f, NULL);
	revert_creds(old);

	if (n < 0) {
		kvfree(buf);
		return n;
	}
	*out = buf;
	return n;
}

static long sk_io_do_write(const char *path, const char *data, size_t len)
{
	const struct cred *old;
	struct file *f;
	loff_t pos = 0;
	ssize_t n;

	if (!sk_filp_open || !sk_kernel_write || !sk_filp_close || !sk_init_cred)
		return -EOPNOTSUPP;

	old = override_creds(sk_init_cred);
	f = sk_filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(f)) {
		revert_creds(old);
		return PTR_ERR(f);
	}
	n = sk_kernel_write(f, data, len, &pos);
	sk_filp_close(f, NULL);
	revert_creds(old);
	return n;
}


/* 目录列举：用 iterate_dir + 自定义 actor 把名字收进缓冲区 */
struct sk_ls_ctx {
	struct dir_context ctx;
	char  *buf;
	size_t len;
	size_t cap;
};

static SK_LS_SIG sk_ls_actor(struct dir_context *ctx, const char *name, int namlen,
			loff_t offset, u64 ino, unsigned int d_type)
{
	struct sk_ls_ctx *c = container_of(ctx, struct sk_ls_ctx, ctx);

	(void)offset; (void)ino; (void)d_type;
	if (namlen <= 0)
		return SK_LS_GO;
	if (namlen == 1 && name[0] == '.')
		return SK_LS_GO;
	if (namlen == 2 && name[0] == '.' && name[1] == '.')
		return SK_LS_GO;
	if (c->len + namlen + 2 > c->cap)
		return SK_LS_STOP;			/* 满了就停 */
	memcpy(c->buf + c->len, name, namlen);
	c->len += namlen;
	c->buf[c->len++] = '\n';
	return SK_LS_GO;
}


static long sk_io_do_list(const char *path, char **out)
{
	const struct cred *old;
	struct file *f;
	struct sk_ls_ctx *c;
	int rc;

	if (!sk_filp_open || !sk_filp_close || !sk_init_cred || !sk_iterate_dir)
		return -EOPNOTSUPP;

	c = kvzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return -ENOMEM;
	c->buf = kvzalloc(SK_IO_MAX, GFP_KERNEL);
	if (!c->buf) {
		kvfree(c);
		return -ENOMEM;
	}
	c->cap = SK_IO_MAX;
	c->ctx.actor = sk_ls_actor;
	c->ctx.pos = 0;

	old = override_creds(sk_init_cred);
	f = sk_filp_open(path, O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(f)) {
		revert_creds(old);
		kvfree(c->buf);
		kvfree(c);
		return PTR_ERR(f);
	}
	rc = sk_iterate_dir(f, &c->ctx);
	sk_filp_close(f, NULL);
	revert_creds(old);

	if (rc < 0) {
		kvfree(c->buf);
		kvfree(c);
		return rc;
	}
	*out = c->buf;
	rc = (int)c->len;
	kvfree(c);
	return rc;
}

static int sk_io_open(struct inode *i, struct file *f)
{
	struct sk_io_ctx *c = kzalloc(sizeof(*c), GFP_KERNEL);

	if (!c)
		return -ENOMEM;
	f->private_data = c;
	return 0;
}

static int sk_io_release(struct inode *i, struct file *f)
{
	struct sk_io_ctx *c = f->private_data;

	if (c) {
		kvfree(c->buf);
		kfree(c);
		f->private_data = NULL;
	}
	return 0;
}

static ssize_t sk_io_write(struct file *f, const char __user *ubuf,
			   size_t len, loff_t *off)
{
	struct sk_io_ctx *c = f->private_data;
	char *req = NULL;
	char *sp;
	ssize_t ret = -EINVAL;

	if (!sk_writer_allowed())
		return -EPERM;
	if (!c || len == 0 || len > 8192)
		return -EINVAL;

	req = kmalloc(len + 1, GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	if (copy_from_user(req, ubuf, len)) {
		kfree(req);
		return -EFAULT;
	}
	req[len] = 0;

	kvfree(c->buf);
	c->buf = NULL;
	c->len = c->pos = 0;

	if (!strncmp(req, "read ", 5)) {
		char *out = NULL;
		long n;

		strim(req + 5);
		n = sk_io_do_read(req + 5, &out);
		if (n < 0)
			ret = n;
		else {
			c->buf = out;
			c->len = (size_t)n;
			ret = len;
		}
	} else if (!strncmp(req, "write ", 6)) {
		/* 格式：write <path>\n<数据> */
		sp = strchr(req + 6, '\n');
		if (!sp) {
			ret = -EINVAL;
		} else {
			*sp = 0;
			strim(req + 6);
			ret = sk_io_do_write(req + 6, sp + 1, len - (size_t)(sp + 1 - req));
			if (ret >= 0)
				ret = len;
		}
	} else if (!strncmp(req, "list ", 5)) {
		char *out = NULL;
		long n;

		strim(req + 5);
		n = sk_io_do_list(req + 5, &out);
		if (n < 0) {
			ret = n;
		} else {
			c->buf = out;
			c->len = (size_t)n;
			ret = len;
		}
	}

	kfree(req);
	return ret;
}

static ssize_t sk_io_read(struct file *f, char __user *ubuf,
			  size_t len, loff_t *off)
{
	struct sk_io_ctx *c = f->private_data;
	size_t n;

	if (!c || !c->buf)
		return 0;
	if (c->pos >= c->len)
		return 0;

	n = c->len - c->pos;
	if (n > len)
		n = len;
	if (copy_to_user(ubuf, c->buf + c->pos, n))
		return -EFAULT;
	c->pos += n;
	return (ssize_t)n;
}

static const SK_PROC_OPS sk_io_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_open    = sk_io_open,
	.proc_read    = sk_io_read,
	.proc_write   = sk_io_write,
	.proc_lseek   = no_llseek,
	.proc_release = sk_io_release,
#else
	.open    = sk_io_open,
	.read    = sk_io_read,
	.write   = sk_io_write,
	.llseek  = no_llseek,
	.release = sk_io_release,
#endif
};

static int sk_io_register(struct proc_dir_entry *dir)
{
	sk_io_resolve();
	if (!proc_create("io", 0666, dir, &sk_io_ops))
		return -ENOMEM;
	pr_info(SK_TAG "/proc/sk/io 已就绪（内核代读）\n");
	return 0;
}

/* ══════════════════ su 兼容层（照 KSU 的做法）══════════════════ */

/*
 * 目标：任何应用执行 exec("su") 时，内核把路径重定向到我们自己的壳：
 *
 *     /data/adb/umbral/bin/su
 *
 * 这个壳做的事：
 *     ① 把 shell 自己的 pid 登记进 /proc/sk/grant
 *     ② exec 用户要的命令 → 那个进程变成真 uid 0
 *
 * 为什么不用 Magisk 那套（mount 覆盖 /system/bin/su）：
 *   要改动系统分区或依赖 overlay，跨机型不稳。
 *   KernelSU 用的是「内核里改 execve 的路径」，我们抄这个。
 *
 * 实现点：do_execveat_common(int fd, struct filename *filename, ...)
 *   filename 是内核对象，->name 是内核态字符串，
 *   直接把它换成我们自己的常量串即可 —— 不动用户内存，最干净。
 *
 * 安全：只对「已授权 uid」生效；没授权的应用 exec("su") 照旧 ENOENT。
 */
static const char sk_su_path[] = SK_SU_PATH;

static int sk_exec_entry(struct kprobe *p, struct pt_regs *regs)
{
	struct filename *fn;
	const char *name;

	if (atomic_read(&sk_ugrant_n) == 0)
		return 0;

	fn = (struct filename *)regs_get_kernel_argument(regs, 1);
	if (!fn || !fn->name)
		return 0;

	name = fn->name;

	/* 只认 basename 恰好是 "su"，且不是我们自己的路径 */
	{
		size_t len = strlen(name);

		if (len < 2 || name[len-1] != 'u' || name[len-2] != 's')
			return 0;
		if (len > 2 && name[len-3] != '/')
			return 0;
	}
	/*
	 * ★ 这条判断必须放在赋权之后 ★
	 *
	 * 原来这里是「名字等于 SK_SU_PATH 就 return 0，别自递归」，
	 * 那时 SK_SU_PATH 是个 shell 脚本（脚本里再 exec su 会递归）。
	 *
	 * 现在 SK_SU_PATH 本身就是真正的 su 二进制，
	 * App 直接 exec 它才是传统 su 的调用方式 ——
	 * 如果在这里 return，赋权永远不发生，id -u 永远是非 0。
	 *
	 * 所以改成：先赋权，之后只跳过「路径改写」（避免无意义的自我替换）。
	 */
	if (!sk_uid_privileged(__kuid_val(current_uid())))
		return 0;

	/*
	 * ══════════════════════════════════════════════════════
	 *  ★ 照 KernelSU / Magisk 的做法：在 execve 这一刻直接赋权 ★
	 * ══════════════════════════════════════════════════════
	 *
	 * 它们的逻辑只有一句：进程要 exec "su" → 内核检查组授权 →
	 * 通过就把这个进程的 creds 换成 root，然后放行 exec。
	 * root 身份是「被赋予」的，不是进程自己写文件申请。
	 *
	 * 之前我们是让 su 脚本自己写 /proc/sk/grant 申请提权，那条路
	 * 有时序和匹配字段一堆坑（v1.06~v1.09 一直没通）。
	 * 现在改成这里直接换 cred：
	 *   · 用工作队列里预先备好的 sk_init_cred（pid1 的域，init 级权限）
	 *   · commit_creds 会在 exec 完成前生效，脚本一跑起来就是 uid 0
	 *   · 不再依赖 /proc/sk/grant，也不再依赖 pid 表匹配
	 */
	/*
	 * ④ 签名校验：打开了 sig_required 就必须先拿到管理器签名摘要。
	 * 摘要为空 = App 被换掉或文件被删 → 拒绝提权（对齐 KSU 的 signature 机制）。
	 */
	if (sk_sig_required && !sk_sig_loaded) {
		pr_warn(SK_TAG "拒绝提权：管理器签名摘要缺失（pid=%d）\n", current->pid);
		return 0;
	}

	/*
	 * ★ 用「同 uid 的 cred 缓存」，不要用 pid1 的 cred ★
	 *
	 * 之前用 prepare_kernel_cred(pid1) → 域是 u:r:init:s0。
	 * 结果：execve 换上 init 域之后，init 域对
	 * /data/local/tmp/umbral/su（app_data_file）没有 execute 权限
	 * → exec 在进入程序之前就被 SELinux 拒
	 * → 表现为 su 一条输出都没有、退出码 255。
	 *
	 * 正确做法（技能里也写过）：cred 由工作队列用
	 * prepare_kernel_cred(同 uid 的 task) 提前建好并缓存，
	 * 保持 untrusted_app 域不变，只把 uid 提成 0 + caps 拉满。
	 * 这样 exec 合法，uid 也是 0。
	 */
	/*
	 * ★ v1.17：execve 钩子里不再提权 ★
	 *
	 * 这一段（用缓存 cred 在钩子里 commit_creds）和 v1.14 的 init_cred 版
	 * 有同样的毛病：钩子是原子上下文，拿到的 cred 缺 user/ucounts 的正确处理，
	 * 装上之后 exec 会被 SELinux 拒（255、零输出），su 二进制根本没机会运行。
	 *
	 * KSU 也不在 execve 里提权 —— 它让被杀的程序自己走 supercall。
	 * 我们对应的是 /proc/sk/escape：su 二进制启动后自己写它，在进程上下文
	 * 里用 prepare_creds() 干干净净地提权。
	 *
	 * 这里保留代码但关掉，只做「授权判断 + 记录日志」。
	 */
	if (0) {
		struct cred *cached = sk_cred_lookup(__kuid_val(current_uid()),
						     SK_GRANT_SUPER);

		if (cached) {
			sk_commit_creds(get_new_cred(cached));
			atomic64_inc(&sk_su_redirect);
			pr_info(SK_TAG "execve 赋权(缓存cred)：pid=%d uid=0\n",
				current->pid);
		} else {
			/* 缓存还没建好：登记一下，下一次再来就命中 */
			sk_cred_request(__kuid_val(current_uid()), SK_GRANT_SUPER);
			pr_info(SK_TAG "execve 赋权：cred 未就绪，已登记 uid=%u\n",
				__kuid_val(current_uid()));
			return 0;
		}
	}

	if (0) {
		struct cred *nc = get_new_cred(sk_init_cred);

		/*
		 * ★ 连域一起换 ★
		 * 光 uid 0 不够 —— 域还是原来的（init 或 untrusted_app），
		 * SELinux 照样拦。这里把新 cred 的 SELinux sid 改成探测到的 su 域。
		 * cred 是我们自己 get_new_cred 出来的私有副本，改它不影响别人。
		 */
		if (sk_dom_switch && !sk_dom_probed)
			sk_probe_domains();
		if (sk_dom_switch && sk_lbs_cred >= 0 && nc && nc->security) {
			int i;
			u32 want = 0;

			for (i = 0; i < SK_DOM_N; i++) {
				if (sk_dom_sid[i]) {
					want = sk_dom_sid[i];
					break;
				}
			}
			if (want) {
				/*
				 * struct task_security_struct { u32 osid; u32 sid; ... }
				 * 本机 RANDSTRUCT_NONE，sid 在 +4。
				 */
				*(u32 *)((char *)nc->security + sk_lbs_cred + 4) = want;
			}
		}
		sk_commit_creds(nc);
		atomic64_inc(&sk_su_redirect);
		pr_info(SK_TAG "execve 赋权：pid=%d comm=%s → uid 0 dom=%d\n",
			current->pid, current->comm,
			(sk_dom_switch && sk_lbs_cred >= 0) ? 1 : 0);
	}

	/* 已经是目标路径 → 不需要改写（但仍然已经赋权） */
	if (!strcmp(name, SK_SU_PATH))
		return 0;

	/*
	 * ★ 必须堆分配，不能用静态字符串 ★
	 *
	 * 内核在 execve 收尾时会 __putname(filename)：
	 *     if (name->name != name->iname)
	 *         kfree(name->name);        ← 对我们的字符串调 kfree
	 *
	 * 如果 fn->name 指向 .rodata 里的静态串，这里就是
	 *   「kfree 一个非堆指针」→ SLUB 直接 BUG → 内核 panic → 设备重启。
	 * 这就是「一开管理器 App 设备就重启」的真正原因（App 启动时会探测 su）。
	 *
	 * 用 kmemdup_nul 分配一份，__putname 的 kfree 就合法了。
	 * 用 GFP_ATOMIC：execve 的 kprobe 上下文不能睡眠。
	 */
	{
		size_t plen = strlen(sk_su_path);
		char *dup = kmemdup_nul(sk_su_path, plen, GFP_ATOMIC);

		if (!dup)
			return 0;		/* 分配失败就放弃重定向，按原样 exec */
		fn->name = dup;
	}
	atomic64_inc(&sk_su_redirect);
	pr_info(SK_TAG "su 重定向：pid=%d uid=%u comm=%s\n",
		current->pid, __kuid_val(current_uid()), current->comm);
	return 0;
}

/* 零1：do_filp_open 钩子 —— system/ 目录覆盖 */
static struct kprobe sk_kp_open_reg = {
	.symbol_name = "do_filp_open",
	.pre_handler = sk_open_entry,
};
static bool sk_open_registered;

static void sk_open_register(void)
{
	if (sk_open_registered)
		return;
	if (register_kprobe(&sk_kp_open_reg)) {
		pr_warn(SK_TAG "do_filp_open 钩子失败，system 覆盖不可用\n");
		return;
	}
	sk_open_registered = true;
	pr_info(SK_TAG "system 覆盖钩子已就绪\n");
}

static void __maybe_unused sk_open_unregister(void)
{
	if (sk_open_registered) {
		unregister_kprobe(&sk_kp_open_reg);
		sk_open_registered = false;
	}
}

static struct kprobe sk_kp_exec = {
	.symbol_name = "do_execveat_common",
	.pre_handler = sk_exec_entry,
};

static bool sk_exec_registered;

static void sk_exec_register(void)
{
	if (register_kprobe(&sk_kp_exec)) {
		pr_warn(SK_TAG "do_execveat_common 钩子失败，su 兼容层不可用\n");
		return;
	}
	sk_exec_registered = true;
	pr_info(SK_TAG "su 兼容层已就绪 → %s\n", SK_SU_PATH);
}

static void sk_exec_unregister(void)
{
	if (sk_exec_registered) {
		unregister_kprobe(&sk_kp_exec);
		sk_exec_registered = false;
	}
}

/* ══════════════════ ART 探测屏蔽（为了能写 root 属主文件）══════════════════ */

/*
 * 以前的取舍：为了不让 ART 报 "Writable dex file is not allowed"，
 * 我们对「属主 <= 1000 的文件」一律保持只读判定 ——
 * 代价是影子权限写不了 /data/adb、/system 这些 root 属主的地方。
 *
 * 现在反过来做：
 *   ① 真实写入全部放行（包括 root 属主文件）
 *   ② 只把 ART 那句 access(apk, W_OK) 的答案掐死，让它永远得到「不可写」
 *
 * ART 的判断只走 faccessat / faccessat2，所以只需在这两个入口上
 * 对「带 W_OK 的查询」返回 -EACCES。真实 open(O_WRONLY) 不受任何影响。
 *
 * 副作用：被授权 App 里任何 "这个文件可写吗" 的探测都会得到「不可写」。
 * 对绝大多数 App 无影响；ART 也因此永远满意。
 */
static int sk_acc_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_acc_data *d = (struct sk_acc_data *)ri->data;

	d->path = (const char __user *)regs_get_kernel_argument(regs, 1);
	d->mode = (int)regs_get_kernel_argument(regs, 2);	/* int mode */
	d->uid  = __kuid_val(current_uid());
	return 0;
}

static int sk_acc_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sk_acc_data *d = (struct sk_acc_data *)ri->data;

	/*
	 * 只掐「问可写」这一类。W_OK == 2。
	 * 不掐 R_OK / X_OK / F_OK —— 那些是正常功能要用的。
	 */
	/*
	 * ★ 假装 su 存在 ★
	 *
	 * 很多传统 root 应用/检测器的顺序是：
	 *   ① 先 stat 或 access("/system/bin/su", F_OK)
	 *   ② 存在 → 才去 exec("su")
	 *   ③ 不存在 → 直接判定「没有 root」，连试都不试
	 *
	 * 我们设备上 /system/bin/su 本来就不存在（KSU 被替换掉了），
	 * 所以第 ① 步就把它劝退了。v0.80 的 execve 重定向根本轮不到执行。
	 *
	 * 这里对「已授权 uid 问某个以 /su 结尾的路径」直接答「存在」。
	 * 它随后 exec("su") 就会被 v0.80 重定向到我们的壳，拿到真 uid 0。
	 */
	if (d->path && sk_uid_privileged(d->uid)) {
		char kb[128];
		long n = 0;

		/* 只读路径字符串，长度受限 */
		if (strncpy_from_user(kb, d->path, sizeof(kb) - 1) > 0) {
			kb[sizeof(kb) - 1] = 0;
			n = (long)strlen(kb);
			if (n >= 2 && kb[n-1] == 'u' && kb[n-2] == 's'
			    && (n == 2 || kb[n-3] == '/')) {
				/* 问的就是 su —— 无论原来返回什么，都当作存在 */
				regs_set_return_value(regs, 0);
				atomic64_inc(&sk_acc_blocked);
				return 0;
			}
		}
	}

	if ((d->mode & 2) && sk_uid_privileged(d->uid)) {
		regs_set_return_value(regs, -EACCES);
		atomic64_inc(&sk_acc_blocked);
	}
	return 0;
}

static struct kretprobe sk_krp_acc = {
	.entry_handler = sk_acc_entry,
	.handler       = sk_acc_return,
	.data_size     = sizeof(struct sk_acc_data),
	.maxactive     = 128,
};

static bool sk_acc_registered;

static void __attribute__((unused)) sk_acc_register(void)
{
	static const char *const names[] = {
		"__arm64_sys_faccessat",
		"do_faccessat",
		"__arm64_sys_faccessat2",
	};
	const char *chosen = NULL;

	if (sk_register_first(&sk_krp_acc, names, ARRAY_SIZE(names), &chosen)) {
		pr_warn(SK_TAG "faccessat 钩子全部失败，ART 保护不可用\n");
		return;
	}
	sk_acc_registered = true;
	pr_info(SK_TAG "ART 探测屏蔽已就绪 (%s)\n", chosen);
}

static void __attribute__((unused)) sk_acc_unregister(void)
{
	if (sk_acc_registered) {
		unregister_kretprobe(&sk_krp_acc);
		sk_acc_registered = false;
	}
}

/* ══════════════════ 系统守护（危险写入拦截）══════════════════ */

/*
 * 目标：任何进程试图修改 Android 关键分区/目录时，立刻拦下来，
 *       记录是谁干的（uid + pid + 进程名 + 次数），
 *       并把该进程杀掉，同时让管理器弹告警。
 *
 * 怎么判断"关键"：不猜路径字符串（内核里拿不到路径），
 *   而是在延迟工作里把关键挂载点的 dev_t 记下来，
 *   写钩子里只比较 inode 所在超级块的 s_dev —— 整数比较，零开销、零误判。
 *
 * 关键点清单（存在才记）：
 *   /system  /vendor  /product  /system_ext  /odm
 *   /data/system  /metadata
 *   ★ 刻意不包含 /data/adb —— 那是我们自己的工作目录，
 *     管理器装模块、写规则都要用它，拦了等于自废武功。
 *
 * 例外：特权 uid（管理器自己、真 root、已授影子/SU 的 uid）不受限制，
 *       否则管理器自己装模块都会被自己拦。
 */
#define SK_GUARD_DEVS 8
#define SK_GUARD_HITS 32

struct sk_guard_hit {
	u32 uid;
	pid_t pid;
	char comm[16];
	u32 count;
};

static bool sk_guard_on;
static u32 sk_guard_dev[SK_GUARD_DEVS];
static int sk_guard_dev_n;

static struct sk_guard_hit sk_guard_hits[SK_GUARD_HITS];
static int sk_guard_hit_n;		/* 已用的槽位数 */
static DEFINE_SPINLOCK(sk_guard_lock);
static atomic64_t sk_guard_blocked = ATOMIC64_INIT(0);

static void sk_guard_ensure(void)
{
	if (sk_guard_dev_n == 0)
		sk_guard_refresh();
}

static void sk_guard_refresh(void)
{
	static const char *paths[] = {
		"/system", "/vendor", "/product", "/system_ext", "/odm",
		"/data/system", "/metadata",
	};
	int i;

	sk_guard_dev_n = 0;
	for (i = 0; i < (int)ARRAY_SIZE(paths) && sk_guard_dev_n < SK_GUARD_DEVS; i++) {
		struct path pth;
		struct inode *in;

		if (kern_path(paths[i], 0, &pth))
			continue;
		in = d_backing_inode(pth.dentry);
		if (in && in->i_sb) {
			u32 d = new_encode_dev(in->i_sb->s_dev);
			int k, dup = 0;

			for (k = 0; k < sk_guard_dev_n; k++)
				if (sk_guard_dev[k] == d)
					dup = 1;
			if (!dup)
				sk_guard_dev[sk_guard_dev_n++] = d;
		}
		path_put(&pth);
	}
	pr_info(SK_TAG "守卫：记录了 %d 个关键挂载点\n", sk_guard_dev_n);
}

/* 返回 true 表示设备属于关键分区 */
static bool sk_guard_dev_match(u32 dev)
{
	int i;

	for (i = 0; i < sk_guard_dev_n; i++)
		if (sk_guard_dev[i] == dev)
			return true;
	return false;
}

static void sk_guard_record(u32 uid, pid_t pid, const char *comm)
{
	int i;

	spin_lock(&sk_guard_lock);
	for (i = 0; i < sk_guard_hit_n; i++) {
		if (sk_guard_hits[i].uid == uid && sk_guard_hits[i].pid == pid) {
			sk_guard_hits[i].count++;
			spin_unlock(&sk_guard_lock);
			return;
		}
	}
	if (sk_guard_hit_n < SK_GUARD_HITS) {
		struct sk_guard_hit *h = &sk_guard_hits[sk_guard_hit_n++];

		h->uid = uid;
		h->pid = pid;
		h->count = 1;
		strncpy(h->comm, comm, sizeof(h->comm) - 1);
		h->comm[sizeof(h->comm) - 1] = 0;
	}
	spin_unlock(&sk_guard_lock);
}

/*
 * 在写判定里调用。返回 true 表示「拦下」。
 * 注意：这里不能睡眠、不能 kill 进程（kill 需要发信号，可以放这里，
 * 但为安全起见只记录，真正清理交给用户态管理器）。
 */
static bool sk_guard_check(struct inode *ino)
{
	u32 dev, uid;

	if (!sk_guard_on || !ino || !ino->i_sb || sk_guard_dev_n == 0)
		return false;

	dev = new_encode_dev(ino->i_sb->s_dev);
	if (!sk_guard_dev_match(dev))
		return false;

	/*
	 * ★ 豁免只给「真 root」和「管理器自己」★
	 *
	 * 用户明确要求：即使是已经授予影子/超级用户权限的 App，
	 * 只要去动关键分区也必须拦下来 —— 防止被授权应用滥用权限毁系统。
	 *
	 * 所以这里不能用 sk_uid_privileged()（它把已授权 uid 也算自己人）。
	 */
	uid = __kuid_val(current_uid());
	if (uid == 0)
		return false;			/* 真 root */
	if (sk_grant_uid > 0 && uid == (u32)sk_grant_uid)
		return false;			/* 管理器自己是唯一例外 */

	sk_guard_record(uid, current->pid, current->comm);
	atomic64_inc(&sk_guard_blocked);
	pr_warn(SK_TAG "守卫拦截：uid=%u pid=%d comm=%s\n",
		uid, current->pid, current->comm);
	return true;
}

static int sk_guard_show(struct seq_file *m, void *v)
{
	int i;

	seq_printf(m, "state   %s\n", sk_guard_on ? "on" : "off");
	seq_printf(m, "blocked %lld\n", (long long)atomic64_read(&sk_guard_blocked));
	seq_printf(m, "devs    %d\n", sk_guard_dev_n);
	for (i = 0; i < sk_guard_dev_n; i++)
		seq_printf(m, "dev     %u\n", sk_guard_dev[i]);
	seq_printf(m, "offenders %d\n", sk_guard_hit_n);
	for (i = 0; i < sk_guard_hit_n; i++)
		seq_printf(m, "hit  uid=%u pid=%d comm=%s count=%u\n",
			   sk_guard_hits[i].uid, sk_guard_hits[i].pid,
			   sk_guard_hits[i].comm, sk_guard_hits[i].count);
	return 0;
}

static ssize_t sk_guard_write(struct file *f, const char __user *ubuf,
			      size_t len, loff_t *off)
{
	char buf[32];

	if (!sk_writer_allowed())
		return -EPERM;
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = 0;
	strim(buf);

	if (!strcmp(buf, "on")) {
		if (sk_guard_dev_n == 0)
			sk_guard_refresh();
		sk_guard_on = true;
		pr_info(SK_TAG "守卫已开启（%d 个关键挂载点）\n", sk_guard_dev_n);
	} else if (!strcmp(buf, "off")) {
		sk_guard_on = false;
		pr_info(SK_TAG "守卫已关闭\n");
	} else if (!strcmp(buf, "clear")) {
		spin_lock(&sk_guard_lock);
		sk_guard_hit_n = 0;
		memset(sk_guard_hits, 0, sizeof(sk_guard_hits));
		spin_unlock(&sk_guard_lock);
		atomic64_set(&sk_guard_blocked, 0);
	} else if (!strcmp(buf, "refresh")) {
		sk_guard_refresh();
	} else {
		return -EINVAL;
	}
	return len;
}

static int sk_guard_open(struct inode *i, struct file *f)
{
	return single_open(f, sk_guard_show, NULL);
}

static const SK_PROC_OPS sk_guard_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_open    = sk_guard_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = sk_guard_write,
#else
	.open    = sk_guard_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = sk_guard_write,
#endif
};

static int sk_guard_register(struct proc_dir_entry *dir)
{
	if (!proc_create("guard", 0666, dir, &sk_guard_ops))
		return -ENOMEM;
	pr_info(SK_TAG "/proc/sk/guard 已就绪\n");
	return 0;
}

/* ══════════════════ 运行时功能开关 ══════════════════ */

/*
 * /proc/sk/feature —— 不用重新 insmod 就能开关新钩子。
 *
 * 为什么需要：
 *   目录列表过滤（判定点3）和内容伪造（判定点4）是新加的钩子，
 *   默认关闭 —— 万一逻辑有问题，至少能开机、能进来把它关掉，
 *   而不是 insmod 即 panic、只能重刷 boot。
 *
 * 用法：
 *   echo "readdir on"  > /proc/sk/feature
 *   echo "readfake on" > /proc/sk/feature
 *   echo "all on"      > /proc/sk/feature
 *   echo "all off"     > /proc/sk/feature
 */
static int sk_feature_show(struct seq_file *m, void *v)
{
	seq_printf(m, "readdir  %s\n", sk_iop_enable ? "on" : "off");
	seq_printf(m, "readfake %s\n", sk_rd_enable  ? "on" : "off");
	return 0;
}

static ssize_t sk_feature_write(struct file *f, const char __user *ubuf,
				size_t len, loff_t *off)
{
	char buf[48];
	char what[16] = {0}, val[8] = {0};

	if (!sk_writer_allowed())
		return -EPERM;
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = 0;
	strim(buf);

	if (sscanf(buf, "%15s %7s", what, val) < 2)
		return -EINVAL;

	{
		bool on = !strcmp(val, "on") || !strcmp(val, "1");

		if (!strcmp(what, "all")) {
			sk_iop_enable = on;
			sk_rd_enable  = on;
		} else if (!strcmp(what, "readdir")) {
			sk_iop_enable = on;
		} else if (!strcmp(what, "readfake")) {
			sk_rd_enable = on;
		} else {
			return -EINVAL;
		}
	}
	pr_info(SK_TAG "feature: %s=%s (readdir=%d readfake=%d)\n",
		what, val, sk_iop_enable, sk_rd_enable);
	return len;
}

static int sk_feature_open(struct inode *i, struct file *f)
{
	return single_open(f, sk_feature_show, NULL);
}

static const SK_PROC_OPS sk_feature_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	.proc_open    = sk_feature_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = sk_feature_write,
#else
	.open    = sk_feature_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = sk_feature_write,
#endif
};

static int sk_feature_register(struct proc_dir_entry *dir)
{
	if (!proc_create("feature", 0666, dir, &sk_feature_ops))
		return -ENOMEM;
	pr_info(SK_TAG "运行时开关已就绪：/proc/sk/feature\n");
	return 0;
}

static int __init sk_root_init(void)
{
	unsigned long v;
	int rc;

	v = sk_probe_helper((unsigned long)sk_probe_val);

	/* 6.5+ 不允许 prepare_kernel_cred(NULL)，必须给真实 task */
	sk_root_cred = prepare_kernel_cred(&init_task);
	if (!sk_root_cred) {
		pr_err(SK_TAG "prepare_kernel_cred(&init_task) failed\n");
		return -ENOMEM;
	}

	pr_info(SK_TAG "v%s init, helper=%lx, msg=%s, param=%d\n",
		SK_VERSION, v, sk_probe_msg, sk_param_int);

	rc = sk_hooks_install();
	if (rc) {
		put_cred(sk_root_cred);
		sk_root_cred = NULL;
		return rc;
	}

	rc = sk_proc_init();
	if (rc) {
		pr_err(SK_TAG "proc init failed: %d\n", rc);
		sk_hooks_remove();
		put_cred(sk_root_cred);
		sk_root_cred = NULL;
		return rc;
	}

	pr_info(SK_TAG "/proc/sk ready, backend=%s hooks=0x%x\n", sk_backend, sk_hooks);

	/*
	 * 所有初始化做完再隐藏 —— 太早摘链表会让后续 pr_info 拿不到模块信息。
	 * sk_hide 默认 0，所以正常加载时这里什么也不做。
	 */
	sk_resolve_commit_creds();
	sk_resolve_secctx();
	sk_btf_init();
	sk_um_bootload();

	/*
	 * 记录 /proc/sk/grant 的 inode。
	 *
	 * 为什么需要：影子模式为了救 ART，对「属主 <= 1000 的文件」保留只读判定，
	 * 而 /proc/sk/grant 属主是 root(0) —— 结果管理器连授权表都写不了。
	 * 这是自家节点，必须放行，所以在权限钩子里按 inode 开白名单。
	 */
	{
		static const char *own[] = {
			"/proc/sk/grant", "/proc/sk/claim", "/proc/sk/um",
			"/proc/sk/umstat", "/proc/sk/umdbg",
		};
		int oi;

		for (oi = 0; oi < (int)(sizeof(own) / sizeof(own[0])); oi++) {
			struct file *gf = sk_filp_open(own[oi], O_RDONLY, 0);

			if (IS_ERR(gf))
				continue;
			if (gf->f_inode && sk_own_ino_n < 8) {
				sk_own_ino[sk_own_ino_n++] = gf->f_inode->i_ino;
				pr_info(SK_TAG "白名单节点 %s inode=%llu\n", own[oi],
					(unsigned long long)gf->f_inode->i_ino);
			}
			sk_filp_close(gf, NULL);
		}
	}

	/* 从磁盘恢复用户上次的授权决定 */
	sk_load_grants();

	sk_exec_register();
	sk_open_register();
	sk_iop_register();
	sk_rd_register();

	/* 启动延迟发现（/data 挂载后在后台自动授权管理器） */
	INIT_DELAYED_WORK(&sk_late_work, sk_late_fn);
	INIT_WORK(&sk_boot_work, sk_boot_work_fn);
	sk_boot_wq_ready = true;
	schedule_delayed_work(&sk_late_work, msecs_to_jiffies(2000));

	/* vfs_getattr 探针（只在校准时用，不影响正常功能） */
	if (register_kretprobe(&sk_krp_getattr))
		pr_warn(SK_TAG "vfs_getattr 探针注册失败（可能被内联）\n");
	else
		pr_info(SK_TAG "vfs_getattr 探针已注册\n");

	sk_wq = alloc_workqueue("umbral_cred", WQ_UNBOUND, 0);
	if (!sk_wq)
		pr_warn(SK_TAG "workqueue alloc failed (提权会失效)\n");

	/*
	 * 自举路径二：从文件读管理器 uid。
	 *
	 * 为什么需要：
	 *   Boot 修补时把 umbral.ko 打进 ramdisk，由 init 加载 ——
	 *   那时我们不知道管理器的 uid（它可能装/重装过，uid 会变）。
	 *   所以管理器每次启动会把自己的 uid 写到这个文件，
	 *   模块加载时读它，就能在没有任何 root 的情况下完成自举。
	 *
	 * 文件路径必须在 /data/adb 下 —— 那是 root 空间里持久、且
	 * 模块 init 阶段（可睡眠）能读到的位置。
	 */
	if (sk_grant_uid <= 0) {
		int u = sk_read_manager_uid();

		if (u > 0) {
			sk_grant_uid = u;
			pr_info(SK_TAG "从文件读到管理器 uid=%d\n", u);
		} else {
			/*
			 * 文件不存在（新设备/刷 boot 后第一次启动）——
			 * 自己去找管理器包的数据目录属主。
			 */
			u = sk_discover_manager_uid();
			if (u > 0)
				sk_grant_uid = u;
		}
	}

	/* 自举：把管理器自己的 uid 加进授权表 */
	if (sk_grant_uid > 0) {
		/*
		 * 管理器（自动发现的那个 uid）一律给**超级用户模式**：
		 * 它要装模块、写 /data/adb、改系统文件，shadow 不够用。
		 * 其它通过参数指定的 uid 仍然听 sk_grant_mode。
		 */
		/*
		 * 管理器一律影子模式（原因见扫描层注释）。
		 * 只有显式 grant_mode=1 且不是管理器时，才给超级用户模式。
		 */
		int is_mgr = sk_mgr_uid_found;
		int mode = (!is_mgr && sk_grant_mode == 1) ? SK_GRANT_SUPER
							   : SK_GRANT_SHADOW;
		int rc2 = sk_ugrant_add((u32)sk_grant_uid, mode);
		pr_info(SK_TAG "auto-grant uid=%d mode=%s rc=%d\n",
			sk_grant_uid,
			sk_grant_mode == 1 ? "super" : "shadow", rc2);
		/*
		 * 把自己写进 manager.uid：下次开机没传 grant_uid 时
		 * 模块就能靠这个文件自举。模块是内核态 root，能写 /data/adb，
		 * 管理器自己写不了（DAC 规则为 ART 保留了 root 属主文件的只读）。
		 */
		if (rc2 == 0)
			sk_write_manager_uid(sk_grant_uid);

	}

	sk_hide_self();

	return 0;
}

static void __exit sk_root_exit(void)
{
	sk_rd_unregister();
	sk_exec_unregister();
	sk_iop_unregister();
	sk_proc_exit();
	sk_hooks_remove();
	sk_grant_exit();
	sk_cred_flush();
	if (sk_wq) {
		destroy_workqueue(sk_wq);
		sk_wq = NULL;
	}

	if (sk_root_cred) {
		put_cred(sk_root_cred);
		sk_root_cred = NULL;
	}

	pr_info(SK_TAG "v%s exit, seen=%lld elevated=%lld reverted=%lld "
		"lsm_seen=%lld lsm_bypass=%lld\n",
		SK_VERSION,
		atomic64_read(&sk_seen), atomic64_read(&sk_elevated),
		atomic64_read(&sk_reverted),
		atomic64_read(&sk_lsm_seen), atomic64_read(&sk_lsm_bypass));
}

module_init(sk_root_init);
module_exit(sk_root_exit);

MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Umbral");
MODULE_DESCRIPTION("Umbral kernel module (shadow privilege + SELinux bridge)");
MODULE_VERSION(SK_VERSION);
