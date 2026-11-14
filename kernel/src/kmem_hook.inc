/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kmem_hook.inc —— 用户态指令执行探针（硬件执行断点）
 *
 * 规格来源：E:\暗区突围\暗区突围：无限\内核HOOK能力需求规格-v1.md
 *
 * 边界（已知且已与需求方确认）：
 *   · 命中瞬间的 q0~q31 拿不到（pt_regs 不含浮点；NMI 里不能碰 FPU）
 *   · 明文只能从内存取：mem=[x<n>±off] / mem=[sp±off]，单条最多 4 个窗口
 *   · NMI 里只做快照（tid/sp/gpr/seq），内存用 workqueue 延迟补读，
 *     补读用的是「NMI 时刻的 sp 快照」，不是补读时的 sp
 *
 * 命令：
 *   hkadd <名字> <目标表达式> [gpr=0-8] [fp=n] [off] [tid=n,n] [mem=expr:len]...
 *   hkdel [名字]
 *   hkon <名字>  /  hkoff <名字>
 *   hks
 *   hkev [名字] [条数]
 *   hkreset [名字]
 *
 * 目标表达式（第一批）：
 *   0xADDR            绝对地址
 *   libUE4.so@0x1a2b  模块名 + 偏移（基址运行时从 /proc/<pid>/maps 解析）
 *   *0xADDR           解引用一次（取该地址里的指针值作为目标）
 *   以上可叠加：*lib@off 表示"模块内某指针的值"
 */

#define KM_HK_MAX      8
#define KM_HK_NMEM     4
#define KM_HK_RING     256
#define KM_HK_NAME     16

struct km_hk_memwin {
	u8 kind;		/* 0=绝对 1=寄存器 2=sp */
	u8 reg;			/* kind=1 时的 xN */
	s32 off;		/* 可负 */
	u32 len;		/* <= 256 */
};

struct km_hk_evt {
	u32 seq;
	u32 tid;
	u64 pc;
	u64 sp;
	u64 gpr[9];
	struct {
		u64 addr;
		u32 len;
		u32 ok;		/* 1=已补读 */
		u8 data[64];
	} mem[KM_HK_NMEM];
	u8 nmem;
	u8 done;
};

struct km_hk {
	char name[KM_HK_NAME];
	char expr[96];
	bool used;
	bool enabled;
	u64 va;			/* 当前解析出的目标 */
	u32 gpr_mask;
	int nmem;
	struct km_hk_memwin mem[KM_HK_NMEM];
	u32 tids[8];
	int ntid;
	atomic64_t hits, drops, errs;
	struct perf_event *ev;
};

static struct km_hk km_hk[KM_HK_MAX];
static struct km_hk_evt *km_hk_ring;
static u32 km_hk_head, km_hk_tail, km_hk_seq;
static DEFINE_SPINLOCK(km_hk_lock);
static DEFINE_MUTEX(km_hk_mtx);

static bool km_hk_ready;
static unsigned int km_hk_want;		/* 延迟补读队列长度 */

static void km_hk_fill_mem(struct km_hk *h, struct km_hk_evt *e);

/* ─────────────────────────── 目标解析 ─────────────────────────── */


/* ── 基础读写：复用模块已有的 km_access_process_vm / filp_open ── */

static struct task_struct *km_hk_task(pid_t pid)
{
	return km_task_by_pid(pid);
}

static int km_hk_read(pid_t pid, u64 addr, void *buf, u32 len)
{
	struct task_struct *t = km_hk_task(pid);
	int r;

	if (!t)
		return -ESRCH;
	if (!km_access_process_vm) {
		put_task_struct(t);
		return -ENOSYS;
	}
	r = km_access_process_vm(t, (unsigned long)addr, buf, len, 0);
	put_task_struct(t);
	return r;
}

static char *km_hk_maps_read(pid_t pid, ssize_t *outlen)
{
	char path[48];
	char *buf;
	struct file *f;
	loff_t pos = 0;
	ssize_t n;

	if (!km_filp_open || !km_kernel_read || !km_filp_close)
		return NULL;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	f = km_filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f))
		return NULL;

	buf = vzalloc(65536);
	if (!buf) {
		km_filp_close(f, NULL);
		return NULL;
	}
	n = km_kernel_read(f, buf, 65535, &pos);
	km_filp_close(f, NULL);
	if (n <= 0) {
		vfree(buf);
		return NULL;
	}
	*outlen = n;
	return buf;
}

static void km_hk_maps_free(char *p)
{
	if (p)
		vfree(p);
}

/* /proc/<pid>/maps 里找模块基址 */
static u64 km_hk_mod_base(pid_t pid, const char *lib)
{
	char *buf;
	u64 base = 0;
	ssize_t n;
	loff_t pos = 0;

	buf = km_hk_maps_read(pid, &n);
	if (!buf)
		return 0;

	{
		char *p = buf;
		char *end = buf + n;

		while (p < end) {
			char *nl = p;
			char *slash;
			char *nm;

			while (nl < end && *nl != '\n')
				nl++;
			*nl = 0;

			/* 形如 "7c00000000-7c0a000000 r-xp ... /data/app/.../libUE4.so" */
			slash = strrchr(p, '/');
			if (slash) {
				nm = strrchr(slash, '/');
				nm = nm ? nm + 1 : slash + 1;
				if (!strncmp(nm, lib, strlen(lib)) &&
				    strstr(p, "r-xp")) {
					u64 lo = 0;

					if (!kstrtoull(p, 16, &lo)) {
						base = lo;
						break;
					}
				}
			}
			p = nl + 1;
		}
	}
	km_hk_maps_free(buf);
	(void)pos;
	return base;
}

/* 解析表达式；失败返回 0 */
static u64 km_hk_resolve(pid_t pid, const char *expr, u64 *out)
{
	char buf[96];
	char *at;
	u64 v = 0;

	strlcpy(buf, expr, sizeof(buf));

	/* 前缀 * = 解引用一次 */
	if (buf[0] == '*') {
		u64 inner = 0;

		if (!km_hk_resolve(pid, buf + 1, &inner) || !inner)
			return 0;
		if (km_hk_read(pid, inner, &v, 8) != 8)
			return 0;
		*out = v;
		return 1;
	}

	at = strchr(buf, '@');
	if (at) {
		u64 base;

		*at = 0;
		base = km_hk_mod_base(pid, buf);
		if (!base)
			return 0;
		if (kstrtoull(at + 1, 16, &v))
			return 0;
		*out = base + v;
		return 1;
	}

	if (kstrtoull(buf, 16, &v))
		return 0;
	*out = v;
	return 1;
}

/* ─────────────────────────── 命中处理（NMI）─────────────────────────── */

static void km_hk_handler(struct perf_event *ev, struct perf_sample_data *sd,
			  struct pt_regs *regs)
{
	int i;

	for (i = 0; i < KM_HK_MAX; i++) {
		struct km_hk *h = &km_hk[i];
		struct km_hk_evt *e;
		u32 pos;
		int k;

		if (!h->used || !h->enabled || h->ev != ev)
			continue;

		atomic64_inc(&h->hits);

		if (h->ntid) {
			int hit = 0;

			for (k = 0; k < h->ntid; k++)
				if (h->tids[k] == (u32)current->pid)
					hit = 1;
			if (!hit)
				return;
		}

		pos = km_hk_head % KM_HK_RING;
		e = &km_hk_ring[pos];
		if (e->done) {
			atomic64_inc(&h->drops);
			return;
		}
		memset(e, 0, sizeof(*e));
		e->seq = ++km_hk_seq;
		e->tid = (u32)current->pid;
		e->pc = regs->pc;
		e->sp = regs->sp;
		for (k = 0; k < 9; k++)
			e->gpr[k] = regs->regs[k];
		e->nmem = (u8)h->nmem;
		/* 快照地址（用 NMI 时刻的 sp / gpr 计算，绝不在补读时重算） */
		for (k = 0; k < h->nmem; k++) {
			u64 base = 0;

			if (h->mem[k].kind == 1)
				base = regs->regs[h->mem[k].reg & 31];
			else if (h->mem[k].kind == 2)
				base = regs->sp;
			e->mem[k].addr = (u64)((s64)base + h->mem[k].off);
			e->mem[k].len = h->mem[k].len;
			e->mem[k].ok = 0;
		}
		km_hk_head++;
		km_hk_want = 1;
		return;
	}
}

/* ─────────────────────────── 延迟补读（可睡眠）─────────────────────────── */

static void km_hk_fill_mem(struct km_hk *h, struct km_hk_evt *e)
{
	int i;

	for (i = 0; i < KM_HK_NMEM; i++) {
		u32 len;

		if (!e->mem[i].len)
			continue;
		len = e->mem[i].len;
		if (len > sizeof(e->mem[i].data))
			len = sizeof(e->mem[i].data);
		if (km_hk_read(e->tid, e->mem[i].addr, e->mem[i].data, len) == len)
			e->mem[i].ok = 1;
		else
			atomic64_inc(&h->errs);
	}
}

static void km_hk_work_fn(struct work_struct *w);
static DECLARE_WORK(km_hk_work, km_hk_work_fn);

static void km_hk_work_fn(struct work_struct *w)
{
	u32 pos;

	(void)w;
	if (!km_hk_ring)
		return;

	for (pos = km_hk_tail; pos != km_hk_head; pos++) {
		struct km_hk_evt *e = &km_hk_ring[pos % KM_HK_RING];
		int i;

		if (e->done)
			continue;
		for (i = 0; i < KM_HK_MAX; i++) {
			if (km_hk[i].used) {
				km_hk_fill_mem(&km_hk[i], e);
				break;
			}
		}
		e->done = 1;
	}
}

/* ─────────────────────────── 注册 / 卸载 ─────────────────────────── */

static int km_hk_install(struct km_hk *h, pid_t pid)
{
	struct perf_event_attr attr;
	struct perf_event *ev;
	struct task_struct *t;

	t = km_task_by_pid(pid);
	if (!t)
		return -ESRCH;

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_BREAKPOINT;
	attr.size = sizeof(attr);
	attr.bp_type = HW_BREAKPOINT_X;		/* ★ 指令执行断点 */
	attr.bp_addr = h->va;
	attr.bp_len = HW_BREAKPOINT_LEN_1;	/* 执行断点必须 1 */
	attr.sample_period = 1;
	attr.disabled = h->enabled ? 0 : 1;

	if (!km_reg_user_bp) {
		put_task_struct(t);
		return -ENOSYS;
	}

	ev = km_reg_user_bp(&attr, km_hk_handler, NULL, t);
	put_task_struct(t);
	if (IS_ERR(ev))
		return (int)PTR_ERR(ev);

	h->ev = ev;
	return 0;
}

static void km_hk_uninstall(struct km_hk *h)
{
	if (h->ev && km_unreg_bp) {
		km_unreg_bp(h->ev);
		h->ev = NULL;
	}
}

static struct km_hk *km_hk_by_name(const char *n)
{
	int i;

	for (i = 0; i < KM_HK_MAX; i++)
		if (km_hk[i].used && !strcmp(km_hk[i].name, n))
			return &km_hk[i];
	return NULL;
}

/* hkadd <name> <expr> [opts] */
static long km_hk_add(unsigned int pid, const char *name, const char *expr,
		      const char *opts)
{
	struct km_hk *h = NULL;
	u64 va = 0;
	int i, rc;

	if (!pid || !name || !*name || !expr || !*expr)
		return -EINVAL;

	if (!km_hk_resolve(pid, expr, &va) || !va)
		return -EFAULT;

	mutex_lock(&km_hk_mtx);
	if (km_hk_by_name(name)) {		/* 同名必须报错，不覆盖 */
		mutex_unlock(&km_hk_mtx);
		return -EEXIST;
	}
	for (i = 0; i < KM_HK_MAX; i++) {
		if (!km_hk[i].used) {
			h = &km_hk[i];
			break;
		}
	}
	if (!h) {
		mutex_unlock(&km_hk_mtx);
		return -ENOSPC;
	}

	memset(h, 0, sizeof(*h));
	strlcpy(h->name, name, sizeof(h->name));
	strlcpy(h->expr, expr, sizeof(h->expr));
	h->va = va;
	h->enabled = true;
	h->gpr_mask = 0x1ff;			/* 默认 x0..x8 */
	h->used = true;

	/* 解析选项 */
	while (opts && *opts) {
		const char *sp = opts;

		while (*opts && *opts != ' ')
			opts++;
		{
			char o[64];
			size_t n = (size_t)(opts - sp);

			if (n >= sizeof(o))
				n = sizeof(o) - 1;
			memcpy(o, sp, n);
			o[n] = 0;

			if (!strncmp(o, "gpr=", 4)) {
				unsigned int m = 0;

				if (!kstrtouint(o + 4, 10, &m))
					h->gpr_mask = (m >= 30) ? 0x7fffffffU
							       : ((1U << (m + 1)) - 1);
			} else if (!strncmp(o, "off", 3)) {
				h->enabled = false;
			} else if (!strncmp(o, "tid=", 4)) {
				char tmp[64];
				char *tok, *save = NULL;

				char *p2 = o + 4;

				while (*p2 && h->ntid < 8) {
					char *comma = strchr(p2, ',');
					unsigned int tv = 0;

					if (comma)
						*comma = 0;
					if (!kstrtouint(p2, 10, &tv))
						h->tids[h->ntid++] = tv;
					if (!comma)
						break;
					p2 = comma + 1;
				}
				(void)tmp;
				(void)tok;
				(void)save;
			} else if (!strncmp(o, "mem=", 4)) {
				/* mem=[x0-0x220]:0x30 / mem=[sp+0]:0x400 / mem=0xADDR:len */
				char e2[64];
				char *colon;
				u32 len = 0;

				strlcpy(e2, o + 4, sizeof(e2));
				colon = strrchr(e2, ':');
				if (colon) {
					*colon = 0;
					if (kstrtouint(colon + 1, 16, &len) && len == 0)
						len = 32;
				} else {
					len = 32;
				}
				if (len > 64)
					len = 64;
				if (h->nmem < KM_HK_NMEM) {
					struct km_hk_memwin *mw = &h->mem[h->nmem];
					const char *q = e2;

					mw->len = len;
					mw->kind = 0;
					mw->off = 0;
					if (*q == '[') {
						q++;
						if (q[0] == 's' && q[1] == 'p') {
							mw->kind = 2;
							q += 2;
						} else if (q[0] == 'x') {
							unsigned int r = 0;

							q++;
							if (!kstrtouint(q, 10, &r)) {
								mw->kind = 1;
								mw->reg = (u8)r;
								while (*q && *q != ']' &&
								       *q != '+' && *q != '-')
									q++;
							}
						}
						if (*q == '+' || *q == '-') {
							int sgn = (*q == '-') ? -1 : 1;
							unsigned int ov = 0;

							q++;
							if (!kstrtouint(q, 16, &ov))
								mw->off = sgn * (int)ov;
						}
					} else {
						u64 a = 0;

						if (!kstrtoull(q, 16, &a)) {
							mw->kind = 0;
							mw->off = 0;
							/* 绝对地址窗口：把地址塞进 reg 字段不可能，
							 * 用 kind=3 表示"不依赖 sp/gpr" */
							mw->kind = 3;
							mw->reg = 0;
							mw->off = 0;
						}
					}
					h->nmem++;
				}
			}
		}
		if (*opts == ' ')
			opts++;
	}

	if (!km_hk_ring) {
		km_hk_ring = vzalloc(sizeof(struct km_hk_evt) * KM_HK_RING);
		if (!km_hk_ring) {
			h->used = false;
			mutex_unlock(&km_hk_mtx);
			return -ENOMEM;
		}
	}

	rc = km_hk_install(h, (pid_t)pid);
	if (rc) {
		h->used = false;
		mutex_unlock(&km_hk_mtx);
		return rc;
	}
	mutex_unlock(&km_hk_mtx);
	return 0;
}

static long km_hk_del(const char *name)
{
	int i;

	mutex_lock(&km_hk_mtx);
	for (i = 0; i < KM_HK_MAX; i++) {
		struct km_hk *h = &km_hk[i];

		if (!h->used)
			continue;
		if (name && *name && strcmp(h->name, name))
			continue;
		km_hk_uninstall(h);
		memset(h, 0, sizeof(*h));
	}
	if (!name || !*name) {
		km_hk_head = km_hk_tail = km_hk_seq = 0;
		if (km_hk_ring)
			memset(km_hk_ring, 0,
			       sizeof(struct km_hk_evt) * KM_HK_RING);
	}
	mutex_unlock(&km_hk_mtx);
	return 0;
}

static long km_hk_show(char *out, size_t outmax)
{
	int i, n = 0, cnt = 0;
	u64 th = 0, td = 0, te = 0;

	n += scnprintf(out + n, outmax - n,
		       "name             expr                       va                 en hits drops errs\n");
	for (i = 0; i < KM_HK_MAX; i++) {
		struct km_hk *h = &km_hk[i];
		u64 hits, drops, errs;

		if (!h->used)
			continue;
		hits = (u64)atomic64_read(&h->hits);
		drops = (u64)atomic64_read(&h->drops);
		errs = (u64)atomic64_read(&h->errs);
		th += hits;
		td += drops;
		te += errs;
		cnt++;
		n += scnprintf(out + n, outmax - n,
			       "%-16s %-26s 0x%016llx %d %llu %llu %llu\n",
			       h->name, h->expr, h->va, h->enabled ? 1 : 0,
			       hits, drops, errs);
		if (n >= outmax - 64)
			break;
	}
	n += scnprintf(out + n, outmax - n,
		       "total %d probe(s) max=%d hits=%llu drops=%llu errs=%llu\n",
		       cnt, KM_HK_MAX, th, td, te);
	return 0;
}

static long km_hk_events(const char *name, unsigned int want,
			 char *out, size_t outmax)
{
	unsigned int got = 0;
	int n = 0;

	if (!km_hk_ring) {
		n += scnprintf(out + n, outmax - n,
			       "hkev: 0 events (no ring; run hkadd first)\n");
		return 0;
	}

	while (km_hk_tail != km_hk_head && got < want) {
		struct km_hk_evt *e = &km_hk_ring[km_hk_tail % KM_HK_RING];
		int k;

		if (!e->done) {			/* 还没补读，等下一轮 */
			break;
		}
		if (name && *name) {
			/* 事件里不存名字，按命中 VA 反查 */
			int found = 0;

			for (k = 0; k < KM_HK_MAX; k++)
				if (km_hk[k].used && !strcmp(km_hk[k].name, name) &&
				    km_hk[k].va == e->pc)
					found = 1;
			if (!found) {
				km_hk_tail++;
				continue;
			}
		}

		n += scnprintf(out + n, outmax - n,
			       "HK %u 0x%016llx %u %u", e->seq, e->pc, e->tid,
			       0);
		for (k = 0; k < 9; k++) {
			if (n >= outmax - 96)
				break;
			n += scnprintf(out + n, outmax - n, " %llx",
				       e->gpr[k]);
		}
		for (k = 0; k < KM_HK_NMEM; k++) {
			u32 j;

			if (!e->mem[k].len)
				continue;
			n += scnprintf(out + n, outmax - n, " %s=",
				       e->mem[k].ok ? "mem=ok" : "mem=deferred");
			for (j = 0; j < e->mem[k].len && j < 64; j++)
				n += scnprintf(out + n, outmax - n, "%02x",
					       e->mem[k].data[j]);
			if (n >= outmax - 64)
				break;
		}
		n += scnprintf(out + n, outmax - n, "\n");
		km_hk_tail++;
		got++;
		if (n >= outmax - 128)
			break;
	}

	if (got == 0) {
		n += scnprintf(out + n, outmax - n,
			       "hkev: 0 events (ring empty; pending=%u)\n",
			       km_hk_head - km_hk_tail);
	}
	return 0;
}
