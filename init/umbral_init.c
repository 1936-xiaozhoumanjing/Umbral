// sk_init - SK-Root 的 ramdisk init 包装器（全量日志版）
//
// 设计原则：
//   1. 每一步都打日志，崩在哪一眼能看出
//   2. 所有失败路径都不退出（PID 1 退出 = 内核 panic）
//   3. 日志前缀统一 [SK]，便于 grep 和过滤
//   4. 记录 errno 及其含义，不只是数字
//
// 日志去向：/dev/kmsg（内核环形缓冲），QEMU/串口能直接看到
//
// 编译：aarch64-linux-gnu-gcc -static -Os -s -o sk_init sk_init.c

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/sysmacros.h>

#define TAG "[SK] "

/* ── 掉电保留日志（写 misc 分区）───────────────────────────────
 *
 * 为什么需要：卡 logo 时 adb 起不来、pstore 要 root、misc 的 bootloader_message
 * 不记录我们的崩溃。唯一能拿到「真机到底卡在哪一行」的办法，就是自己往一个
 * 掉电保留、且事后能读出来的地方写日志。
 *
 * misc 分区实测：1MB，bootloader_message 只用前 2KB，0x8000 之后全是 0。
 * 本设备 misc = /dev/block/sda3，块设备号 8:3。
 *
 * 事后怎么读：
 *   卡 logo → 进 9008 → edl.py r misc misc.img --lun=0
 *   在偏移 0x8000 处搜 "===SKLOG-BEGIN==="
 */
#define MISC_LOG_OFF  0x40000     /* 256KB：实测 0x8000 有厂商数据，前移避开 */
#define MISC_LOG_MAX  0x4000      /* 最多写 16KB，写满就停，不覆盖状态区 */

/* ══════════════════ 日志 ══════════════════ */

static int g_fd = -1;
static int g_index = 0;

/* 掉电保留日志的句柄和写指针 */
static int   g_misc_fd  = -1;
static off_t g_misc_pos = 0;

/* 前向声明：buf_flush 在上面就要用到这两个 */
static void misc_log_open(void);
static void L(const char *fmt, ...);

/* 内存缓冲：早期 UFS 块设备可能还没就绪，所以先把日志攒在内存里，
 * 到 execve 之前再一次性刷进 misc。这样只需要 open 成功一次。 */
#define LOG_BUF_MAX 16384
#define LOGOUT_MAX  24576   /* 头 + 缓冲 + 补齐余量 */
static char   g_buf[LOG_BUF_MAX];
static size_t g_buf_len = 0;

static void buf_append(const char *s, size_t n) {
    if (g_buf_len + n > LOG_BUF_MAX) return;
    memcpy(g_buf + g_buf_len, s, n);
    g_buf_len += n;
}

/* 把缓冲整体刷进 misc。
 *
 * 关键：块设备写入要按扇区对齐。头 "===SKLOG-BEGIN===" 只占 18 字节，
 * 单独 pwrite 18 字节大概率被丢弃或直接报错。所以把「头 + 全部日志」
 * 拼成一整块、补齐到 4096 的整数倍，一次 pwrite 出去。
 * 偏移 0x40000 本身是 4096 对齐的。
 *
 * 任何一步失败都静默放弃 —— 日志绝不能影响启动。
 */
static void buf_flush(void) {
    if (g_buf_len == 0) return;

    if (g_misc_fd < 0) misc_log_open();
    if (g_misc_fd < 0) return;

    static char out[LOGOUT_MAX];
    static const char HDR[] = "===SKLOG-BEGIN===\n";
    const size_t hl = sizeof(HDR) - 1;

    size_t n = 0;
    memcpy(out, HDR, hl); n += hl;

    size_t body = g_buf_len;
    if (body > LOG_BUF_MAX) body = LOG_BUF_MAX;
    memcpy(out + n, g_buf, body); n += body;

    size_t padded = (n + 4095) & ~(size_t)4095;
    if (padded > LOGOUT_MAX) return;
    memset(out + n, 0, padded - n);

    errno = 0;
    ssize_t w = pwrite(g_misc_fd, out, padded, (off_t)MISC_LOG_OFF);
    if (w == (ssize_t)padded) {
        /* 关键：块设备是 buffered write，不 fsync 数据只停在页缓存。
         * 系统一旦卡死/重启，页缓存全丢 —— 这就是真机上 pwrite 返回成功
         * 但 misc 一字节没变的原因。 */
        int fs = fsync(g_misc_fd);
        int efs = errno;
        L("misc log: wrote %zu bytes (payload %zu) at 0x%x\n",
          padded, n, (unsigned)MISC_LOG_OFF);
        L("misc log: fsync=%d errno=%d (%s)\n", fs, efs, strerror(efs));
    } else {
        L("misc log: write FAILED w=%zd need=%zu errno=%d (%s)\n",
          w, padded, errno, strerror(errno));
    }
}

/* 打开 misc 分区用于追加日志。
 *
 * 注意：initramfs 阶段 /dev 是 tmpfs，只有 ramdisk 里静态带的几个节点，
 * 没有 /dev/block/by-name/ 这些由 ueventd 建立的符号链接。所以要三级回退：
 *   ① 如果 devtmpfs 已经挂了或链接已存在 → 直接用
 *   ② /dev/sda3（本设备 misc 的裸节点，如果 devtmpfs 挂了会有）
 *   ③ 自己 mknod —— 本设备 misc = 主设备号 8, 次设备号 3
 */
/* 从 /proc/partitions 里挑出大小为 1024 个 512B 块（=1MB）的块设备，
 * 用它的 major:minor 自己造节点。返回 0 表示造好并打开成功。
 *
 * 为什么这么做：misc 在真机上是 UFS 的 /dev/sda3（8:3），在 QEMU 里是
 * virtio-blk 的 vda，设备号完全不同。硬编码 8:3 只会两边都不通用。
 */
static int try_open_by_size(int want_kb_x1000)
{
    int fd = open("/proc/partitions", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    char b[4096];
    ssize_t n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return -1;
    b[n] = 0;

    /* 逐行解析: "major minor #blocks name" */
    char *save = NULL;
    for (char *line = strtok_r(b, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        int maj = -1, min = -1;
        long blocks = -1;
        char name[64];
        name[0] = 0;
        if (sscanf(line, " %d %d %ld %63s", &maj, &min, &blocks, name) != 4)
            continue;
        if (maj < 0 || min < 0 || blocks <= 0) continue;

        /* #blocks 单位是 1KB（内核的 blocks 就是 KB） */
        if (blocks * 1000 < want_kb_x1000 - 50000) continue;
        if (blocks * 1000 > want_kb_x1000 + 50000) continue;

        L("partitions: candidate %s %d:%d %ldKB\n", name, maj, min, blocks);

        char node[64];
        snprintf(node, sizeof(node), "/dev/sk_%d_%d", maj, min);
        unlink(node);
        if (mknod(node, S_IFBLK | 0600, makedev(maj, min)) != 0) {
            L("  mknod(%s) failed errno=%d\n", node, errno);
            continue;
        }
        g_misc_fd = open(node, O_WRONLY | O_CLOEXEC);
        if (g_misc_fd >= 0) {
            L("  opened %s as %d:%d\n", node, maj, min);
            return 0;
        }
        L("  open(%s) errno=%d (%s)\n", node, errno, strerror(errno));
    }
    return -1;
}

static int misc_try_open(void) {
    g_misc_fd = -1;

    /* 1) 标准符号链接（devtmpfs + ueventd 就绪时） */
    g_misc_fd = open("/dev/block/by-name/misc", O_WRONLY | O_CLOEXEC);
    if (g_misc_fd >= 0) return 0;

    /* 2) 裸节点名 */
    g_misc_fd = open("/dev/sda3", O_WRONLY | O_CLOEXEC);
    if (g_misc_fd >= 0) return 0;

    /* 3) 硬编码 8:3（本设备 UFS misc） */
    unlink("/dev/sk_hard");
    if (mknod("/dev/sk_hard", S_IFBLK | 0600, makedev(8, 3)) == 0) {
        g_misc_fd = open("/dev/sk_hard", O_WRONLY | O_CLOEXEC);
        if (g_misc_fd >= 0) return 0;
    }

    /* 4) 按大小自动找 1MB 的块设备（QEMU virtio / 其他机型） */
    if (try_open_by_size(1024 * 1000) == 0) return 0;

    return -1;
}

/* 等 misc 就绪：UFS 块设备 probe 可能比 init 慢好几百毫秒。
 * 最多等 3 秒，每 100ms 试一次。 */
static void misc_log_open(void) {
    static int tried = 0;
    for (int i = 0; i < 30; i++) {
        if (misc_try_open() == 0) {
            L("misc opened (attempt %d, ~%d ms)\n", i + 1, i * 100);
            return;
        }
        usleep(100000);
    }
    if (!tried) { tried = 1; L("misc: not ready after 3s\n"); }
}

/* 把 /proc/partitions 的前几十行打进日志，用于事后判断块设备到底有没有就绪 */
static void dump_partitions(void) {
    int fd = open("/proc/partitions", O_RDONLY);
    if (fd < 0) { L("dump_partitions: open failed errno=%d\n", errno); return; }
    char b[1024];
    ssize_t n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) { L("dump_partitions: read failed errno=%d\n", errno); return; }
    b[n] = 0;
    L("---- /proc/partitions ----\n%s---- end ----\n", b);
}



static void klog_open(void) {
    g_fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (g_fd < 0) {
        int e1 = errno;
        g_fd = open("/kmsg", O_WRONLY | O_CLOEXEC);
        if (g_fd < 0) {
            /* 两个都失败：退回 stderr（串口可能能看到） */
            dprintf(2, TAG "klog: /dev/kmsg(%d) and /kmsg(%d) both failed\n", e1, errno);
            g_fd = 2;
            return;
        }
        dprintf(g_fd, TAG "klog: using /kmsg (fd=%d), /dev/kmsg errno=%d\n", g_fd, e1);
        return;
    }
    dprintf(g_fd, TAG "klog: /dev/kmsg opened (fd=%d)\n", g_fd);
}

/* 全局日志：自动编号，同时写 kmsg 和 stderr（串口）
 *
 * 双写的原因：/dev/kmsg 在大批量写入时可能被丢弃（缓冲/速率限制），
 * 而 initramfs 阶段的 stderr 直接连串口，最可靠。
 * 任何一路写失败都会在另一路留痕。
 */
static void L(const char *fmt, ...) {
    char body[400];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    char buf[480];
    int n = snprintf(buf, sizeof(buf), TAG "%02d|%s", ++g_index, body);
    if (n <= 0 || n >= (int)sizeof(buf)) return;

    /* 路 1：kmsg */
    if (g_fd >= 0) {
        ssize_t w = write(g_fd, buf, n);
        if (w != n) {
            static int warned = 0;
            if (!warned) {
                warned = 1;
                dprintf(2, TAG "!! kmsg write failed (w=%zd n=%d errno=%d)\n",
                        w, n, errno);
            }
        }
    }

    /* 路 2：stderr（串口） */
    ssize_t w2 = write(2, buf, n);
    (void)w2;

    /* 路 3：攒进内存缓冲，execve 前统一刷进 misc
     * （早期块设备可能没就绪，不能在这里直接写盘） */
    buf_append(buf, (size_t)n);
}

/* 带 errno 的日志 */
static void LE(const char *what, long ret) {
    int e = errno;
    L("%s => ret=%ld errno=%d (%s)\n", what, ret, e, strerror(e));
}

static void SEP(const char *title) {
    L("-------- %s --------\n", title);
}

/* ══════════════════ 工具 ══════════════════ */

static int ensure_mount(const char *src, const char *tgt, const char *type) {
    int mk = mkdir(tgt, 0755);
    L("mkdir(%s) = %d%s\n", tgt, mk, (mk < 0 && errno != EEXIST) ? " [FAIL]" : "");

    int e_mk = errno;
    errno = 0;
    int r = mount(src, tgt, type, 0, NULL);
    int e = errno;

    if (r == 0) {
        L("mount(%s -> %s, %s) = 0 [OK]\n", src, tgt, type);
        return 0;
    }
    if (e == EBUSY) {
        L("mount(%s -> %s) = EBUSY（已挂载，可接受）\n", src, tgt);
        return 0;
    }
    L("mount(%s -> %s, %s) = -1 errno=%d (%s) "
      "[mkdir 先前返回 %d errno=%d]\n",
      src, tgt, type, e, strerror(e), mk, e_mk);
    return -1;
}

/* 检查路径是否可访问，并报告类型/大小 */
static void probe(const char *path, const char *label) {
    struct stat st;
    if (stat(path, &st) != 0) {
        L("%s: %s 不存在 (errno=%d %s)\n", label, path, errno, strerror(errno));
        return;
    }
    const char *type = "?";
    if (S_ISREG(st.st_mode))  type = "普通文件";
    else if (S_ISDIR(st.st_mode)) type = "目录";
    else if (S_ISLNK(st.st_mode)) type = "符号链接";
    else if (S_ISCHR(st.st_mode)) type = "字符设备";
    else if (S_ISBLK(st.st_mode)) type = "块设备";

    L("%s: %s 存在  类型=%s size=%lld mode=%04o uid=%d gid=%d\n",
      label, path, type, (long long)st.st_size,
      (unsigned)(st.st_mode & 07777), (int)st.st_uid, (int)st.st_gid);
}

/* 读一个小文件的内容（用于确认挂载成功） */
static void peek(const char *path, int maxlen) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        L("peek(%s) 打开失败 errno=%d (%s)\n", path, errno, strerror(errno));
        return;
    }
    char buf[128];
    int n = read(fd, buf, maxlen < 127 ? maxlen : 127);
    close(fd);
    if (n <= 0) {
        L("peek(%s) 读失败 n=%d errno=%d\n", path, n, errno);
        return;
    }
    buf[n] = 0;
    /* 去掉换行 */
    for (int i = 0; i < n; i++) if (buf[i] == '\n') { buf[i] = 0; break; }
    L("peek(%s) = \"%s\"\n", path, buf);
}

/* 列目录前 N 项 */
static void list_dir(const char *path, int maxitems) {
    DIR *d = opendir(path);
    if (!d) {
        L("list_dir(%s) 打开失败 errno=%d (%s)\n", path, errno, strerror(errno));
        return;
    }
    struct dirent *de;
    int n = 0;
    char line[256] = {0};
    while ((de = readdir(d)) != NULL && n < maxitems) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        strncat(line, de->d_name, sizeof(line) - strlen(line) - 2);
        strncat(line, " ", sizeof(line) - strlen(line) - 2);
        n++;
    }
    closedir(d);
    L("list_dir(%s) [%d 项] %s\n", path, n, line);
}

/* ══════════════════ 模块加载 ══════════════════ */

static int load_module(const char *path) {
    SEP("load_module");

    struct stat st;
    if (stat(path, &st) != 0) {
        L("stat(%s) 失败 errno=%d (%s)\n", path, errno, strerror(errno));
        return -1;
    }
    L("模块文件 %s  size=%lld\n", path, (long long)st.st_size);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        L("open(%s) 失败 errno=%d (%s)\n", path, errno, strerror(errno));
        return -1;
    }
    L("open(%s) = %d\n", path, fd);

    /* 读前 4 字节验 ELF magic */
    unsigned char magic[4];
    int n = read(fd, magic, 4);
    if (n == 4) {
        L("ELF magic = %02x %02x %02x %02x %s\n",
          magic[0], magic[1], magic[2], magic[3],
          (magic[0]==0x7f && magic[1]=='E' && magic[2]=='L' && magic[3]=='F') ? "[OK]" : "[非 ELF!]");
    } else {
        L("读 magic 失败 n=%d\n", n);
    }
    lseek(fd, 0, SEEK_SET);

    /* 方案 A：finit_module（内核直接从 fd 读） */
    errno = 0;
    long r = syscall(SYS_finit_module, fd, "", 0);
    int e = errno;
    if (r == 0) {
        L("finit_module() = 0 [加载成功]\n");
        close(fd);
        return 0;
    }
    L("finit_module() = %ld errno=%d (%s)\n", r, e, strerror(e));

    /* 方案 B：init_module（读到内存再交） */
    lseek(fd, 0, SEEK_SET);
    size_t sz = (size_t)st.st_size;
    void *buf = malloc(sz);
    if (!buf) {
        L("malloc(%zu) 失败\n", sz);
        close(fd);
        return -1;
    }
    ssize_t got = read(fd, buf, sz);
    close(fd);
    if (got != (ssize_t)sz) {
        L("read() 短读 got=%zd 期望=%zu\n", got, sz);
        free(buf);
        return -1;
    }
    L("已读入 %zu 字节到 %p\n", sz, buf);

    errno = 0;
    r = syscall(SYS_init_module, buf, sz, "");
    e = errno;
    L("init_module() = %ld errno=%d (%s)\n", r, e, strerror(e));

    free(buf);

    if (r == 0) {
        L("模块加载成功（init_module）\n");
        return 0;
    }

    /* errno 解释 */
    if (e == ENOEXEC)
        L("  → ENOEXEC：内核拒绝，最常见原因是 __this_module section 大小"
          "或 vermagic 不匹配\n");
    else if (e == EPERM)
        L("  → EPERM：模块签名校验失败\n");
    else if (e == ENOENT)
        L("  → ENOENT：引用的符号找不到\n");
    else if (e == EINVAL)
        L("  → EINVAL：版本 CRC 不匹配\n");

    return -1;
}

/* ══════════════════ init 替换 ══════════════════ */

static const char *find_downstream(void) {
    SEP("find_downstream");

    // 顺序按「最可能是我们改名的原厂 first-stage init」排：
    //   init.skroot  = 自适应修补器的首选名（打补丁时按冲突情况选定）
    //   init.orig / init.original / init.bak / init.sk = 其他候选
    //   init.ksu     = KSU 方案遗留
    //   init.real    = ⚠ 最后才考虑：原厂 ramdisk 里本来就有它，
    //                  那是 Android 的 second-stage，不是我们要接的
    const char *cands[] = {
        "/init.skroot",
        "/init.orig",
        "/init.original",
        "/init.bak",
        "/init.sk",
        "/init.ksu",
        "/init.android",
        "/init.real",
    };

    for (int i = 0; i < (int)(sizeof(cands)/sizeof(cands[0])); i++) {
        struct stat st;
        if (stat(cands[i], &st) == 0) {
            L("找到下游 init: %s  size=%lld mode=%04o\n",
              cands[i], (long long)st.st_size, (unsigned)(st.st_mode & 07777));
            if (!(st.st_mode & S_IXUSR))
                L("  ⚠ 没有执行权限！execve 会失败\n");
            if (i >= 7)
                L("  ⚠ 用的是 init.real，它通常是原厂 second-stage，"
                  "如果系统起不来请确认改名目标\n");
            return cands[i];
        }
        L("%s 不存在 (errno=%d)\n", cands[i], errno);
    }
    L("❌ 没有找到任何下游 init\n");
    return NULL;
}

static int replace_init(const char *next) {
    SEP("replace_init");

    errno = 0;
    int r = unlink("/init");
    int e = errno;
    L("unlink(/init) = %d errno=%d (%s)\n", r, e, strerror(e));
    if (r != 0 && e != ENOENT) {
        L("⚠ unlink 失败，/init 仍然是我们自己\n");
    }

    errno = 0;
    r = symlink(next, "/init");
    e = errno;
    L("symlink(%s, /init) = %d errno=%d (%s)\n", next, r, e, strerror(e));
    if (r != 0) {
        L("❌ 符号链接失败！后续 execve 会找不到 /init\n");
        return -1;
    }

    /* 确认链接生效 */
    char target[256];
    ssize_t n = readlink("/init", target, sizeof(target) - 1);
    if (n > 0) {
        target[n] = 0;
        L("readlink(/init) = \"%s\" [OK]\n", target);
    } else {
        L("readlink(/init) 失败 errno=%d\n", errno);
    }

    return 0;
}

/* ══════════════════ main ══════════════════ */

/* ── 拉起常驻 root 守护进程（对标 KSU 的 ksud）──
 *
 * 我们是 PID 1、root、u:r:init:s0 —— 正是 ksud 需要的父进程。
 * 但此刻 /data 还没挂好，所以子进程先等文件出现再 exec。
 */
static void spawn_umbrald(void)
{
    pid_t p = fork();
    if (p < 0) {
        L("umbrald: fork 失败 errno=%d\n", errno);
        return;
    }
    if (p > 0)
        return;                       /* 父进程继续走 execve */

    setsid();
    {
        pid_t p2 = fork();
        if (p2 > 0)
            _exit(0);                 /* 中间进程退出，孙进程脱离 */
    }

    /* 等 /data 挂好、二进制就位（最多 60 秒） */
    {
        int i;
        for (i = 0; i < 600; i++) {
            if (access("/data/local/tmp/umbral/umbrald", X_OK) == 0)
                break;
            usleep(100000);
        }
    }
    execl("/data/local/tmp/umbral/umbrald", "umbrald", (char *)NULL);
    _exit(127);
}


int main(int argc, char **argv, char **envp) {
    klog_open();
    misc_log_open();   /* 必须在第一条 L() 之前，否则首行日志留不下来 */

    L("================================\n");
    L("sk_init v0.1 (full-log build)\n");
    L("================================\n");
    L("pid=%d ppid=%d uid=%d euid=%d gid=%d\n",
      getpid(), getppid(), getuid(), geteuid(), getgid());
    L("argc=%d\n", argc);
    for (int i = 0; i < argc && i < 8; i++)
        L("argv[%d] = \"%s\"\n", i, argv[i] ? argv[i] : "(null)");

    int envc = 0;
    if (envp) while (envp[envc]) envc++;
    L("envc=%d\n", envc);

    /* ── 环境侦察 ── */
    SEP("环境侦察");
    list_dir("/", 30);
    list_dir("/dev", 20);
    probe("/init", "自身");
    probe("/umbral.ko", "模块");
    probe("/sk_root.ko", "旧模块名");
    peek("/proc/version", 100);

    /* ── 挂载 ── */
    SEP("挂载");
    ensure_mount("proc", "/proc", "proc");
    peek("/proc/version", 100);
    ensure_mount("sysfs", "/sys", "sysfs");
    probe("/sys/kernel", "sysfs");

    /* ── 加载模块 ── */
    /* 优先加载 umbral.ko；不存在才退回旧名（兼容旧镜像布局） */
    int modret = load_module("/umbral.ko");
    if (modret != 0)
        modret = load_module("/sk_root.ko");
    L("模块加载结果: %d (%s)\n", modret, modret == 0 ? "成功" : "失败但不阻塞");

    /* ── 替换 init ── */
    const char *next = find_downstream();
    if (!next) {
        L("❌❌❌ 致命：找不到下游 init\n");
        L("进入永久 pause，等待人工介入\n");
        for (;;) pause();
    }
    replace_init(next);

    /* ── 恢复挂载现场（关键！）──
     *
     * 原厂 init 的 first stage 会自己挂载 /proc 和 /sys。
     * 我们前面为了探测先挂了一遍，如果不卸掉：
     *   原厂 init 的 mount("sysfs", "/sys", ...) 会返回 EINVAL
     *   → /sys 下没有 fs 子树
     *   → mkdir("/sys/fs/selinux") 失败
     *   → mount("selinuxfs", "/sys/fs/selinux", ...) 报 ENOENT
     *   → "Init encountered errors starting first stage, aborting"
     *   → PID 1 退出 → 内核 panic（真机上表现为卡 logo）
     *
     * QEMU 实测证据：
     *   base（不干预）    mount("sysfs") 报错次数 0
     *   pure（极简转发）  mount("sysfs") 报错次数 0
     *   full（预挂了）    mount("sysfs") 报错次数 1  ← 就这一行害的
     */
    /* 趁 /proc 还在，先把块设备现场拍下来 —— 这是判断 UFS 有没有就绪的关键证据 */
    dump_partitions();

    /* flush 必须在卸载 /proc 之前 —— try_open_by_size 要读 /proc/partitions */
    SEP("flush misc log");
    buf_flush();

    SEP("恢复挂载现场");
    errno = 0;
    int ur = umount("/sys");
    L("umount(/sys) = %d errno=%d (%s)\n", ur, errno, strerror(errno));
    errno = 0;
    ur = umount("/proc");
    L("umount(/proc) = %d errno=%d (%s)\n", ur, errno, strerror(errno));


    /* ── 关闭所有继承的 fd（关键！）──
     *
     * 不加这一步，我们打开的 /dev/kmsg、/dev/miscblk 等 fd 会被
     * 原厂 init 继承，再传给 zygote。zygote fork system_server 时会遍历
     * 所有 fd 并 readlink("/proc/self/fd/N") 取路径；而 /dev 后来被
     * ueventd 重建，那些 mknod 出来的节点已不存在 → readlink 失败 →
     * FileDescriptorInfo::CreateFromFd 空指针 → SIGSEGV。
     *
     * 实测证据（tombstone_30）：
     *   signal 11 SEGV_MAPERR fault addr 0x7a
     *   #00 GetOpenFdsIgnoring(...)
     *   #04 FileDescriptorInfo::CreateFromFd(...)
     *   #07 Zygote_nativeForkSystemServer(...)
     */
    SEP("close inherited fds");
    if (g_fd >= 0 && g_fd > 2) { close(g_fd); g_fd = -1; }
    if (g_misc_fd >= 0)       { close(g_misc_fd); g_misc_fd = -1; }
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3U, ~0U, 0U) != 0)
#endif
    {
        for (int f = 3; f < 1024; f++) close(f);
    }
    L("fd cleanup done\n");

    /* ── execve ── */
    SEP("execve");
    probe("/init", "即将执行");
    L("execve(\"/init\", argv, envp) ...\n");

    errno = 0;
    spawn_umbrald();
    execve("/init", argv, envp);
    int e = errno;
    L("❌❌❌ execve 返回了！errno=%d (%s)\n", e, strerror(e));
    L("不退出（退出会导致内核 panic），进入永久 pause\n");

    for (;;) pause();
    return 0;
}
