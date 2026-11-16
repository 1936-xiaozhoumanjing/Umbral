// sk_init - SK-Root 的 ramdisk init 包装器
// 参照 KernelSU 的 ksuinit 实现（userspace/ksuinit/src/init.rs）
//
// 流程：
//   1. 打开 /dev/kmsg
//   2. 挂载 /proc
//   3. 加载 /umbral.ko
//   4. unlink /init，symlink /init -> 下游 init
//   5. execve("/init")  ← argv[0] 仍是 /init
//
// 编译：aarch64-linux-gnu-gcc -static -Os -s -o sk_init sk_init.c

#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define KMSG_PATH "/dev/kmsg"

static int g_kmsg_fd = -1;

static void klog_init(void) {
    g_kmsg_fd = open(KMSG_PATH, O_WRONLY);
    if (g_kmsg_fd < 0) {
        // /dev 可能还没挂，试 /kmsg
        g_kmsg_fd = open("/kmsg", O_WRONLY);
    }
}

static void klog(const char *msg) {
    if (g_kmsg_fd < 0) return;
    ssize_t r = write(g_kmsg_fd, msg, strlen(msg));
    (void)r;
}

// 挂载文件系统（幂等）
static int ensure_mount(const char *src, const char *target, const char *fstype) {
    mkdir(target, 0755);            // 忽略 EEXIST
    if (mount(src, target, fstype, 0, NULL) == 0) {
        return 0;
    }
    // 已经挂载过会返回 EBUSY
    return (errno == EBUSY) ? 0 : -1;
}

// 用 init_module syscall 加载 .ko
static int load_module(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        char b[128];
        snprintf(b, sizeof(b), "SK-Root: cannot open %s (errno=%d)\n", path, errno);
        klog(b);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }

    size_t sz = (size_t)st.st_size;
    void *buf = malloc(sz);
    if (!buf) { close(fd); return -1; }

    ssize_t n = read(fd, buf, sz);
    close(fd);
    if (n < 0 || (size_t)n != sz) { free(buf); return -1; }

    long ret = syscall(SYS_init_module, buf, sz, "");
    free(buf);

    if (ret < 0) {
        char b[160];
        snprintf(b, sizeof(b), "SK-Root: init_module failed (errno=%d)\n", errno);
        klog(b);
        return -1;
    }

    klog("Umbral: sk_root.ko loaded OK\n");
    return 0;
}

// 把 /init 换成指向下游 init 的符号链接（KSU 的做法）
static void replace_init(void) {
    // 找下游 init
    const char *next = NULL;
    if (access("/init.ksu", F_OK) == 0) {
        next = "/init.ksu";
    } else if (access("/init.real", F_OK) == 0) {
        next = "/init.real";
    } else {
        klog("SK-Root: no downstream init found\n");
        return;
    }

    // 删掉自己（正在运行的可执行文件，inode 还在，安全）
    if (unlink("/init") != 0) {
        char b[96];
        snprintf(b, sizeof(b), "SK-Root: unlink /init failed (errno=%d)\n", errno);
        klog(b);
    }

    // 建符号链接
    if (symlink(next, "/init") != 0) {
        char b[128];
        snprintf(b, sizeof(b), "SK-Root: symlink failed (errno=%d)\n", errno);
        klog(b);
    } else {
        char b[160];
        snprintf(b, sizeof(b), "SK-Root: /init -> %s\n", next);
        klog(b);
    }
}

int main(int argc, char **argv, char **envp) {
    klog_init();
    klog("SK-Root: init wrapper starting\n");

    // 1. 挂载 /proc（KSU 第一件事也做这个）
    if (ensure_mount("proc", "/proc", "proc") != 0) {
        char b[96];
        snprintf(b, sizeof(b), "SK-Root: mount /proc failed (errno=%d)\n", errno);
        klog(b);
    }

    // 2. 挂载 /sys（部分内核功能需要）
    ensure_mount("sysfs", "/sys", "sysfs");

    // 3. 加载我们的模块（失败不阻塞启动）
    load_module("/umbral.ko");
    /* propfix：隐藏 Bootloader 解锁状态（改 cmdline + 属性区，值保留到重启）
     *  存在才加载：未勾选高级选项时 ramdisk 里没有这个文件
     *  加载失败不影响主流程 */
    load_module("/propfix.ko");

    // 4. 把 /init 换成符号链接
    replace_init();

    // 5. exec /init（现在它是符号链接，跟到下游 init）
    execve("/init", argv, envp);

    // 兜底
    klog("SK-Root: FATAL - execve /init failed\n");
    return 1;
}
