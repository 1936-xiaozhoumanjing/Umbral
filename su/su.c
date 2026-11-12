/* 影核 su —— 真 ELF 二进制 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

static int umbral_escape(void)
{
    /*
     * escape 节点在改名后是 /proc/umbral/escape；
     * 旧内核（v124 及以前）还在 /proc/sk/escape。
     * 两个都试，谁存在用谁 —— 这样 su 二进制对新旧内核都兼容。
     */
    static const char *paths[] = { "/proc/umbral/escape", "/proc/sk/escape", NULL };
    int i;

    for (i = 0; paths[i]; i++) {
        int fd = open(paths[i], O_WRONLY);
        if (fd < 0)
            continue;
        if (write(fd, "1", 1) < 0) {
            int e = errno;
            close(fd);
            return -e;
        }
        close(fd);
        return (int)getuid();
    }
    return -2;   /* 两个都不存在 */
}

/* 读 /proc/self/attr/current 看当前域 */
static void show_context(void)
{
    char b[128];
    int fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd < 0) { dprintf(2, "umbral-su: 读不到 attr/current\n"); return; }
    int n = (int)read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n > 0) { b[n] = 0; dprintf(1, "context=%s", b); }
}

/*
 * 内核没切成域时，自己 setcon 兜底。
 * 已是 uid 0 + CAP_MAC_ADMIN 时，写 attr/current 常常能成功。
 */
static void try_setcon(void)
{
    static const char *cands[] = {
        "u:r:su:s0", "u:r:ksu:s0", "u:r:magisk:s0",
        "u:r:supersu:s0", "u:r:sukisu:s0", "u:r:shell:s0", NULL
    };
    int i;

    for (i = 0; cands[i]; i++) {
        int fd = open("/proc/self/attr/current", O_WRONLY);
        if (fd < 0) {
            dprintf(2, "umbral-su: attr/current 不可写 errno=%d\n", errno);
            return;
        }
        ssize_t r = write(fd, cands[i], strlen(cands[i]) + 1);
        close(fd);
        if (r > 0) {
            dprintf(2, "umbral-su: setcon 成功 -> %s\n", cands[i]);
            return;
        }
    }
    dprintf(2, "umbral-su: setcon 全部候选失败（内核域切换也没生效）\n");
}

int main(int argc, char **argv)
{
    if (getuid() != 0) {
        int r = umbral_escape();
        if (getuid() != 0)
            dprintf(2, "umbral-su: escape 失败 r=%d uid=%d\n", r, (int)getuid());
    }
    if (getuid() == 0)
        try_setcon();

    {
        const char *shell = "/system/bin/sh";
        const char *cmd = NULL;
        int login = 0;
        int i;

        /*
         * 支持：-c CMD / -s SHELL / -t|-tt / -l|- / -- 终止符
         * 不实现 -v / --version：版本串是经典 root 检测点，故意不提供。
         */
        for (i = 1; i < argc; i++) {
            if (argv[i][0] != '-' || !argv[i][1])
                break;
            if (!strcmp(argv[i], "--")) { i++; break; }
            if (!strcmp(argv[i], "-c")) {
                if (i + 1 >= argc) { dprintf(2, "su: -c needs arg\n"); return 2; }
                cmd = argv[i + 1];
                i++;
                break;
            }
            if (!strcmp(argv[i], "-s")) {
                if (i + 1 >= argc) { dprintf(2, "su: -s needs arg\n"); return 2; }
                shell = argv[i + 1];
                i++;
                continue;
            }
            if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "-"))
                login = 1;
            /* -t/-tt 与其他未知选项：忽略 */
        }

        setenv("PATH",
               "/sbin:/system/sbin:/system/bin:/system/xbin:/odm/bin:/vendor/bin",
               1);
        setenv("HOME", "/", 1);
        setenv("USER", "root", 1);
        setenv("LOGNAME", "root", 1);
        setenv("SHELL", shell, 1);
        unsetenv("LD_PRELOAD");
        unsetenv("LD_LIBRARY_PATH");

        if (cmd) {
            execl(shell, shell, "-c", cmd, (char *)NULL);
            execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
            _exit(127);
        }
        if (i < argc) {
            execv(argv[i], &argv[i]);
            _exit(127);
        }
        if (login) {
            execl(shell, shell, "-l", (char *)NULL);
            execl("/system/bin/sh", "sh", (char *)NULL);
            _exit(127);
        }
        execl(shell, shell, (char *)NULL);
        execl("/system/bin/sh", "sh", (char *)NULL);
        _exit(127);
    }
}
