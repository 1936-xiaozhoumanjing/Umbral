/*
 * umbrald —— 常驻 root 守护进程（对标 KernelSU 的 ksud）
 *
 * 由我们自己的 init（PID 1、root、u:r:init:s0）在开机时 fork 出来，
 * 所以它一出生就是 root，不需要任何提权动作。
 *
 * 协议（文件队列，简单可靠、好排查）：
 *   <dir>/cmd    App 写命令（原子替换写入）
 *   <dir>/out    守护写输出
 *   <dir>/ack    守护写完输出后 touch
 *   <dir>/pid    自己的 pid
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/prctl.h>

#define DIR   "/data/local/tmp/umbral/daemon"
#define CMD   DIR "/cmd"
#define OUT   DIR "/out"
#define ACK   DIR "/ack"
#define PIDF  DIR "/pid"

static void write_file(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        size_t n = strlen(s);
        ssize_t r = write(fd, s, n);
        (void)r;
        close(fd);
    }
}


/*
 * ══════════════════ 判定点⑥ 的替代路径 B：全局属性伪装 ══════════════════
 *
 * 为什么不在内核做：getprop 走 /dev/__properties__ 的 mmap，
 * 之后是纯用户态内存读，**不发系统调用** —— 内核钩不到。
 *
 * 这里用最朴素的办法：root 身份调 setprop，真改属性。
 * 好处：所有进程看到的值一致，不会被"两个进程对比"发现不一致。
 * 代价：重启后恢复（本函数每次开机都会重新执行一遍）。
 *
 * 配置格式（/data/adb/umbral/fake_props.conf）：
 *     ro.product.model=NX769J
 *     ro.product.brand=nubia
 *     # 注释行与空行跳过
 */
static void apply_fake_props(void)
{
    FILE *fp;
    char line[512];
    int done = 0;

    fp = fopen("/data/adb/umbral/fake_props.conf", "r");
    if (!fp)
        return;

    while (fgets(line, sizeof(line), fp)) {
        char *eq;
        char *nl;

        /* 去行尾换行 */
        nl = strchr(line, '\n');
        if (nl)
            *nl = 0;
        if (line[0] == '#' || line[0] == 0)
            continue;
        eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = 0;

        /*
         * 用 setprop 子进程而不是 __system_property_set：
         *   静态链接下直接调 libc 的 property API 在部分机型上
         *   会因为 selinux 上下文不对而静默失败；
         *   走 /system/bin/setprop 至少失败会打日志。
         */
        {
            pid_t pid = fork();

            if (pid == 0) {
                execl("/system/bin/setprop", "setprop", line, eq + 1,
                      (char *)NULL);
                _exit(127);
            } else if (pid > 0) {
                int st = 0;

                waitpid(pid, &st, 0);
                if (WIFEXITED(st) && WEXITSTATUS(st) == 0)
                    done++;
            }
        }
    }
    fclose(fp);
    fprintf(stderr, "umbrald: fake_props 已应用 %d 条\n", done);
}

int main(int argc, char **argv)
{
    char buf[8192];
    int fd, n;

    mkdir("/data/local/tmp", 0771);
    mkdir("/data/local/tmp/umbral", 0770);
    mkdir(DIR, 0770);

    /*
     * ★ 进程名伪装（H3：进程与身份暴露点）★
     * ps 里看到 "umbrald" 一眼就知道是什么，改成内核工作线程风格的名字。
     * 同时把 argv[0] 也覆写掉 —— /proc/pid/cmdline 读的是用户栈那块内存。
     */
    apply_fake_props();

    prctl(PR_SET_NAME, "kworker/u16:2", 0, 0, 0);
    if (argc > 0 && argv && argv[0]) {
        /* 覆写 cmdline：长度不超过原字符串 */
        size_t l = strlen(argv[0]);
        const char *fake = "[kworker/u16:2]";
        size_t fl = strlen(fake);
        if (fl <= l) {
            memcpy(argv[0], fake, fl);
            argv[0][fl] = 0;
        }
    }
    {
        extern char **environ;
        (void)environ;
    }

    snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
    write_file(PIDF, buf);

    /* 开机自检：把身份写进 out，方便确认它是 root */
    {
        int f = open(OUT, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (f >= 0) {
            int m = snprintf(buf, sizeof(buf),
                             "umbrald pid=%d uid=%d euid=%d\n",
                             (int)getpid(), (int)getuid(), (int)geteuid());
            ssize_t r = write(f, buf, m);
            (void)r;
            close(f);
        }
    }

    for (;;) {
        fd = open(CMD, O_RDONLY);
        if (fd < 0) {
            usleep(50000);
            continue;
        }
        n = (int)read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) {
            usleep(50000);
            continue;
        }
        buf[n] = 0;
        unlink(CMD);

        /* 用 sh -c 执行，输出重定向到 out */
        {
            pid_t p = fork();
            if (p == 0) {
                int o = open(OUT, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (o >= 0) {
                    dup2(o, 1);
                    dup2(o, 2);
                    close(o);
                }
                execl("/system/bin/sh", "sh", "-c", buf, (char *)NULL);
                _exit(127);
            } else if (p > 0) {
                int st = 0;
                waitpid(p, &st, 0);
                write_file(ACK, "done\n");
            }
        }
    }
    return 0;
}