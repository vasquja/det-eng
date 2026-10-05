/*
 * setns host-namespace join — behavioral telemetry generator.
 *
 * Emits open("/proc/<pid>/ns/mnt") followed by `setns(2)` — the syscall
 * pattern of a container-escape primitive. The default target is pid 1,
 * whose mount namespace is the container init's (inside a container) or the
 * one this process already belongs to (on a bare host); either way joining
 * it crosses no privilege boundary. Without CAP_SYS_ADMIN the setns() call
 * returns EPERM, and the attempt itself is the telemetry this test produces.
 *
 * Not a working exploit. For detection validation only. Safe to run.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *pid = (argc > 1) ? argv[1] : "1";
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/ns/mnt", pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr,
                "[setns-behavioral] open(%s): %s. The open attempt is still "
                "emitted as telemetry.\n",
                path, strerror(errno));
        return 0;
    }

    if (setns(fd, 0) < 0) {
        fprintf(stderr,
                "[setns-behavioral] setns(): %s (EPERM expected without "
                "CAP_SYS_ADMIN). The syscall attempt is still emitted as "
                "telemetry.\n",
                strerror(errno));
        close(fd);
        return 0;
    }

    close(fd);
    fprintf(stderr,
            "[setns-behavioral] open(/proc/%s/ns/mnt) + setns() emitted; "
            "joined namespace crosses no privilege boundary. Safe.\n",
            pid);
    return 0;
}
