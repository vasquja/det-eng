/*
 * io_uring syscall-bypass — behavioral telemetry generator.
 *
 * Emits `io_uring_setup(2)` and a zero-submission `io_uring_enter(2)`.
 * io_uring lets a process perform file and network I/O through a shared ring
 * instead of the classic read()/write()/openat() syscalls, which is a known
 * blind spot for syscall-hooking sensors. This program only creates a ring
 * and issues an enter with zero submissions — no file is opened, read, or
 * written. The point is to let a team measure whether its tooling sees
 * io_uring at all.
 *
 * Not a working exploit. For detection validation only. Safe to run.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif

int main(void)
{
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));

    int fd = (int)syscall(__NR_io_uring_setup, 8, &p);
    if (fd < 0) {
        fprintf(stderr,
                "[io_uring-behavioral] io_uring_setup(): %s (may be disabled "
                "via kernel.io_uring_disabled). The syscall attempt is still "
                "emitted as telemetry.\n",
                strerror(errno));
        return 0;
    }

    /* Zero-submission enter: exercises io_uring_enter with no I/O queued. */
    (void)syscall(__NR_io_uring_enter, fd, 0, 0, 0, NULL, (size_t)0);

    close(fd);
    fprintf(stderr,
            "[io_uring-behavioral] io_uring_setup + zero-op io_uring_enter "
            "emitted; no file I/O performed. Safe.\n");
    return 0;
}
