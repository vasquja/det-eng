/*
 * userfaultfd heap-grooming — behavioral telemetry generator.
 *
 * Emits the rare syscall `userfaultfd(2)` plus the UFFDIO_REGISTER ioctl.
 * userfaultfd lets userspace pause the kernel mid-copy; it is a common
 * timing primitive in use-after-free and heap-spray privilege-escalation
 * exploits. This program creates a userfaultfd, registers one anonymous
 * page, then STOPS — it never faults the page, never starts a handler that
 * races a kernel copy, and unregisters before exit.
 *
 * Not a working exploit. For detection validation only. Safe to run.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>

#ifndef __NR_userfaultfd
#define __NR_userfaultfd 323
#endif

int main(void)
{
    int uffd = (int)syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd < 0) {
        fprintf(stderr,
                "[userfaultfd-behavioral] userfaultfd(): %s (may be disabled "
                "via vm.unprivileged_userfaultfd). The syscall attempt is "
                "still emitted as telemetry.\n",
                strerror(errno));
        return 0;
    }

    struct uffdio_api api;
    memset(&api, 0, sizeof(api));
    api.api = UFFD_API;
    if (ioctl(uffd, UFFDIO_API, &api) < 0) {
        fprintf(stderr, "ioctl(UFFDIO_API): %s\n", strerror(errno));
        close(uffd);
        return 0;
    }

    size_t len = (size_t)sysconf(_SC_PAGESIZE);
    void *region = mmap(NULL, len, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        close(uffd);
        return 0;
    }

    struct uffdio_register reg;
    memset(&reg, 0, sizeof(reg));
    reg.range.start = (uint64_t)(uintptr_t)region;
    reg.range.len = len;
    reg.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &reg) < 0)
        fprintf(stderr, "ioctl(UFFDIO_REGISTER): %s\n", strerror(errno));

    /* STOP: no fault is ever triggered and no race is run. */
    ioctl(uffd, UFFDIO_UNREGISTER, &reg.range);
    munmap(region, len);
    close(uffd);
    fprintf(stderr,
            "[userfaultfd-behavioral] userfaultfd created + page registered; "
            "stopped before any fault/race. Safe.\n");
    return 0;
}
