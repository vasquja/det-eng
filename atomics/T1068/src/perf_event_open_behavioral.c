/*
 * perf_event_open unusual-use — behavioral telemetry generator.
 *
 * Emits the `perf_event_open(2)` syscall from a non-profiler process.
 * perf_event_open has been a repeated local privilege-escalation surface
 * (e.g. CVE-2013-2094, perf_swevent). This program opens one benign software
 * counter (task-clock) that monitors only itself, never enables it, never
 * reads samples, and closes it. Nothing is profiled.
 *
 * Not a working exploit. For detection validation only. Safe to run.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif

int main(void)
{
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_TASK_CLOCK;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    /* pid 0 = this task, cpu -1 = any, no group, no flags. */
    int fd = (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0UL);
    if (fd < 0) {
        fprintf(stderr,
                "[perf-behavioral] perf_event_open(): %s (may be gated by "
                "kernel.perf_event_paranoid). The syscall attempt is still "
                "emitted as telemetry.\n",
                strerror(errno));
        return 0;
    }

    /* STOP: counter is never enabled and no samples are read. */
    close(fd);
    fprintf(stderr,
            "[perf-behavioral] perf_event_open on a benign software counter "
            "emitted; counter never enabled. Safe.\n");
    return 0;
}
