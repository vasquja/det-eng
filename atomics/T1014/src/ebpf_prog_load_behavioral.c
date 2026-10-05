/*
 * eBPF program load — behavioral telemetry generator.
 *
 * Emits `bpf(BPF_MAP_CREATE)` followed by `bpf(BPF_PROG_LOAD)` — the first
 * steps of an eBPF rootkit or a BPF-based privilege-escalation chain. The
 * loaded program is a no-op (`r0 = 0; exit`) of type SOCKET_FILTER, and it
 * is NEVER attached to any hook, socket, tracepoint, or kprobe. The map and
 * program fds are closed immediately, so nothing persists in the kernel.
 *
 * Not a working exploit. For detection validation only. Safe to run.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

static int sys_bpf(int cmd, union bpf_attr *attr)
{
    return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int main(void)
{
    union bpf_attr attr;

    /* 1) Create a tiny array map (mirrors real program/map setup). */
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 4;
    attr.max_entries = 1;
    int map_fd = sys_bpf(BPF_MAP_CREATE, &attr);
    if (map_fd < 0)
        fprintf(stderr,
                "[ebpf-behavioral] BPF_MAP_CREATE: %s (may need CAP_BPF or "
                "unprivileged_bpf_disabled=0). Attempt still emitted.\n",
                strerror(errno));

    /* 2) Load a no-op program: r0 = 0; exit. */
    struct bpf_insn insns[] = {
        { .code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 }, /* MOV64 r0,0 */
        { .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 }, /* EXIT */
    };
    char license[] = "GPL";

    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = 2;
    attr.insns = (uint64_t)(uintptr_t)insns;
    attr.license = (uint64_t)(uintptr_t)license;
    int prog_fd = sys_bpf(BPF_PROG_LOAD, &attr);
    if (prog_fd < 0) {
        fprintf(stderr,
                "[ebpf-behavioral] BPF_PROG_LOAD: %s (may need CAP_BPF or "
                "unprivileged_bpf_disabled=0). The syscall attempt is still "
                "emitted as telemetry.\n",
                strerror(errno));
        if (map_fd >= 0)
            close(map_fd);
        return 0;
    }

    /* STOP: the program is never attached anywhere. */
    close(prog_fd);
    if (map_fd >= 0)
        close(map_fd);
    fprintf(stderr,
            "[ebpf-behavioral] BPF_MAP_CREATE + BPF_PROG_LOAD emitted; program "
            "never attached. Safe.\n");
    return 0;
}
