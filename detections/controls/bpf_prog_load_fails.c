/*
 * Control for the eBPF program-load rule.
 *
 * bpf(BPF_PROG_LOAD, NULL, 0): the right syscall and command, but the kernel
 * rejects it and loads nothing. An attempt the kernel refused is not an
 * execution of the technique.
 */
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    (void)syscall(SYS_bpf, 5 /* BPF_PROG_LOAD */, NULL, 0);
    return 0;
}
