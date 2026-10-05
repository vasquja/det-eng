/*
 * AF_XDP socket — behavioral telemetry generator.
 *
 * Emits the high-signal syscall:
 *   socket(AF_XDP, SOCK_RAW, 0)       // AF_XDP = 44 = 0x2c
 *
 * AF_XDP is the kernel's express data path: a user process maps a UMEM region
 * and binds an XDP socket to a queue to receive frames with near-zero copy,
 * usually alongside a loaded XDP/eBPF program. It is a modern, high-performance
 * sniffing and traffic-interception surface (T1040) that many sensors do not
 * watch. Almost no ordinary process opens an AF_XDP socket, so the family
 * alone is a strong, rare signal.
 *
 * This is the AF_XDP *socket* half of the primitive. The eBPF program-load
 * half (bpf(BPF_PROG_LOAD)) that an XDP capture pipeline also performs is
 * already covered by detections/sigma/T1014/bpf_prog_load.yml and its
 * paired atomic — this test deliberately does not load a program.
 *
 * This program opens the socket and immediately closes it. It performs NO
 * UMEM registration (setsockopt XDP_UMEM_REG), NO bind() to a queue, and NO
 * ring mmap — so no frames are ever received.
 *
 * AF_XDP needs CAP_NET_RAW and a kernel built with CONFIG_XDP_SOCKETS. Where
 * it is missing, socket() returns EAFNOSUPPORT; without the capability it
 * returns EPERM. Either way the syscall is issued and recorded, so the
 * attempt itself is the telemetry this test is designed to generate.
 *
 * Not a working exploit. For detection validation only.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

/* AF_XDP / PF_XDP may be absent from older libc headers. */
#ifndef AF_XDP
#define AF_XDP 44
#endif

int main(void)
{
    int fd = socket(AF_XDP, SOCK_RAW, 0);
    if (fd < 0) {
        fprintf(stderr,
                "[afxdp] socket(AF_XDP, SOCK_RAW, 0) returned errno=%d (%s). "
                "The attempt is still emitted as telemetry; EPERM (no "
                "CAP_NET_RAW) or EAFNOSUPPORT (no CONFIG_XDP_SOCKETS) is "
                "expected on many hosts.\n",
                errno, strerror(errno));
        /* Exit 0: the socket() record is already the telemetry we wanted. */
        return 0;
    }

    /* STOP here: no XDP_UMEM_REG setsockopt, no bind() to a queue, no ring
     * mmap. No frames are received. */
    fprintf(stderr,
            "[afxdp] created AF_XDP socket; stopped before UMEM reg / bind / "
            "ring mmap. No frames received.\n");

    close(fd);
    return 0;
}
