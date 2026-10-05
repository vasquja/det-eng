/*
 * AF_INET raw socket — behavioral telemetry generator.
 *
 * Emits the high-signal syscall:
 *   socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
 *
 * A raw IP socket lets a process read and write whole IP packets, bypassing
 * the kernel transport layer. It is used both to sniff/craft traffic
 * (T1040 Network Sniffing) and as a building block for spoofing and covert
 * channels. Unlike AF_PACKET (link-layer) sockets, an AF_INET raw socket is
 * the classic BSD-sockets raw interface — the one `ping` and `traceroute`
 * use — so detection must lean on process context, not the family alone.
 *
 * This program opens the socket and immediately closes it. It performs NO
 * bind(), NO connect(), NO sendto()/recvfrom() — no packet is ever read or
 * written.
 *
 * CAP_NET_RAW is normally required. Without it socket() returns EPERM — but
 * the syscall is still issued and still recorded by auditd, so the attempt
 * itself is the telemetry this test is designed to generate.
 *
 * Not a working exploit. For detection validation only.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

int main(void)
{
    /* AF_INET + SOCK_RAW. IPPROTO_ICMP is a concrete, commonly-seen choice
     * (the same one ping uses); IPPROTO_RAW, IPPROTO_TCP, etc. would emit the
     * same family/type signature. The detection keys on family + raw type,
     * not on the protocol in a2. */
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        fprintf(stderr,
                "[afinet-raw] socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) returned "
                "errno=%d (%s). The attempt is still emitted as telemetry; "
                "EPERM is expected without CAP_NET_RAW.\n",
                errno, strerror(errno));
        /* Exit 0: the socket() record is already the telemetry we wanted. */
        return 0;
    }

    /* STOP here: no bind(), no sendto()/recvfrom(). */
    fprintf(stderr,
            "[afinet-raw] created AF_INET SOCK_RAW socket; stopped before "
            "bind/send/recv. No packets read or written.\n");

    close(fd);
    return 0;
}
