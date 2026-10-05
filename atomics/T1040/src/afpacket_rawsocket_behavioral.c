/*
 * AF_PACKET raw socket — behavioral telemetry generator.
 *
 * Emits the high-signal syscall:
 *   socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
 *
 * A raw AF_PACKET socket is the entry point for both network sniffing
 * (T1040) and a repeated class of kernel privilege-escalation bugs in the
 * packet-socket ring code (e.g. CVE-2016-8655, CVE-2017-7308). Outside a
 * small set of sniffers and network daemons, almost no process opens one.
 *
 * This program opens the socket and immediately closes it. It performs NO
 * bind() to an interface, NO recvfrom(), and NO PACKET_RX_RING / PACKET_TX_RING
 * setup, so no packets are ever captured and the vulnerable ring path is
 * never touched.
 *
 * CAP_NET_RAW is normally required. Without it the socket() call returns
 * EPERM — but the syscall is still issued and still recorded by auditd, so
 * the attempt itself is the telemetry this test is designed to generate.
 *
 * Not a working exploit. For detection validation only.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

int main(void)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        fprintf(stderr,
                "[afpacket-behavioral] socket(AF_PACKET, SOCK_RAW) returned "
                "errno=%d (%s). The attempt is still emitted as telemetry; "
                "EPERM is expected without CAP_NET_RAW.\n",
                errno, strerror(errno));
        /* Exit 0: an EPERM attempt is a successful test run — the syscall
         * record is what we wanted to produce. */
        return 0;
    }

    /* STOP here: no bind(), no recvfrom(), no ring setup. */
    fprintf(stderr,
            "[afpacket-behavioral] created AF_PACKET SOCK_RAW socket; "
            "stopped before bind/recv/ring setup. No packets captured.\n");

    close(fd);
    return 0;
}
