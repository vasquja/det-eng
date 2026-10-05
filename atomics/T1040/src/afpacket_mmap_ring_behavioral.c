/*
 * AF_PACKET PACKET_RX_RING (TPACKET_V3) + mmap — behavioral telemetry generator.
 *
 * Emits the syscall chain that a high-rate packet sniffer sets up before it
 * starts to capture:
 *   socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
 *   setsockopt(fd, SOL_PACKET, PACKET_VERSION, TPACKET_V3)
 *   setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &tpacket_req3, ...)
 *   mmap(... fd ...)                      // map the kernel RX ring buffer
 *
 * The PACKET_RX_RING path is both the fast, zero-copy capture interface used
 * by tcpdump/libpcap (T1040 Network Sniffing) and the code path behind a
 * repeated class of packet-socket ring kernel bugs (e.g. CVE-2017-7308, a
 * TPACKET_V3 ring overflow). The combination of an AF_PACKET socket, a
 * PACKET_RX_RING setsockopt, and an mmap of that socket is a stronger, more
 * specific signal than the bare socket() call alone.
 *
 * This program STOPS before it captures anything: it performs NO bind() to an
 * interface and runs NO poll()/recvfrom() loop, so the ring is never armed
 * against a live interface and no packets are read. The ring memory is
 * unmapped and the socket is closed on exit.
 *
 * CAP_NET_RAW is normally required. Without it socket() returns EPERM — but
 * the syscall is still issued and still recorded by auditd, so the attempt
 * itself is the telemetry this test is designed to generate. Each later step
 * is also tolerant of failure: the records that did get emitted are the point.
 *
 * Not a working exploit. For detection validation only.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

/* Keep the ring tiny: one block, one frame. We never fill it. */
#define BLOCK_SIZE  4096u
#define BLOCK_NR    1u
#define FRAME_SIZE  2048u
#define FRAME_NR    2u

int main(void)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        fprintf(stderr,
                "[afpacket-mmap-ring] socket(AF_PACKET, SOCK_RAW) returned "
                "errno=%d (%s). The attempt is still emitted as telemetry; "
                "EPERM is expected without CAP_NET_RAW.\n",
                errno, strerror(errno));
        /* Exit 0: the socket() record is already the telemetry we wanted. */
        return 0;
    }

    /* Select the TPACKET_V3 ring ABI. */
    int version = TPACKET_V3;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION,
                   &version, sizeof(version)) < 0) {
        fprintf(stderr,
                "[afpacket-mmap-ring] setsockopt(PACKET_VERSION, TPACKET_V3) "
                "errno=%d (%s); continuing — the setsockopt record is still "
                "emitted.\n", errno, strerror(errno));
    }

    /* Request the RX ring. This setsockopt is the enrichment signal. */
    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = BLOCK_SIZE;
    req.tp_block_nr   = BLOCK_NR;
    req.tp_frame_size = FRAME_SIZE;
    req.tp_frame_nr   = FRAME_NR;
    req.tp_retire_blk_tov = 0;
    req.tp_sizeof_priv    = 0;
    req.tp_feature_req_word = 0;

    int ring_ok = setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
                             &req, sizeof(req));
    if (ring_ok < 0) {
        fprintf(stderr,
                "[afpacket-mmap-ring] setsockopt(PACKET_RX_RING) errno=%d "
                "(%s); continuing — the setsockopt record is still emitted.\n",
                errno, strerror(errno));
    }

    /* mmap the ring the kernel just allocated. Only meaningful if the ring
     * request succeeded; attempt it regardless so the mmap record appears. */
    size_t ring_bytes = (size_t)BLOCK_SIZE * BLOCK_NR;
    void *ring = mmap(NULL, ring_bytes, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        fprintf(stderr,
                "[afpacket-mmap-ring] mmap of RX ring errno=%d (%s); the ring "
                "was not mapped.\n", errno, strerror(errno));
        ring = NULL;
    }

    /* STOP here: no bind() to an interface, no poll()/recvfrom() loop. The
     * ring is never armed against a live link and no packets are captured. */
    fprintf(stderr,
            "[afpacket-mmap-ring] AF_PACKET socket + PACKET_RX_RING (TPACKET_V3)"
            " set up%s; stopped before bind/poll/recv. No packets captured.\n",
            ring ? " and mmapped" : "");

    /* Cleanup. */
    if (ring)
        munmap(ring, ring_bytes);
    close(fd);
    return 0;
}
