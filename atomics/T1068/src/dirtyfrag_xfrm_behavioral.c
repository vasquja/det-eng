/*
 * DirtyFrag xfrm-ESP (CVE-2026-43284) — behavioral telemetry generator.
 *
 * Emits the rare syscall pattern:
 *   unshare(CLONE_NEWUSER | CLONE_NEWNET) + socket(AF_NETLINK, NETLINK_XFRM)
 *
 * Stops before sending any XFRM SA / policy netlink request and before
 * any ESP packet handling — i.e. well before the kernel path that
 * performs the page-cache write. Safe to run.
 *
 * Not a working exploit. For detection validation only.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#ifndef NETLINK_XFRM
#define NETLINK_XFRM 6
#endif

int main(void)
{
    if (unshare(CLONE_NEWUSER) < 0)
        fprintf(stderr, "unshare(CLONE_NEWUSER): %s\n", strerror(errno));
    if (unshare(CLONE_NEWNET) < 0)
        fprintf(stderr, "unshare(CLONE_NEWNET): %s (likely blocked by policy)\n",
                strerror(errno));

    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (nl < 0) {
        perror("socket(NETLINK_XFRM)");
        return 1;
    }
    close(nl);

    printf("[+] dirtyfrag xfrm-ESP behavioral pattern emitted\n");
    return 0;
}
