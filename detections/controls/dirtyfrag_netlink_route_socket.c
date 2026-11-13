/*
 * Control for the DirtyFrag xfrm correlation (dirtyfrag_xfrm_unshare_netlink.yml:
 * an unshare with CLONE_NEWNET and a NETLINK_XFRM socket in the same pid).
 *
 * The atomic calls unshare(CLONE_NEWUSER), unshare(CLONE_NEWNET) and
 * socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM). This control makes the same three
 * calls in one process with ONE argument changed: the netlink protocol is
 * NETLINK_ROUTE (0), not NETLINK_XFRM (6). When the calls succeed, only the a2
 * (NETLINK_XFRM) item of the socket base keeps the rule quiet: the correlation
 * must NOT fire.
 *
 * The new namespaces belong to this process only and end with it. The socket is
 * closed at once and no netlink request is sent. As the atomic does, the control
 * continues when an unshare is refused. The rule needs only the CLONE_NEWNET
 * call: when the kernel refuses that one, no call of the control matches the
 * unshare base, and the validator reports that the control is not held by the
 * item it declares.
 *
 * Exit code: 0 when the kernel accepted the three calls; 1, with the error on
 * stderr, when it rejected one of them. The validator reads the audit records,
 * not the exit code: a control that exits with 1 because only the
 * CLONE_NEWUSER call was refused is still held as declared.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef NETLINK_ROUTE
#define NETLINK_ROUTE 0
#endif

int main(void)
{
    int rc = 0;
    if (unshare(CLONE_NEWUSER) < 0) {
        perror("unshare(CLONE_NEWUSER)");
        rc = 1;
    }
    if (unshare(CLONE_NEWNET) < 0) {
        perror("unshare(CLONE_NEWNET)");
        rc = 1;
    }
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        perror("socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)");
        return 1;
    }
    close(fd);
    return rc;
}
