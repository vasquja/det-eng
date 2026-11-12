/*
 * Control for the AF_XDP socket rule (afxdp_socket.yml).
 *
 * The atomic calls socket(AF_XDP, SOCK_RAW, 0). This control makes the same call
 * with ONE argument changed: the family is AF_NETLINK (16), not AF_XDP (44). The
 * type and the protocol stay. For AF_NETLINK, protocol 0 is NETLINK_ROUTE, and
 * the call needs no privilege, so the kernel accepts it. The rule's a0 (AF_XDP)
 * item must reject it.
 *
 * The socket is closed at once. Nothing is bound and nothing is sent.
 */
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, 0);
    if (fd < 0) {
        perror("socket(AF_NETLINK, SOCK_RAW, 0)");
        return 1;
    }
    close(fd);
    return 0;
}
