/*
 * Control for the AF_RXRPC socket rule (dirtyfrag_rxrpc_socket.yml).
 *
 * The atomic calls socket(AF_RXRPC, SOCK_DGRAM, 2). This control makes the same
 * call with ONE argument changed: the family is AF_NETLINK (16), not AF_RXRPC
 * (33). The type and the protocol number stay. For AF_NETLINK, protocol 2 is
 * NETLINK_USERSOCK, and the call needs no privilege, so the kernel accepts it.
 * The rule's a0 (AF_RXRPC) item must reject it.
 *
 * The socket is closed at once. Nothing is bound and nothing is sent.
 *
 * Exit code: 0 when the kernel accepted the socket call; 1, with the error on
 * stderr, when it rejected the call. The validator reads the audit records, not
 * the exit code.
 */
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int fd = socket(AF_NETLINK, SOCK_DGRAM, 2 /* the atomic's protocol number */);
    if (fd < 0) {
        perror("socket(AF_NETLINK, SOCK_DGRAM, 2)");
        return 1;
    }
    close(fd);
    return 0;
}
