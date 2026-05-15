/*
 * DirtyFrag RxRPC (CVE-2026-43500) — behavioral telemetry generator.
 *
 * Emits the rare syscall pattern:
 *   socket(AF_RXRPC, SOCK_DGRAM, 0)
 *
 * AF_RXRPC use is uncommon outside AFS clients; a socket() of this family
 * from a non-AFS process is a high-signal detection. This program opens
 * and immediately closes the socket — no bind, no sendmsg, no operations
 * that touch the vulnerable page-cache write path. Safe to run.
 *
 * Not a working exploit. For detection validation only.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif

int main(void)
{
    int fd = socket(AF_RXRPC, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "socket(AF_RXRPC): %s\n", strerror(errno));
        fprintf(stderr, "[*] rxrpc kernel module may not be loaded\n");
        return 1;
    }
    close(fd);
    printf("[+] dirtyfrag rxrpc behavioral pattern emitted\n");
    return 0;
}
