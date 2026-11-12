/*
 * Control for the CopyFail correlation (copyfail_af_alg_authencesn.yml:
 * an AF_ALG socket and a splice in the same pid).
 *
 * The atomic calls socket(AF_ALG, SOCK_SEQPACKET, 0), then pipe() and splice().
 * This control makes the same three calls in one process with ONE argument
 * changed: the socket family is AF_UNIX (1), not AF_ALG (38). All three calls
 * succeed, in the same pid and inside the time window, so only the a0 (AF_ALG)
 * item of the socket base keeps the rule quiet: the correlation must NOT fire.
 *
 * The splice moves 16 bytes from a temporary file into a pipe, as the atomic does
 * when it has no AF_ALG operation socket. The file is unlinked before the first
 * audited call, so nothing stays on the machine on any path. The socket is never
 * bound or connected.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    char path[] = "/tmp/deteng_copyfail_ctl_XXXXXX";
    int file = mkstemp(path);
    if (file < 0) {
        perror("mkstemp");
        return 1;
    }
    unlink(path);   /* the open descriptor keeps the data until the process ends */
    if (write(file, "AAAAAAAAAAAAAAAA", 16) != 16) {
        perror("write");
        return 1;
    }

    int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock < 0) {
        perror("socket(AF_UNIX, SOCK_SEQPACKET, 0)");
        return 1;
    }

    int p[2];
    if (pipe(p) < 0) {
        perror("pipe");
        return 1;
    }
    loff_t off = 0;
    if (splice(file, &off, p[1], NULL, 16, 0) != 16) {
        perror("splice");
        return 1;
    }
    return 0;
}
