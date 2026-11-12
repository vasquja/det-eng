/*
 * Control for the CopyFail correlation (copyfail_af_alg_authencesn.yml:
 * an AF_ALG socket and a splice in the same pid).
 *
 * The audited calls of the atomic are socket(AF_ALG, SOCK_SEQPACKET, 0), pipe()
 * and splice(). This control makes these three calls in one process with ONE
 * argument changed: the socket family is AF_UNIX (1), not AF_ALG (38). All
 * three calls succeed, in the same pid and inside the time window, so only the
 * a0 (AF_ALG) item of the socket base keeps the rule quiet: the correlation
 * must NOT fire.
 *
 * What differs from the atomic, other than the family:
 *   - The splice. The control calls splice(file, NULL, pipe, NULL, 16, 0): from
 *     a temporary file into the pipe. The atomic makes a call with these
 *     arguments only when it has no AF_ALG operation socket. When it has one,
 *     it calls splice(pipe, NULL, socket, NULL, 16, 0): from the pipe into that
 *     socket. The control has no such socket. The rule reads no argument of the
 *     splice.
 *   - The numbers of the file descriptors, which the rule does not read.
 *   - The atomic also calls bind(), accept() and sendmsg(). They are not
 *     audited (detections/audit/atomic.rules), and no rule reads them.
 *
 * The pipe and the splice of this control, in one pid, also satisfy
 * dirtypipe_splice_readonly.yml (a pipe and a splice in the same pid). That
 * does not fail a run: the validator grades a control against its own rule
 * only, the rule of its CONTROLS row.
 *
 * Exit code: 0 when the three calls succeeded; 1, with the error on stderr,
 * when a step failed. The validator reads the audit records, not the exit
 * code.
 *
 * The temporary file is unlinked before the first audited call, so nothing
 * stays on the machine on any path. The socket is never bound or connected.
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
    /* As in the atomic, the splice takes no offset: it reads at the file
     * position, so go back to the start of the 16 bytes first. */
    if (lseek(file, 0, SEEK_SET) != 0) {
        perror("lseek");
        return 1;
    }
    if (splice(file, NULL, p[1], NULL, 16, 0) != 16) {
        perror("splice");
        return 1;
    }
    return 0;
}
