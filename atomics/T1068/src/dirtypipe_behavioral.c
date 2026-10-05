/*
 * DirtyPipe (CVE-2022-0847) — behavioral telemetry generator.
 *
 * Emits the characteristic syscall pattern of the DirtyPipe primitive:
 *   1. pipe()                  — create a pipe
 *   2. fill then drain it      — every pipe buffer now carries the
 *                                PIPE_BUF_FLAG_CAN_MERGE flag (the state the
 *                                bug abuses)
 *   3. open(target, O_RDONLY)  — open a file read-only
 *   4. splice(ro_fd -> pipe)   — splice a byte from the read-only file into
 *                                the pipe; the page reference inherits the
 *                                CAN_MERGE flag from step 2
 *
 * It then STOPS. The real exploit's next step is write(pipe, data, len),
 * and that write lands in the read-only file's page cache, modifying a file
 * the attacker cannot normally write. This program never performs that
 * write. It also only ever touches a throwaway file it creates itself under
 * /tmp, so no page cache is corrupted and no file is modified.
 *
 * Not a working exploit. For detection validation only. Safe to run as an
 * unprivileged user.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *target = (argc > 1) ? argv[1] : "/tmp/dirtypipe_atomic_target";

    /* Create a throwaway file we own and seed it with harmless content. */
    int wfd = open(target, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (wfd < 0) {
        fprintf(stderr, "open(%s, O_WRONLY): %s\n", target, strerror(errno));
        return 1;
    }
    if (write(wfd, "AAAAAAAAAAAAAAAA", 16) < 0) {
        fprintf(stderr, "write(target): %s\n", strerror(errno));
        close(wfd);
        return 1;
    }
    close(wfd);

    /* 1. Create a pipe. */
    int p[2];
    if (pipe(p) < 0) {
        fprintf(stderr, "pipe: %s\n", strerror(errno));
        return 1;
    }

    /* 2. Fill the pipe to capacity, then drain it completely. After this the
     *    pipe's buffers retain PIPE_BUF_FLAG_CAN_MERGE — the precondition. */
    int pipe_sz = fcntl(p[1], F_GETPIPE_SZ);
    if (pipe_sz <= 0)
        pipe_sz = 65536;

    char *chunk = malloc(pipe_sz);
    if (!chunk) {
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        return 1;
    }
    memset(chunk, 'x', pipe_sz);

    int remaining = pipe_sz;
    while (remaining > 0) {
        ssize_t n = write(p[1], chunk, remaining);
        if (n < 0) {
            fprintf(stderr, "write(pipe fill): %s\n", strerror(errno));
            free(chunk);
            return 1;
        }
        remaining -= (int)n;
    }
    remaining = pipe_sz;
    while (remaining > 0) {
        ssize_t n = read(p[0], chunk, remaining);
        if (n < 0) {
            fprintf(stderr, "read(pipe drain): %s\n", strerror(errno));
            free(chunk);
            return 1;
        }
        if (n == 0)
            break;
        remaining -= (int)n;
    }
    free(chunk);

    /* 3. Open the target file READ-ONLY. */
    int rfd = open(target, O_RDONLY);
    if (rfd < 0) {
        fprintf(stderr, "open(%s, O_RDONLY): %s\n", target, strerror(errno));
        return 1;
    }

    /* 4. splice() one byte from the read-only file into the pipe. This is the
     *    high-signal artifact: splice(fd_in=<read-only regular file>,
     *    fd_out=<pipe>). */
    loff_t off = 0;
    ssize_t spliced = splice(rfd, &off, p[1], NULL, 1, 0);
    if (spliced < 0) {
        fprintf(stderr, "splice: %s\n", strerror(errno));
        close(rfd);
        return 1;
    }

    /* STOP. The exploit would now write() into the pipe to overwrite the
     * read-only file's page cache. We do not. */
    fprintf(stderr,
            "[dirtypipe-behavioral] emitted pipe fill/drain + "
            "splice(RO file -> pipe); stopped before the page-cache write. "
            "No file modified.\n");

    close(rfd);
    close(p[0]);
    close(p[1]);
    return 0;
}
