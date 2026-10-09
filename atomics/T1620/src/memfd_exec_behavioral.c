/*
 * memfd fileless execution — behavioral telemetry generator.
 *
 * Emits `memfd_create(2)` followed by `fexecve()` (execveat with
 * AT_EMPTY_PATH) on the anonymous fd — the fileless-execution pattern used
 * by many Linux droppers. The executed payload is a benign, already-present
 * system binary (default /bin/true), copied into the memfd; no attacker code
 * runs and no file is written to disk. The process replaces itself, so both
 * syscalls come from the same PID (what the paired correlation rule groups
 * on), and it then shows an executable path like `/memfd:atomic (deleted)`.
 *
 * Not a working exploit. For detection validation only. Safe to run.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

int main(int argc, char **argv)
{
    const char *payload = (argc > 1) ? argv[1] : "/bin/true";

    int src = open(payload, O_RDONLY);
    if (src < 0) {
        fprintf(stderr, "open(%s): %s\n", payload, strerror(errno));
        return 1;
    }

    int mfd = memfd_create("atomic", 0); /* no CLOEXEC: fd must survive exec */
    if (mfd < 0) {
        fprintf(stderr, "memfd_create: %s\n", strerror(errno));
        close(src);
        return 1;
    }

    char buf[65536];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(mfd, buf + off, (size_t)(n - off));
            if (w < 0) {
                fprintf(stderr, "write(memfd): %s\n", strerror(errno));
                close(src);
                close(mfd);
                return 1;
            }
            off += w;
        }
    }
    close(src);

    /* Exec from the memfd in THIS process (no fork), so memfd_create and
     * execveat share a PID. On success this call does not return. */
    fprintf(stderr,
            "[memfd-behavioral] fileless exec of %s via memfd; exe path "
            "becomes /memfd:atomic (deleted). Safe.\n",
            payload);
    char *cargv[] = { (char *)"atomic-memfd", NULL };
    char *cenv[] = { NULL };
    fexecve(mfd, cargv, cenv);
    fprintf(stderr, "fexecve: %s\n", strerror(errno));
    close(mfd);
    return 1;
}
