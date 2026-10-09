/*
 * Control for the memfd_create -> execveat correlation (same pid).
 *
 * memfd_create() in the parent, fexecve() of a benign binary in a forked
 * child: both syscalls succeed, but in different pids. The rule documents
 * this fork variant as a coverage gap, so it must not be reported as a pass.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    int src = open("/bin/true", O_RDONLY);
    int mfd = memfd_create("control", 0);
    char buf[65536];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0)
        if (write(mfd, buf, (size_t)n) != n)
            return 1;
    if (fork() == 0) {
        char *argv[] = { (char *)"control", NULL };
        char *envp[] = { NULL };
        fexecve(mfd, argv, envp);
        _exit(127);
    }
    wait(NULL);
    return 0;
}
