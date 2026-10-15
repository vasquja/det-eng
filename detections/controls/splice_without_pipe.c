/*
 * Control for the DirtyPipe correlation (pipe + splice, same pid).
 *
 * The parent creates the pipe; a forked child (a different pid) splices a file
 * into that inherited pipe. Both syscalls succeed and both processes belong to
 * the stimulus tree, so only the rule's group-by (pid) keeps them apart: the
 * correlation must NOT fire. (A splice with no pipe at all is rejected by the
 * kernel with EINVAL and never reaches the rule, so it would test nothing.)
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    char path[] = "/tmp/deteng_splice_ctl_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    if (write(fd, "AAAAAAAAAAAAAAAA", 16) != 16) {
        perror("write");
        return 1;
    }
    close(fd);

    int p[2];
    if (pipe(p) < 0) {
        perror("pipe");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        int in = open(path, O_RDONLY);
        if (in < 0) {
            perror("open");
            _exit(1);
        }
        loff_t off = 0;
        if (splice(in, &off, p[1], NULL, 1, 0) < 0) {
            perror("splice");
            _exit(1);
        }
        _exit(0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    unlink(path);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
