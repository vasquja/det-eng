/*
 * Control for the DirtyPipe correlation (pipe + splice, same pid).
 *
 * Calls splice() with NO pipe()/pipe2() in this process. Other processes in
 * the same window (the validator's own subprocess plumbing uses pipe2) must
 * not complete the correlation.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    int fd = open("/etc/hostname", O_RDONLY);
    int out = open("/dev/null", O_WRONLY);
    (void)splice(fd, NULL, out, NULL, 16, 0);
    return 0;
}
