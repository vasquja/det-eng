/*
 * Control for the AF_INET raw-socket rule.
 *
 * socket(AF_INET, SOCK_STREAM, 0) succeeds, with the right syscall and family
 * but the wrong type. The rule's a1 (SOCK_RAW) constraint must reject it.
 */
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0)
        close(fd);
    return 0;
}
