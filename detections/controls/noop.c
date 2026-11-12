/*
 * Baseline control (the "no-op"): a process that is not a technique.
 *
 * It makes ONE syscall that detections/audit/atomic.rules audits and that no
 * rule matches: socket(AF_UNIX, SOCK_STREAM, 0). The validator evaluates this
 * process against every rule, and every rule must stay quiet.
 *
 * The record is there so that the validator can show that it read the records
 * of this process. A baseline whose process tree left no record proves nothing:
 * the validator reports it as vacuous and fails the run.
 *
 * It breaks no item of any rule on purpose, so it is never the live negative
 * control of a rule. The socket is closed at once and is never bound or connected.
 */
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0)
        close(fd);
    return 0;
}
