/*
 * Baseline control (the "no-op"): a process that is not a technique.
 *
 * It makes ONE syscall that detections/audit/atomic.rules audits:
 * socket(AF_UNIX, SOCK_STREAM, 0). The record of that call fires no rule. The
 * validator evaluates this process against every rule, and every rule must stay
 * quiet.
 *
 * The record is there so that the validator can show that it read the records
 * of this process. A baseline whose process tree left no record proves nothing:
 * the validator reports it as vacuous and fails the run.
 *
 * The no-op declares no item of a rule, so the validator never counts it as the
 * live negative control of a rule. (Its record is one item away from some
 * rules, for example from afxdp_socket.yml by the socket family. The validator
 * does not grade the no-op by item.)
 *
 * Exit code: always 0, also when the kernel rejects the socket call. The
 * validator reads the audit records, not the exit code, and a rejected call
 * leaves a record too. The socket is closed at once and is never bound or
 * connected.
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
