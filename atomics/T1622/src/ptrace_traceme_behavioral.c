/*
 * PTRACE_TRACEME self-trace — behavioral telemetry generator.
 *
 * Emits `ptrace(PTRACE_TRACEME)` from a child that then execs a harmless
 * command — the classic anti-debug pattern (only one tracer may attach, so a
 * process that traces itself blocks later debugger/EDR attachment) also seen
 * in some SUID privilege-escalation tricks. The parent acts as the minimal
 * tracer so the child (/bin/true) runs to completion.
 *
 * Not a working exploit. For detection validation only. Safe to run.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            fprintf(stderr,
                    "[ptrace-behavioral] ptrace(PTRACE_TRACEME): %s. The "
                    "syscall attempt is still emitted as telemetry.\n",
                    strerror(errno));
            _exit(0);
        }
        execl("/bin/true", "true", (char *)NULL);
        fprintf(stderr, "execl(/bin/true): %s\n", strerror(errno));
        _exit(127);
    }

    /* Parent is the minimal tracer: let the child proceed until it exits. */
    int status;
    while (waitpid(pid, &status, 0) > 0) {
        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;
        ptrace(PTRACE_CONT, pid, NULL, NULL);
    }
    fprintf(stderr,
            "[ptrace-behavioral] child issued PTRACE_TRACEME then exec'd "
            "/bin/true; completed. Safe.\n");
    return 0;
}
