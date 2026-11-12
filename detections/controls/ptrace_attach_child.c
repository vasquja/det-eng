/*
 * Control for the PTRACE_TRACEME rule (ptrace_traceme.yml).
 *
 * In the atomic a forked child calls ptrace(PTRACE_TRACEME). Here the roles are
 * the other way round: the child never asks to be traced, and the parent calls
 * ptrace(PTRACE_ATTACH, child), then ptrace(PTRACE_DETACH, child). Both calls
 * are the rule's syscall and they succeed, with ONE item changed: the request
 * (a0) is 0x10 or 0x11, not 0 (PTRACE_TRACEME). The rule's a0 item must reject
 * them. (PTRACE_TRACEME is the only request that a process makes about itself.
 * Every other request names a tracee, so the wrong request comes from the
 * parent and names the child.)
 *
 * The child makes no audited syscall. It cannot stay behind: the kernel kills
 * it when the parent dies (PR_SET_PDEATHSIG), an alarm ends it after 20 s, and
 * the parent kills it and waits for it on every path.
 *
 * When the kernel refuses the attach (for example with Yama ptrace_scope 3), the
 * only audited call is a rejected one. The control exits with 1, and the
 * validator reports that the control is not held by the item it declares.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != parent)    /* the parent died before the prctl */
            _exit(0);
        alarm(20);
        for (;;)
            pause();
    }

    int rc = 0, status = 0;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace(PTRACE_ATTACH)");
        rc = 1;
    } else {
        /* The attach stops the child. Wait for that stop, then let it go. */
        if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status)) {
            fprintf(stderr, "the child did not stop after PTRACE_ATTACH\n");
            rc = 1;
        } else if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
            perror("ptrace(PTRACE_DETACH)");
            rc = 1;
        }
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return rc;
}
