/*
 * Control for the userfaultfd rule (userfaultfd_syscall.yml).
 *
 * userfaultfd(0xffff): the rule's syscall, with flags that the kernel rejects.
 * No userfaultfd object is created. The atomic passes O_CLOEXEC | O_NONBLOCK,
 * which the kernel accepts.
 *
 * This control does NOT break an item of the rule. The rule reads only the
 * syscall name, so no argument value can keep it quiet, and the rule's logic
 * matches this rejected call. What holds the control is the success gate of the
 * validator (success=yes): a call that the kernel rejected is an attempt, not an
 * execution of the technique. The control must NOT count as a detection.
 */
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    long fd = syscall(SYS_userfaultfd, 0xffff);
    if (fd >= 0)    /* not expected: then the rule fires, and the validator says so */
        close((int)fd);
    return 0;
}
