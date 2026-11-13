/*
 * Control for the io_uring_setup rule (io_uring_setup.yml).
 *
 * io_uring_setup(0, &params): the rule's syscall, with 0 entries, which the
 * kernel rejects. No ring is created. The atomic asks for 8 entries, which the
 * kernel accepts.
 *
 * This control does NOT break an item of the rule. The rule reads only the
 * syscall name, so no argument value can keep it quiet, and the rule's logic
 * matches this rejected call. What holds the control is the success gate of the
 * validator (success=yes): a call that the kernel rejected is an attempt, not an
 * execution of the technique. The control must NOT count as a detection.
 *
 * Exit code: always 0, whether the kernel rejects the call (as it must) or
 * accepts it. The validator reads the audit records, not the exit code: if the
 * kernel accepted the call, the rule fires on its record, and the validator
 * reports this control as BROKEN.
 */
#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

int main(void)
{
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    long fd = syscall(__NR_io_uring_setup, 0, &params);
    if (fd >= 0)    /* not expected: then the rule fires, and the validator says so */
        close((int)fd);
    return 0;
}
