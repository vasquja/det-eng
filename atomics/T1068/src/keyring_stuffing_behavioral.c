/*
 * Keyring stuffing — behavioral telemetry generator.
 *
 * Emits a burst of `add_key(2)` syscalls, the setup used by several kernel
 * keyring privilege-escalation bugs (e.g. CVE-2016-0728, CVE-2022-1998).
 * All keys are tiny, harmless, and added to the caller's PROCESS keyring
 * (KEY_SPEC_PROCESS_KEYRING), which is private to this process and discarded
 * when it exits — the user's real session/user keyrings are never touched.
 * The keyring is also explicitly cleared before exit.
 *
 * Not a working exploit. For detection validation only. Safe to run.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>

#ifndef __NR_add_key
#define __NR_add_key 248
#endif
#ifndef __NR_keyctl
#define __NR_keyctl 250
#endif

int main(int argc, char **argv)
{
    long count = (argc > 1) ? strtol(argv[1], NULL, 10) : 100;
    if (count < 1)
        count = 1;
    if (count > 1000)
        count = 1000;

    const char payload[] = "atomic";
    long ok = 0;
    for (long i = 0; i < count; i++) {
        char desc[64];
        snprintf(desc, sizeof(desc), "atomic_key_%ld", i);
        long key = syscall(__NR_add_key, "user", desc, payload,
                           (size_t)sizeof(payload), KEY_SPEC_PROCESS_KEYRING);
        if (key < 0) {
            if (i == 0) {
                fprintf(stderr,
                        "[keyring-behavioral] add_key(): %s. The syscall "
                        "attempt is still emitted as telemetry.\n",
                        strerror(errno));
                return 0;
            }
            break;
        }
        ok++;
    }

    /* Cleanup: clear only our private process keyring. */
    syscall(__NR_keyctl, KEYCTL_CLEAR, KEY_SPEC_PROCESS_KEYRING);
    fprintf(stderr,
            "[keyring-behavioral] added %ld 'user' keys to the private process "
            "keyring then cleared them. Safe.\n",
            ok);
    return 0;
}
