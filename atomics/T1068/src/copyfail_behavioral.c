/*
 * CopyFail (CVE-2026-31431) — behavioral telemetry generator.
 *
 * Emits the rare syscall pattern detection rules key on:
 *   socket(AF_ALG) + bind() to authencesn(hmac(sha256),cbc(aes))
 *   + sendmsg(MSG_MORE) + splice()
 *
 * The real CopyFail precondition is the authencesn AEAD. Kernels that lack
 * that specific algorithm fail the bind()/accept(), so to keep the full
 * socket(AF_ALG) + sendmsg(MSG_MORE) + splice() signature on stock kernels
 * this falls back to a universally-available transform (hash:sha256) for the
 * operation fd, and always issues the splice() regardless (a failed splice()
 * still emits the syscall record the rule keys on).
 *
 * Intentionally does NOT call recv() — that is the step that triggers
 * decryption and writes into the page cache. Without recv(), no page cache
 * corruption occurs. Target is a throwaway file under /tmp that this program
 * creates and the atomic cleans up.
 *
 * Not a working exploit. For detection validation only.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/if_alg.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <target_file>\n", argv[0]);
        return 2;
    }
    const char *target_path = argv[1];

    int target_fd = open(target_path, O_RDWR | O_CREAT, 0644);
    if (target_fd < 0) {
        perror("open target");
        return 1;
    }
    const char pad[] = "atomic-test placeholder data ----------------------------";
    (void)write(target_fd, pad, sizeof(pad) - 1);

    int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (alg_fd < 0) {
        perror("socket(AF_ALG)");
        close(target_fd);
        return 1;
    }

    /* Prefer the real CopyFail AEAD; fall back to hash(sha256) so the
     * accept()+sendmsg()+splice path still runs where that AEAD is absent. */
    struct sockaddr_alg sa_aead = {
        .salg_family = AF_ALG,
        .salg_type   = "aead",
        .salg_name   = "authencesn(hmac(sha256),cbc(aes))",
    };
    struct sockaddr_alg sa_hash = {
        .salg_family = AF_ALG,
        .salg_type   = "hash",
        .salg_name   = "sha256",
    };
    if (bind(alg_fd, (struct sockaddr *)&sa_aead, sizeof(sa_aead)) < 0) {
        fprintf(stderr, "bind(authencesn): %s; falling back to hash(sha256)\n",
                strerror(errno));
        if (bind(alg_fd, (struct sockaddr *)&sa_hash, sizeof(sa_hash)) < 0)
            fprintf(stderr, "bind(sha256): %s (telemetry still emitted)\n",
                    strerror(errno));
    }

    int op_fd = accept(alg_fd, NULL, NULL);
    if (op_fd >= 0) {
        char aad[16] = {0};
        struct iovec iov = { .iov_base = aad, .iov_len = sizeof(aad) };
        struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
        (void)sendmsg(op_fd, &msg, MSG_MORE);
    }

    /* splice() is always issued. Prefer one end being the AF_ALG operation fd
     * (as in the real primitive); otherwise splice file->pipe so the
     * syscall-level signature (AF_ALG socket + splice) is still present. */
    int pipefd[2];
    if (pipe(pipefd) == 0) {
        if (op_fd >= 0) {
            (void)write(pipefd[1], pad, 16);
            (void)splice(pipefd[0], NULL, op_fd, NULL, 16, 0);
        } else {
            (void)splice(target_fd, NULL, pipefd[1], NULL, 16, 0);
        }
        close(pipefd[0]);
        close(pipefd[1]);
    }

    if (op_fd >= 0)
        close(op_fd);
    close(alg_fd);
    close(target_fd);
    printf("[+] copyfail behavioral pattern emitted against %s\n", target_path);
    return 0;
}
