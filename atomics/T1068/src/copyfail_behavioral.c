/*
 * CopyFail (CVE-2026-31431) — behavioral telemetry generator.
 *
 * Emits the rare syscall pattern detection rules key on:
 *   socket(AF_ALG) + bind() to authencesn(hmac(sha256),cbc(aes))
 *   + sendmsg(MSG_MORE) + splice()
 *
 * Intentionally does NOT call recv() — that is the step that triggers
 * decryption and writes into the page cache. Without recv(), no page
 * cache corruption occurs. Target is a throwaway file under /tmp that
 * this program creates and the atomic cleans up.
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

    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type   = "aead",
        .salg_name   = "authencesn(hmac(sha256),cbc(aes))",
    };
    if (bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "bind(authencesn): %s (telemetry still emitted)\n",
                strerror(errno));
    }

    int op_fd = accept(alg_fd, NULL, NULL);
    if (op_fd >= 0) {
        char aad[16] = {0};
        struct iovec iov = { .iov_base = aad, .iov_len = sizeof(aad) };
        struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
        (void)sendmsg(op_fd, &msg, MSG_MORE);

        int pipefd[2];
        if (pipe(pipefd) == 0) {
            (void)splice(target_fd, NULL, pipefd[1], NULL, 16, 0);
            close(pipefd[0]);
            close(pipefd[1]);
        }
        close(op_fd);
    }

    close(alg_fd);
    close(target_fd);
    printf("[+] copyfail behavioral pattern emitted against %s\n", target_path);
    return 0;
}
