/*
 * CopyFail (CVE-2026-31431) — behavioral telemetry generator.
 *
 * Emits the rare syscall pattern detection rules key on:
 *   socket(AF_ALG) + bind() to authencesn(hmac(sha256),cbc(aes))
 *   + sendmsg(MSG_MORE) + splice()
 *
 * The real CopyFail precondition is the authencesn AEAD. Kernels that lack
 * that specific algorithm fail the bind(), so to keep the full
 * socket(AF_ALG) + sendmsg(MSG_MORE) + splice() signature on stock kernels
 * this falls back to a universally-available transform (hash:sha256) for the
 * operation fd.
 *
 * Where the AEAD is present, this program sets a key on it before accept(), as
 * the real primitive must. An AEAD operation socket with no key rejects
 * sendmsg() and splice() with ENOKEY. A rejected splice() is an attempt, not an
 * execution: detections/validate_detections.py counts only the syscalls that
 * the kernel accepted, and it failed this emulation for that reason on a
 * GitHub runner with Ubuntu 26.04 (2026-11-12), the first runner image on
 * which the bind() to the AEAD worked. The key is a fixed dummy value. It
 * protects nothing, and no data is encrypted or decrypted with it.
 *
 * The program ends with 0 only when the kernel accepted the splice(). It ends
 * with 1 when the kernel rejected it, and says which call was rejected.
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
#include <arpa/inet.h>
#include <linux/if_alg.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

/* The key of an authenc() or authencesn() transform, as the kernel reads it
 * (crypto/authenc.c, crypto_authenc_extractkeys): one struct rtattr of type
 * CRYPTO_AUTHENC_KEYA_PARAM (1) that holds the length of the cipher key as a
 * big-endian number, then the key of the hash, then the key of the cipher. */
struct authenc_key {
    unsigned short rta_len;      /* length of the attribute: 8 */
    unsigned short rta_type;     /* CRYPTO_AUTHENC_KEYA_PARAM */
    unsigned int   enckeylen;    /* big endian: 16, the AES-128 key below */
    unsigned char  authkey[32];  /* key of hmac(sha256) */
    unsigned char  enckey[16];   /* key of cbc(aes) */
};

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
    struct authenc_key key;
    memset(&key, 0, sizeof(key));
    key.rta_len = 8;
    key.rta_type = 1;
    key.enckeylen = htonl(sizeof(key.enckey));
    memset(key.authkey, 0x41, sizeof(key.authkey));
    memset(key.enckey, 0x42, sizeof(key.enckey));

    int aead = 0;   /* 1 when the socket is the AEAD with its key set */
    if (bind(alg_fd, (struct sockaddr *)&sa_aead, sizeof(sa_aead)) < 0) {
        fprintf(stderr, "bind(authencesn): %s; falling back to hash(sha256)\n",
                strerror(errno));
    } else if (setsockopt(alg_fd, SOL_ALG, ALG_SET_KEY, &key, sizeof(key)) < 0) {
        fprintf(stderr, "setsockopt(ALG_SET_KEY): %s; falling back to hash(sha256)\n",
                strerror(errno));
    } else {
        aead = 1;
    }
    /* A socket with no operation socket can be bound again. hash(sha256) needs no key. */
    if (!aead && bind(alg_fd, (struct sockaddr *)&sa_hash, sizeof(sa_hash)) < 0)
        fprintf(stderr, "bind(sha256): %s\n", strerror(errno));

    int op_fd = accept(alg_fd, NULL, NULL);
    if (op_fd >= 0) {
        char aad[16] = {0};
        struct iovec iov = { .iov_base = aad, .iov_len = sizeof(aad) };
        struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
        if (sendmsg(op_fd, &msg, MSG_MORE) < 0)
            fprintf(stderr, "sendmsg(MSG_MORE): %s\n", strerror(errno));
    }

    /* splice() is always issued. Prefer one end being the AF_ALG operation fd
     * (as in the real primitive); otherwise splice file->pipe so the
     * syscall-level signature (AF_ALG socket + splice) is still present. */
    const char *into = op_fd < 0 ? "a pipe (there is no AF_ALG operation socket)"
                     : aead ? "the authencesn operation socket"
                     : "the sha256 operation socket";
    int accepted = 0;   /* 1 when the kernel accepted the splice() */
    int pipefd[2];
    if (pipe(pipefd) == 0) {
        ssize_t moved;
        if (op_fd >= 0) {
            (void)write(pipefd[1], pad, 16);
            moved = splice(pipefd[0], NULL, op_fd, NULL, 16, 0);
        } else {
            moved = splice(target_fd, NULL, pipefd[1], NULL, 16, 0);
        }
        if (moved < 0)
            fprintf(stderr, "splice() into %s: %s\n", into, strerror(errno));
        else
            accepted = 1;
        close(pipefd[0]);
        close(pipefd[1]);
    } else {
        perror("pipe");
    }

    if (op_fd >= 0)
        close(op_fd);
    close(alg_fd);
    close(target_fd);
    if (!accepted) {
        fprintf(stderr, "[-] copyfail: the kernel accepted no splice() into %s: "
                "an attempt, not the pattern\n", into);
        return 1;
    }
    printf("[+] copyfail behavioral pattern emitted against %s (splice() into %s)\n",
           target_path, into);
    return 0;
}
