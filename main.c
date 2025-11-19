#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "crypto.h"
#include "network.h"

// ---------- Chat threads ----------

typedef struct {
    int sock;
    unsigned char aes_key[32];
} thread_args_t;

void *recv_loop(void *arg) {
    thread_args_t *t = arg;
    int sock = t->sock;
    unsigned char key[32]; memcpy(key, t->aes_key, 32);
    while (1) {
        // receive iv
        unsigned char *iv = NULL; uint32_t ivlen;
        if (recv_blob(sock, &iv, &ivlen) < 0) break;
        // receive ct
        unsigned char *ct = NULL; uint32_t ctlen;
        if (recv_blob(sock, &ct, &ctlen) < 0) { if (iv) OPENSSL_free(iv); break; }
        // receive tag
        unsigned char *tag = NULL; uint32_t taglen;
        if (recv_blob(sock, &tag, &taglen) < 0) { if (iv) OPENSSL_free(iv); if (ct) OPENSSL_free(ct); break; }

        unsigned char *pt = NULL; int ptlen;
        int ok = aes_gcm_decrypt(key, 32, iv, ivlen, ct, ctlen, tag, taglen, &pt, &ptlen);
        if (!ok) {
            fprintf(stderr, "Decryption failed (tag mismatch?)\n");
        } else {
            // print plaintext
            fwrite(pt, 1, ptlen, stdout);
            printf("\n> "); fflush(stdout);
            OPENSSL_free(pt);
        }
        if (iv) OPENSSL_free(iv);
        if (ct) OPENSSL_free(ct);
        if (tag) OPENSSL_free(tag);
    }
    return NULL;
}

void *send_loop(void *arg) {
    thread_args_t *t = arg;
    int sock = t->sock;
    unsigned char key[32]; memcpy(key, t->aes_key, 32);
    char buf[4096];
    while (1) {
        printf("> "); fflush(stdout);
        if (!fgets(buf, sizeof(buf), stdin)) break;
        size_t len = strlen(buf);
        if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0', len--;
        unsigned char *iv = NULL, *ct = NULL, *tag = NULL;
        int ivlen, ctlen, taglen;
        if (!aes_gcm_encrypt(key, 32, (unsigned char*)buf, (int)len, &iv, &ivlen, &ct, &ctlen, &tag, &taglen)) {
            fprintf(stderr, "Encryption failed\n"); break;
        }
        // send iv, ct, tag as blobs
        if (send_blob(sock, iv, ivlen) < 0) { OPENSSL_free(iv); OPENSSL_free(ct); OPENSSL_free(tag); break; }
        if (send_blob(sock, ct, ctlen) < 0) { OPENSSL_free(iv); OPENSSL_free(ct); OPENSSL_free(tag); break; }
        if (send_blob(sock, tag, taglen) < 0) { OPENSSL_free(iv); OPENSSL_free(ct); OPENSSL_free(tag); break; }
        OPENSSL_free(iv); OPENSSL_free(ct); OPENSSL_free(tag);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s server|client ip port\n", argv[0]);
        return 1;
    }
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    const char *mode = argv[1];
    const char *ip = argv[2];
    int port = atoi(argv[3]);

    int sock = -1;
    if (strcmp(mode, "server") == 0) {
        sock = start_server(ip, port);
    } else {
        sock = start_client(ip, port);
    }
    if (sock < 0) return 1;
    printf("Connected.\n");

    // generate keypairs
    EVP_PKEY *kx = generate_dh_key();
    EVP_PKEY *sig = generate_dsa_key();

    if (!kx || !sig) { fprintf(stderr, "Keygen failed\n"); return 1; }

    unsigned char aes_key[32];
    if (!do_handshake(sock, kx, sig, aes_key)) {
        fprintf(stderr, "Handshake failed\n"); close(sock); return 1;
    }
    printf("Handshake done. AES-256 key derived.\n");

    // start send/receive threads
    pthread_t t1, t2;
    thread_args_t args;
    args.sock = sock;
    memcpy(args.aes_key, aes_key, 32);
    if (pthread_create(&t1, NULL, recv_loop, &args) != 0) { perror("pthread_create"); close(sock); return 1; }
    if (pthread_create(&t2, NULL, send_loop, &args) != 0) { perror("pthread_create"); close(sock); return 1; }

    pthread_join(t2, NULL);
    // if send_loop ends (e.g. EOF), shutdown socket to notify other side
    shutdown(sock, SHUT_WR);

    pthread_join(t1, NULL);

    close(sock);
    EVP_PKEY_free(kx);
    EVP_PKEY_free(sig);

    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
