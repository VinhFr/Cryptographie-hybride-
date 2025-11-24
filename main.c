#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

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

    // 1) Kết nối socket
    int sock = (strcmp(mode, "server") == 0) ? start_server(ip, port)
                                             : start_client(ip, port);
    if (sock < 0) return 1;
    printf("Connected.\n");

    // 2) Generate DH key
    EVP_PKEY *kx = generate_dh_key("dhparams.pem");
    if (!kx) {
        fprintf(stderr, "Failed to generate DH key\n");
        close(sock);
        return 1;
    }

    // 3) Load DSA keys từ file
    EVP_PKEY *sig = NULL;
    EVP_PKEY *peer_sig_pub = NULL;
    if (strcmp(mode, "server") == 0) {
        sig = load_dsa_private("server_dsa_priv.pem");
        peer_sig_pub = load_dsa_public("client_dsa_pub.pem");
    } else {
        sig = load_dsa_private("client_dsa_priv.pem");
        peer_sig_pub = load_dsa_public("server_dsa_pub.pem");
    }

    if (!sig || !peer_sig_pub) {
        fprintf(stderr, "Failed to load DSA keys\n");
        EVP_PKEY_free(kx);
        close(sock);
        return 1;
    }

    // 4) In thông tin DH public key (optional)
    int publen = 0;
    unsigned char *pubder = pubkey_to_der(kx, &publen);
    if (pubder) {
        print_sha256("[LOCAL] pubder", pubder, publen);
        dump_hex("[LOCAL] pubder head", pubder, publen < 64 ? publen : 64, 64);
        int tail = publen < 64 ? publen : 64;
        dump_hex("[LOCAL] pubder tail", pubder + publen - tail, tail, tail);

        // ghi ra file để tham khảo
        FILE *f = fopen("last_pub.der", "wb");
        if (f) { fwrite(pubder, 1, publen, f); fclose(f); }
        OPENSSL_free(pubder);
    }

    // 5) Handshake
    unsigned char aes_key[32];
    if (!do_handshake(sock, kx, sig, peer_sig_pub, aes_key)) {
        fprintf(stderr, "Handshake failed\n");
        EVP_PKEY_free(kx);
        EVP_PKEY_free(sig);
        EVP_PKEY_free(peer_sig_pub);
        close(sock);
        return 1;
    }
    printf("Handshake done. AES-256 key derived.\n");

    // 6) Start send/receive threads
    thread_args_t args;
    args.sock = sock;
    memcpy(args.aes_key, aes_key, 32);

    pthread_t t1, t2;
    if (pthread_create(&t1, NULL, recv_loop, &args) != 0 ||
        pthread_create(&t2, NULL, send_loop, &args) != 0) {
        perror("pthread_create");
        EVP_PKEY_free(kx);
        EVP_PKEY_free(sig);
        EVP_PKEY_free(peer_sig_pub);
        close(sock);
        return 1;
    }

    pthread_join(t2, NULL);
    shutdown(sock, SHUT_WR);
    pthread_join(t1, NULL);

    // 7) Cleanup
    EVP_PKEY_free(kx);
    EVP_PKEY_free(sig);
    EVP_PKEY_free(peer_sig_pub);
    close(sock);

    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
