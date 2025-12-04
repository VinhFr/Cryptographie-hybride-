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

// ---------- Threads de communication (envoi / réception) ----------

typedef struct {
    int sock;
    unsigned char aes_key[32];
} thread_args_t;

void *recv_loop(void *arg) {
    thread_args_t *t = arg;
    int sock = t->sock;

    /* clé maître (PRK) issue du handshake */
    unsigned char master[32];
    memcpy(master, t->aes_key, 32);

    while (1) {
        /* 1) recevoir le compteur (4 octets) */
        unsigned char *cnt_buf = NULL; uint32_t cnt_len;
        if (recv_blob(sock, &cnt_buf, &cnt_len) < 0) break;
        if (!cnt_buf || cnt_len != 4) { if (cnt_buf) OPENSSL_free(cnt_buf); break; }
        uint32_t counter_net;
        memcpy(&counter_net, cnt_buf, 4);
        OPENSSL_free(cnt_buf);
        uint32_t counter = ntohl(counter_net);

        /* 2) recevoir l'IV */
        unsigned char *iv = NULL; uint32_t ivlen;
        if (recv_blob(sock, &iv, &ivlen) < 0) break;

        /* 3) recevoir le ciphertext */
        unsigned char *ct = NULL; uint32_t ctlen;
        if (recv_blob(sock, &ct, &ctlen) < 0) { if (iv) OPENSSL_free(iv); break; }

        /* 4) recevoir le tag */
        unsigned char *tag = NULL; uint32_t taglen;
        if (recv_blob(sock, &tag, &taglen) < 0) { if (iv) OPENSSL_free(iv); if (ct) OPENSSL_free(ct); break; }

        /* 5) dériver la clé de session par-message à partir de la clé maître + compteur */
        unsigned char session_key[32];
        if (!refresh_session_key_per_message(master, sizeof(master), session_key, counter)) {
            fprintf(stderr, "Failed to derive per-message key (recv)\n");
            if (iv) OPENSSL_free(iv);
            if (ct) OPENSSL_free(ct);
            if (tag) OPENSSL_free(tag);
            break;
        }

        /* 6) Optionnel : afficher la clé de session (debug) */
        fprintf(stderr, "[SESSION RCV #%u] ", counter);
        for (int i = 0; i < 32; ++i) fprintf(stderr, "%02X", session_key[i]);
        fprintf(stderr, "\n");

        /* 7) déchiffrer avec session_key */
        unsigned char *pt = NULL; int ptlen;
        int ok = aes_gcm_decrypt(session_key, 32, iv, ivlen, ct, ctlen, tag, taglen, &pt, &ptlen);
        if (!ok) {
            fprintf(stderr, "Decryption failed (tag mismatch?)\n");
        } else {
            /* afficher le texte clair */
            fwrite(pt, 1, ptlen, stdout);
            printf("\n> "); fflush(stdout);
            OPENSSL_free(pt);
        }

        /* 8) nettoyage des buffers reçus */
        OPENSSL_free(iv);
        OPENSSL_free(ct);
        OPENSSL_free(tag);

        /* effacer la clé de session de la mémoire */
        OPENSSL_cleanse(session_key, sizeof(session_key));
    }

    return NULL;
}

void *send_loop(void *arg) {
    thread_args_t *t = arg;
    int sock = t->sock;

    /* clé maître (PRK) issue du handshake */
    unsigned char master[32];
    memcpy(master, t->aes_key, 32);

    char buf[4096];
    uint32_t counter = 1; /* commence à 1 */

    while (1) {
        printf("> "); fflush(stdout);
        if (!fgets(buf, sizeof(buf), stdin)) break;
        size_t len = strlen(buf);
        if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0', len--;

        /* 1) dériver la clé de session par-message */
        unsigned char session_key[32];
        if (!refresh_session_key_per_message(master, sizeof(master), session_key, counter)) {
            fprintf(stderr, "Failed to derive per-message key (send)\n");
            break;
        }

        /* 2) Optionnel : afficher la clé de session (debug) */
        fprintf(stderr, "[SESSION SND #%u] ", counter);
        for (int i = 0; i < 32; ++i) fprintf(stderr, "%02X", session_key[i]);
        fprintf(stderr, "\n");

        /* 3) chiffrer avec session_key */
        unsigned char *iv = NULL, *ct = NULL, *tag = NULL;
        int ivlen, ctlen, taglen;
        if (!aes_gcm_encrypt(session_key, 32, (unsigned char*)buf, (int)len,
                             &iv, &ivlen, &ct, &ctlen, &tag, &taglen)) {
            fprintf(stderr, "Encryption failed\n");
            OPENSSL_cleanse(session_key, sizeof(session_key));
            break;
        }

        /* 4) envoyer d'abord le compteur (ordre réseau) sur 4 octets */
        uint32_t counter_net = htonl(counter);
        if (send_blob(sock, (unsigned char*)&counter_net, sizeof(counter_net)) < 0) {
            OPENSSL_free(iv); OPENSSL_free(ct); OPENSSL_free(tag);
            OPENSSL_cleanse(session_key, sizeof(session_key));
            break;
        }

        /* 5) envoyer iv, ct, tag */
        if (send_blob(sock, iv, ivlen) < 0) { OPENSSL_free(iv); OPENSSL_free(ct); OPENSSL_free(tag); OPENSSL_cleanse(session_key, sizeof(session_key)); break; }
        if (send_blob(sock, ct, ctlen) < 0) { OPENSSL_free(iv); OPENSSL_free(ct); OPENSSL_free(tag); OPENSSL_cleanse(session_key, sizeof(session_key)); break; }
        if (send_blob(sock, tag, taglen) < 0) { OPENSSL_free(iv); OPENSSL_free(ct); OPENSSL_free(tag); OPENSSL_cleanse(session_key, sizeof(session_key)); break; }

        OPENSSL_free(iv); OPENSSL_free(ct); OPENSSL_free(tag);

        /* 6) effacer la clé de session et incrémenter le compteur */
        OPENSSL_cleanse(session_key, sizeof(session_key));
        counter++;
    }

    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s server|client ip port\n", argv[0]);
        return 1;
    }

    OpenSSL_add_all_algorithms();

    const char *mode = argv[1];
    const char *ip = argv[2];
    int port = atoi(argv[3]);

    /* Connexion socket */
    int sock = (strcmp(mode, "server") == 0) ? start_server(ip, port)
                                             : start_client(ip, port);
    if (sock < 0) return 1;
    printf("Connected.\n");

    /* Générer la clé DH */
    EVP_PKEY *kx = generate_dh_key("dhparams.pem");
    if (!kx) {
        fprintf(stderr, "Failed to generate DH key\n");
        close(sock);
        return 1;
    }

    /* Charger les clés DSA depuis des fichiers */
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

    /* Affichage et sauvegarde de la clé publique DH (optionnel) */
    int publen = 0;
    unsigned char *pubder = pubkey_to_der(kx, &publen);
    if (pubder) {
        print_sha256("[LOCAL] pubder", pubder, publen);
        dump_hex("[LOCAL] pubder head", pubder, publen < 64 ? publen : 64, 64);
        int tail = publen < 64 ? publen : 64;
        dump_hex("[LOCAL] pubder tail", pubder + publen - tail, tail, tail);
        FILE *f = fopen("last_pub.der", "wb");
        if (f) { fwrite(pubder, 1, publen, f); fclose(f); }
        OPENSSL_free(pubder);
    }

    /* Effectuer le handshake et échanger la clé publique DH */
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

    /* Lancer les threads d'envoi / réception */
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

    /* Exécution de 2 threads en parallèle (envoi / réception) */
    pthread_join(t2, NULL);
    shutdown(sock, SHUT_WR);
    pthread_join(t1, NULL);

    /* Libération des ressources allouées */
    EVP_PKEY_free(kx);
    EVP_PKEY_free(sig);
    EVP_PKEY_free(peer_sig_pub);
    close(sock);

    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
