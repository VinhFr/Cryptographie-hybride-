#include "crypto.h"

#include <string.h>          // memcpy, strlen
#include <stdint.h>          // uint32_t (send_blob, recv_blob)
#include <openssl/rand.h>    // RAND_bytes
#include <openssl/pem.h>     // PEM_read/write (private/public key)
#include <openssl/x509.h>    // i2d_PUBKEY, d2i_PUBKEY
#include <openssl/bio.h>     // BIO_new_file, PEM_read_bio_DHparams
#include <openssl/kdf.h>     // pour HKDF

/*
  Génère une paire de clés DH à partir d’un fichier de paramètres (p, g).

  Étapes :
    1) Lecture des paramètres DH depuis un fichier PEM.
    2) Création d’un EVP_PKEY contenant ces paramètres.
    3) Génération de la clé DH (publique + privée).

  Retour :
    - EVP_PKEY* : clé DH complète
    - NULL : erreur
*/

EVP_PKEY *generate_dh_key(const char *param_file) {
  EVP_PKEY *pkey = NULL;
  DH *dh_params = NULL;
  BIO *bio = NULL;

  /* 1) Ouvrir le fichier de paramètres DH */
  bio = BIO_new_file(param_file, "r");
  if (!bio) {
      fprintf(stderr, "Erreur : impossible d'ouvrir le fichier de paramètres DH %s\n", param_file);
      return NULL;
  }

  /* 2) Lire la structure DH* depuis le PEM */
  dh_params = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_free(bio); // libération du BIO

  if (!dh_params) {
      fprintf(stderr, "Erreur : impossible de lire les paramètres DH depuis le fichier\n");
      return NULL;
  }

  /* 3) Créer un EVP_PKEY pour contenir les paramètres (p,g) */
  pkey = EVP_PKEY_new();
  if (!pkey) {
      DH_free(dh_params);
      return NULL;
  }

  /* 4) Assigner les paramètres DH à l'EVP_PKEY (pkey prend la propriété de dh_params) */
  if (EVP_PKEY_assign_DH(pkey, dh_params) != 1) {
      /* si échec, dh_params n'est pas pris en charge -> free */
      DH_free(dh_params);
      EVP_PKEY_free(pkey);
      return NULL;
  }

  /* 5) Initialiser le contexte pour générer la paire de clés */
  EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!kctx) {
      EVP_PKEY_free(pkey);
      return NULL;
  }

  if (EVP_PKEY_keygen_init(kctx) <= 0) {
      EVP_PKEY_CTX_free(kctx);
      EVP_PKEY_free(pkey);
      return NULL;
  }

  EVP_PKEY *dh_key = NULL;
  /* Génération de la paire (priv/pub) basée sur les paramètres chargés */
  if (EVP_PKEY_keygen(kctx, &dh_key) <= 0) {
      EVP_PKEY_CTX_free(kctx);
      EVP_PKEY_free(pkey);
      return NULL;
  }

  /* on n'a plus besoin de l'objet contenant seulement les paramètres */
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(kctx);

  /* dh_key contient maintenant la paire complète et les paramètres (p,g) */
  return dh_key;
}

/* Chargement d'une clé privée DSA depuis un fichier PEM */
EVP_PKEY *load_dsa_private(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return pkey;
}

/* Chargement d'une clé publique DSA depuis un fichier PEM */
EVP_PKEY *load_dsa_public(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;
    EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    return pkey;
}

/*
  Signature DSA (avec SHA-256).
  Renvoie un buffer alloué (OPENSSL_malloc) contenant la signature et met à jour siglen.
  NULL en cas d'erreur.
*/
unsigned char *dsa_sign(EVP_PKEY *priv, const unsigned char *msg, size_t msglen, size_t *siglen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char *sig = NULL;
    size_t slen = 0;
    if (!ctx) return NULL;

    /* On spécifie SHA256 pour DSA */
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv) <= 0)
        goto err;

    /* déterminer la taille nécessaire pour la signature */
    if (EVP_DigestSign(ctx, NULL, &slen, msg, msglen) <= 0)
        goto err;

    sig = OPENSSL_malloc(slen);
    if (!sig) goto err;

    /* calcul réel de la signature */
    if (EVP_DigestSign(ctx, sig, &slen, msg, msglen) <= 0) {
        OPENSSL_free(sig);
        sig = NULL;
        goto err;
    }

    *siglen = slen;

err:
    EVP_MD_CTX_free(ctx);
    return sig;
}

/* Sérialise une clé publique en DER (i2d_PUBKEY) */
unsigned char *pubkey_to_der(EVP_PKEY *pkey, int *out_len) {
    unsigned char *der = NULL;
    int len = i2d_PUBKEY(pkey, &der);
    if (len <= 0) { if (der) OPENSSL_free(der); return NULL; }
    *out_len = len;
    return der;
}

/* Désérialise une clé publique depuis DER */
EVP_PKEY *der_to_pubkey(const unsigned char *der, int der_len) {
    const unsigned char *p = der;
    return d2i_PUBKEY(NULL, &p, der_len);
}

/* Vérification DSA (SHA-256). Retourne 1 si OK, 0 sinon. */
int dsa_verify(EVP_PKEY *pub, const unsigned char *msg, size_t msglen,
               const unsigned char *sig, size_t siglen) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;

    if (!ctx) return 0;

    if (!pub) {
        fprintf(stderr, "Clé publique NULL !\n");
        return 0;
    }

    fprintf(stderr, "Type de clé: %d\n", EVP_PKEY_base_id(pub));
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) <= 0)
        goto end;
    if (EVP_DigestVerify(ctx, sig, siglen, msg, msglen) == 1)
        ok = 1;   // signature valide

end:
    EVP_MD_CTX_free(ctx);
    return ok;
}

/*
  Dérive le secret partagé (classic DH) :
  Entrées : clé privée locale (EVP_PKEY) et clé publique du pair (EVP_PKEY).
  Renvoie un buffer (OPENSSL_malloc) contenant le secret et met à jour secret_len.
  NULL en cas d'erreur.
*/
unsigned char *dh_derive_shared(EVP_PKEY *priv, EVP_PKEY *peer_pub, size_t *secret_len) {
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *secret = NULL;
    size_t slen = 0;

    /* Context basé sur la clé privée locale */
    ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_derive_init(ctx) <= 0) goto err;

    /* associer la clé publique du pair */
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub) <= 0) goto err;

    /* déterminer la longueur du secret partagé */
    if (EVP_PKEY_derive(ctx, NULL, &slen) <= 0) goto err;

    secret = OPENSSL_malloc(slen);
    if (!secret) goto err;

    /* dérivation effective */
    if (EVP_PKEY_derive(ctx, secret, &slen) <= 0) {
        OPENSSL_free(secret);
        secret = NULL;
        goto err;
    }

    *secret_len = slen;

err:
    EVP_PKEY_CTX_free(ctx);
    return secret;
}

/*
  Dérive une clé de session AES-256 (32 octets) à partir d'un secret partagé
  en utilisant HKDF (SHA-256).

  Paramètres :
    - shared/shared_len : secret d'entrée
    - session_key : buffer de sortie (doit avoir au moins 32 octets)
    - salt/salt_len : sel (peut être NULL/0)
    - info/info_len : information contextuelle (peut être NULL/0)

  Retour : 1 = succès, 0 = échec
*/
int derive_session_key_hkdf(const unsigned char *shared, size_t shared_len, unsigned char *session_key, const unsigned char *salt, size_t salt_len, const unsigned char *info, size_t info_len) {
    if (!shared || !session_key) return 0;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return 0;

    if (EVP_PKEY_derive_init(pctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto err;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) <= 0) goto err;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, shared, (int)shared_len) <= 0) goto err;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0) goto err;

    size_t out_len = 32; // longueur souhaitée (AES-256)
    if (EVP_PKEY_derive(pctx, session_key, &out_len) <= 0 || out_len != 32) goto err;

    EVP_PKEY_CTX_free(pctx);
    return 1;

err:
    EVP_PKEY_CTX_free(pctx);
    return 0;
}

/*
  Wrapper pratique pour dériver une nouvelle clé de session par message
  en incorporant un compteur (big-endian) dans le paramètre "info".
*/
int refresh_session_key_per_message(
    const unsigned char *shared, size_t shared_len,
    unsigned char *session_key,
    uint32_t counter
) {
    unsigned char info[4];
    /* stocke le compteur en big-endian */
    info[0] = (counter >> 24) & 0xFF;
    info[1] = (counter >> 16) & 0xFF;
    info[2] = (counter >> 8) & 0xFF;
    info[3] = counter & 0xFF;

    return derive_session_key_hkdf(shared, shared_len, session_key, NULL, 0, info, 4);
}

/*
  AES-GCM encryption :
  - Génère un IV aléatoire (12 octets)
  - Alloue et renvoie le ciphertext et le tag séparément

  Sortie : *out_iv (IV), *out_ct (ciphertext), *out_tag (tag)
  Les buffers sont alloués via OPENSSL_malloc et doivent être libérés par l'appelant.
*/
int aes_gcm_encrypt(const unsigned char *key, int keylen, const unsigned char *plaintext, int ptlen, unsigned char **out_iv, int *iv_len, unsigned char **out_ct, int *ct_len, unsigned char **out_tag, int *tag_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *iv = NULL, *ct = NULL, *tag = NULL;
    int len, flen;
    int ret = 0;
    int tlen = 16;
    int ct_alloc = ptlen + 16;

    iv = OPENSSL_malloc(12);
    if (!iv) goto cleanup;
    if (RAND_bytes(iv, 12) != 1) goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto cleanup;

    ct = OPENSSL_malloc(ct_alloc);
    if (!ct) goto cleanup;

    if (EVP_EncryptUpdate(ctx, ct, &len, plaintext, ptlen) != 1) goto cleanup;
    flen = len;

    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) goto cleanup;
    flen += len;

    tag = OPENSSL_malloc(tlen);
    if (!tag) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tlen, tag) != 1) goto cleanup;

    *out_iv = iv; *iv_len = 12;
    *out_ct = ct; *ct_len = flen;
    *out_tag = tag; *tag_len = tlen;
    iv = ct = tag = NULL; // transfert de propriété
    ret = 1;
cleanup:
    if (iv) OPENSSL_free(iv);
    if (ct) OPENSSL_free(ct);
    if (tag) OPENSSL_free(tag);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
  AES-GCM decryption : renvoie le plaintext (OPENSSL_malloc) sur succès.
  Vérifie le tag ; si échec, retourne 0.
*/
int aes_gcm_decrypt( const unsigned char *key, int keylen, const unsigned char *iv, int ivlen,const unsigned char *ct, int ctlen,const unsigned char *tag, int taglen, unsigned char **out_plain, int *out_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *pt = NULL;
    int len, flen;
    int ret = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL) != 1) goto cleanup;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto cleanup;

    pt = OPENSSL_malloc(ctlen + 16);
    if (!pt) goto cleanup;

    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ctlen) != 1) goto cleanup;
    flen = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, taglen, (void *)tag) != 1) goto cleanup;
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1) goto cleanup; // échec si tag invalide
    flen += len;

    *out_plain = pt; *out_len = flen;
    pt = NULL;
    ret = 1;
cleanup:
    if (pt) OPENSSL_free(pt);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* Affiche un buffer en hexadécimal (debug) */
void dump_hex(const char *label, const unsigned char *buf, size_t len, size_t show) {
    fprintf(stderr, "%s (%zu bytes):", label, len);
    size_t n = (show && show < len) ? show : len;
    for (size_t i = 0; i < n; ++i) fprintf(stderr, "%02X", buf[i]);
    if (n < len) fprintf(stderr, "...");
    fprintf(stderr, "\n");
}

/* Affiche les 8 premiers octets du SHA-256 d'un buffer (empreinte abrégée) */
void print_sha256(const char *label, const unsigned char *buf, size_t len) {
    unsigned char dgst[32];
    if (EVP_Digest(buf, len, dgst, NULL, EVP_sha256(), NULL)) {
        fprintf(stderr, "%s sha256: ", label);
        for (int i = 0; i < 8; ++i) fprintf(stderr, "%02X", dgst[i]); // empreinte 8 octets
        fprintf(stderr, "...\n");
    }
}

/*
  Effectue le handshake DH signé et dérive la clé AES-256 finale.

  Protocole (simplifié) :
    - Sérialiser notre clé publique DH (DER)
    - Signer cette DER avec notre clé privée DSA
    - Envoyer (pub_der, signature)
    - Recevoir (peer_pub_der, peer_signature)
    - Vérifier la signature DSA du pair
    - Calculer le secret DH partagé
    - Dériver la clé AES-256 via HKDF
*/
int do_handshake(int sock, EVP_PKEY *kx_priv, EVP_PKEY *sig_priv, EVP_PKEY *peer_sig_pub, unsigned char *aes_key_out) {
    int ok = 0;
    unsigned char *kx_pub_der = NULL, *sig_of_kx = NULL;
    unsigned char *kx_pub_peer = NULL, *sig_of_kx_peer = NULL;
    int kx_pub_len = 0;
    size_t sig_of_kx_len = 0;
    uint32_t len = 0;
    EVP_PKEY *peer_kx_key = NULL;

    /* 1) Sérialiser la clé publique DH locale (DER)  */
    kx_pub_der = pubkey_to_der(kx_priv, &kx_pub_len);
    if (!kx_pub_der) goto cleanup;

    /* 2) Signer cette clé DH avec la clé privée DSA */
    sig_of_kx = dsa_sign(sig_priv, kx_pub_der, kx_pub_len, &sig_of_kx_len);
    if (!sig_of_kx) goto cleanup;

    /* 3) Journaux (log) : tête/queue + empreintes */
    fprintf(stderr, "[LOCAL] DH public key length: %d\n", kx_pub_len);
    int head_len = kx_pub_len < 64 ? kx_pub_len : 64;
    int tail_len = head_len;
    dump_hex("[LOCAL] DH HEAD", kx_pub_der, head_len, head_len);
    dump_hex("[LOCAL] DH TAIL", kx_pub_der + kx_pub_len - tail_len, tail_len, tail_len);
    print_sha256("[LOCAL] DH SHA256", kx_pub_der, kx_pub_len);
    print_sha256("[LOCAL] DSA signature", sig_of_kx, sig_of_kx_len);

    /* 4) Envoyer la clé publique DH et sa signature */
    if (send_blob(sock, kx_pub_der, kx_pub_len) < 0) goto cleanup;
    if (sig_of_kx_len > UINT32_MAX || send_blob(sock, sig_of_kx, (uint32_t)sig_of_kx_len) < 0) goto cleanup;

    /* 5) Recevoir la clé publique DH du pair */
    if (recv_blob(sock, &kx_pub_peer, &len) < 0 || !kx_pub_peer || len == 0) goto cleanup;
    int peer_kx_len = (int)len;

    /* 6) Recevoir la signature DSA de la clé DH du pair */
    if (recv_blob(sock, &sig_of_kx_peer, &len) < 0 || !sig_of_kx_peer) goto cleanup;
    uint32_t sig_of_kx_peer_len = len;

    /* 7) Journaux pour la clé reçue */
    fprintf(stderr, "[PEER] DH public key length: %d\n", peer_kx_len);
    head_len = peer_kx_len < 64 ? peer_kx_len : 64;
    tail_len = head_len;
    dump_hex("[PEER] DH HEAD", kx_pub_peer, head_len, head_len);
    dump_hex("[PEER] DH TAIL", kx_pub_peer + peer_kx_len - tail_len, tail_len, tail_len);
    print_sha256("[PEER] DH SHA256", kx_pub_peer, peer_kx_len);
    print_sha256("[PEER] DSA signature", sig_of_kx_peer, sig_of_kx_peer_len);

    /* 8) Vérifier la signature DSA du pair */
    if (!dsa_verify(peer_sig_pub, kx_pub_peer, peer_kx_len, sig_of_kx_peer, sig_of_kx_peer_len)) {
        fprintf(stderr, "Échec de la vérification de la signature ! Abandon du handshake.\n");
        goto cleanup;
    }

    /* 9) Reconstruire la clé DH du pair à partir du DER */
    peer_kx_key = der_to_pubkey(kx_pub_peer, peer_kx_len);
    if (!peer_kx_key) goto cleanup;

    /* 10) Calculer le secret partagé DH */
    size_t secret_len = 0;
    unsigned char *secret = dh_derive_shared(kx_priv, peer_kx_key, &secret_len);
    if (!secret) goto cleanup;

    /* 11) Dériver la clé AES-256 à partir du secret DH */
    if (!derive_session_key_hkdf(secret, secret_len, aes_key_out, NULL, 0, NULL, 0)) {
      OPENSSL_free(secret);
      goto cleanup;
    }

    OPENSSL_free(secret);

    /* 12) Journaliser la clé AES dérivée (debug uniquement) */
    fprintf(stderr, "[AES] Derived AES-256 key: ");
    for (int i = 0; i < 32; i++) fprintf(stderr, "%02X", aes_key_out[i]);
    fprintf(stderr, "\n");

    ok = 1;

cleanup:
    if (kx_pub_der) OPENSSL_free(kx_pub_der);
    if (sig_of_kx) OPENSSL_free(sig_of_kx);
    if (kx_pub_peer) OPENSSL_free(kx_pub_peer);
    if (sig_of_kx_peer) OPENSSL_free(sig_of_kx_peer);
    EVP_PKEY_free(peer_kx_key);
    return ok;
}
