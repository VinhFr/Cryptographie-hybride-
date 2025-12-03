#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>

/* ---------- Génération de clés ----------
 * Paramètres :
 *   - param_file : fichier contenant les paramètres DH
 *                  (par exemple : p = 2048 bits, g = 2)
 *
 *   - filename   : fichier contenant une clé privée (private key)
 *                  ou une clé publique (public key), selon la fonction.
 */
EVP_PKEY *generate_dh_key(const char *param_file);

/* Charge une clé privée DSA depuis un fichier PEM */
EVP_PKEY *load_dsa_private(const char *filename);

/* Charge une clé publique DSA depuis un fichier PEM */
EVP_PKEY *load_dsa_public(const char *filename);

/* ---------- DSA sign / verify ----------
 * Signer un message avec une clé privée DSA
 * Paramètres :
 *   - priv : clé privée DSA, utilisée pour signer
 *   - pub  : clé publique DSA, utilisée pour vérifier
 *   - msg  : message à signer ou vérifier
 */
unsigned char *dsa_sign(EVP_PKEY *priv, const unsigned char *msg, size_t msglen, size_t *siglen);

/* Vérifier une signature DSA avec une clé publique */
int dsa_verify(EVP_PKEY *pub, const unsigned char *msg, size_t msglen,const unsigned char *sig, size_t siglen);

/* ---------- DH derive ----------
 * Paramètres :
 *   - priv      : clé privée DH (notre clé)
 *   - peer_pub  : clé publique DH de l'autre partie
 *   - secret_len: longueur du secret dérivé (sortie)
 *
 * Retourne : le secret partagé dérivé (buffer alloué via OPENSSL_malloc)
 */
unsigned char *dh_derive_shared(EVP_PKEY *priv, EVP_PKEY *peer_pub, size_t *secret_len);

/* ---------- Dérivation de clé de session ---------- */
/* Dérive une clé de session AES-256 à partir d'un secret partagé en utilisant HKDF-SHA256 */
int derive_session_key_hkdf(
    const unsigned char *shared, size_t shared_len,
    unsigned char *session_key,
    const unsigned char *salt, size_t salt_len,
    const unsigned char *info, size_t info_len
);

/* Wrapper pratique pour générer une clé de session par message avec un compteur */
int refresh_session_key_per_message(
    const unsigned char *shared, size_t shared_len,
    unsigned char *session_key,
    uint32_t counter
);

/* ---------- Conversion clé publique <-> DER ---------- */
/* Convertit une clé publique EVP_PKEY vers le format DER */
unsigned char *pubkey_to_der(EVP_PKEY *pkey, int *out_len);

/* Reconstruit une clé publique EVP_PKEY à partir d'un buffer DER */
EVP_PKEY *der_to_pubkey(const unsigned char *der, int der_len);

/* ---------- AES-256-GCM encrypt/decrypt ----------
 * Renvoie 1 si succès, 0 sinon.
 */

 /* Chiffrement AES-256-GCM */
int aes_gcm_encrypt(const unsigned char *key, int keylen, const unsigned char *plaintext, int ptlen, unsigned char **out_iv, int *iv_len, unsigned char **out_ct, int *ct_len, unsigned char **out_tag, int *tag_len);

/* Déchiffrement AES-256-GCM */
int aes_gcm_decrypt( const unsigned char *key, int keylen, const unsigned char *iv, int ivlen,const unsigned char *ct, int ctlen,const unsigned char *tag, int taglen, unsigned char **out_plain, int *out_len);

/* ---------- Echange (Handshake E2EE) ---------- */
int do_handshake(int sock, EVP_PKEY *kx_priv, EVP_PKEY *sig_priv, EVP_PKEY *peer_sig_pub, unsigned char *aes_key_out);

#endif /* CRYPTO_H */
