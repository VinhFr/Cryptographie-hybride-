#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <stdlib.h>


#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>

/* ---------- Key generation ----------
 * Paramètres :
 *   - param_file : fichier contenant les paramètres DH
 *                  (par exemple : p = 2048 bits, g = 2)
 *
 *   - filename   : fichier contenant une clé privée (private key)
 *                  ou une clé publique (public key), selon la fonction.
 */
EVP_PKEY *generate_dh_key(const char *param_file);
EVP_PKEY *load_dsa_private(const char *filename);
EVP_PKEY *load_dsa_public(const char *filename);

/* ---------- DSA sign / verify ----------
 * Paramètres :
 *   - priv : clé privée DSA, utilisée pour signer
 *   - pub  : clé publique DSA, utilisée pour vérifier
 *   - msg  : message à signer ou vérifier
 */
unsigned char *dsa_sign(EVP_PKEY *priv, const unsigned char *msg, size_t msglen, size_t *siglen);
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
int derive_aes_key( const unsigned char *shared, size_t shared_len,unsigned char *out32);

/* Convertit une clé publique EVP_PKEY vers le format DER (binaire).
 * Retourne un buffer alloué via OPENSSL_malloc(), à libérer avec OPENSSL_free().
 */
unsigned char *pubkey_to_der(EVP_PKEY *pkey, int *out_len);

/* Reconstruit une clé publique EVP_PKEY à partir d'un buffer DER (binaire). */
EVP_PKEY *der_to_pubkey(const unsigned char *der, int der_len);

/* ---------- Session key (DH → HKDF → AES-256) ---------- */

/* Dérive une clé AES-256 à partir d'un secret DH via HKDF-SHA256 */
int generate_session_key(
    const unsigned char *dh_secret, size_t secret_len,
    unsigned char *session_key_out, size_t key_len
);

/* Renouvelle la clé de session (nouvelle DH → nouvelle clé AES) */
int refresh_session_key(
    EVP_PKEY *dh_priv, EVP_PKEY *peer_pub,
    unsigned char *session_key_out
);

/* Efface une clé de session de la mémoire */
void clear_session_key(unsigned char *key, size_t len);

/* ---------- AES-256-GCM encrypt/decrypt ----------
 * Renvoie 1 si succès, 0 sinon.
 */
int aes_gcm_encrypt(const unsigned char *key, int keylen, const unsigned char *plaintext, int ptlen, unsigned char **out_iv, int *iv_len, unsigned char **out_ct, int *ct_len, unsigned char **out_tag, int *tag_len);
int aes_gcm_decrypt( const unsigned char *key, int keylen, const unsigned char *iv, int ivlen,const unsigned char *ct, int ctlen,const unsigned char *tag, int taglen, unsigned char **out_plain, int *out_len);

/* ---------- Echange (Handshake E2EE) ---------- */
int do_handshake(int sock, EVP_PKEY *kx_priv, EVP_PKEY *sig_priv, EVP_PKEY *peer_sig_pub, unsigned char *aes_key_out);

#endif /* CRYPTO_H */
