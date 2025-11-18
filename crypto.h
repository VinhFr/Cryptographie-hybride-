#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>

EVP_PKEY *generate_dh_key();
EVP_PKEY *generate_dsa_key();
unsigned char *dsa_sign(EVP_PKEY *priv, const unsigned char *msg, size_t msglen, size_t *siglen);
int dsa_verify(EVP_PKEY *pub, const unsigned char *msg, size_t msglen,const unsigned char *sig, size_t siglen);
unsigned char *dh_derive_shared(EVP_PKEY *priv, EVP_PKEY *peer_pub, size_t *secret_len);
int derive_aes_key( const unsigned char *shared, size_t shared_len,unsigned char *out32);
int aes_gcm_encrypt(const unsigned char *key, int keylen, const unsigned char *plaintext, int ptlen, unsigned char **out_iv, int *iv_len, unsigned char **out_ct, int *ct_len, unsigned char **out_tag, int *tag_len);
int aes_gcm_decrypt( const unsigned char *key, int keylen, const unsigned char *iv, int ivlen,const unsigned char *ct, int ctlen,const unsigned char *tag, int taglen, unsigned char **out_plain, int *out_len);
#endif /* CRYPTO_H */
