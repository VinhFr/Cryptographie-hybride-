#include "crypto.h"   // prototypes của các hàm crypto
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/*
  Paramètres :
  pkey : pointeur vers la clé DH générée (clé publique et clé privée)
  pctx : contexte pour la génération des paramètres DH (p, g)
  kctx : contexte pour la génération de la clé DH

  Cette fonction génère une paire de clés Diffie-Hellman (DH) traditionnelle :
  1) Création d'un contexte pour générer les paramètres DH (longueur de la clé par défaut 2048 bits).
  2) Génération des paramètres DH (nombre premier p et générateur g).
  3) Création d'un contexte à partir des paramètres générés pour produire la paire de clés.
  4) Génération effective de la clé privée et publique DH dans pkey.
  5) Nettoyage des contextes et renvoi de la clé générée ou NULL en cas d'erreur.

  Note : la clé retournée dans pkey contient à la fois la clé privée et la clé publique.
*/
EVP_PKEY *generate_dh_key() {
    EVP_PKEY *pkey = NULL;
    DH *dh = NULL;

    // 1) Tạo DH với độ dài 2048 bits và generator 2
    dh = DH_new();
    if (!dh) return NULL;

    if (DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL) != 1) {
        DH_free(dh);
        return NULL;
    }

    // 2) Tạo EVP_PKEY từ DH
    pkey = EVP_PKEY_new();
    if (!pkey) {
        DH_free(dh);
        return NULL;
    }

    if (EVP_PKEY_assign_DH(pkey, dh) != 1) {
        DH_free(dh);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    // Lưu ý: pkey giờ quản lý dh, không cần free dh nữa

    // 3) Tạo keypair (public/private) cho DH
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
    if (EVP_PKEY_keygen(kctx, &dh_key) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return dh_key;
}


EVP_PKEY *generate_dsa_key() {
    EVP_PKEY *params = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;

    // 1) Tạo context sinh parameters DSA
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    if (!pctx) return NULL;

    if (EVP_PKEY_paramgen_init(pctx) <= 0) goto err;

    // Thiết lập độ dài DSA (2048 bits)
    if (EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, 2048) <= 0) goto err;

    // Sinh parameters (p, q, g)
    if (EVP_PKEY_paramgen(pctx, &params) <= 0) goto err;

    // 2) Tạo context sinh key dựa trên parameters
    kctx = EVP_PKEY_CTX_new(params, NULL);
    if (!kctx) goto err;

    if (EVP_PKEY_keygen_init(kctx) <= 0) goto err;

    // 3) Sinh keypair
    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) goto err;

    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    return pkey;

err:
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    return NULL;
}

unsigned char *dsa_sign(EVP_PKEY *priv, const unsigned char *msg, size_t msglen, size_t *siglen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char *sig = NULL;
    size_t slen = 0;
    if (!ctx) return NULL;

    // MUST specify SHA256 for DSA
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv) <= 0)
        goto err;

    // Lấy độ dài chữ ký cần thiết
    if (EVP_DigestSign(ctx, NULL, &slen, msg, msglen) <= 0)
        goto err;

    sig = OPENSSL_malloc(slen);
    if (!sig) goto err;

    // Ký số thật
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

// serialize public key to DER (i2d)
unsigned char *pubkey_to_der(EVP_PKEY *pkey, int *out_len) {
    unsigned char *der = NULL;
    int len = i2d_PUBKEY(pkey, &der);
    if (len <= 0) { if (der) OPENSSL_free(der); return NULL; }
    *out_len = len;
    return der;
}

// load public key from DER
EVP_PKEY *der_to_pubkey(const unsigned char *der, int der_len) {
    const unsigned char *p = der;
    return d2i_PUBKEY(NULL, &p, der_len);
}

int dsa_verify(EVP_PKEY *pub, const unsigned char *msg, size_t msglen,
               const unsigned char *sig, size_t siglen) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;

    if (!ctx) return 0;

    // MUST specify SHA256 for DSA verify
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) <= 0)
        goto end;

    if (EVP_DigestVerify(ctx, sig, siglen, msg, msglen) == 1)
        ok = 1;   // OK

end:
    EVP_MD_CTX_free(ctx);
    return ok;
}

// derive shared secret using classic DH
// hàm này dùng để tạo share-secret-key chung giữa 2 thiết bị.
// nhận vào publickey của đối tác và private key của mình để tính
unsigned char *dh_derive_shared(EVP_PKEY *priv, EVP_PKEY *peer_pub, size_t *secret_len) {
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *secret = NULL;
    size_t slen = 0;

    // Context dựa trên private key DH của mình
    ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) return NULL;

    // Khởi tạo quá trình derive (tính shared secret)
    if (EVP_PKEY_derive_init(ctx) <= 0) goto err;

    // Gán public key của peer (đối tác)
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub) <= 0) goto err;

    // Lấy độ dài của shared secret
    if (EVP_PKEY_derive(ctx, NULL, &slen) <= 0) goto err;

    // Cấp phát bộ nhớ để chứa shared secret
    secret = OPENSSL_malloc(slen);
    if (!secret) goto err;

    // Derive thực tế: tạo ra shared secret
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

int derive_aes_key( const unsigned char *shared, size_t shared_len,unsigned char *out32) {
    if (!EVP_Digest(shared, shared_len, out32, NULL, EVP_sha256(), NULL))
        return 0;
    return 1;
}

// AES-GCM encrypt: returns ciphertext (OPENSSL_malloc) with tag appended after ciphertext
// out: ct = malloc(ivlen + ctlen + taglen) ??? We'll send iv (12 bytes) separately then ct and tag separately.
// Simpler: encrypt and return ct and tag buffers separately.
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
    iv = ct = tag = NULL; // handed off
    ret = 1;
cleanup:
    if (iv) OPENSSL_free(iv);
    if (ct) OPENSSL_free(ct);
    if (tag) OPENSSL_free(tag);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// AES-GCM decrypt; returns plaintext allocated by OPENSSL_malloc
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
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1) goto cleanup; // will fail if tag mismatch
    flen += len;

    *out_plain = pt; *out_len = flen;
    pt = NULL;
    ret = 1;
cleanup:
    if (pt) OPENSSL_free(pt);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int do_handshake(int sock, EVP_PKEY *kx_priv, EVP_PKEY *sig_priv, EVP_PKEY *peer_sig_pub, unsigned char *aes_key_out) {
    int ok = 0;
    unsigned char *kx_pub_der = NULL, *sig_of_kx = NULL;
    unsigned char *kx_pub_peer = NULL, *sig_of_kx_peer = NULL;
    int kx_pub_len = 0;
    size_t sig_of_kx_len = 0;
    uint32_t len = 0;
    EVP_PKEY *peer_kx_key = NULL;

    // 1) Serialize DH public key
    kx_pub_der = pubkey_to_der(kx_priv, &kx_pub_len);
    if (!kx_pub_der) goto cleanup;

    // 2) Sign DH public key bytes with DSA
    sig_of_kx = dsa_sign(sig_priv, kx_pub_der, kx_pub_len, &sig_of_kx_len);
    if (!sig_of_kx) goto cleanup;

    // 3) Send: [kx_pub][signature]
    if (send_blob(sock, kx_pub_der, kx_pub_len) < 0) goto cleanup;
    if (sig_of_kx_len > UINT32_MAX || send_blob(sock, sig_of_kx, (uint32_t)sig_of_kx_len) < 0) goto cleanup;

    // 4) Receive peer DH public key
    if (recv_blob(sock, &kx_pub_peer, &len) < 0 || !kx_pub_peer || len == 0) goto cleanup;
    int peer_kx_len = (int)len;

    // 5) Receive peer signature
    if (recv_blob(sock, &sig_of_kx_peer, &len) < 0 || !sig_of_kx_peer) goto cleanup;
    uint32_t sig_of_kx_peer_len = len;

    // 6) Verify peer signature over their DH public key
    if (!dsa_verify(peer_sig_pub, kx_pub_peer, peer_kx_len, sig_of_kx_peer, sig_of_kx_peer_len)) {
        fprintf(stderr, "Signature verification failed! Aborting handshake.\n");
        goto cleanup;
    }

    // 7) Reconstruct peer DH public key
    peer_kx_key = der_to_pubkey(kx_pub_peer, peer_kx_len);
    if (!peer_kx_key) goto cleanup;

    // 8) Derive shared secret
    size_t secret_len = 0;
    unsigned char *secret = dh_derive_shared(kx_priv, peer_kx_key, &secret_len);
    if (!secret) goto cleanup;

    // 9) Derive AES-256 key from shared secret
    if (!derive_aes_key(secret, secret_len, aes_key_out)) {
        OPENSSL_free(secret);
        goto cleanup;
    }
    OPENSSL_free(secret);

    ok = 1;

cleanup:
    if (kx_pub_der) OPENSSL_free(kx_pub_der);
    if (sig_of_kx) OPENSSL_free(sig_of_kx);
    if (kx_pub_peer) OPENSSL_free(kx_pub_peer);
    if (sig_of_kx_peer) OPENSSL_free(sig_of_kx_peer);
    EVP_PKEY_free(peer_kx_key);
    return ok;
}
