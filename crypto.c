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
EVP_PKEY *generate_dh_key(const char *param_file) {
  EVP_PKEY *pkey = NULL;
  DH *dh_params = NULL;
  BIO *bio = NULL;

  // 1) Đọc tham số DH (p, g) từ file PEM
  bio = BIO_new_file(param_file, "r");
  if (!bio) {
      fprintf(stderr, "Error: Could not open DH parameters file %s\n", param_file);
      return NULL;
  }

  // Đọc cấu trúc DH* từ file PEM
  dh_params = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_free(bio); // Giải phóng BIO

  if (!dh_params) {
      fprintf(stderr, "Error: Could not read DH parameters from file\n");
      return NULL;
  }

  // 2) Tạo EVP_PKEY để chứa các tham số (p, g) này
  pkey = EVP_PKEY_new();
  if (!pkey) {
      DH_free(dh_params);
      return NULL;
  }

  // Gán tham số DH đã đọc vào EVP_PKEY. pkey giờ quản lý dh_params
  if (EVP_PKEY_assign_DH(pkey, dh_params) != 1) {
      // Nếu thất bại, dh_params không được quản lý bởi pkey, cần free
      DH_free(dh_params);
      EVP_PKEY_free(pkey);
      return NULL;
  }

  // 3) Tạo context để sinh cặp khóa (private/public) DH
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
  // Sinh khóa riêng/công khai DH dựa trên P và G đã load
  if (EVP_PKEY_keygen(kctx, &dh_key) <= 0) {
      EVP_PKEY_CTX_free(kctx);
      EVP_PKEY_free(pkey);
      return NULL;
  }

  EVP_PKEY_free(pkey); // Giải phóng EVP_PKEY chỉ chứa tham số DH
  EVP_PKEY_CTX_free(kctx);

  // dh_key là EVP_PKEY chứa keypair hoàn chỉnh và tham số (p, g)
  return dh_key;
}

EVP_PKEY *load_dsa_private(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return pkey;
}

EVP_PKEY *load_dsa_public(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;
    EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    return pkey;
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
    if (!pub) {
    printf("Public key NULL!!!\n");
    return 0;
    }

    printf("Type key: %d\n", EVP_PKEY_base_id(pub));
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) <= 0)
        goto end;
    printf("123\n");
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

void dump_hex(const char *label, const unsigned char *buf, size_t len, size_t show) {
    fprintf(stderr, "%s (%zu bytes):", label, len);
    size_t n = (show && show < len) ? show : len;
    for (size_t i = 0; i < n; ++i) fprintf(stderr, "%02X", buf[i]);
    if (n < len) fprintf(stderr, "...");
    fprintf(stderr, "\n");
}

void print_sha256(const char *label, const unsigned char *buf, size_t len) {
    unsigned char dgst[32];
    if (EVP_Digest(buf, len, dgst, NULL, EVP_sha256(), NULL)) {
        fprintf(stderr, "%s sha256: ", label);
        for (int i = 0; i < 8; ++i) fprintf(stderr, "%02X", dgst[i]); // 8 bytes fingerprint
        fprintf(stderr, "...\n");
    }
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

    // 3) Log local key
    fprintf(stderr, "[LOCAL] DH public key length: %d\n", kx_pub_len);
    int head_len = kx_pub_len < 64 ? kx_pub_len : 64;
    int tail_len = head_len;
    dump_hex("[LOCAL] DH HEAD", kx_pub_der, head_len, head_len);
    dump_hex("[LOCAL] DH TAIL", kx_pub_der + kx_pub_len - tail_len, tail_len, tail_len);
    print_sha256("[LOCAL] DH SHA256", kx_pub_der, kx_pub_len);
    print_sha256("[LOCAL] DSA signature", sig_of_kx, sig_of_kx_len);

    // 4) Send: [kx_pub][signature]
    if (send_blob(sock, kx_pub_der, kx_pub_len) < 0) goto cleanup;
    if (sig_of_kx_len > UINT32_MAX || send_blob(sock, sig_of_kx, (uint32_t)sig_of_kx_len) < 0) goto cleanup;

    // 5) Receive peer DH public key
    if (recv_blob(sock, &kx_pub_peer, &len) < 0 || !kx_pub_peer || len == 0) goto cleanup;
    int peer_kx_len = (int)len;

    // 6) Receive peer signature
    if (recv_blob(sock, &sig_of_kx_peer, &len) < 0 || !sig_of_kx_peer) goto cleanup;
    uint32_t sig_of_kx_peer_len = len;

    // 7) Log received key
    fprintf(stderr, "[PEER] DH public key length: %d\n", peer_kx_len);
    head_len = peer_kx_len < 64 ? peer_kx_len : 64;
    tail_len = head_len;
    dump_hex("[PEER] DH HEAD", kx_pub_peer, head_len, head_len);
    dump_hex("[PEER] DH TAIL", kx_pub_peer + peer_kx_len - tail_len, tail_len, tail_len);
    print_sha256("[PEER] DH SHA256", kx_pub_peer, peer_kx_len);
    print_sha256("[PEER] DSA signature", sig_of_kx_peer, sig_of_kx_peer_len);

    // 8) Verify peer signature over their DH public key
    if (!dsa_verify(peer_sig_pub, kx_pub_peer, peer_kx_len, sig_of_kx_peer, sig_of_kx_peer_len)) {
        fprintf(stderr, "Signature verification failed! Aborting handshake.\n");
        goto cleanup;
    }

    // 9) Reconstruct peer DH public key
    peer_kx_key = der_to_pubkey(kx_pub_peer, peer_kx_len);
    if (!peer_kx_key) goto cleanup;

    // 10) Derive shared secret
    size_t secret_len = 0;
    unsigned char *secret = dh_derive_shared(kx_priv, peer_kx_key, &secret_len);
    if (!secret) goto cleanup;

    // 11) Derive AES-256 key from shared secret
    if (!derive_aes_key(secret, secret_len, aes_key_out)) {
        OPENSSL_free(secret);
        goto cleanup;
    }
    OPENSSL_free(secret);

    // 12) Log AES key
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
