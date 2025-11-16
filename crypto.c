
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
EVP_PKEY *generate_dh_key(){
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY_CTX *kctx = NULL;

  // Création d'un contexte pour générer les paramètres DH (p et g)
  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
  if (!pctx)  return NULL;

  // Initialisation de la génération des paramètres DH
  if (EVP_PKEY_paramgen_init(pctx) <= 0) goto err;

  // Définition de la longueur de la clé DH (ici 2048 bits)
  if (EVP_PKEY_CTX_set_dh_paramgen_length(pctx, 2048) <= 0) goto err;

  EVP_PKEY *params = NULL;

  // Génération effective des paramètres DH
  if (EVP_PKEY_paramgen(pctx, &params) <= 0) goto err;

  // Création d'un contexte pour générer la paire de clés DH en se basant sur les paramètres générés
  kctx = EVP_PKEY_CTX_new(params, NULL);
  if (!kctx) {
      EVP_PKEY_free(params);
      goto err;
  }
  if (EVP_PKEY_keygen_init(kctx) <= 0) {
      EVP_PKEY_free(params);
      goto err;
  }

  // Génération de la paire de clés DH (clé publique et privée)
  if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {
      EVP_PKEY_free(params);
      goto err;
  }
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
