
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
