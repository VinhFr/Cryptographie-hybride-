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

#endif /* CRYPTO_H */
