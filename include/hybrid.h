#ifndef TOY_RSA_HYBRID_H
#define TOY_RSA_HYBRID_H

#include "rsa.h"

#define HYBRID_OK 0
#define HYBRID_ERR_NULL (-1)
#define HYBRID_ERR_RANGE (-2)
#define HYBRID_ERR_CAPACITY (-3)
#define HYBRID_ERR_KEY (-4)
#define HYBRID_ERR_RNG (-5)
#define HYBRID_ERR_RSA (-6)
#define HYBRID_ERR_FORMAT (-7)
#define HYBRID_ERR_M3 (-8)
#define HYBRID_ERR_M2 (-9)
#define HYBRID_ERR_M1 (-10)
#define HYBRID_ERR_ARITHMETIC (-11)
#define HYBRID_ERR_MEMORY (-12)

#define HYBRID_LENGTH_BYTES 4U
#define HYBRID_DIGEST_BYTES 8U
#define HYBRID_SESSION_KEY_BYTES 8U
#define HYBRID_MIN_MODULUS_BYTES 21U
#define HYBRID_MAX_PLAINTEXT 0xffffffd0UL

int hybrid_ciphertext_size(const RSA_PUBLIC_KEY *public_key,
                           unsigned long plaintext_length,
                           unsigned long *ciphertext_length);

int hybrid_encrypt(const RSA_PUBLIC_KEY *public_key,
                   RNG_CTX *rng,
                   const unsigned char *plaintext,
                   unsigned long plaintext_length,
                   unsigned char *ciphertext,
                   unsigned long ciphertext_capacity,
                   unsigned long *ciphertext_length);

int hybrid_decrypt(const RSA_PRIVATE_KEY *private_key,
                   const unsigned char *ciphertext,
                   unsigned long ciphertext_length,
                   unsigned char *plaintext,
                   unsigned long plaintext_capacity,
                   unsigned long *plaintext_length);

#endif
