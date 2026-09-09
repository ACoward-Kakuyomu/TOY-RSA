#ifndef TOY_RSA_RSA_H
#define TOY_RSA_RSA_H

#include "bigint.h"
#include "rng.h"

#define RSA_OK 0
#define RSA_ERR_NULL (-1)
#define RSA_ERR_INVALID (-2)
#define RSA_ERR_RANGE (-3)
#define RSA_ERR_ARITHMETIC (-4)
#define RSA_ERR_RNG (-5)
#define RSA_ERR_ATTEMPTS (-6)
#define RSA_ERR_KEY (-7)
#define RSA_ERR_FORMAT (-8)
#define RSA_ERR_CAPACITY (-9)

#define RSA_PUBLIC_EXPONENT 65537UL
#define RSA_STORY_MODULUS_BITS 512U
#define RSA_MIN_GENERATED_MODULUS_BITS 32U
#define RSA_VALIDATION_ROUNDS 9U
#define RSA_KEY_READY 0x52534150UL
#define RSA_PRIVATE_KEY_READY 0x52534153UL

#define RSA_PUBLIC_KEY_MAX_SERIALIZED (10U + BIGINT_MAX_BYTES)
#define RSA_PRIVATE_KEY_MAX_SERIALIZED \
    (16U + BIGINT_MAX_BYTES * 4U)

typedef struct rsa_public_key_tag {
    BIGINT n;
    BIGINT e;
    unsigned int modulus_bits;
    unsigned long initialized;
} RSA_PUBLIC_KEY;

typedef struct rsa_private_key_tag {
    RSA_PUBLIC_KEY public_key;
    BIGINT d;
    BIGINT p;
    BIGINT q;
    BIGINT dp;
    BIGINT dq;
    BIGINT q_inverse;
    unsigned long initialized;
} RSA_PRIVATE_KEY;

typedef struct rsa_keygen_stats_tag {
    unsigned long p_candidates;
    unsigned long q_candidates;
    unsigned int restarts;
} RSA_KEYGEN_STATS;

int rsa_private_key_from_primes(const BIGINT *p,
                                const BIGINT *q,
                                RSA_PRIVATE_KEY *private_key);

int rsa_generate_key(RNG_CTX *rng,
                     unsigned int modulus_bits,
                     unsigned int miller_rabin_rounds,
                     unsigned long maximum_prime_attempts,
                     unsigned int maximum_restarts,
                     RSA_PRIVATE_KEY *private_key,
                     RSA_KEYGEN_STATS *statistics);

int rsa_public_from_private(const RSA_PRIVATE_KEY *private_key,
                            RSA_PUBLIC_KEY *public_key);

int rsa_validate_public_key(const RSA_PUBLIC_KEY *public_key, int *valid);
int rsa_validate_private_key(const RSA_PRIVATE_KEY *private_key, int *valid);

int rsa_public_operation(const RSA_PUBLIC_KEY *public_key,
                         const BIGINT *message,
                         BIGINT *ciphertext);
int rsa_private_operation_standard(const RSA_PRIVATE_KEY *private_key,
                                   const BIGINT *ciphertext,
                                   BIGINT *message);
int rsa_private_operation(const RSA_PRIVATE_KEY *private_key,
                          const BIGINT *ciphertext,
                          BIGINT *message);

int rsa_public_key_serialized_size(const RSA_PUBLIC_KEY *public_key,
                                   unsigned int *size);
int rsa_serialize_public_key(const RSA_PUBLIC_KEY *public_key,
                             unsigned char *output,
                             unsigned int output_capacity,
                             unsigned int *output_length);
int rsa_deserialize_public_key(const unsigned char *input,
                               unsigned int input_length,
                               RSA_PUBLIC_KEY *public_key);

int rsa_private_key_serialized_size(const RSA_PRIVATE_KEY *private_key,
                                    unsigned int *size);
int rsa_serialize_private_key(const RSA_PRIVATE_KEY *private_key,
                              unsigned char *output,
                              unsigned int output_capacity,
                              unsigned int *output_length);
int rsa_deserialize_private_key(const unsigned char *input,
                                unsigned int input_length,
                                RSA_PRIVATE_KEY *private_key);

#endif
