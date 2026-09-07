#ifndef TOY_RSA_NUMBER_H
#define TOY_RSA_NUMBER_H

#include "bigint.h"
#include "rng.h"

#define NUMBER_OK 0
#define NUMBER_ERR_NULL (-1)
#define NUMBER_ERR_INVALID (-2)
#define NUMBER_ERR_RANGE (-3)
#define NUMBER_ERR_MODULUS (-4)
#define NUMBER_ERR_NO_INVERSE (-5)
#define NUMBER_ERR_ARITHMETIC (-6)
#define NUMBER_ERR_RNG (-7)
#define NUMBER_ERR_ATTEMPTS (-8)

#define NUMBER_SMALL_PRIME_LIMIT 997U
#define NUMBER_WITNESS_REJECTION_LIMIT 128U

int number_gcd(const BIGINT *left,
               const BIGINT *right,
               BIGINT *greatest_common_divisor);

int number_mod_inverse(const BIGINT *value,
                       const BIGINT *modulus,
                       BIGINT *inverse);

int number_mod_multiply(const BIGINT *left,
                        const BIGINT *right,
                        const BIGINT *modulus,
                        BIGINT *result);

int number_mod_pow(const BIGINT *base,
                   const BIGINT *exponent,
                   const BIGINT *modulus,
                   BIGINT *result);

int number_trial_division(const BIGINT *candidate,
                          unsigned int *factor);

int number_miller_rabin_bases(const BIGINT *candidate,
                              const unsigned long *bases,
                              unsigned int rounds,
                              int *probable_prime);

int number_miller_rabin(const BIGINT *candidate,
                        RNG_CTX *rng,
                        unsigned int rounds,
                        int *probable_prime);

int number_generate_probable_prime(RNG_CTX *rng,
                                   unsigned int bits,
                                   unsigned int rounds,
                                   unsigned long maximum_attempts,
                                   BIGINT *prime,
                                   unsigned long *attempts_used);

#endif
