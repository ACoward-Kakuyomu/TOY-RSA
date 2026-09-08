#ifndef TOY_RSA_MONTGOMERY_H
#define TOY_RSA_MONTGOMERY_H

#include "bigint.h"

#define MONT_OK 0
#define MONT_ERR_NULL (-1)
#define MONT_ERR_INVALID (-2)
#define MONT_ERR_MODULUS (-3)
#define MONT_ERR_RANGE (-4)
#define MONT_ERR_ARITHMETIC (-5)
#define MONT_ERR_CONTEXT (-6)

#define MONT_WIDE_MAX_LIMBS (BIGINT_MAX_LIMBS * 2U + 2U)
#define MONT_CONTEXT_READY 0x4d4f4e54UL

typedef struct mont_wide_tag {
    BIGINT_LIMB limb[MONT_WIDE_MAX_LIMBS];
    unsigned int used;
} MONT_WIDE;

typedef struct mont_context_tag {
    BIGINT modulus;
    BIGINT r_mod_n;
    BIGINT r2_mod_n;
    unsigned int limbs;
    BIGINT_LIMB n0_prime;
    unsigned long initialized;
} MONT_CTX;

int mont_init(MONT_CTX *context, const BIGINT *modulus);

int mont_wide_from_bigint(const BIGINT *value, MONT_WIDE *wide_value);
int mont_wide_multiply(const BIGINT *left,
                       const BIGINT *right,
                       MONT_WIDE *wide_product);
int mont_reduce(const MONT_CTX *context,
                const MONT_WIDE *wide_value,
                BIGINT *result);

int mont_to(const MONT_CTX *context,
            const BIGINT *value,
            BIGINT *montgomery_value);
int mont_from(const MONT_CTX *context,
              const BIGINT *montgomery_value,
              BIGINT *value);
int mont_mul(const MONT_CTX *context,
             const BIGINT *left,
             const BIGINT *right,
             BIGINT *result);
int mont_pow(const MONT_CTX *context,
             const BIGINT *base,
             const BIGINT *exponent,
             BIGINT *result);

#endif
