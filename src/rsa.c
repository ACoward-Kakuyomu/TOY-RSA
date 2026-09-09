#include <limits.h>
#include <stddef.h>
#include <string.h>

#include "montgomery.h"
#include "number.h"
#include "rsa.h"

static const unsigned long rsa_validation_bases[RSA_VALIDATION_ROUNDS] = {
    2UL, 3UL, 5UL, 7UL, 11UL, 13UL, 17UL, 19UL, 23UL
};

static int rsa_bigint_error(int status)
{
    if (status == BIGINT_ERR_INVALID) {
        return RSA_ERR_INVALID;
    }
    if (status == BIGINT_ERR_CAPACITY) {
        return RSA_ERR_CAPACITY;
    }
    return RSA_ERR_ARITHMETIC;
}

static int rsa_number_error(int status)
{
    if (status == NUMBER_ERR_INVALID) {
        return RSA_ERR_INVALID;
    }
    if (status == NUMBER_ERR_RNG) {
        return RSA_ERR_RNG;
    }
    if (status == NUMBER_ERR_ATTEMPTS) {
        return RSA_ERR_ATTEMPTS;
    }
    return RSA_ERR_ARITHMETIC;
}

static int rsa_mont_error(int status)
{
    if (status == MONT_ERR_INVALID) {
        return RSA_ERR_INVALID;
    }
    if (status == MONT_ERR_RANGE) {
        return RSA_ERR_RANGE;
    }
    return RSA_ERR_ARITHMETIC;
}

static int rsa_validate_bigint(const BIGINT *value)
{
    unsigned int bits;
    int status;

    if (value == NULL) {
        return RSA_ERR_NULL;
    }
    status = bigint_bit_length(value, &bits);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    return RSA_OK;
}

static int rsa_compare(const BIGINT *left,
                       const BIGINT *right,
                       int *comparison)
{
    int status;

    status = bigint_compare(left, right, comparison);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    return RSA_OK;
}

static int rsa_make_exponent(BIGINT *exponent)
{
    int status;

    status = bigint_from_ulong(exponent, RSA_PUBLIC_EXPONENT);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    return RSA_OK;
}

static int rsa_public_basic_valid(const RSA_PUBLIC_KEY *key)
{
    BIGINT one;
    BIGINT exponent;
    unsigned int bits;
    int comparison;
    int is_odd;
    int status;

    if (key->initialized != RSA_KEY_READY) {
        return 0;
    }
    if (rsa_validate_bigint(&key->n) != RSA_OK ||
        rsa_validate_bigint(&key->e) != RSA_OK) {
        return 0;
    }
    status = bigint_from_ulong(&one, 1UL);
    if (status != BIGINT_OK) {
        return 0;
    }
    if (rsa_make_exponent(&exponent) != RSA_OK) {
        return 0;
    }
    status = bigint_compare(&key->n, &one, &comparison);
    if (status != BIGINT_OK || comparison <= 0) {
        return 0;
    }
    status = bigint_is_odd(&key->n, &is_odd);
    if (status != BIGINT_OK || is_odd == 0) {
        return 0;
    }
    status = bigint_compare(&key->e, &exponent, &comparison);
    if (status != BIGINT_OK || comparison != 0) {
        return 0;
    }
    status = bigint_bit_length(&key->n, &bits);
    if (status != BIGINT_OK || bits != key->modulus_bits) {
        return 0;
    }
    return 1;
}

static int rsa_private_basic_valid(const RSA_PRIVATE_KEY *key)
{
    if (key->initialized != RSA_PRIVATE_KEY_READY ||
        !rsa_public_basic_valid(&key->public_key)) {
        return 0;
    }
    if (rsa_validate_bigint(&key->d) != RSA_OK ||
        rsa_validate_bigint(&key->p) != RSA_OK ||
        rsa_validate_bigint(&key->q) != RSA_OK ||
        rsa_validate_bigint(&key->dp) != RSA_OK ||
        rsa_validate_bigint(&key->dq) != RSA_OK ||
        rsa_validate_bigint(&key->q_inverse) != RSA_OK) {
        return 0;
    }
    return 1;
}

static int rsa_gcd_is_one(const BIGINT *left,
                          const BIGINT *right,
                          int *is_one)
{
    BIGINT gcd;
    BIGINT one;
    int comparison;
    int status;

    status = number_gcd(left, right, &gcd);
    if (status != NUMBER_OK) {
        return rsa_number_error(status);
    }
    status = bigint_from_ulong(&one, 1UL);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = rsa_compare(&gcd, &one, &comparison);
    if (status != RSA_OK) {
        return status;
    }
    *is_one = comparison == 0;
    return RSA_OK;
}

static int rsa_derive_private(const BIGINT *p,
                              const BIGINT *q,
                              RSA_PRIVATE_KEY *private_key)
{
    RSA_PRIVATE_KEY temporary;
    BIGINT one;
    BIGINT p_minus_one;
    BIGINT q_minus_one;
    BIGINT phi;
    int comparison;
    int coprime;
    int status;

    status = rsa_compare(p, q, &comparison);
    if (status != RSA_OK) {
        return status;
    }
    if (comparison == 0) {
        return RSA_ERR_KEY;
    }
    status = bigint_from_ulong(&one, 1UL);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = bigint_subtract(p, &one, &p_minus_one);
    if (status != BIGINT_OK) {
        return RSA_ERR_KEY;
    }
    status = bigint_subtract(q, &one, &q_minus_one);
    if (status != BIGINT_OK) {
        return RSA_ERR_KEY;
    }
    memset(&temporary, 0, sizeof(temporary));
    status = rsa_make_exponent(&temporary.public_key.e);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_gcd_is_one(&temporary.public_key.e,
                            &p_minus_one, &coprime);
    if (status != RSA_OK) {
        return status;
    }
    if (coprime == 0) {
        return RSA_ERR_KEY;
    }
    status = rsa_gcd_is_one(&temporary.public_key.e,
                            &q_minus_one, &coprime);
    if (status != RSA_OK) {
        return status;
    }
    if (coprime == 0) {
        return RSA_ERR_KEY;
    }
    status = bigint_multiply(p, q, &temporary.public_key.n);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = bigint_multiply(&p_minus_one, &q_minus_one, &phi);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = number_mod_inverse(&temporary.public_key.e, &phi,
                                &temporary.d);
    if (status != NUMBER_OK) {
        return rsa_number_error(status);
    }
    status = bigint_modulo(&temporary.d, &p_minus_one, &temporary.dp);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = bigint_modulo(&temporary.d, &q_minus_one, &temporary.dq);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = number_mod_inverse(q, p, &temporary.q_inverse);
    if (status != NUMBER_OK) {
        return rsa_number_error(status);
    }
    memcpy(&temporary.p, p, sizeof(temporary.p));
    memcpy(&temporary.q, q, sizeof(temporary.q));
    status = bigint_bit_length(&temporary.public_key.n,
                               &temporary.public_key.modulus_bits);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    temporary.public_key.initialized = RSA_KEY_READY;
    temporary.initialized = RSA_PRIVATE_KEY_READY;
    memcpy(private_key, &temporary, sizeof(temporary));
    return RSA_OK;
}

int rsa_private_key_from_primes(const BIGINT *p,
                                const BIGINT *q,
                                RSA_PRIVATE_KEY *private_key)
{
    RSA_PRIVATE_KEY temporary;
    int p_prime;
    int q_prime;
    int status;

    if (p == NULL || q == NULL || private_key == NULL) {
        return RSA_ERR_NULL;
    }
    status = rsa_validate_bigint(p);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_validate_bigint(q);
    if (status != RSA_OK) {
        return status;
    }
    status = number_miller_rabin_bases(p, rsa_validation_bases,
                                       RSA_VALIDATION_ROUNDS, &p_prime);
    if (status != NUMBER_OK) {
        return rsa_number_error(status);
    }
    status = number_miller_rabin_bases(q, rsa_validation_bases,
                                       RSA_VALIDATION_ROUNDS, &q_prime);
    if (status != NUMBER_OK) {
        return rsa_number_error(status);
    }
    if (p_prime == 0 || q_prime == 0) {
        return RSA_ERR_KEY;
    }
    status = rsa_derive_private(p, q, &temporary);
    if (status != RSA_OK) {
        return status;
    }
    memcpy(private_key, &temporary, sizeof(temporary));
    return RSA_OK;
}

static int rsa_add_attempts(unsigned long *total, unsigned long addition)
{
    if (*total > ULONG_MAX - addition) {
        return RSA_ERR_ATTEMPTS;
    }
    *total += addition;
    return RSA_OK;
}

int rsa_generate_key(RNG_CTX *rng,
                     unsigned int modulus_bits,
                     unsigned int miller_rabin_rounds,
                     unsigned long maximum_prime_attempts,
                     unsigned int maximum_restarts,
                     RSA_PRIVATE_KEY *private_key,
                     RSA_KEYGEN_STATS *statistics)
{
    RSA_PRIVATE_KEY temporary;
    RSA_KEYGEN_STATS stats;
    BIGINT p;
    BIGINT q;
    BIGINT p_minus_one;
    BIGINT q_minus_one;
    BIGINT exponent;
    BIGINT one;
    BIGINT modulus;
    unsigned long attempts;
    unsigned int actual_bits;
    unsigned int p_bits;
    unsigned int q_bits;
    int have_p;
    int coprime;
    int comparison;
    int status;

    if (rng == NULL || private_key == NULL || statistics == NULL) {
        return RSA_ERR_NULL;
    }
    if (modulus_bits < RSA_MIN_GENERATED_MODULUS_BITS ||
        modulus_bits > BIGINT_MAX_BITS || (modulus_bits & 1U) != 0U ||
        miller_rabin_rounds == 0U || maximum_prime_attempts == 0UL ||
        maximum_restarts == 0U) {
        return RSA_ERR_RANGE;
    }
    memset(&stats, 0, sizeof(stats));
    status = rsa_make_exponent(&exponent);
    if (status != RSA_OK) {
        return status;
    }
    status = bigint_from_ulong(&one, 1UL);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    p_bits = modulus_bits / 2U;
    q_bits = modulus_bits - p_bits;
    have_p = 0;

    for (;;) {
        if (have_p == 0) {
            attempts = 0UL;
            status = number_generate_probable_prime(
                rng, p_bits, miller_rabin_rounds,
                maximum_prime_attempts, &p, &attempts);
            if (status != NUMBER_OK) {
                return rsa_number_error(status);
            }
            status = rsa_add_attempts(&stats.p_candidates, attempts);
            if (status != RSA_OK) {
                return status;
            }
            status = bigint_subtract(&p, &one, &p_minus_one);
            if (status != BIGINT_OK) {
                return rsa_bigint_error(status);
            }
            status = rsa_gcd_is_one(&exponent, &p_minus_one, &coprime);
            if (status != RSA_OK) {
                return status;
            }
            if (coprime == 0) {
                ++stats.restarts;
                if (stats.restarts > maximum_restarts) {
                    return RSA_ERR_ATTEMPTS;
                }
                continue;
            }
            have_p = 1;
        }

        attempts = 0UL;
        status = number_generate_probable_prime(
            rng, q_bits, miller_rabin_rounds,
            maximum_prime_attempts, &q, &attempts);
        if (status != NUMBER_OK) {
            return rsa_number_error(status);
        }
        status = rsa_add_attempts(&stats.q_candidates, attempts);
        if (status != RSA_OK) {
            return status;
        }
        status = rsa_compare(&p, &q, &comparison);
        if (status != RSA_OK) {
            return status;
        }
        status = bigint_subtract(&q, &one, &q_minus_one);
        if (status != BIGINT_OK) {
            return rsa_bigint_error(status);
        }
        status = rsa_gcd_is_one(&exponent, &q_minus_one, &coprime);
        if (status != RSA_OK) {
            return status;
        }
        if (comparison == 0 || coprime == 0) {
            ++stats.restarts;
            if (stats.restarts > maximum_restarts) {
                return RSA_ERR_ATTEMPTS;
            }
            continue;
        }
        status = bigint_multiply(&p, &q, &modulus);
        if (status != BIGINT_OK) {
            return rsa_bigint_error(status);
        }
        status = bigint_bit_length(&modulus, &actual_bits);
        if (status != BIGINT_OK) {
            return rsa_bigint_error(status);
        }
        if (actual_bits != modulus_bits) {
            ++stats.restarts;
            if (stats.restarts > maximum_restarts) {
                return RSA_ERR_ATTEMPTS;
            }
            continue;
        }
        status = rsa_private_key_from_primes(&p, &q, &temporary);
        if (status != RSA_OK) {
            return status;
        }
        memcpy(private_key, &temporary, sizeof(temporary));
        memcpy(statistics, &stats, sizeof(stats));
        return RSA_OK;
    }
}

int rsa_public_from_private(const RSA_PRIVATE_KEY *private_key,
                            RSA_PUBLIC_KEY *public_key)
{
    if (private_key == NULL || public_key == NULL) {
        return RSA_ERR_NULL;
    }
    if (!rsa_private_basic_valid(private_key)) {
        return RSA_ERR_KEY;
    }
    memcpy(public_key, &private_key->public_key, sizeof(*public_key));
    return RSA_OK;
}

int rsa_validate_public_key(const RSA_PUBLIC_KEY *public_key, int *valid)
{
    int status;

    if (public_key == NULL || valid == NULL) {
        return RSA_ERR_NULL;
    }
    status = rsa_validate_bigint(&public_key->n);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_validate_bigint(&public_key->e);
    if (status != RSA_OK) {
        return status;
    }
    *valid = rsa_public_basic_valid(public_key);
    return RSA_OK;
}

int rsa_validate_private_key(const RSA_PRIVATE_KEY *private_key, int *valid)
{
    BIGINT product;
    BIGINT p_minus_one;
    BIGINT q_minus_one;
    BIGINT phi;
    BIGINT check;
    BIGINT one;
    int comparison;
    int p_prime;
    int q_prime;
    int coprime;
    int public_valid;
    int status;

    if (private_key == NULL || valid == NULL) {
        return RSA_ERR_NULL;
    }
    status = rsa_validate_public_key(&private_key->public_key,
                                     &public_valid);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_validate_bigint(&private_key->d);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_validate_bigint(&private_key->p);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_validate_bigint(&private_key->q);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_validate_bigint(&private_key->dp);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_validate_bigint(&private_key->dq);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_validate_bigint(&private_key->q_inverse);
    if (status != RSA_OK) {
        return status;
    }
    if (public_valid == 0) {
        *valid = 0;
        return RSA_OK;
    }
    if (!rsa_private_basic_valid(private_key)) {
        *valid = 0;
        return RSA_OK;
    }
    status = number_miller_rabin_bases(
        &private_key->p, rsa_validation_bases,
        RSA_VALIDATION_ROUNDS, &p_prime);
    if (status != NUMBER_OK) {
        return rsa_number_error(status);
    }
    status = number_miller_rabin_bases(
        &private_key->q, rsa_validation_bases,
        RSA_VALIDATION_ROUNDS, &q_prime);
    if (status != NUMBER_OK) {
        return rsa_number_error(status);
    }
    if (p_prime == 0 || q_prime == 0) {
        *valid = 0;
        return RSA_OK;
    }
    status = rsa_compare(&private_key->p, &private_key->q, &comparison);
    if (status != RSA_OK) {
        return status;
    }
    if (comparison == 0) {
        *valid = 0;
        return RSA_OK;
    }
    status = bigint_multiply(&private_key->p, &private_key->q, &product);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = rsa_compare(&product, &private_key->public_key.n, &comparison);
    if (status != RSA_OK) {
        return status;
    }
    if (comparison != 0) {
        *valid = 0;
        return RSA_OK;
    }
    status = bigint_from_ulong(&one, 1UL);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = bigint_subtract(&private_key->p, &one, &p_minus_one);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = bigint_subtract(&private_key->q, &one, &q_minus_one);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = rsa_gcd_is_one(&private_key->public_key.e,
                            &p_minus_one, &coprime);
    if (status != RSA_OK) {
        return status;
    }
    if (coprime == 0) {
        *valid = 0;
        return RSA_OK;
    }
    status = rsa_gcd_is_one(&private_key->public_key.e,
                            &q_minus_one, &coprime);
    if (status != RSA_OK) {
        return status;
    }
    if (coprime == 0) {
        *valid = 0;
        return RSA_OK;
    }
    status = bigint_multiply(&p_minus_one, &q_minus_one, &phi);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = number_mod_multiply(&private_key->public_key.e,
                                 &private_key->d, &phi, &check);
    if (status != NUMBER_OK) {
        return rsa_number_error(status);
    }
    status = rsa_compare(&check, &one, &comparison);
    if (status != RSA_OK || comparison != 0) {
        if (status != RSA_OK) {
            return status;
        }
        *valid = 0;
        return RSA_OK;
    }
    status = bigint_modulo(&private_key->d, &p_minus_one, &check);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = rsa_compare(&check, &private_key->dp, &comparison);
    if (status != RSA_OK || comparison != 0) {
        if (status != RSA_OK) {
            return status;
        }
        *valid = 0;
        return RSA_OK;
    }
    status = bigint_modulo(&private_key->d, &q_minus_one, &check);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = rsa_compare(&check, &private_key->dq, &comparison);
    if (status != RSA_OK || comparison != 0) {
        if (status != RSA_OK) {
            return status;
        }
        *valid = 0;
        return RSA_OK;
    }
    status = number_mod_multiply(&private_key->q,
                                 &private_key->q_inverse,
                                 &private_key->p, &check);
    if (status != NUMBER_OK) {
        return rsa_number_error(status);
    }
    status = rsa_compare(&check, &one, &comparison);
    if (status != RSA_OK) {
        return status;
    }
    *valid = comparison == 0;
    return RSA_OK;
}

static int rsa_input_in_range(const BIGINT *input, const BIGINT *modulus)
{
    int comparison;
    int status;

    status = rsa_validate_bigint(input);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_compare(input, modulus, &comparison);
    if (status != RSA_OK) {
        return status;
    }
    if (comparison >= 0) {
        return RSA_ERR_RANGE;
    }
    return RSA_OK;
}

int rsa_public_operation(const RSA_PUBLIC_KEY *public_key,
                         const BIGINT *message,
                         BIGINT *ciphertext)
{
    MONT_CTX context;
    BIGINT temporary;
    int status;

    if (public_key == NULL || message == NULL || ciphertext == NULL) {
        return RSA_ERR_NULL;
    }
    if (!rsa_public_basic_valid(public_key)) {
        return RSA_ERR_KEY;
    }
    status = rsa_input_in_range(message, &public_key->n);
    if (status != RSA_OK) {
        return status;
    }
    status = mont_init(&context, &public_key->n);
    if (status != MONT_OK) {
        return rsa_mont_error(status);
    }
    status = mont_pow(&context, message, &public_key->e, &temporary);
    if (status != MONT_OK) {
        return rsa_mont_error(status);
    }
    memcpy(ciphertext, &temporary, sizeof(temporary));
    return RSA_OK;
}

int rsa_private_operation_standard(const RSA_PRIVATE_KEY *private_key,
                                   const BIGINT *ciphertext,
                                   BIGINT *message)
{
    MONT_CTX context;
    BIGINT temporary;
    int status;

    if (private_key == NULL || ciphertext == NULL || message == NULL) {
        return RSA_ERR_NULL;
    }
    if (!rsa_private_basic_valid(private_key)) {
        return RSA_ERR_KEY;
    }
    status = rsa_input_in_range(ciphertext, &private_key->public_key.n);
    if (status != RSA_OK) {
        return status;
    }
    status = mont_init(&context, &private_key->public_key.n);
    if (status != MONT_OK) {
        return rsa_mont_error(status);
    }
    status = mont_pow(&context, ciphertext, &private_key->d, &temporary);
    if (status != MONT_OK) {
        return rsa_mont_error(status);
    }
    memcpy(message, &temporary, sizeof(temporary));
    return RSA_OK;
}

static int rsa_mod_subtract(const BIGINT *left,
                            const BIGINT *right,
                            const BIGINT *modulus,
                            BIGINT *result)
{
    BIGINT reduced_right;
    BIGINT difference;
    int comparison;
    int status;

    status = bigint_modulo(right, modulus, &reduced_right);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = rsa_compare(left, &reduced_right, &comparison);
    if (status != RSA_OK) {
        return status;
    }
    if (comparison >= 0) {
        status = bigint_subtract(left, &reduced_right, &difference);
    } else {
        status = bigint_subtract(&reduced_right, left, &difference);
        if (status == BIGINT_OK) {
            status = bigint_subtract(modulus, &difference, &difference);
        }
    }
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    memcpy(result, &difference, sizeof(difference));
    return RSA_OK;
}

int rsa_private_operation(const RSA_PRIVATE_KEY *private_key,
                          const BIGINT *ciphertext,
                          BIGINT *message)
{
    MONT_CTX p_context;
    MONT_CTX q_context;
    BIGINT m1;
    BIGINT m2;
    BIGINT difference;
    BIGINT h;
    BIGINT qh;
    BIGINT temporary;
    int comparison;
    int status;

    if (private_key == NULL || ciphertext == NULL || message == NULL) {
        return RSA_ERR_NULL;
    }
    if (!rsa_private_basic_valid(private_key)) {
        return RSA_ERR_KEY;
    }
    status = rsa_input_in_range(ciphertext, &private_key->public_key.n);
    if (status != RSA_OK) {
        return status;
    }
    status = mont_init(&p_context, &private_key->p);
    if (status != MONT_OK) {
        return rsa_mont_error(status);
    }
    status = mont_init(&q_context, &private_key->q);
    if (status != MONT_OK) {
        return rsa_mont_error(status);
    }
    status = mont_pow(&p_context, ciphertext, &private_key->dp, &m1);
    if (status != MONT_OK) {
        return rsa_mont_error(status);
    }
    status = mont_pow(&q_context, ciphertext, &private_key->dq, &m2);
    if (status != MONT_OK) {
        return rsa_mont_error(status);
    }
    status = rsa_mod_subtract(&m1, &m2, &private_key->p, &difference);
    if (status != RSA_OK) {
        return status;
    }
    status = number_mod_multiply(&private_key->q_inverse, &difference,
                                 &private_key->p, &h);
    if (status != NUMBER_OK) {
        return rsa_number_error(status);
    }
    status = bigint_multiply(&private_key->q, &h, &qh);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = bigint_add(&m2, &qh, &temporary);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    status = rsa_compare(&temporary, &private_key->public_key.n,
                         &comparison);
    if (status != RSA_OK) {
        return status;
    }
    if (comparison >= 0) {
        return RSA_ERR_ARITHMETIC;
    }
    memcpy(message, &temporary, sizeof(temporary));
    return RSA_OK;
}

static unsigned int rsa_bigint_bytes(const BIGINT *value)
{
    unsigned int bits;

    if (bigint_bit_length(value, &bits) != BIGINT_OK) {
        return 0U;
    }
    return bits == 0U ? 1U : (bits + 7U) / 8U;
}

static void rsa_put_u16(unsigned char *output, unsigned int value)
{
    output[0] = (unsigned char)((value >> 8U) & 0xffU);
    output[1] = (unsigned char)(value & 0xffU);
}

static unsigned int rsa_get_u16(const unsigned char *input)
{
    return ((unsigned int)input[0] << 8U) | (unsigned int)input[1];
}

static int rsa_write_bigint(const BIGINT *value,
                            unsigned char *output,
                            unsigned int length)
{
    int status;

    status = bigint_to_bytes_fixed(value, output, length);
    if (status != BIGINT_OK) {
        return rsa_bigint_error(status);
    }
    return RSA_OK;
}

static int rsa_read_bigint(const unsigned char *input,
                           unsigned int length,
                           BIGINT *value)
{
    int status;

    if (length == 0U || length > BIGINT_MAX_BYTES ||
        (length > 1U && input[0] == 0U)) {
        return RSA_ERR_FORMAT;
    }
    status = bigint_from_bytes(value, input, length);
    if (status != BIGINT_OK) {
        return RSA_ERR_FORMAT;
    }
    return RSA_OK;
}

int rsa_public_key_serialized_size(const RSA_PUBLIC_KEY *public_key,
                                   unsigned int *size)
{
    unsigned int n_length;

    if (public_key == NULL || size == NULL) {
        return RSA_ERR_NULL;
    }
    if (!rsa_public_basic_valid(public_key)) {
        return RSA_ERR_KEY;
    }
    n_length = rsa_bigint_bytes(&public_key->n);
    if (n_length == 0U || n_length > 65535U) {
        return RSA_ERR_RANGE;
    }
    *size = 10U + n_length;
    return RSA_OK;
}

int rsa_serialize_public_key(const RSA_PUBLIC_KEY *public_key,
                             unsigned char *output,
                             unsigned int output_capacity,
                             unsigned int *output_length)
{
    unsigned char temporary[RSA_PUBLIC_KEY_MAX_SERIALIZED];
    unsigned int required;
    unsigned int n_length;
    int status;

    if (public_key == NULL || output_length == NULL) {
        return RSA_ERR_NULL;
    }
    status = rsa_public_key_serialized_size(public_key, &required);
    if (status != RSA_OK) {
        return status;
    }
    *output_length = required;
    if (output_capacity < required) {
        return RSA_ERR_CAPACITY;
    }
    if (output == NULL) {
        return RSA_ERR_NULL;
    }
    n_length = required - 10U;
    temporary[0] = 'T';
    temporary[1] = 'R';
    temporary[2] = 'P';
    temporary[3] = '8';
    rsa_put_u16(temporary + 4U, n_length);
    status = rsa_write_bigint(&public_key->n, temporary + 6U, n_length);
    if (status != RSA_OK) {
        return status;
    }
    temporary[6U + n_length] = 0x00U;
    temporary[7U + n_length] = 0x01U;
    temporary[8U + n_length] = 0x00U;
    temporary[9U + n_length] = 0x01U;
    memcpy(output, temporary, required);
    return RSA_OK;
}

int rsa_deserialize_public_key(const unsigned char *input,
                               unsigned int input_length,
                               RSA_PUBLIC_KEY *public_key)
{
    RSA_PUBLIC_KEY temporary;
    unsigned int n_length;
    int valid;
    int status;

    if (input == NULL || public_key == NULL) {
        return RSA_ERR_NULL;
    }
    if (input_length < 11U || input[0] != 'T' || input[1] != 'R' ||
        input[2] != 'P' || input[3] != '8') {
        return RSA_ERR_FORMAT;
    }
    n_length = rsa_get_u16(input + 4U);
    if (n_length == 0U || n_length > BIGINT_MAX_BYTES ||
        input_length != 10U + n_length) {
        return RSA_ERR_FORMAT;
    }
    if (input[6U + n_length] != 0x00U ||
        input[7U + n_length] != 0x01U ||
        input[8U + n_length] != 0x00U ||
        input[9U + n_length] != 0x01U) {
        return RSA_ERR_FORMAT;
    }
    memset(&temporary, 0, sizeof(temporary));
    status = rsa_read_bigint(input + 6U, n_length, &temporary.n);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_make_exponent(&temporary.e);
    if (status != RSA_OK) {
        return status;
    }
    status = bigint_bit_length(&temporary.n, &temporary.modulus_bits);
    if (status != BIGINT_OK) {
        return RSA_ERR_FORMAT;
    }
    temporary.initialized = RSA_KEY_READY;
    status = rsa_validate_public_key(&temporary, &valid);
    if (status != RSA_OK || valid == 0) {
        return RSA_ERR_FORMAT;
    }
    memcpy(public_key, &temporary, sizeof(temporary));
    return RSA_OK;
}

int rsa_private_key_serialized_size(const RSA_PRIVATE_KEY *private_key,
                                    unsigned int *size)
{
    unsigned int n_length;
    unsigned int d_length;
    unsigned int p_length;
    unsigned int q_length;
    int valid;
    int status;

    if (private_key == NULL || size == NULL) {
        return RSA_ERR_NULL;
    }
    status = rsa_validate_private_key(private_key, &valid);
    if (status != RSA_OK) {
        return status;
    }
    if (valid == 0) {
        return RSA_ERR_KEY;
    }
    n_length = rsa_bigint_bytes(&private_key->public_key.n);
    d_length = rsa_bigint_bytes(&private_key->d);
    p_length = rsa_bigint_bytes(&private_key->p);
    q_length = rsa_bigint_bytes(&private_key->q);
    if (n_length > 65535U || d_length > 65535U ||
        p_length > 65535U || q_length > 65535U) {
        return RSA_ERR_RANGE;
    }
    *size = 16U + n_length + d_length + p_length + q_length;
    return RSA_OK;
}

int rsa_serialize_private_key(const RSA_PRIVATE_KEY *private_key,
                              unsigned char *output,
                              unsigned int output_capacity,
                              unsigned int *output_length)
{
    unsigned char temporary[RSA_PRIVATE_KEY_MAX_SERIALIZED];
    unsigned int required;
    unsigned int n_length;
    unsigned int d_length;
    unsigned int p_length;
    unsigned int q_length;
    unsigned int offset;
    int status;

    if (private_key == NULL || output_length == NULL) {
        return RSA_ERR_NULL;
    }
    status = rsa_private_key_serialized_size(private_key, &required);
    if (status != RSA_OK) {
        return status;
    }
    *output_length = required;
    if (output_capacity < required) {
        return RSA_ERR_CAPACITY;
    }
    if (output == NULL) {
        return RSA_ERR_NULL;
    }
    n_length = rsa_bigint_bytes(&private_key->public_key.n);
    d_length = rsa_bigint_bytes(&private_key->d);
    p_length = rsa_bigint_bytes(&private_key->p);
    q_length = rsa_bigint_bytes(&private_key->q);
    temporary[0] = 'T';
    temporary[1] = 'R';
    temporary[2] = 'S';
    temporary[3] = '8';
    rsa_put_u16(temporary + 4U, n_length);
    offset = 6U;
    status = rsa_write_bigint(&private_key->public_key.n,
                              temporary + offset, n_length);
    if (status != RSA_OK) {
        return status;
    }
    offset += n_length;
    temporary[offset++] = 0x00U;
    temporary[offset++] = 0x01U;
    temporary[offset++] = 0x00U;
    temporary[offset++] = 0x01U;
    rsa_put_u16(temporary + offset, d_length);
    offset += 2U;
    status = rsa_write_bigint(&private_key->d,
                              temporary + offset, d_length);
    if (status != RSA_OK) {
        return status;
    }
    offset += d_length;
    rsa_put_u16(temporary + offset, p_length);
    offset += 2U;
    status = rsa_write_bigint(&private_key->p,
                              temporary + offset, p_length);
    if (status != RSA_OK) {
        return status;
    }
    offset += p_length;
    rsa_put_u16(temporary + offset, q_length);
    offset += 2U;
    status = rsa_write_bigint(&private_key->q,
                              temporary + offset, q_length);
    if (status != RSA_OK) {
        return status;
    }
    offset += q_length;
    if (offset != required) {
        return RSA_ERR_ARITHMETIC;
    }
    memcpy(output, temporary, required);
    return RSA_OK;
}

static int rsa_parse_field(const unsigned char *input,
                           unsigned int input_length,
                           unsigned int *offset,
                           BIGINT *value)
{
    unsigned int length;
    int status;

    if (*offset > input_length || input_length - *offset < 2U) {
        return RSA_ERR_FORMAT;
    }
    length = rsa_get_u16(input + *offset);
    *offset += 2U;
    if (length == 0U || length > BIGINT_MAX_BYTES ||
        *offset > input_length || input_length - *offset < length) {
        return RSA_ERR_FORMAT;
    }
    status = rsa_read_bigint(input + *offset, length, value);
    if (status != RSA_OK) {
        return status;
    }
    *offset += length;
    return RSA_OK;
}

int rsa_deserialize_private_key(const unsigned char *input,
                                unsigned int input_length,
                                RSA_PRIVATE_KEY *private_key)
{
    RSA_PRIVATE_KEY temporary;
    BIGINT serialized_n;
    BIGINT serialized_d;
    BIGINT p;
    BIGINT q;
    unsigned int n_length;
    unsigned int offset;
    int comparison;
    int status;

    if (input == NULL || private_key == NULL) {
        return RSA_ERR_NULL;
    }
    if (input_length < 20U || input[0] != 'T' || input[1] != 'R' ||
        input[2] != 'S' || input[3] != '8') {
        return RSA_ERR_FORMAT;
    }
    n_length = rsa_get_u16(input + 4U);
    if (n_length == 0U || n_length > BIGINT_MAX_BYTES ||
        input_length - 6U < n_length + 4U) {
        return RSA_ERR_FORMAT;
    }
    status = rsa_read_bigint(input + 6U, n_length, &serialized_n);
    if (status != RSA_OK) {
        return status;
    }
    offset = 6U + n_length;
    if (input[offset] != 0x00U || input[offset + 1U] != 0x01U ||
        input[offset + 2U] != 0x00U || input[offset + 3U] != 0x01U) {
        return RSA_ERR_FORMAT;
    }
    offset += 4U;
    status = rsa_parse_field(input, input_length, &offset, &serialized_d);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_parse_field(input, input_length, &offset, &p);
    if (status != RSA_OK) {
        return status;
    }
    status = rsa_parse_field(input, input_length, &offset, &q);
    if (status != RSA_OK || offset != input_length) {
        return RSA_ERR_FORMAT;
    }
    status = rsa_private_key_from_primes(&p, &q, &temporary);
    if (status != RSA_OK) {
        return RSA_ERR_FORMAT;
    }
    status = rsa_compare(&serialized_n, &temporary.public_key.n,
                         &comparison);
    if (status != RSA_OK || comparison != 0) {
        return RSA_ERR_FORMAT;
    }
    status = rsa_compare(&serialized_d, &temporary.d, &comparison);
    if (status != RSA_OK || comparison != 0) {
        return RSA_ERR_FORMAT;
    }
    memcpy(private_key, &temporary, sizeof(temporary));
    return RSA_OK;
}
