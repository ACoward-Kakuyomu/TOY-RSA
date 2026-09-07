#include <stddef.h>
#include <string.h>

#include "number.h"

static const unsigned short number_small_primes[] = {
    2U, 3U, 5U, 7U, 11U, 13U, 17U, 19U, 23U, 29U,
    31U, 37U, 41U, 43U, 47U, 53U, 59U, 61U, 67U, 71U,
    73U, 79U, 83U, 89U, 97U, 101U, 103U, 107U, 109U, 113U,
    127U, 131U, 137U, 139U, 149U, 151U, 157U, 163U, 167U, 173U,
    179U, 181U, 191U, 193U, 197U, 199U, 211U, 223U, 227U, 229U,
    233U, 239U, 241U, 251U, 257U, 263U, 269U, 271U, 277U, 281U,
    283U, 293U, 307U, 311U, 313U, 317U, 331U, 337U, 347U, 349U,
    353U, 359U, 367U, 373U, 379U, 383U, 389U, 397U, 401U, 409U,
    419U, 421U, 431U, 433U, 439U, 443U, 449U, 457U, 461U, 463U,
    467U, 479U, 487U, 491U, 499U, 503U, 509U, 521U, 523U, 541U,
    547U, 557U, 563U, 569U, 571U, 577U, 587U, 593U, 599U, 601U,
    607U, 613U, 617U, 619U, 631U, 641U, 643U, 647U, 653U, 659U,
    661U, 673U, 677U, 683U, 691U, 701U, 709U, 719U, 727U, 733U,
    739U, 743U, 751U, 757U, 761U, 769U, 773U, 787U, 797U, 809U,
    811U, 821U, 823U, 827U, 829U, 839U, 853U, 857U, 859U, 863U,
    877U, 881U, 883U, 887U, 907U, 911U, 919U, 929U, 937U, 941U,
    947U, 953U, 967U, 971U, 977U, 983U, 991U, 997U
};

#define NUMBER_SMALL_PRIME_COUNT \
    ((unsigned int)(sizeof(number_small_primes) / \
                    sizeof(number_small_primes[0])))

static int number_bigint_error(int result)
{
    if (result == BIGINT_ERR_INVALID) {
        return NUMBER_ERR_INVALID;
    }
    return NUMBER_ERR_ARITHMETIC;
}

static int number_validate(const BIGINT *value)
{
    unsigned int bits;
    int result;

    if (value == NULL) {
        return NUMBER_ERR_NULL;
    }
    result = bigint_bit_length(value, &bits);
    if (result != BIGINT_OK) {
        return number_bigint_error(result);
    }
    return NUMBER_OK;
}

static int number_is_zero(const BIGINT *value, int *is_zero)
{
    int result;

    result = bigint_is_zero(value, is_zero);
    if (result != BIGINT_OK) {
        return number_bigint_error(result);
    }
    return NUMBER_OK;
}

static int number_compare(const BIGINT *left,
                          const BIGINT *right,
                          int *comparison)
{
    int result;

    result = bigint_compare(left, right, comparison);
    if (result != BIGINT_OK) {
        return number_bigint_error(result);
    }
    return NUMBER_OK;
}

static int number_mod_add_reduced(const BIGINT *left,
                                  const BIGINT *right,
                                  const BIGINT *modulus,
                                  BIGINT *result)
{
    BIGINT distance;
    BIGINT temporary;
    int comparison;
    int status;

    status = bigint_subtract(modulus, right, &distance);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_compare(left, &distance, &comparison);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    if (comparison >= 0) {
        status = bigint_subtract(left, &distance, &temporary);
    } else {
        status = bigint_add(left, right, &temporary);
    }
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    memcpy(result, &temporary, sizeof(temporary));
    return NUMBER_OK;
}

int number_gcd(const BIGINT *left,
               const BIGINT *right,
               BIGINT *greatest_common_divisor)
{
    BIGINT first;
    BIGINT second;
    BIGINT remainder;
    int is_zero;
    int status;

    if (left == NULL || right == NULL || greatest_common_divisor == NULL) {
        return NUMBER_ERR_NULL;
    }
    status = number_validate(left);
    if (status != NUMBER_OK) {
        return status;
    }
    status = number_validate(right);
    if (status != NUMBER_OK) {
        return status;
    }
    memcpy(&first, left, sizeof(first));
    memcpy(&second, right, sizeof(second));
    for (;;) {
        status = number_is_zero(&second, &is_zero);
        if (status != NUMBER_OK) {
            return status;
        }
        if (is_zero != 0) {
            break;
        }
        status = bigint_modulo(&first, &second, &remainder);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        memcpy(&first, &second, sizeof(first));
        memcpy(&second, &remainder, sizeof(second));
    }
    memcpy(greatest_common_divisor, &first, sizeof(first));
    return NUMBER_OK;
}

int number_mod_multiply(const BIGINT *left,
                        const BIGINT *right,
                        const BIGINT *modulus,
                        BIGINT *result)
{
    BIGINT reduced_left;
    BIGINT reduced_right;
    BIGINT product;
    BIGINT accumulator;
    BIGINT addend;
    BIGINT multiplier;
    unsigned int left_bits;
    unsigned int right_bits;
    int is_zero;
    int is_odd;
    int status;

    if (left == NULL || right == NULL || modulus == NULL || result == NULL) {
        return NUMBER_ERR_NULL;
    }
    status = number_validate(left);
    if (status != NUMBER_OK) {
        return status;
    }
    status = number_validate(right);
    if (status != NUMBER_OK) {
        return status;
    }
    status = number_validate(modulus);
    if (status != NUMBER_OK) {
        return status;
    }
    status = number_is_zero(modulus, &is_zero);
    if (status != NUMBER_OK) {
        return status;
    }
    if (is_zero != 0) {
        return NUMBER_ERR_MODULUS;
    }
    status = bigint_modulo(left, modulus, &reduced_left);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_modulo(right, modulus, &reduced_right);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_bit_length(&reduced_left, &left_bits);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_bit_length(&reduced_right, &right_bits);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    if (left_bits + right_bits <= BIGINT_MAX_BITS) {
        status = bigint_multiply(&reduced_left, &reduced_right, &product);
        if (status == BIGINT_OK) {
            status = bigint_modulo(&product, modulus, &accumulator);
            if (status != BIGINT_OK) {
                return number_bigint_error(status);
            }
            memcpy(result, &accumulator, sizeof(accumulator));
            return NUMBER_OK;
        }
        if (status != BIGINT_ERR_OVERFLOW) {
            return number_bigint_error(status);
        }
    }

    status = bigint_zero(&accumulator);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    memcpy(&addend, &reduced_left, sizeof(addend));
    memcpy(&multiplier, &reduced_right, sizeof(multiplier));
    for (;;) {
        status = bigint_is_zero(&multiplier, &is_zero);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        if (is_zero != 0) {
            break;
        }
        status = bigint_is_odd(&multiplier, &is_odd);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        if (is_odd != 0) {
            status = number_mod_add_reduced(&accumulator, &addend,
                                            modulus, &accumulator);
            if (status != NUMBER_OK) {
                return status;
            }
        }
        status = bigint_shift_right(&multiplier, 1U, &multiplier);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        status = bigint_is_zero(&multiplier, &is_zero);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        if (is_zero == 0) {
            status = number_mod_add_reduced(&addend, &addend,
                                            modulus, &addend);
            if (status != NUMBER_OK) {
                return status;
            }
        }
    }
    memcpy(result, &accumulator, sizeof(accumulator));
    return NUMBER_OK;
}

int number_mod_pow(const BIGINT *base,
                   const BIGINT *exponent,
                   const BIGINT *modulus,
                   BIGINT *result)
{
    BIGINT result_value;
    BIGINT power;
    BIGINT exponent_work;
    BIGINT one;
    int is_zero;
    int is_odd;
    int status;

    if (base == NULL || exponent == NULL || modulus == NULL ||
        result == NULL) {
        return NUMBER_ERR_NULL;
    }
    status = number_validate(base);
    if (status != NUMBER_OK) {
        return status;
    }
    status = number_validate(exponent);
    if (status != NUMBER_OK) {
        return status;
    }
    status = number_validate(modulus);
    if (status != NUMBER_OK) {
        return status;
    }
    status = number_is_zero(modulus, &is_zero);
    if (status != NUMBER_OK) {
        return status;
    }
    if (is_zero != 0) {
        return NUMBER_ERR_MODULUS;
    }
    status = bigint_from_ulong(&one, 1UL);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_modulo(&one, modulus, &result_value);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_modulo(base, modulus, &power);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    memcpy(&exponent_work, exponent, sizeof(exponent_work));
    for (;;) {
        status = bigint_is_zero(&exponent_work, &is_zero);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        if (is_zero != 0) {
            break;
        }
        status = bigint_is_odd(&exponent_work, &is_odd);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        if (is_odd != 0) {
            status = number_mod_multiply(&result_value, &power,
                                         modulus, &result_value);
            if (status != NUMBER_OK) {
                return status;
            }
        }
        status = bigint_shift_right(&exponent_work, 1U, &exponent_work);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        status = bigint_is_zero(&exponent_work, &is_zero);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        if (is_zero == 0) {
            status = number_mod_multiply(&power, &power,
                                         modulus, &power);
            if (status != NUMBER_OK) {
                return status;
            }
        }
    }
    memcpy(result, &result_value, sizeof(result_value));
    return NUMBER_OK;
}

static int number_mod_subtract_reduced(const BIGINT *left,
                                       const BIGINT *right,
                                       const BIGINT *modulus,
                                       BIGINT *result)
{
    BIGINT difference;
    int comparison;
    int status;

    status = number_compare(left, right, &comparison);
    if (status != NUMBER_OK) {
        return status;
    }
    if (comparison >= 0) {
        status = bigint_subtract(left, right, &difference);
    } else {
        status = bigint_subtract(right, left, &difference);
        if (status == BIGINT_OK) {
            status = bigint_subtract(modulus, &difference, &difference);
        }
    }
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    memcpy(result, &difference, sizeof(difference));
    return NUMBER_OK;
}

int number_mod_inverse(const BIGINT *value,
                       const BIGINT *modulus,
                       BIGINT *inverse)
{
    BIGINT r;
    BIGINT new_r;
    BIGINT next_r;
    BIGINT t;
    BIGINT new_t;
    BIGINT next_t;
    BIGINT quotient;
    BIGINT product;
    BIGINT one;
    int comparison;
    int is_zero;
    int status;

    if (value == NULL || modulus == NULL || inverse == NULL) {
        return NUMBER_ERR_NULL;
    }
    status = number_validate(value);
    if (status != NUMBER_OK) {
        return status;
    }
    status = number_validate(modulus);
    if (status != NUMBER_OK) {
        return status;
    }
    status = bigint_from_ulong(&one, 1UL);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = number_compare(modulus, &one, &comparison);
    if (status != NUMBER_OK) {
        return status;
    }
    if (comparison <= 0) {
        return NUMBER_ERR_MODULUS;
    }
    memcpy(&r, modulus, sizeof(r));
    status = bigint_modulo(value, modulus, &new_r);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_zero(&t);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    memcpy(&new_t, &one, sizeof(new_t));

    for (;;) {
        status = bigint_is_zero(&new_r, &is_zero);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        if (is_zero != 0) {
            break;
        }
        status = bigint_divmod(&r, &new_r, &quotient, &next_r);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        status = number_mod_multiply(&quotient, &new_t,
                                     modulus, &product);
        if (status != NUMBER_OK) {
            return status;
        }
        status = number_mod_subtract_reduced(&t, &product,
                                             modulus, &next_t);
        if (status != NUMBER_OK) {
            return status;
        }
        memcpy(&r, &new_r, sizeof(r));
        memcpy(&new_r, &next_r, sizeof(new_r));
        memcpy(&t, &new_t, sizeof(t));
        memcpy(&new_t, &next_t, sizeof(new_t));
    }
    status = number_compare(&r, &one, &comparison);
    if (status != NUMBER_OK) {
        return status;
    }
    if (comparison != 0) {
        return NUMBER_ERR_NO_INVERSE;
    }
    memcpy(inverse, &t, sizeof(t));
    return NUMBER_OK;
}

static unsigned int number_remainder_small(const BIGINT *value,
                                           unsigned int divisor)
{
    unsigned long remainder;
    unsigned int index;

    remainder = 0UL;
    index = value->used;
    while (index != 0U) {
        --index;
        remainder = ((remainder << BIGINT_LIMB_BITS) +
                     (unsigned long)value->limb[index]) % divisor;
    }
    return (unsigned int)remainder;
}

int number_trial_division(const BIGINT *candidate,
                          unsigned int *factor)
{
    unsigned int index;
    int status;

    if (candidate == NULL || factor == NULL) {
        return NUMBER_ERR_NULL;
    }
    status = number_validate(candidate);
    if (status != NUMBER_OK) {
        return status;
    }
    for (index = 0U; index < NUMBER_SMALL_PRIME_COUNT; ++index) {
        if (number_remainder_small(candidate,
                                   number_small_primes[index]) == 0U) {
            *factor = number_small_primes[index];
            return NUMBER_OK;
        }
    }
    *factor = 0U;
    return NUMBER_OK;
}

static int number_prime_precheck(const BIGINT *candidate,
                                 int *finished,
                                 int *probable_prime)
{
    BIGINT two;
    BIGINT three;
    BIGINT factor_value;
    unsigned int factor;
    int comparison;
    int is_odd;
    int status;

    status = bigint_from_ulong(&two, 2UL);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_from_ulong(&three, 3UL);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = number_compare(candidate, &two, &comparison);
    if (status != NUMBER_OK) {
        return status;
    }
    if (comparison < 0) {
        *finished = 1;
        *probable_prime = 0;
        return NUMBER_OK;
    }
    if (comparison == 0) {
        *finished = 1;
        *probable_prime = 1;
        return NUMBER_OK;
    }
    status = number_compare(candidate, &three, &comparison);
    if (status != NUMBER_OK) {
        return status;
    }
    if (comparison == 0) {
        *finished = 1;
        *probable_prime = 1;
        return NUMBER_OK;
    }
    status = bigint_is_odd(candidate, &is_odd);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    if (is_odd == 0) {
        *finished = 1;
        *probable_prime = 0;
        return NUMBER_OK;
    }
    status = number_trial_division(candidate, &factor);
    if (status != NUMBER_OK) {
        return status;
    }
    if (factor != 0U) {
        status = bigint_from_ulong(&factor_value, (unsigned long)factor);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        status = number_compare(candidate, &factor_value, &comparison);
        if (status != NUMBER_OK) {
            return status;
        }
        *finished = 1;
        *probable_prime = comparison == 0;
        return NUMBER_OK;
    }
    *finished = 0;
    return NUMBER_OK;
}

static int number_prepare_miller_rabin(const BIGINT *candidate,
                                       BIGINT *odd_part,
                                       BIGINT *candidate_minus_one,
                                       unsigned int *power_of_two)
{
    BIGINT one;
    int is_odd;
    int status;

    status = bigint_from_ulong(&one, 1UL);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_subtract(candidate, &one, candidate_minus_one);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    memcpy(odd_part, candidate_minus_one, sizeof(*odd_part));
    *power_of_two = 0U;
    for (;;) {
        status = bigint_is_odd(odd_part, &is_odd);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        if (is_odd != 0) {
            break;
        }
        status = bigint_shift_right(odd_part, 1U, odd_part);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        ++*power_of_two;
    }
    return NUMBER_OK;
}

static int number_miller_rabin_witness(
    const BIGINT *candidate,
    const BIGINT *odd_part,
    const BIGINT *candidate_minus_one,
    unsigned int power_of_two,
    const BIGINT *witness,
    int *passes)
{
    BIGINT x;
    BIGINT one;
    unsigned int round;
    int comparison;
    int status;

    status = bigint_from_ulong(&one, 1UL);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = number_mod_pow(witness, odd_part, candidate, &x);
    if (status != NUMBER_OK) {
        return status;
    }
    status = number_compare(&x, &one, &comparison);
    if (status != NUMBER_OK) {
        return status;
    }
    if (comparison == 0) {
        *passes = 1;
        return NUMBER_OK;
    }
    status = number_compare(&x, candidate_minus_one, &comparison);
    if (status != NUMBER_OK) {
        return status;
    }
    if (comparison == 0) {
        *passes = 1;
        return NUMBER_OK;
    }
    for (round = 1U; round < power_of_two; ++round) {
        status = number_mod_multiply(&x, &x, candidate, &x);
        if (status != NUMBER_OK) {
            return status;
        }
        status = number_compare(&x, candidate_minus_one, &comparison);
        if (status != NUMBER_OK) {
            return status;
        }
        if (comparison == 0) {
            *passes = 1;
            return NUMBER_OK;
        }
        status = number_compare(&x, &one, &comparison);
        if (status != NUMBER_OK) {
            return status;
        }
        if (comparison == 0) {
            *passes = 0;
            return NUMBER_OK;
        }
    }
    *passes = 0;
    return NUMBER_OK;
}

static int number_ulong_reduced(unsigned long value,
                                const BIGINT *modulus,
                                BIGINT *result)
{
    BIGINT native_value;
    unsigned long native_modulus;
    int status;

    status = bigint_from_ulong(&native_value, value);
    if (status == BIGINT_OK) {
        status = bigint_modulo(&native_value, modulus, result);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        return NUMBER_OK;
    }
    if (status != BIGINT_ERR_OVERFLOW) {
        return number_bigint_error(status);
    }
    status = bigint_to_ulong(modulus, &native_modulus);
    if (status != BIGINT_OK || native_modulus == 0UL) {
        return number_bigint_error(status);
    }
    status = bigint_from_ulong(result, value % native_modulus);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    return NUMBER_OK;
}

static int number_mapped_witness(unsigned long base,
                                 const BIGINT *candidate,
                                 BIGINT *witness)
{
    BIGINT three;
    BIGINT two;
    BIGINT range;
    BIGINT reduced;
    int status;

    status = bigint_from_ulong(&three, 3UL);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_from_ulong(&two, 2UL);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_subtract(candidate, &three, &range);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    if (base < 2UL) {
        return NUMBER_ERR_INVALID;
    }
    status = number_ulong_reduced(base - 2UL, &range, &reduced);
    if (status != NUMBER_OK) {
        return status;
    }
    status = bigint_add(&reduced, &two, witness);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    return NUMBER_OK;
}

int number_miller_rabin_bases(const BIGINT *candidate,
                              const unsigned long *bases,
                              unsigned int rounds,
                              int *probable_prime)
{
    BIGINT odd_part;
    BIGINT candidate_minus_one;
    BIGINT witness;
    unsigned int power_of_two;
    unsigned int round;
    int finished;
    int result_value;
    int passes;
    int status;

    if (candidate == NULL || bases == NULL || probable_prime == NULL) {
        return NUMBER_ERR_NULL;
    }
    if (rounds == 0U) {
        return NUMBER_ERR_RANGE;
    }
    for (round = 0U; round < rounds; ++round) {
        if (bases[round] < 2UL) {
            return NUMBER_ERR_INVALID;
        }
    }
    status = number_validate(candidate);
    if (status != NUMBER_OK) {
        return status;
    }
    status = number_prime_precheck(candidate, &finished, &result_value);
    if (status != NUMBER_OK) {
        return status;
    }
    if (finished != 0) {
        *probable_prime = result_value;
        return NUMBER_OK;
    }
    status = number_prepare_miller_rabin(candidate, &odd_part,
                                         &candidate_minus_one,
                                         &power_of_two);
    if (status != NUMBER_OK) {
        return status;
    }
    for (round = 0U; round < rounds; ++round) {
        status = number_mapped_witness(bases[round], candidate, &witness);
        if (status != NUMBER_OK) {
            return status;
        }
        status = number_miller_rabin_witness(candidate, &odd_part,
                                              &candidate_minus_one,
                                              power_of_two, &witness,
                                              &passes);
        if (status != NUMBER_OK) {
            return status;
        }
        if (passes == 0) {
            *probable_prime = 0;
            return NUMBER_OK;
        }
    }
    *probable_prime = 1;
    return NUMBER_OK;
}

static int number_random_witness(RNG_CTX *rng,
                                 const BIGINT *candidate,
                                 BIGINT *witness)
{
    unsigned char bytes[BIGINT_MAX_BYTES];
    BIGINT candidate_minus_two;
    BIGINT two;
    BIGINT random_value;
    unsigned int bit_length;
    unsigned int byte_length;
    unsigned int top_bits;
    unsigned int attempt;
    int comparison;
    int status;

    status = bigint_from_ulong(&two, 2UL);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_subtract(candidate, &two, &candidate_minus_two);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    status = bigint_bit_length(candidate, &bit_length);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    byte_length = (bit_length + 7U) / 8U;
    top_bits = bit_length % 8U;
    for (attempt = 0U; attempt < NUMBER_WITNESS_REJECTION_LIMIT;
         ++attempt) {
        status = rng_generate(rng, bytes, (unsigned long)byte_length);
        if (status != RNG_OK) {
            return NUMBER_ERR_RNG;
        }
        if (top_bits != 0U) {
            bytes[0] = (unsigned char)(bytes[0] &
                (unsigned char)((1U << top_bits) - 1U));
        }
        status = bigint_from_bytes(&random_value, bytes, byte_length);
        if (status != BIGINT_OK) {
            return number_bigint_error(status);
        }
        status = number_compare(&random_value, &two, &comparison);
        if (status != NUMBER_OK) {
            return status;
        }
        if (comparison < 0) {
            continue;
        }
        status = number_compare(&random_value, &candidate_minus_two,
                                &comparison);
        if (status != NUMBER_OK) {
            return status;
        }
        if (comparison <= 0) {
            memcpy(witness, &random_value, sizeof(random_value));
            return NUMBER_OK;
        }
    }
    return NUMBER_ERR_RNG;
}

int number_miller_rabin(const BIGINT *candidate,
                        RNG_CTX *rng,
                        unsigned int rounds,
                        int *probable_prime)
{
    BIGINT odd_part;
    BIGINT candidate_minus_one;
    BIGINT witness;
    unsigned int power_of_two;
    unsigned int round;
    int finished;
    int result_value;
    int passes;
    int status;

    if (candidate == NULL || rng == NULL || probable_prime == NULL) {
        return NUMBER_ERR_NULL;
    }
    if (rounds == 0U) {
        return NUMBER_ERR_RANGE;
    }
    status = number_validate(candidate);
    if (status != NUMBER_OK) {
        return status;
    }
    status = number_prime_precheck(candidate, &finished, &result_value);
    if (status != NUMBER_OK) {
        return status;
    }
    if (finished != 0) {
        *probable_prime = result_value;
        return NUMBER_OK;
    }
    status = number_prepare_miller_rabin(candidate, &odd_part,
                                         &candidate_minus_one,
                                         &power_of_two);
    if (status != NUMBER_OK) {
        return status;
    }
    for (round = 0U; round < rounds; ++round) {
        status = number_random_witness(rng, candidate, &witness);
        if (status != NUMBER_OK) {
            return status;
        }
        status = number_miller_rabin_witness(candidate, &odd_part,
                                              &candidate_minus_one,
                                              power_of_two, &witness,
                                              &passes);
        if (status != NUMBER_OK) {
            return status;
        }
        if (passes == 0) {
            *probable_prime = 0;
            return NUMBER_OK;
        }
    }
    *probable_prime = 1;
    return NUMBER_OK;
}

static int number_random_candidate(RNG_CTX *rng,
                                   unsigned int bits,
                                   BIGINT *candidate)
{
    unsigned char bytes[BIGINT_MAX_BYTES];
    unsigned int byte_length;
    unsigned int top_bits;
    unsigned int top_bit;
    int status;

    byte_length = (bits + 7U) / 8U;
    status = rng_generate(rng, bytes, (unsigned long)byte_length);
    if (status != RNG_OK) {
        return NUMBER_ERR_RNG;
    }
    top_bits = bits % 8U;
    if (top_bits != 0U) {
        bytes[0] = (unsigned char)(bytes[0] &
            (unsigned char)((1U << top_bits) - 1U));
    }
    top_bit = (bits - 1U) % 8U;
    bytes[0] = (unsigned char)(bytes[0] |
                              (unsigned char)(1U << top_bit));
    bytes[byte_length - 1U] =
        (unsigned char)(bytes[byte_length - 1U] | 1U);
    status = bigint_from_bytes(candidate, bytes, byte_length);
    if (status != BIGINT_OK) {
        return number_bigint_error(status);
    }
    return NUMBER_OK;
}

int number_generate_probable_prime(RNG_CTX *rng,
                                   unsigned int bits,
                                   unsigned int rounds,
                                   unsigned long maximum_attempts,
                                   BIGINT *prime,
                                   unsigned long *attempts_used)
{
    BIGINT candidate;
    unsigned long attempt;
    int probable_prime;
    int status;

    if (rng == NULL || prime == NULL || attempts_used == NULL) {
        return NUMBER_ERR_NULL;
    }
    if (bits < 2U || bits > BIGINT_MAX_BITS || rounds == 0U ||
        maximum_attempts == 0UL) {
        return NUMBER_ERR_RANGE;
    }
    for (attempt = 0UL; attempt < maximum_attempts; ++attempt) {
        status = number_random_candidate(rng, bits, &candidate);
        if (status != NUMBER_OK) {
            return status;
        }
        status = number_miller_rabin(&candidate, rng, rounds,
                                     &probable_prime);
        if (status != NUMBER_OK) {
            return status;
        }
        if (probable_prime != 0) {
            memcpy(prime, &candidate, sizeof(candidate));
            *attempts_used = attempt + 1UL;
            return NUMBER_OK;
        }
    }
    *attempts_used = maximum_attempts;
    return NUMBER_ERR_ATTEMPTS;
}
