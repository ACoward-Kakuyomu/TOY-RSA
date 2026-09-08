#include <stddef.h>
#include <string.h>

#include "montgomery.h"
#include "number.h"

static int mont_bigint_error(int status)
{
    if (status == BIGINT_ERR_INVALID) {
        return MONT_ERR_INVALID;
    }
    return MONT_ERR_ARITHMETIC;
}

static int mont_number_error(int status)
{
    if (status == NUMBER_ERR_INVALID) {
        return MONT_ERR_INVALID;
    }
    if (status == NUMBER_ERR_MODULUS) {
        return MONT_ERR_MODULUS;
    }
    return MONT_ERR_ARITHMETIC;
}

static int mont_validate_bigint(const BIGINT *value)
{
    unsigned int bits;
    int status;

    if (value == NULL) {
        return MONT_ERR_NULL;
    }
    status = bigint_bit_length(value, &bits);
    if (status != BIGINT_OK) {
        return mont_bigint_error(status);
    }
    return MONT_OK;
}

static void mont_wide_clear(MONT_WIDE *value)
{
    memset(value->limb, 0, sizeof(value->limb));
    value->used = 0U;
}

static void mont_wide_normalize(MONT_WIDE *value)
{
    while (value->used != 0U && value->limb[value->used - 1U] == 0U) {
        --value->used;
    }
    if (value->used < MONT_WIDE_MAX_LIMBS) {
        memset(value->limb + value->used, 0,
               (MONT_WIDE_MAX_LIMBS - value->used) *
               sizeof(BIGINT_LIMB));
    }
}

static int mont_wide_valid(const MONT_WIDE *value)
{
    unsigned int index;

    if (value->used > MONT_WIDE_MAX_LIMBS) {
        return 0;
    }
    if (value->used != 0U && value->limb[value->used - 1U] == 0U) {
        return 0;
    }
#if BIGINT_LIMB_MASK < USHRT_MAX
    for (index = 0U; index < value->used; ++index) {
        if ((unsigned long)value->limb[index] > BIGINT_LIMB_MASK) {
            return 0;
        }
    }
#endif
    for (index = value->used; index < MONT_WIDE_MAX_LIMBS; ++index) {
        if (value->limb[index] != 0U) {
            return 0;
        }
    }
    return 1;
}

static int mont_compare_bigint(const BIGINT *left,
                               const BIGINT *right,
                               int *comparison)
{
    int status;

    status = bigint_compare(left, right, comparison);
    if (status != BIGINT_OK) {
        return mont_bigint_error(status);
    }
    return MONT_OK;
}

static int mont_context_valid(const MONT_CTX *context)
{
    BIGINT one;
    unsigned long product;
    int comparison;
    int is_odd;
    int status;

    if (context->initialized != MONT_CONTEXT_READY) {
        return 0;
    }
    if (context->limbs == 0U || context->limbs > BIGINT_MAX_LIMBS ||
        context->modulus.used != context->limbs) {
        return 0;
    }
    if (mont_validate_bigint(&context->modulus) != MONT_OK ||
        mont_validate_bigint(&context->r_mod_n) != MONT_OK ||
        mont_validate_bigint(&context->r2_mod_n) != MONT_OK) {
        return 0;
    }
    status = bigint_from_ulong(&one, 1UL);
    if (status != BIGINT_OK) {
        return 0;
    }
    status = bigint_compare(&context->modulus, &one, &comparison);
    if (status != BIGINT_OK || comparison <= 0) {
        return 0;
    }
    status = bigint_is_odd(&context->modulus, &is_odd);
    if (status != BIGINT_OK || is_odd == 0) {
        return 0;
    }
    status = bigint_compare(&context->r_mod_n,
                            &context->modulus, &comparison);
    if (status != BIGINT_OK || comparison >= 0) {
        return 0;
    }
    status = bigint_compare(&context->r2_mod_n,
                            &context->modulus, &comparison);
    if (status != BIGINT_OK || comparison >= 0) {
        return 0;
    }
    product = (unsigned long)context->modulus.limb[0] *
              (unsigned long)context->n0_prime;
    if ((product & BIGINT_LIMB_MASK) != BIGINT_LIMB_MASK) {
        return 0;
    }
    return 1;
}

static BIGINT_LIMB mont_compute_n0_prime(BIGINT_LIMB least_word)
{
    unsigned long inverse;
    unsigned long product;
    unsigned int iteration;

    inverse = 1UL;
    for (iteration = 0U; iteration < 4U; ++iteration) {
        product = ((unsigned long)least_word * inverse) &
                  BIGINT_LIMB_MASK;
        inverse = (inverse * (2UL - product)) & BIGINT_LIMB_MASK;
    }
    return (BIGINT_LIMB)((0UL - inverse) & BIGINT_LIMB_MASK);
}

static int mont_mod_double(const BIGINT *value,
                           const BIGINT *modulus,
                           BIGINT *result)
{
    BIGINT distance;
    BIGINT temporary;
    int comparison;
    int status;

    status = bigint_subtract(modulus, value, &distance);
    if (status != BIGINT_OK) {
        return mont_bigint_error(status);
    }
    status = bigint_compare(value, &distance, &comparison);
    if (status != BIGINT_OK) {
        return mont_bigint_error(status);
    }
    if (comparison >= 0) {
        status = bigint_subtract(value, &distance, &temporary);
    } else {
        status = bigint_add(value, value, &temporary);
    }
    if (status != BIGINT_OK) {
        return mont_bigint_error(status);
    }
    memcpy(result, &temporary, sizeof(temporary));
    return MONT_OK;
}

int mont_init(MONT_CTX *context, const BIGINT *modulus)
{
    MONT_CTX temporary;
    BIGINT one;
    unsigned int iteration;
    unsigned int double_count;
    int comparison;
    int is_odd;
    int status;

    if (context == NULL || modulus == NULL) {
        return MONT_ERR_NULL;
    }
    status = mont_validate_bigint(modulus);
    if (status != MONT_OK) {
        return status;
    }
    status = bigint_from_ulong(&one, 1UL);
    if (status != BIGINT_OK) {
        return mont_bigint_error(status);
    }
    status = bigint_compare(modulus, &one, &comparison);
    if (status != BIGINT_OK) {
        return mont_bigint_error(status);
    }
    status = bigint_is_odd(modulus, &is_odd);
    if (status != BIGINT_OK) {
        return mont_bigint_error(status);
    }
    if (comparison <= 0 || is_odd == 0) {
        return MONT_ERR_MODULUS;
    }

    memset(&temporary, 0, sizeof(temporary));
    memcpy(&temporary.modulus, modulus, sizeof(temporary.modulus));
    temporary.limbs = modulus->used;
    temporary.n0_prime = mont_compute_n0_prime(modulus->limb[0]);
    memcpy(&temporary.r_mod_n, &one, sizeof(one));
    double_count = temporary.limbs * BIGINT_LIMB_BITS;
    for (iteration = 0U; iteration < double_count; ++iteration) {
        status = mont_mod_double(&temporary.r_mod_n,
                                 &temporary.modulus,
                                 &temporary.r_mod_n);
        if (status != MONT_OK) {
            return status;
        }
    }
    status = number_mod_multiply(&temporary.r_mod_n,
                                 &temporary.r_mod_n,
                                 &temporary.modulus,
                                 &temporary.r2_mod_n);
    if (status != NUMBER_OK) {
        return mont_number_error(status);
    }
    temporary.initialized = MONT_CONTEXT_READY;
    if (!mont_context_valid(&temporary)) {
        return MONT_ERR_ARITHMETIC;
    }
    memcpy(context, &temporary, sizeof(temporary));
    return MONT_OK;
}

int mont_wide_from_bigint(const BIGINT *value, MONT_WIDE *wide_value)
{
    MONT_WIDE temporary;
    int status;

    if (value == NULL || wide_value == NULL) {
        return MONT_ERR_NULL;
    }
    status = mont_validate_bigint(value);
    if (status != MONT_OK) {
        return status;
    }
    mont_wide_clear(&temporary);
    if (value->used != 0U) {
        memcpy(temporary.limb, value->limb,
               value->used * sizeof(BIGINT_LIMB));
        temporary.used = value->used;
    }
    memcpy(wide_value, &temporary, sizeof(temporary));
    return MONT_OK;
}

int mont_wide_multiply(const BIGINT *left,
                       const BIGINT *right,
                       MONT_WIDE *wide_product)
{
    MONT_WIDE temporary;
    unsigned long accumulator;
    unsigned long carry;
    unsigned int target;
    unsigned int left_index;
    unsigned int right_index;
    int status;

    if (left == NULL || right == NULL || wide_product == NULL) {
        return MONT_ERR_NULL;
    }
    status = mont_validate_bigint(left);
    if (status != MONT_OK) {
        return status;
    }
    status = mont_validate_bigint(right);
    if (status != MONT_OK) {
        return status;
    }
    mont_wide_clear(&temporary);
    if (left->used == 0U || right->used == 0U) {
        memcpy(wide_product, &temporary, sizeof(temporary));
        return MONT_OK;
    }
    for (left_index = 0U; left_index < left->used; ++left_index) {
        carry = 0UL;
        for (right_index = 0U; right_index < right->used;
             ++right_index) {
            target = left_index + right_index;
            accumulator = (unsigned long)temporary.limb[target] +
                (unsigned long)left->limb[left_index] *
                (unsigned long)right->limb[right_index] + carry;
            temporary.limb[target] =
                (BIGINT_LIMB)(accumulator & BIGINT_LIMB_MASK);
            carry = accumulator >> BIGINT_LIMB_BITS;
        }
        target = left_index + right->used;
        if (carry != 0UL) {
            temporary.limb[target] = (BIGINT_LIMB)carry;
        }
    }
    temporary.used = left->used + right->used;
    mont_wide_normalize(&temporary);
    memcpy(wide_product, &temporary, sizeof(temporary));
    return MONT_OK;
}

static int mont_wide_less_than_n_r(const MONT_CTX *context,
                                   const MONT_WIDE *value)
{
    unsigned int shifted_used;
    unsigned int index;
    BIGINT_LIMB value_word;
    BIGINT_LIMB modulus_word;

    shifted_used = context->limbs * 2U;
    if (value->used < shifted_used) {
        return 1;
    }
    if (value->used > shifted_used) {
        return 0;
    }
    index = context->limbs;
    while (index != 0U) {
        --index;
        value_word = value->limb[context->limbs + index];
        modulus_word = context->modulus.limb[index];
        if (value_word < modulus_word) {
            return 1;
        }
        if (value_word > modulus_word) {
            return 0;
        }
    }
    return 0;
}

static int mont_reduced_segment_at_least_modulus(
    const MONT_CTX *context,
    const MONT_WIDE *work)
{
    unsigned int index;
    BIGINT_LIMB result_word;
    BIGINT_LIMB modulus_word;

    if (work->limb[context->limbs * 2U] != 0U) {
        return 1;
    }
    index = context->limbs;
    while (index != 0U) {
        --index;
        result_word = work->limb[context->limbs + index];
        modulus_word = context->modulus.limb[index];
        if (result_word > modulus_word) {
            return 1;
        }
        if (result_word < modulus_word) {
            return 0;
        }
    }
    return 1;
}

static int mont_subtract_modulus_from_segment(const MONT_CTX *context,
                                              MONT_WIDE *work)
{
    unsigned long left_word;
    unsigned long right_word;
    unsigned long subtrahend;
    unsigned long difference;
    unsigned long borrow;
    unsigned int index;
    unsigned int target;

    borrow = 0UL;
    for (index = 0U; index < context->limbs; ++index) {
        target = context->limbs + index;
        left_word = work->limb[target];
        right_word = context->modulus.limb[index];
        subtrahend = right_word + borrow;
        if (left_word >= subtrahend) {
            difference = left_word - subtrahend;
            borrow = 0UL;
        } else {
            difference = BIGINT_LIMB_BASE + left_word - subtrahend;
            borrow = 1UL;
        }
        work->limb[target] =
            (BIGINT_LIMB)(difference & BIGINT_LIMB_MASK);
    }
    target = context->limbs * 2U;
    if ((unsigned long)work->limb[target] < borrow) {
        return MONT_ERR_ARITHMETIC;
    }
    work->limb[target] =
        (BIGINT_LIMB)((unsigned long)work->limb[target] - borrow);
    return MONT_OK;
}

int mont_reduce(const MONT_CTX *context,
                const MONT_WIDE *wide_value,
                BIGINT *result)
{
    MONT_WIDE work;
    BIGINT temporary;
    unsigned long multiplier;
    unsigned long accumulator;
    unsigned long carry;
    unsigned int outer;
    unsigned int inner;
    unsigned int target;
    unsigned int index;
    int comparison;
    int status;

    if (context == NULL || wide_value == NULL || result == NULL) {
        return MONT_ERR_NULL;
    }
    if (!mont_context_valid(context)) {
        return MONT_ERR_CONTEXT;
    }
    if (!mont_wide_valid(wide_value)) {
        return MONT_ERR_INVALID;
    }
    if (!mont_wide_less_than_n_r(context, wide_value)) {
        return MONT_ERR_RANGE;
    }
    memcpy(&work, wide_value, sizeof(work));
    for (outer = 0U; outer < context->limbs; ++outer) {
        multiplier = ((unsigned long)work.limb[outer] *
                      (unsigned long)context->n0_prime) &
                     BIGINT_LIMB_MASK;
        carry = 0UL;
        for (inner = 0U; inner < context->limbs; ++inner) {
            target = outer + inner;
            accumulator = (unsigned long)work.limb[target] +
                multiplier * (unsigned long)context->modulus.limb[inner] +
                carry;
            work.limb[target] =
                (BIGINT_LIMB)(accumulator & BIGINT_LIMB_MASK);
            carry = accumulator >> BIGINT_LIMB_BITS;
        }
        target = outer + context->limbs;
        while (carry != 0UL) {
            if (target >= MONT_WIDE_MAX_LIMBS) {
                return MONT_ERR_ARITHMETIC;
            }
            accumulator = (unsigned long)work.limb[target] + carry;
            work.limb[target] =
                (BIGINT_LIMB)(accumulator & BIGINT_LIMB_MASK);
            carry = accumulator >> BIGINT_LIMB_BITS;
            ++target;
        }
        if (work.limb[outer] != 0U) {
            return MONT_ERR_ARITHMETIC;
        }
    }
    if (mont_reduced_segment_at_least_modulus(context, &work)) {
        status = mont_subtract_modulus_from_segment(context, &work);
        if (status != MONT_OK) {
            return status;
        }
    }
    for (index = context->limbs * 2U;
         index < MONT_WIDE_MAX_LIMBS; ++index) {
        if (work.limb[index] != 0U) {
            return MONT_ERR_ARITHMETIC;
        }
    }
    status = bigint_zero(&temporary);
    if (status != BIGINT_OK) {
        return mont_bigint_error(status);
    }
    memcpy(temporary.limb, work.limb + context->limbs,
           context->limbs * sizeof(BIGINT_LIMB));
    temporary.used = context->limbs;
    while (temporary.used != 0U &&
           temporary.limb[temporary.used - 1U] == 0U) {
        --temporary.used;
    }
    if (temporary.used < BIGINT_MAX_LIMBS) {
        memset(temporary.limb + temporary.used, 0,
               (BIGINT_MAX_LIMBS - temporary.used) *
               sizeof(BIGINT_LIMB));
    }
    status = bigint_compare(&temporary, &context->modulus, &comparison);
    if (status != BIGINT_OK) {
        return mont_bigint_error(status);
    }
    if (comparison >= 0) {
        return MONT_ERR_ARITHMETIC;
    }
    memcpy(result, &temporary, sizeof(temporary));
    return MONT_OK;
}

static int mont_operand_in_range(const MONT_CTX *context,
                                 const BIGINT *value)
{
    int comparison;
    int status;

    status = mont_validate_bigint(value);
    if (status != MONT_OK) {
        return status;
    }
    status = mont_compare_bigint(value, &context->modulus, &comparison);
    if (status != MONT_OK) {
        return status;
    }
    if (comparison >= 0) {
        return MONT_ERR_RANGE;
    }
    return MONT_OK;
}

int mont_mul(const MONT_CTX *context,
             const BIGINT *left,
             const BIGINT *right,
             BIGINT *result)
{
    MONT_WIDE product;
    BIGINT temporary;
    int status;

    if (context == NULL || left == NULL || right == NULL || result == NULL) {
        return MONT_ERR_NULL;
    }
    if (!mont_context_valid(context)) {
        return MONT_ERR_CONTEXT;
    }
    status = mont_operand_in_range(context, left);
    if (status != MONT_OK) {
        return status;
    }
    status = mont_operand_in_range(context, right);
    if (status != MONT_OK) {
        return status;
    }
    status = mont_wide_multiply(left, right, &product);
    if (status != MONT_OK) {
        return status;
    }
    status = mont_reduce(context, &product, &temporary);
    if (status != MONT_OK) {
        return status;
    }
    memcpy(result, &temporary, sizeof(temporary));
    return MONT_OK;
}

int mont_to(const MONT_CTX *context,
            const BIGINT *value,
            BIGINT *montgomery_value)
{
    BIGINT reduced;
    BIGINT temporary;
    int status;

    if (context == NULL || value == NULL || montgomery_value == NULL) {
        return MONT_ERR_NULL;
    }
    if (!mont_context_valid(context)) {
        return MONT_ERR_CONTEXT;
    }
    status = mont_validate_bigint(value);
    if (status != MONT_OK) {
        return status;
    }
    status = bigint_modulo(value, &context->modulus, &reduced);
    if (status != BIGINT_OK) {
        return mont_bigint_error(status);
    }
    status = mont_mul(context, &reduced, &context->r2_mod_n, &temporary);
    if (status != MONT_OK) {
        return status;
    }
    memcpy(montgomery_value, &temporary, sizeof(temporary));
    return MONT_OK;
}

int mont_from(const MONT_CTX *context,
              const BIGINT *montgomery_value,
              BIGINT *value)
{
    BIGINT one;
    BIGINT temporary;
    int status;

    if (context == NULL || montgomery_value == NULL || value == NULL) {
        return MONT_ERR_NULL;
    }
    if (!mont_context_valid(context)) {
        return MONT_ERR_CONTEXT;
    }
    status = bigint_from_ulong(&one, 1UL);
    if (status != BIGINT_OK) {
        return mont_bigint_error(status);
    }
    status = mont_mul(context, montgomery_value, &one, &temporary);
    if (status != MONT_OK) {
        return status;
    }
    memcpy(value, &temporary, sizeof(temporary));
    return MONT_OK;
}

int mont_pow(const MONT_CTX *context,
             const BIGINT *base,
             const BIGINT *exponent,
             BIGINT *result)
{
    BIGINT result_bar;
    BIGINT power_bar;
    BIGINT exponent_work;
    BIGINT temporary;
    int is_zero;
    int is_odd;
    int status;

    if (context == NULL || base == NULL || exponent == NULL ||
        result == NULL) {
        return MONT_ERR_NULL;
    }
    if (!mont_context_valid(context)) {
        return MONT_ERR_CONTEXT;
    }
    status = mont_validate_bigint(base);
    if (status != MONT_OK) {
        return status;
    }
    status = mont_validate_bigint(exponent);
    if (status != MONT_OK) {
        return status;
    }
    memcpy(&result_bar, &context->r_mod_n, sizeof(result_bar));
    status = mont_to(context, base, &power_bar);
    if (status != MONT_OK) {
        return status;
    }
    memcpy(&exponent_work, exponent, sizeof(exponent_work));
    for (;;) {
        status = bigint_is_zero(&exponent_work, &is_zero);
        if (status != BIGINT_OK) {
            return mont_bigint_error(status);
        }
        if (is_zero != 0) {
            break;
        }
        status = bigint_is_odd(&exponent_work, &is_odd);
        if (status != BIGINT_OK) {
            return mont_bigint_error(status);
        }
        if (is_odd != 0) {
            status = mont_mul(context, &result_bar, &power_bar,
                              &result_bar);
            if (status != MONT_OK) {
                return status;
            }
        }
        status = bigint_shift_right(&exponent_work, 1U, &exponent_work);
        if (status != BIGINT_OK) {
            return mont_bigint_error(status);
        }
        status = bigint_is_zero(&exponent_work, &is_zero);
        if (status != BIGINT_OK) {
            return mont_bigint_error(status);
        }
        if (is_zero == 0) {
            status = mont_mul(context, &power_bar, &power_bar,
                              &power_bar);
            if (status != MONT_OK) {
                return status;
            }
        }
    }
    status = mont_from(context, &result_bar, &temporary);
    if (status != MONT_OK) {
        return status;
    }
    memcpy(result, &temporary, sizeof(temporary));
    return MONT_OK;
}
