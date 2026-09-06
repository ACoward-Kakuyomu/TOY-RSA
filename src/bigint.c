#include <limits.h>
#include <stddef.h>
#include <string.h>

#include "bigint.h"

static void bigint_clear_raw(BIGINT *value)
{
    memset(value->limb, 0, sizeof(value->limb));
    value->used = 0U;
}

static int bigint_valid(const BIGINT *value)
{
    unsigned int index;

    if (value->used > BIGINT_MAX_LIMBS) {
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
    for (index = value->used; index < BIGINT_MAX_LIMBS; ++index) {
        if (value->limb[index] != 0U) {
            return 0;
        }
    }
    return 1;
}

static void bigint_normalize(BIGINT *value)
{
    while (value->used != 0U && value->limb[value->used - 1U] == 0U) {
        --value->used;
    }
    if (value->used < BIGINT_MAX_LIMBS) {
        memset(value->limb + value->used, 0,
               (BIGINT_MAX_LIMBS - value->used) * sizeof(BIGINT_LIMB));
    }
}

static int bigint_compare_raw(const BIGINT *left, const BIGINT *right)
{
    unsigned int index;

    if (left->used < right->used) {
        return -1;
    }
    if (left->used > right->used) {
        return 1;
    }
    index = left->used;
    while (index != 0U) {
        --index;
        if (left->limb[index] < right->limb[index]) {
            return -1;
        }
        if (left->limb[index] > right->limb[index]) {
            return 1;
        }
    }
    return 0;
}

static unsigned int bigint_bit_length_raw(const BIGINT *value)
{
    BIGINT_LIMB top;
    unsigned int bits;

    if (value->used == 0U) {
        return 0U;
    }
    bits = (value->used - 1U) * BIGINT_LIMB_BITS;
    top = value->limb[value->used - 1U];
    while (top != 0U) {
        ++bits;
        top = (BIGINT_LIMB)(top >> 1U);
    }
    return bits;
}

int bigint_zero(BIGINT *value)
{
    if (value == NULL) {
        return BIGINT_ERR_NULL;
    }
    bigint_clear_raw(value);
    return BIGINT_OK;
}

int bigint_from_ulong(BIGINT *value, unsigned long native_value)
{
    BIGINT temporary;

    if (value == NULL) {
        return BIGINT_ERR_NULL;
    }
    bigint_clear_raw(&temporary);
    while (native_value != 0UL) {
        if (temporary.used == BIGINT_MAX_LIMBS) {
            return BIGINT_ERR_OVERFLOW;
        }
        temporary.limb[temporary.used] =
            (BIGINT_LIMB)(native_value & BIGINT_LIMB_MASK);
        ++temporary.used;
        native_value >>= BIGINT_LIMB_BITS;
    }
    memcpy(value, &temporary, sizeof(temporary));
    return BIGINT_OK;
}

int bigint_to_ulong(const BIGINT *value, unsigned long *native_value)
{
    unsigned long result;
    unsigned int index;

    if (value == NULL || native_value == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(value)) {
        return BIGINT_ERR_INVALID;
    }
    result = 0UL;
    index = value->used;
    while (index != 0U) {
        --index;
        if (result > (ULONG_MAX >> BIGINT_LIMB_BITS)) {
            return BIGINT_ERR_OVERFLOW;
        }
        result = (result << BIGINT_LIMB_BITS) |
                 (unsigned long)value->limb[index];
    }
    *native_value = result;
    return BIGINT_OK;
}

int bigint_copy(BIGINT *destination, const BIGINT *source)
{
    if (destination == NULL || source == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(source)) {
        return BIGINT_ERR_INVALID;
    }
    if (destination != source) {
        memcpy(destination, source, sizeof(*destination));
    }
    return BIGINT_OK;
}

int bigint_is_zero(const BIGINT *value, int *is_zero)
{
    if (value == NULL || is_zero == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(value)) {
        return BIGINT_ERR_INVALID;
    }
    *is_zero = value->used == 0U;
    return BIGINT_OK;
}

int bigint_is_odd(const BIGINT *value, int *is_odd)
{
    if (value == NULL || is_odd == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(value)) {
        return BIGINT_ERR_INVALID;
    }
    *is_odd = value->used != 0U && (value->limb[0] & 1U) != 0U;
    return BIGINT_OK;
}

int bigint_compare(const BIGINT *left,
                   const BIGINT *right,
                   int *comparison)
{
    if (left == NULL || right == NULL || comparison == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(left) || !bigint_valid(right)) {
        return BIGINT_ERR_INVALID;
    }
    *comparison = bigint_compare_raw(left, right);
    return BIGINT_OK;
}

int bigint_bit_length(const BIGINT *value, unsigned int *bits)
{
    if (value == NULL || bits == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(value)) {
        return BIGINT_ERR_INVALID;
    }
    *bits = bigint_bit_length_raw(value);
    return BIGINT_OK;
}

int bigint_get_bit(const BIGINT *value,
                   unsigned int bit_index,
                   int *bit)
{
    unsigned int limb_index;
    unsigned int offset;

    if (value == NULL || bit == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(value)) {
        return BIGINT_ERR_INVALID;
    }
    if (bit_index >= BIGINT_MAX_BITS) {
        return BIGINT_ERR_RANGE;
    }
    limb_index = bit_index / BIGINT_LIMB_BITS;
    offset = bit_index % BIGINT_LIMB_BITS;
    if (limb_index >= value->used) {
        *bit = 0;
    } else {
        *bit = (int)((value->limb[limb_index] >> offset) & 1U);
    }
    return BIGINT_OK;
}

int bigint_set_bit(BIGINT *value, unsigned int bit_index, int bit)
{
    BIGINT temporary;
    unsigned int limb_index;
    unsigned int offset;
    BIGINT_LIMB mask;

    if (value == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(value)) {
        return BIGINT_ERR_INVALID;
    }
    if (bit_index >= BIGINT_MAX_BITS) {
        return BIGINT_ERR_RANGE;
    }
    if (bit != 0 && bit != 1) {
        return BIGINT_ERR_INVALID;
    }
    memcpy(&temporary, value, sizeof(temporary));
    limb_index = bit_index / BIGINT_LIMB_BITS;
    offset = bit_index % BIGINT_LIMB_BITS;
    mask = (BIGINT_LIMB)(1U << offset);
    if (bit != 0) {
        temporary.limb[limb_index] =
            (BIGINT_LIMB)(temporary.limb[limb_index] | mask);
        if (temporary.used <= limb_index) {
            temporary.used = limb_index + 1U;
        }
    } else {
        temporary.limb[limb_index] =
            (BIGINT_LIMB)(temporary.limb[limb_index] &
                          (BIGINT_LIMB)(~mask));
        bigint_normalize(&temporary);
    }
    memcpy(value, &temporary, sizeof(temporary));
    return BIGINT_OK;
}

int bigint_add(const BIGINT *left,
               const BIGINT *right,
               BIGINT *result)
{
    BIGINT temporary;
    unsigned long sum;
    unsigned long carry;
    unsigned long left_word;
    unsigned long right_word;
    unsigned int maximum_used;
    unsigned int index;

    if (left == NULL || right == NULL || result == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(left) || !bigint_valid(right)) {
        return BIGINT_ERR_INVALID;
    }
    bigint_clear_raw(&temporary);
    maximum_used = left->used > right->used ? left->used : right->used;
    carry = 0UL;
    for (index = 0U; index < maximum_used; ++index) {
        left_word = index < left->used ? left->limb[index] : 0UL;
        right_word = index < right->used ? right->limb[index] : 0UL;
        sum = left_word + right_word + carry;
        temporary.limb[index] =
            (BIGINT_LIMB)(sum & BIGINT_LIMB_MASK);
        carry = sum >> BIGINT_LIMB_BITS;
    }
    temporary.used = maximum_used;
    if (carry != 0UL) {
        if (temporary.used == BIGINT_MAX_LIMBS) {
            return BIGINT_ERR_OVERFLOW;
        }
        temporary.limb[temporary.used] = (BIGINT_LIMB)carry;
        ++temporary.used;
    }
    bigint_normalize(&temporary);
    memcpy(result, &temporary, sizeof(temporary));
    return BIGINT_OK;
}

int bigint_subtract(const BIGINT *left,
                    const BIGINT *right,
                    BIGINT *result)
{
    BIGINT temporary;
    unsigned long left_word;
    unsigned long right_word;
    unsigned long subtrahend;
    unsigned long difference;
    unsigned long borrow;
    unsigned int index;

    if (left == NULL || right == NULL || result == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(left) || !bigint_valid(right)) {
        return BIGINT_ERR_INVALID;
    }
    if (bigint_compare_raw(left, right) < 0) {
        return BIGINT_ERR_UNDERFLOW;
    }
    bigint_clear_raw(&temporary);
    borrow = 0UL;
    for (index = 0U; index < left->used; ++index) {
        left_word = left->limb[index];
        right_word = index < right->used ? right->limb[index] : 0UL;
        subtrahend = right_word + borrow;
        if (left_word >= subtrahend) {
            difference = left_word - subtrahend;
            borrow = 0UL;
        } else {
            difference = BIGINT_LIMB_BASE + left_word - subtrahend;
            borrow = 1UL;
        }
        temporary.limb[index] =
            (BIGINT_LIMB)(difference & BIGINT_LIMB_MASK);
    }
    temporary.used = left->used;
    bigint_normalize(&temporary);
    memcpy(result, &temporary, sizeof(temporary));
    return BIGINT_OK;
}

int bigint_shift_left(const BIGINT *value,
                      unsigned int bits,
                      BIGINT *result)
{
    BIGINT temporary;
    unsigned long combined;
    unsigned long high;
    unsigned int bit_length;
    unsigned int limb_shift;
    unsigned int bit_shift;
    unsigned int target;
    unsigned int index;

    if (value == NULL || result == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(value)) {
        return BIGINT_ERR_INVALID;
    }
    bit_length = bigint_bit_length_raw(value);
    if (bit_length != 0U &&
        (bits > BIGINT_MAX_BITS || bit_length > BIGINT_MAX_BITS - bits)) {
        return BIGINT_ERR_OVERFLOW;
    }
    bigint_clear_raw(&temporary);
    if (value->used == 0U) {
        memcpy(result, &temporary, sizeof(temporary));
        return BIGINT_OK;
    }
    limb_shift = bits / BIGINT_LIMB_BITS;
    bit_shift = bits % BIGINT_LIMB_BITS;
    for (index = 0U; index < value->used; ++index) {
        target = index + limb_shift;
        combined = (unsigned long)value->limb[index] << bit_shift;
        temporary.limb[target] = (BIGINT_LIMB)(
            temporary.limb[target] |
            (BIGINT_LIMB)(combined & BIGINT_LIMB_MASK));
        high = combined >> BIGINT_LIMB_BITS;
        if (high != 0UL) {
            temporary.limb[target + 1U] = (BIGINT_LIMB)(
                temporary.limb[target + 1U] | (BIGINT_LIMB)high);
        }
    }
    temporary.used = (bit_length + bits + BIGINT_LIMB_BITS - 1U) /
                     BIGINT_LIMB_BITS;
    bigint_normalize(&temporary);
    memcpy(result, &temporary, sizeof(temporary));
    return BIGINT_OK;
}

int bigint_shift_right(const BIGINT *value,
                       unsigned int bits,
                       BIGINT *result)
{
    BIGINT temporary;
    unsigned long word;
    unsigned int limb_shift;
    unsigned int bit_shift;
    unsigned int target;
    unsigned int index;

    if (value == NULL || result == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(value)) {
        return BIGINT_ERR_INVALID;
    }
    bigint_clear_raw(&temporary);
    if (value->used == 0U || bits >= BIGINT_MAX_BITS) {
        memcpy(result, &temporary, sizeof(temporary));
        return BIGINT_OK;
    }
    limb_shift = bits / BIGINT_LIMB_BITS;
    bit_shift = bits % BIGINT_LIMB_BITS;
    if (limb_shift >= value->used) {
        memcpy(result, &temporary, sizeof(temporary));
        return BIGINT_OK;
    }
    for (index = limb_shift; index < value->used; ++index) {
        target = index - limb_shift;
        word = value->limb[index];
        temporary.limb[target] = (BIGINT_LIMB)(
            temporary.limb[target] |
            (BIGINT_LIMB)(word >> bit_shift));
        if (bit_shift != 0U && target != 0U) {
            temporary.limb[target - 1U] = (BIGINT_LIMB)(
                temporary.limb[target - 1U] |
                (BIGINT_LIMB)((word <<
                    (BIGINT_LIMB_BITS - bit_shift)) &
                    BIGINT_LIMB_MASK));
        }
    }
    temporary.used = value->used - limb_shift;
    bigint_normalize(&temporary);
    memcpy(result, &temporary, sizeof(temporary));
    return BIGINT_OK;
}

int bigint_multiply(const BIGINT *left,
                    const BIGINT *right,
                    BIGINT *result)
{
    BIGINT temporary;
    unsigned long accumulator;
    unsigned long carry;
    unsigned int target;
    unsigned int left_index;
    unsigned int right_index;

    if (left == NULL || right == NULL || result == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(left) || !bigint_valid(right)) {
        return BIGINT_ERR_INVALID;
    }
    bigint_clear_raw(&temporary);
    if (left->used == 0U || right->used == 0U) {
        memcpy(result, &temporary, sizeof(temporary));
        return BIGINT_OK;
    }
    for (left_index = 0U; left_index < left->used; ++left_index) {
        carry = 0UL;
        for (right_index = 0U; right_index < right->used;
             ++right_index) {
            target = left_index + right_index;
            if (target >= BIGINT_MAX_LIMBS) {
                return BIGINT_ERR_OVERFLOW;
            }
            accumulator = (unsigned long)temporary.limb[target] +
                (unsigned long)left->limb[left_index] *
                (unsigned long)right->limb[right_index] + carry;
            temporary.limb[target] =
                (BIGINT_LIMB)(accumulator & BIGINT_LIMB_MASK);
            carry = accumulator >> BIGINT_LIMB_BITS;
        }
        target = left_index + right->used;
        if (carry != 0UL) {
            if (target >= BIGINT_MAX_LIMBS) {
                return BIGINT_ERR_OVERFLOW;
            }
            temporary.limb[target] = (BIGINT_LIMB)carry;
        }
    }
    temporary.used = left->used + right->used;
    if (temporary.used > BIGINT_MAX_LIMBS) {
        temporary.used = BIGINT_MAX_LIMBS;
    }
    bigint_normalize(&temporary);
    memcpy(result, &temporary, sizeof(temporary));
    return BIGINT_OK;
}

int bigint_divmod(const BIGINT *numerator,
                  const BIGINT *denominator,
                  BIGINT *quotient,
                  BIGINT *remainder)
{
    BIGINT quotient_value;
    BIGINT remainder_value;
    BIGINT shifted_denominator;
    unsigned int numerator_bits;
    unsigned int denominator_bits;
    unsigned int shift;
    int result;

    if (numerator == NULL || denominator == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (quotient == NULL && remainder == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (quotient != NULL && quotient == remainder) {
        return BIGINT_ERR_INVALID;
    }
    if (!bigint_valid(numerator) || !bigint_valid(denominator)) {
        return BIGINT_ERR_INVALID;
    }
    if (denominator->used == 0U) {
        return BIGINT_ERR_DIVIDE_BY_ZERO;
    }
    bigint_clear_raw(&quotient_value);
    memcpy(&remainder_value, numerator, sizeof(remainder_value));
    if (bigint_compare_raw(numerator, denominator) >= 0) {
        numerator_bits = bigint_bit_length_raw(numerator);
        denominator_bits = bigint_bit_length_raw(denominator);
        shift = numerator_bits - denominator_bits;
        result = bigint_shift_left(denominator, shift,
                                   &shifted_denominator);
        if (result != BIGINT_OK) {
            return result;
        }
        for (;;) {
            if (bigint_compare_raw(&remainder_value,
                                   &shifted_denominator) >= 0) {
                result = bigint_subtract(&remainder_value,
                                          &shifted_denominator,
                                          &remainder_value);
                if (result != BIGINT_OK) {
                    return result;
                }
                result = bigint_set_bit(&quotient_value, shift, 1);
                if (result != BIGINT_OK) {
                    return result;
                }
            }
            if (shift == 0U) {
                break;
            }
            result = bigint_shift_right(&shifted_denominator, 1U,
                                        &shifted_denominator);
            if (result != BIGINT_OK) {
                return result;
            }
            --shift;
        }
    }
    if (quotient != NULL) {
        memcpy(quotient, &quotient_value, sizeof(quotient_value));
    }
    if (remainder != NULL) {
        memcpy(remainder, &remainder_value, sizeof(remainder_value));
    }
    return BIGINT_OK;
}

int bigint_divide(const BIGINT *numerator,
                  const BIGINT *denominator,
                  BIGINT *quotient)
{
    if (quotient == NULL) {
        return BIGINT_ERR_NULL;
    }
    return bigint_divmod(numerator, denominator, quotient, NULL);
}

int bigint_modulo(const BIGINT *numerator,
                  const BIGINT *denominator,
                  BIGINT *remainder)
{
    if (remainder == NULL) {
        return BIGINT_ERR_NULL;
    }
    return bigint_divmod(numerator, denominator, NULL, remainder);
}

int bigint_from_bytes(BIGINT *value,
                      const unsigned char *input,
                      unsigned int input_length)
{
    BIGINT temporary;
    unsigned int position;
    unsigned int input_index;
    unsigned int limb_index;
    unsigned int shift;

    if (value == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (input_length != 0U && input == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (input_length > BIGINT_MAX_BYTES) {
        return BIGINT_ERR_OVERFLOW;
    }
    bigint_clear_raw(&temporary);
    for (position = 0U; position < input_length; ++position) {
        input_index = input_length - 1U - position;
        limb_index = position / 2U;
        shift = (position % 2U) * 8U;
        temporary.limb[limb_index] = (BIGINT_LIMB)(
            temporary.limb[limb_index] |
            (BIGINT_LIMB)((unsigned int)input[input_index] << shift));
    }
    temporary.used = (input_length + 1U) / 2U;
    bigint_normalize(&temporary);
    memcpy(value, &temporary, sizeof(temporary));
    return BIGINT_OK;
}

int bigint_to_bytes(const BIGINT *value,
                    unsigned char *output,
                    unsigned int output_capacity,
                    unsigned int *output_length)
{
    unsigned int bit_length;
    unsigned int required;
    unsigned int position;
    unsigned int limb_index;
    unsigned int shift;

    if (value == NULL || output_length == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(value)) {
        return BIGINT_ERR_INVALID;
    }
    bit_length = bigint_bit_length_raw(value);
    required = bit_length == 0U ? 1U : (bit_length + 7U) / 8U;
    *output_length = required;
    if (output_capacity < required) {
        return BIGINT_ERR_CAPACITY;
    }
    if (output == NULL) {
        return BIGINT_ERR_NULL;
    }
    memset(output, 0, required);
    for (position = 0U; position < required; ++position) {
        limb_index = position / 2U;
        shift = (position % 2U) * 8U;
        if (limb_index < value->used) {
            output[required - 1U - position] = (unsigned char)(
                (value->limb[limb_index] >> shift) & 0xffU);
        }
    }
    return BIGINT_OK;
}

int bigint_to_bytes_fixed(const BIGINT *value,
                          unsigned char *output,
                          unsigned int output_length)
{
    unsigned int bit_length;
    unsigned int required;
    unsigned int position;
    unsigned int limb_index;
    unsigned int shift;

    if (value == NULL || output == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(value)) {
        return BIGINT_ERR_INVALID;
    }
    bit_length = bigint_bit_length_raw(value);
    required = bit_length == 0U ? 1U : (bit_length + 7U) / 8U;
    if (output_length < required) {
        return BIGINT_ERR_CAPACITY;
    }
    memset(output, 0, output_length);
    for (position = 0U; position < required; ++position) {
        limb_index = position / 2U;
        shift = (position % 2U) * 8U;
        if (limb_index < value->used) {
            output[output_length - 1U - position] = (unsigned char)(
                (value->limb[limb_index] >> shift) & 0xffU);
        }
    }
    return BIGINT_OK;
}

static int bigint_hex_value(char character, unsigned int *value)
{
    if (character >= '0' && character <= '9') {
        *value = (unsigned int)(character - '0');
        return 1;
    }
    if (character >= 'A' && character <= 'F') {
        *value = (unsigned int)(character - 'A') + 10U;
        return 1;
    }
    if (character >= 'a' && character <= 'f') {
        *value = (unsigned int)(character - 'a') + 10U;
        return 1;
    }
    return 0;
}

int bigint_from_hex(BIGINT *value, const char *text)
{
    BIGINT temporary;
    size_t length;
    unsigned int position;
    unsigned int text_index;
    unsigned int limb_index;
    unsigned int shift;
    unsigned int digit;

    if (value == NULL || text == NULL) {
        return BIGINT_ERR_NULL;
    }
    length = strlen(text);
    if (length == 0U) {
        return BIGINT_ERR_INVALID;
    }
    if (length > (size_t)BIGINT_MAX_HEX_DIGITS) {
        return BIGINT_ERR_OVERFLOW;
    }
    bigint_clear_raw(&temporary);
    for (position = 0U; position < (unsigned int)length; ++position) {
        text_index = (unsigned int)length - 1U - position;
        if (!bigint_hex_value(text[text_index], &digit)) {
            return BIGINT_ERR_INVALID;
        }
        limb_index = position / 4U;
        shift = (position % 4U) * 4U;
        temporary.limb[limb_index] = (BIGINT_LIMB)(
            temporary.limb[limb_index] |
            (BIGINT_LIMB)(digit << shift));
    }
    temporary.used = ((unsigned int)length + 3U) / 4U;
    bigint_normalize(&temporary);
    memcpy(value, &temporary, sizeof(temporary));
    return BIGINT_OK;
}

int bigint_to_hex(const BIGINT *value,
                  char *output,
                  unsigned int output_capacity)
{
    static const char digits[] = "0123456789ABCDEF";
    unsigned int bit_length;
    unsigned int required_digits;
    unsigned int output_index;
    unsigned int nibble_position;
    unsigned int limb_index;
    unsigned int shift;
    unsigned int nibble;

    if (value == NULL) {
        return BIGINT_ERR_NULL;
    }
    if (!bigint_valid(value)) {
        return BIGINT_ERR_INVALID;
    }
    bit_length = bigint_bit_length_raw(value);
    required_digits = bit_length == 0U ? 1U : (bit_length + 3U) / 4U;
    if (output_capacity < required_digits + 1U) {
        return BIGINT_ERR_CAPACITY;
    }
    if (output == NULL) {
        return BIGINT_ERR_NULL;
    }
    for (output_index = 0U; output_index < required_digits;
         ++output_index) {
        nibble_position = required_digits - 1U - output_index;
        limb_index = nibble_position / 4U;
        shift = (nibble_position % 4U) * 4U;
        if (limb_index < value->used) {
            nibble = (unsigned int)(
                (value->limb[limb_index] >> shift) & 0x0fU);
        } else {
            nibble = 0U;
        }
        output[output_index] = digits[nibble];
    }
    output[required_digits] = '\0';
    return BIGINT_OK;
}
