#ifndef TOY_RSA_BIGINT_H
#define TOY_RSA_BIGINT_H

#include <limits.h>

#ifndef BIGINT_MAX_BITS
#define BIGINT_MAX_BITS 1024U
#endif

#define BIGINT_LIMB_BITS 16U
#define BIGINT_LIMB_BASE 65536UL
#define BIGINT_LIMB_MASK 0xffffUL
#define BIGINT_MAX_LIMBS (BIGINT_MAX_BITS / BIGINT_LIMB_BITS)
#define BIGINT_MAX_BYTES (BIGINT_MAX_BITS / 8U)
#define BIGINT_MAX_HEX_DIGITS (BIGINT_MAX_BITS / 4U)

#if BIGINT_MAX_BITS < 16
#error BIGINT_MAX_BITS must be at least 16
#endif

#if (BIGINT_MAX_BITS % 16) != 0
#error BIGINT_MAX_BITS must be a multiple of 16
#endif

#if USHRT_MAX < 0xffffU
#error unsigned short must hold at least 16 bits
#endif

#if ULONG_MAX < 0xffffffffUL
#error unsigned long must hold at least 32 bits
#endif

#define BIGINT_OK 0
#define BIGINT_ERR_NULL (-1)
#define BIGINT_ERR_INVALID (-2)
#define BIGINT_ERR_RANGE (-3)
#define BIGINT_ERR_OVERFLOW (-4)
#define BIGINT_ERR_UNDERFLOW (-5)
#define BIGINT_ERR_DIVIDE_BY_ZERO (-6)
#define BIGINT_ERR_CAPACITY (-7)

typedef unsigned short BIGINT_LIMB;

typedef struct bigint_tag {
    BIGINT_LIMB limb[BIGINT_MAX_LIMBS];
    unsigned int used;
} BIGINT;

int bigint_zero(BIGINT *value);
int bigint_from_ulong(BIGINT *value, unsigned long native_value);
int bigint_to_ulong(const BIGINT *value, unsigned long *native_value);
int bigint_copy(BIGINT *destination, const BIGINT *source);

int bigint_is_zero(const BIGINT *value, int *is_zero);
int bigint_is_odd(const BIGINT *value, int *is_odd);
int bigint_compare(const BIGINT *left,
                   const BIGINT *right,
                   int *comparison);
int bigint_bit_length(const BIGINT *value, unsigned int *bits);
int bigint_get_bit(const BIGINT *value,
                   unsigned int bit_index,
                   int *bit);
int bigint_set_bit(BIGINT *value, unsigned int bit_index, int bit);

int bigint_add(const BIGINT *left,
               const BIGINT *right,
               BIGINT *result);
int bigint_subtract(const BIGINT *left,
                    const BIGINT *right,
                    BIGINT *result);
int bigint_shift_left(const BIGINT *value,
                      unsigned int bits,
                      BIGINT *result);
int bigint_shift_right(const BIGINT *value,
                       unsigned int bits,
                       BIGINT *result);
int bigint_multiply(const BIGINT *left,
                    const BIGINT *right,
                    BIGINT *result);

int bigint_divmod(const BIGINT *numerator,
                  const BIGINT *denominator,
                  BIGINT *quotient,
                  BIGINT *remainder);
int bigint_divide(const BIGINT *numerator,
                  const BIGINT *denominator,
                  BIGINT *quotient);
int bigint_modulo(const BIGINT *numerator,
                  const BIGINT *denominator,
                  BIGINT *remainder);

int bigint_from_bytes(BIGINT *value,
                      const unsigned char *input,
                      unsigned int input_length);
int bigint_to_bytes(const BIGINT *value,
                    unsigned char *output,
                    unsigned int output_capacity,
                    unsigned int *output_length);
int bigint_to_bytes_fixed(const BIGINT *value,
                          unsigned char *output,
                          unsigned int output_length);

int bigint_from_hex(BIGINT *value, const char *text);
int bigint_to_hex(const BIGINT *value,
                  char *output,
                  unsigned int output_capacity);

#endif
