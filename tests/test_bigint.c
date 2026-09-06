#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "bigint.h"

static int failures = 0;

static void expect_int(const char *name, int actual, int expected)
{
    if (actual != expected) {
        fprintf(stderr, "%s: expected %d, got %d\n",
                name, expected, actual);
        ++failures;
    }
}

static void expect_true(const char *name, int condition)
{
    if (!condition) {
        fprintf(stderr, "%s: condition is false\n", name);
        ++failures;
    }
}

static void load_hex(const char *name, BIGINT *value, const char *text)
{
    expect_int(name, bigint_from_hex(value, text), BIGINT_OK);
}

static void expect_hex(const char *name,
                       const BIGINT *value,
                       const char *expected)
{
    char actual[BIGINT_MAX_HEX_DIGITS + 1U];
    int status;

    actual[0] = '\0';
    status = bigint_to_hex(value, actual, sizeof(actual));
    if (status != BIGINT_OK) {
        fprintf(stderr, "%s: conversion returned %d\n", name, status);
        ++failures;
        return;
    }
    if (strcmp(actual, expected) != 0) {
        fprintf(stderr, "%s: expected %s, got %s\n",
                name, expected, actual);
        ++failures;
    }
}

static void expect_same(const char *name,
                        const BIGINT *actual,
                        const BIGINT *expected)
{
    int comparison;
    int status;

    comparison = 99;
    status = bigint_compare(actual, expected, &comparison);
    if (status != BIGINT_OK || comparison != 0) {
        fprintf(stderr, "%s: values differ (status %d, comparison %d)\n",
                name, status, comparison);
        ++failures;
    }
}

static void test_initialization_and_queries(void)
{
    BIGINT value;
    BIGINT copy;
    unsigned long native_value;
    unsigned int bits;
    int flag;
    int comparison;

    expect_int("zero", bigint_zero(&value), BIGINT_OK);
    expect_hex("zero hex", &value, "0");
    expect_int("zero query", bigint_is_zero(&value, &flag), BIGINT_OK);
    expect_int("zero flag", flag, 1);
    expect_int("zero odd", bigint_is_odd(&value, &flag), BIGINT_OK);
    expect_int("zero is not odd", flag, 0);
    expect_int("zero bits", bigint_bit_length(&value, &bits), BIGINT_OK);
    expect_int("zero bit length", (int)bits, 0);

    expect_int("from ulong", bigint_from_ulong(&value, 0x89abcdefUL),
               BIGINT_OK);
    expect_hex("ulong hex", &value, "89ABCDEF");
    native_value = 0UL;
    expect_int("to ulong", bigint_to_ulong(&value, &native_value),
               BIGINT_OK);
    expect_true("ulong round trip", native_value == 0x89abcdefUL);
    expect_int("ulong odd", bigint_is_odd(&value, &flag), BIGINT_OK);
    expect_int("ulong is odd", flag, 1);
    expect_int("ulong bits", bigint_bit_length(&value, &bits), BIGINT_OK);
    expect_int("ulong bit length", (int)bits, 32);

    expect_int("copy", bigint_copy(&copy, &value), BIGINT_OK);
    expect_same("copied value", &copy, &value);
    expect_int("self copy", bigint_copy(&copy, &copy), BIGINT_OK);
    expect_int("compare equal",
               bigint_compare(&copy, &value, &comparison), BIGINT_OK);
    expect_int("comparison equal", comparison, 0);

    expect_int("set high bit", bigint_set_bit(&copy, 63U, 1), BIGINT_OK);
    expect_int("get high bit", bigint_get_bit(&copy, 63U, &flag),
               BIGINT_OK);
    expect_int("high bit value", flag, 1);
    expect_int("compare greater",
               bigint_compare(&copy, &value, &comparison), BIGINT_OK);
    expect_int("comparison greater", comparison, 1);
    expect_int("clear high bit", bigint_set_bit(&copy, 63U, 0), BIGINT_OK);
    expect_same("clear normalizes", &copy, &value);
    expect_int("get absent bit", bigint_get_bit(&copy, 100U, &flag),
               BIGINT_OK);
    expect_int("absent bit value", flag, 0);
}

static void test_add_subtract_and_aliasing(void)
{
    BIGINT left;
    BIGINT right;
    BIGINT result;
    BIGINT unchanged;

    load_hex("load add left", &left, "FFFFFFFF");
    load_hex("load add right", &right, "1");
    expect_int("word carry add", bigint_add(&left, &right, &result),
               BIGINT_OK);
    expect_hex("word carry result", &result, "100000000");
    expect_int("borrow subtract", bigint_subtract(&result, &right, &result),
               BIGINT_OK);
    expect_same("borrow result", &result, &left);

    load_hex("load alias left", &left, "123456789ABCDEF0");
    load_hex("load alias right", &right, "FEDCBA987654321");
    expect_int("aliased add", bigint_add(&left, &right, &left), BIGINT_OK);
    expect_hex("aliased add result", &left, "2222222222222211");
    expect_int("aliased subtract", bigint_subtract(&left, &right, &left),
               BIGINT_OK);
    expect_hex("aliased subtract result", &left, "123456789ABCDEF0");

    expect_int("copy unchanged", bigint_copy(&unchanged, &right), BIGINT_OK);
    expect_int("underflow", bigint_subtract(&right, &left, &right),
               BIGINT_ERR_UNDERFLOW);
    expect_same("underflow preserves output", &right, &unchanged);
}

static void test_shifts(void)
{
    BIGINT value;
    BIGINT result;

    load_hex("load shift", &value, "123456789ABCDEF0");
    expect_int("left shift zero", bigint_shift_left(&value, 0U, &result),
               BIGINT_OK);
    expect_same("left zero result", &result, &value);
    expect_int("left shift 17", bigint_shift_left(&value, 17U, &result),
               BIGINT_OK);
    expect_hex("left 17 result", &result, "2468ACF13579BDE00000");
    expect_int("right shift 17", bigint_shift_right(&value, 17U, &result),
               BIGINT_OK);
    expect_hex("right 17 result", &result, "91A2B3C4D5E");
    expect_int("right shift word", bigint_shift_right(&value, 16U, &result),
               BIGINT_OK);
    expect_hex("right word result", &result, "123456789ABC");
    expect_int("right shift all",
               bigint_shift_right(&value, BIGINT_MAX_BITS, &result),
               BIGINT_OK);
    expect_hex("right all result", &result, "0");

    expect_int("aliased left", bigint_shift_left(&value, 1U, &value),
               BIGINT_OK);
    expect_hex("aliased left result", &value, "2468ACF13579BDE0");
    expect_int("aliased right", bigint_shift_right(&value, 1U, &value),
               BIGINT_OK);
    expect_hex("aliased right result", &value, "123456789ABCDEF0");
}

static void test_multiplication(void)
{
    BIGINT left;
    BIGINT right;
    BIGINT result;

    load_hex("load multiply left", &left, "123456789ABCDEF0");
    load_hex("load multiply right", &right, "FEDCBA987654321");
    expect_int("large multiply", bigint_multiply(&left, &right, &result),
               BIGINT_OK);
    expect_hex("large product", &result,
               "121FA00AD77D7422236D88FE5618CF0");
    expect_int("aliased multiply", bigint_multiply(&left, &right, &left),
               BIGINT_OK);
    expect_same("aliased product", &left, &result);

    expect_int("zero multiplier", bigint_zero(&right), BIGINT_OK);
    expect_int("multiply by zero", bigint_multiply(&left, &right, &result),
               BIGINT_OK);
    expect_hex("zero product", &result, "0");
}

static void test_division(void)
{
    BIGINT numerator;
    BIGINT denominator;
    BIGINT quotient;
    BIGINT remainder;
    BIGINT product;
    BIGINT recomposed;
    BIGINT saved;
    int comparison;

    load_hex("load division numerator", &numerator,
             "123456789ABCDEF00112233445566778899AABBCCDDEEFF");
    load_hex("load division denominator", &denominator,
             "1FEDCBA987654321");
    expect_int("large divmod",
               bigint_divmod(&numerator, &denominator,
                             &quotient, &remainder), BIGINT_OK);
    expect_hex("large quotient", &quotient,
               "91F5BCB8BB02D9434AA77476509A71B");
    expect_hex("large remainder", &remainder, "1814ED55153C5384");
    expect_int("division product",
               bigint_multiply(&quotient, &denominator, &product), BIGINT_OK);
    expect_int("division recompose",
               bigint_add(&product, &remainder, &recomposed), BIGINT_OK);
    expect_same("division identity", &recomposed, &numerator);
    expect_int("remainder compare",
               bigint_compare(&remainder, &denominator, &comparison),
               BIGINT_OK);
    expect_int("remainder is smaller", comparison, -1);

    expect_int("divide wrapper",
               bigint_divide(&numerator, &denominator, &product), BIGINT_OK);
    expect_same("divide wrapper result", &product, &quotient);
    expect_int("modulo wrapper",
               bigint_modulo(&numerator, &denominator, &product), BIGINT_OK);
    expect_same("modulo wrapper result", &product, &remainder);

    expect_int("alias numerator copy", bigint_copy(&product, &numerator),
               BIGINT_OK);
    expect_int("alias denominator copy", bigint_copy(&recomposed,
                                                      &denominator),
               BIGINT_OK);
    expect_int("aliased divmod",
               bigint_divmod(&product, &recomposed, &product, &recomposed),
               BIGINT_OK);
    expect_same("aliased quotient", &product, &quotient);
    expect_same("aliased remainder", &recomposed, &remainder);

    expect_int("same output rejected",
               bigint_divmod(&numerator, &denominator, &product, &product),
               BIGINT_ERR_INVALID);
    expect_int("save numerator", bigint_copy(&saved, &numerator), BIGINT_OK);
    expect_int("zero denominator", bigint_zero(&denominator), BIGINT_OK);
    expect_int("divide by zero",
               bigint_divmod(&numerator, &denominator,
                             &numerator, &remainder),
               BIGINT_ERR_DIVIDE_BY_ZERO);
    expect_same("divide by zero preserves output", &numerator, &saved);

    load_hex("load small denominator", &denominator, "10000000000000000");
    load_hex("load small numerator", &numerator, "1234");
    expect_int("numerator smaller",
               bigint_divmod(&numerator, &denominator,
                             &quotient, &remainder), BIGINT_OK);
    expect_hex("smaller quotient", &quotient, "0");
    expect_same("smaller remainder", &remainder, &numerator);
}

static void test_serialization(void)
{
    static const unsigned char expected[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    unsigned char bytes[12];
    unsigned char fixed[12];
    BIGINT value;
    BIGINT decoded;
    unsigned int length;

    expect_int("from bytes",
               bigint_from_bytes(&value, expected, sizeof(expected)),
               BIGINT_OK);
    expect_hex("bytes decoded", &value, "123456789ABCDEF");
    memset(bytes, 0xa5, sizeof(bytes));
    length = 0U;
    expect_int("to bytes",
               bigint_to_bytes(&value, bytes, sizeof(bytes), &length),
               BIGINT_OK);
    expect_int("minimal byte length", (int)length, 8);
    expect_true("minimal bytes",
                memcmp(bytes, expected, sizeof(expected)) == 0);

    memset(fixed, 0xa5, sizeof(fixed));
    expect_int("to fixed bytes",
               bigint_to_bytes_fixed(&value, fixed, sizeof(fixed)),
               BIGINT_OK);
    expect_true("fixed leading zero",
                fixed[0] == 0U && fixed[1] == 0U &&
                fixed[2] == 0U && fixed[3] == 0U);
    expect_true("fixed value",
                memcmp(fixed + 4, expected, sizeof(expected)) == 0);
    expect_int("fixed too small",
               bigint_to_bytes_fixed(&value, fixed, 7U),
               BIGINT_ERR_CAPACITY);

    length = 0U;
    expect_int("minimal capacity report",
               bigint_to_bytes(&value, bytes, 7U, &length),
               BIGINT_ERR_CAPACITY);
    expect_int("reported required bytes", (int)length, 8);

    expect_int("empty bytes are zero",
               bigint_from_bytes(&decoded, NULL, 0U), BIGINT_OK);
    expect_hex("empty bytes result", &decoded, "0");
    length = 0U;
    expect_int("zero to bytes",
               bigint_to_bytes(&decoded, bytes, sizeof(bytes), &length),
               BIGINT_OK);
    expect_int("zero byte length", (int)length, 1);
    expect_int("zero byte", (int)bytes[0], 0);

    expect_int("lowercase hex",
               bigint_from_hex(&decoded, "0000abcdef"), BIGINT_OK);
    expect_hex("normalized uppercase hex", &decoded, "ABCDEF");
    expect_int("empty hex", bigint_from_hex(&decoded, ""),
               BIGINT_ERR_INVALID);
    expect_int("prefixed hex", bigint_from_hex(&decoded, "0x10"),
               BIGINT_ERR_INVALID);
    expect_int("bad hex", bigint_from_hex(&decoded, "12G4"),
               BIGINT_ERR_INVALID);
}

static void make_maximum(BIGINT *value)
{
    char text[BIGINT_MAX_HEX_DIGITS + 1U];
    unsigned int index;

    for (index = 0U; index < BIGINT_MAX_HEX_DIGITS; ++index) {
        text[index] = 'F';
    }
    text[BIGINT_MAX_HEX_DIGITS] = '\0';
    load_hex("load maximum", value, text);
}

static void test_boundaries_and_errors(void)
{
    BIGINT maximum;
    BIGINT one;
    BIGINT output;
    BIGINT unchanged;
    BIGINT invalid;
    char oversized[BIGINT_MAX_HEX_DIGITS + 2U];
    unsigned int index;
    int bit;

    make_maximum(&maximum);
    expect_int("one", bigint_from_ulong(&one, 1UL), BIGINT_OK);
    expect_int("unchanged sentinel",
               bigint_from_ulong(&unchanged, 0x55aaUL), BIGINT_OK);
    expect_int("output sentinel", bigint_copy(&output, &unchanged),
               BIGINT_OK);
    expect_int("maximum add overflow",
               bigint_add(&maximum, &one, &output), BIGINT_ERR_OVERFLOW);
    expect_same("add overflow preserves output", &output, &unchanged);
    expect_int("maximum shift overflow",
               bigint_shift_left(&maximum, 1U, &output),
               BIGINT_ERR_OVERFLOW);
    expect_same("shift overflow preserves output", &output, &unchanged);
    expect_int("maximum multiply overflow",
               bigint_multiply(&maximum, &maximum, &output),
               BIGINT_ERR_OVERFLOW);
    expect_same("multiply overflow preserves output", &output, &unchanged);
    expect_int("maximum times one",
               bigint_multiply(&maximum, &one, &output), BIGINT_OK);
    expect_same("maximum times one result", &output, &maximum);

    expect_int("bit index range",
               bigint_get_bit(&one, BIGINT_MAX_BITS, &bit),
               BIGINT_ERR_RANGE);
    expect_int("invalid bit value", bigint_set_bit(&one, 0U, 2),
               BIGINT_ERR_INVALID);

    expect_int("zero invalid value", bigint_zero(&invalid), BIGINT_OK);
    invalid.limb[0] = 1U;
    expect_int("invalid representation",
               bigint_add(&invalid, &one, &output), BIGINT_ERR_INVALID);

    for (index = 0U; index < BIGINT_MAX_HEX_DIGITS + 1U; ++index) {
        oversized[index] = '0';
    }
    oversized[BIGINT_MAX_HEX_DIGITS + 1U] = '\0';
    expect_int("oversized hex",
               bigint_from_hex(&output, oversized), BIGINT_ERR_OVERFLOW);
}

static void test_small_native_cross_checks(void)
{
    static const unsigned long values[] = {
        0UL, 1UL, 2UL, 15UL, 16UL, 255UL, 256UL,
        65535UL, 65536UL, 99991UL, 1000003UL, 0xffffffffUL
    };
    BIGINT left;
    BIGINT right;
    BIGINT quotient;
    BIGINT remainder;
    unsigned long quotient_native;
    unsigned long remainder_native;
    unsigned int left_index;
    unsigned int right_index;

    for (left_index = 0U;
         left_index < sizeof(values) / sizeof(values[0]); ++left_index) {
        expect_int("native left load",
                   bigint_from_ulong(&left, values[left_index]), BIGINT_OK);
        for (right_index = 1U;
             right_index < sizeof(values) / sizeof(values[0]); ++right_index) {
            expect_int("native right load",
                       bigint_from_ulong(&right, values[right_index]),
                       BIGINT_OK);
            expect_int("native divmod",
                       bigint_divmod(&left, &right, &quotient, &remainder),
                       BIGINT_OK);
            quotient_native = ULONG_MAX;
            remainder_native = ULONG_MAX;
            expect_int("native quotient conversion",
                       bigint_to_ulong(&quotient, &quotient_native),
                       BIGINT_OK);
            expect_int("native remainder conversion",
                       bigint_to_ulong(&remainder, &remainder_native),
                       BIGINT_OK);
            expect_true("native quotient match",
                        quotient_native ==
                        values[left_index] / values[right_index]);
            expect_true("native remainder match",
                        remainder_native ==
                        values[left_index] % values[right_index]);
        }
    }
}

static void test_null_arguments(void)
{
    BIGINT value;
    unsigned char byte;
    unsigned int length;

    expect_int("null zero", bigint_zero(NULL), BIGINT_ERR_NULL);
    expect_int("null from hex", bigint_from_hex(NULL, "1"),
               BIGINT_ERR_NULL);
    expect_int("initialize null test", bigint_zero(&value), BIGINT_OK);
    expect_int("null divmod outputs",
               bigint_divmod(&value, &value, NULL, NULL), BIGINT_ERR_NULL);
    length = 0U;
    byte = 0U;
    expect_int("null byte output",
               bigint_to_bytes(&value, NULL, 1U, &length), BIGINT_ERR_NULL);
    expect_int("null output reports length", (int)length, 1);
    expect_int("unused byte", (int)byte, 0);
}

int main(void)
{
    test_initialization_and_queries();
    test_add_subtract_and_aliasing();
    test_shifts();
    test_multiplication();
    test_division();
    test_serialization();
    test_boundaries_and_errors();
    test_small_native_cross_checks();
    test_null_arguments();

    if (failures != 0) {
        fprintf(stderr, "%d Week5 bigint test(s) failed\n", failures);
        return 1;
    }
    printf("Week5 multi-precision integer tests passed\n");
    return 0;
}
