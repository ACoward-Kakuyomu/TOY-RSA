#include <stdio.h>
#include <string.h>

#include "montgomery.h"
#include "number.h"

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

static void expect_wide_hex(const char *name,
                            const MONT_WIDE *value,
                            const char *expected)
{
    static const char digits[] = "0123456789ABCDEF";
    char actual[BIGINT_MAX_HEX_DIGITS * 2U + 9U];
    unsigned int top_nibbles;
    unsigned int required;
    unsigned int output_index;
    unsigned int nibble_position;
    unsigned int limb_index;
    unsigned int shift;
    unsigned int nibble;
    BIGINT_LIMB top;

    if (value->used == 0U) {
        actual[0] = '0';
        actual[1] = '\0';
    } else {
        top = value->limb[value->used - 1U];
        top_nibbles = 0U;
        while (top != 0U) {
            ++top_nibbles;
            top = (BIGINT_LIMB)(top >> 4U);
        }
        required = (value->used - 1U) * 4U + top_nibbles;
        for (output_index = 0U; output_index < required;
             ++output_index) {
            nibble_position = required - 1U - output_index;
            limb_index = nibble_position / 4U;
            shift = (nibble_position % 4U) * 4U;
            nibble = (unsigned int)((value->limb[limb_index] >> shift) &
                                    0x0fU);
            actual[output_index] = digits[nibble];
        }
        actual[required] = '\0';
    }
    if (strcmp(actual, expected) != 0) {
        fprintf(stderr, "%s: expected %s, got %s\n",
                name, expected, actual);
        ++failures;
    }
}

static void test_context(void)
{
    BIGINT modulus;
    MONT_CTX context;
    unsigned long relation;

    load_hex("context modulus", &modulus, "FFFFFFFF00000001");
    expect_int("context init", mont_init(&context, &modulus), MONT_OK);
    expect_int("context limbs", (int)context.limbs, 4);
    expect_hex("R modulo n", &context.r_mod_n, "FFFFFFFF");
    expect_hex("R squared modulo n", &context.r2_mod_n,
               "FFFFFFFE00000001");
    relation = (unsigned long)modulus.limb[0] *
               (unsigned long)context.n0_prime;
    expect_true("n0 prime relation",
                (relation & BIGINT_LIMB_MASK) == BIGINT_LIMB_MASK);
    expect_true("context ready",
                context.initialized == MONT_CONTEXT_READY);
}

static void test_wide_and_reduce(void)
{
    BIGINT left;
    BIGINT right;
    BIGINT modulus;
    BIGINT reduced;
    BIGINT sentinel;
    MONT_WIDE wide;
    MONT_WIDE range_limit;
    MONT_CTX context;

    load_hex("wide left", &left, "123456789ABCDEF0");
    load_hex("wide right", &right, "FEDCBA987654321");
    load_hex("wide modulus", &modulus, "FFFFFFFF00000001");
    expect_int("wide multiply", mont_wide_multiply(&left, &right, &wide),
               MONT_OK);
    expect_wide_hex("wide known product", &wide,
                    "121FA00AD77D7422236D88FE5618CF0");
    expect_int("reduce context", mont_init(&context, &modulus), MONT_OK);
    expect_int("known reduce", mont_reduce(&context, &wide, &reduced),
               MONT_OK);
    expect_hex("known reduced value", &reduced, "F989947FCFAEAFD3");

    expect_int("wide from bigint", mont_wide_from_bigint(&left, &wide),
               MONT_OK);
    expect_wide_hex("wide copied bigint", &wide, "123456789ABCDEF0");

    memset(&range_limit, 0, sizeof(range_limit));
    memcpy(range_limit.limb + context.limbs, context.modulus.limb,
           context.limbs * sizeof(BIGINT_LIMB));
    range_limit.used = context.limbs * 2U;
    load_hex("reduce sentinel", &sentinel, "55AA");
    expect_int("reject n times R",
               mont_reduce(&context, &range_limit, &sentinel),
               MONT_ERR_RANGE);
    expect_hex("range preserves output", &sentinel, "55AA");
}

static void test_conversion_and_multiplication(void)
{
    BIGINT modulus;
    BIGINT left;
    BIGINT right;
    BIGINT left_bar;
    BIGINT right_bar;
    BIGINT product_bar;
    BIGINT result;
    BIGINT expected;
    MONT_CTX context;

    load_hex("conversion modulus", &modulus, "FFFFFFFF00000001");
    load_hex("conversion left", &left, "123456789ABCDEF");
    load_hex("conversion right", &right, "FEDCBA987654321");
    expect_int("conversion context", mont_init(&context, &modulus),
               MONT_OK);
    expect_int("left to Montgomery", mont_to(&context, &left, &left_bar),
               MONT_OK);
    expect_int("left from Montgomery",
               mont_from(&context, &left_bar, &result), MONT_OK);
    expect_same("conversion round trip", &result, &left);

    expect_int("right to Montgomery",
               mont_to(&context, &right, &right_bar), MONT_OK);
    expect_int("Montgomery multiply",
               mont_mul(&context, &left_bar, &right_bar, &product_bar),
               MONT_OK);
    expect_int("product from Montgomery",
               mont_from(&context, &product_bar, &result), MONT_OK);
    expect_int("ordinary modular product",
               number_mod_multiply(&left, &right, &modulus, &expected),
               NUMBER_OK);
    expect_same("Montgomery product equality", &result, &expected);
    expect_hex("Montgomery product value", &result, "2CFAEAFCF36C7BBB");

    load_hex("large conversion input", &result,
             "123456789ABCDEF00112233445566778899AABBCCDDEEFF");
    expect_int("aliased to", mont_to(&context, &result, &result), MONT_OK);
    expect_int("aliased from", mont_from(&context, &result, &result),
               MONT_OK);
    load_hex("large expected remainder source", &left,
             "123456789ABCDEF00112233445566778899AABBCCDDEEFF");
    expect_int("large expected remainder",
               bigint_modulo(&left, &modulus, &expected), BIGINT_OK);
    expect_same("large conversion reduction", &result, &expected);
}

static void compare_pow(const char *name,
                        const char *base_hex,
                        const char *exponent_hex,
                        const char *modulus_hex)
{
    BIGINT base;
    BIGINT exponent;
    BIGINT modulus;
    BIGINT ordinary;
    BIGINT montgomery;
    MONT_CTX context;

    load_hex(name, &base, base_hex);
    load_hex(name, &exponent, exponent_hex);
    load_hex(name, &modulus, modulus_hex);
    expect_int(name, mont_init(&context, &modulus), MONT_OK);
    expect_int(name,
               number_mod_pow(&base, &exponent, &modulus, &ordinary),
               NUMBER_OK);
    expect_int(name, mont_pow(&context, &base, &exponent, &montgomery),
               MONT_OK);
    expect_same(name, &montgomery, &ordinary);
}

static void test_exponentiation(void)
{
    BIGINT base;
    BIGINT exponent;
    BIGINT modulus;
    BIGINT result;
    MONT_CTX context;

    compare_pow("classic exponentiation", "4", "D", "1F1");
    compare_pow("public exponent style",
                "123456789ABCDEF", "10001", "FFFFFFFF00000001");
    compare_pow("multi-limb exponent",
                "FEDCBA9876543210", "123456789ABCDEF",
                "FFFFFFFFFFFFFFC5");
    compare_pow("larger odd modulus",
                "123456789ABCDEF0011223344556677", "10001",
                "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFE7");

    load_hex("zero exponent base", &base, "1234");
    load_hex("zero exponent modulus", &modulus, "1F1");
    expect_int("zero exponent value", bigint_zero(&exponent), BIGINT_OK);
    expect_int("zero exponent context", mont_init(&context, &modulus),
               MONT_OK);
    expect_int("zero exponent result",
               mont_pow(&context, &base, &exponent, &result), MONT_OK);
    expect_hex("zero exponent is one", &result, "1");

    load_hex("alias pow base", &base, "123456789ABCDEF");
    load_hex("alias pow exponent", &exponent, "10001");
    load_hex("alias pow modulus", &modulus, "FFFFFFFF00000001");
    expect_int("alias pow context", mont_init(&context, &modulus), MONT_OK);
    expect_int("alias pow", mont_pow(&context, &base, &exponent, &base),
               MONT_OK);
    expect_hex("alias pow result", &base, "9FDB4D09181F9480");
}

static void make_maximum(BIGINT *value)
{
    char text[BIGINT_MAX_HEX_DIGITS + 1U];
    unsigned int index;

    for (index = 0U; index < BIGINT_MAX_HEX_DIGITS; ++index) {
        text[index] = 'F';
    }
    text[BIGINT_MAX_HEX_DIGITS] = '\0';
    load_hex("maximum modulus", value, text);
}

static void test_full_width_modulus(void)
{
    BIGINT modulus;
    BIGINT one;
    BIGINT operand;
    BIGINT operand_bar;
    BIGINT product_bar;
    BIGINT result;
    MONT_CTX context;

    make_maximum(&modulus);
    expect_int("full width context", mont_init(&context, &modulus),
               MONT_OK);
    expect_hex("full width R", &context.r_mod_n, "1");
    expect_hex("full width R squared", &context.r2_mod_n, "1");
    expect_int("full width one", bigint_from_ulong(&one, 1UL), BIGINT_OK);
    expect_int("full width operand",
               bigint_subtract(&modulus, &one, &operand), BIGINT_OK);
    expect_int("full width to",
               mont_to(&context, &operand, &operand_bar), MONT_OK);
    expect_int("full width square",
               mont_mul(&context, &operand_bar, &operand_bar,
                        &product_bar), MONT_OK);
    expect_int("full width from",
               mont_from(&context, &product_bar, &result), MONT_OK);
    expect_hex("full width square result", &result, "1");
}

static void test_small_native_cross_checks(void)
{
    static const unsigned long moduli[] = {
        3UL, 5UL, 17UL, 257UL, 497UL, 65521UL, 65535UL
    };
    static const unsigned long values[] = {
        0UL, 1UL, 2UL, 15UL, 255UL, 65534UL
    };
    BIGINT modulus;
    BIGINT left;
    BIGINT right;
    BIGINT left_bar;
    BIGINT right_bar;
    BIGINT product_bar;
    BIGINT result;
    BIGINT expected;
    MONT_CTX context;
    unsigned int modulus_index;
    unsigned int left_index;
    unsigned int right_index;

    for (modulus_index = 0U;
         modulus_index < sizeof(moduli) / sizeof(moduli[0]);
         ++modulus_index) {
        expect_int("native modulus",
                   bigint_from_ulong(&modulus, moduli[modulus_index]),
                   BIGINT_OK);
        expect_int("native context", mont_init(&context, &modulus),
                   MONT_OK);
        for (left_index = 0U;
             left_index < sizeof(values) / sizeof(values[0]);
             ++left_index) {
            expect_int("native left",
                       bigint_from_ulong(&left, values[left_index]),
                       BIGINT_OK);
            expect_int("native left to",
                       mont_to(&context, &left, &left_bar), MONT_OK);
            for (right_index = 0U;
                 right_index < sizeof(values) / sizeof(values[0]);
                 ++right_index) {
                expect_int("native right",
                           bigint_from_ulong(&right, values[right_index]),
                           BIGINT_OK);
                expect_int("native right to",
                           mont_to(&context, &right, &right_bar), MONT_OK);
                expect_int("native Montgomery multiply",
                           mont_mul(&context, &left_bar, &right_bar,
                                    &product_bar), MONT_OK);
                expect_int("native Montgomery from",
                           mont_from(&context, &product_bar, &result),
                           MONT_OK);
                expect_int("native ordinary multiply",
                           number_mod_multiply(&left, &right, &modulus,
                                               &expected), NUMBER_OK);
                expect_same("native product equality", &result, &expected);
            }
        }
    }
}

static void test_errors(void)
{
    BIGINT zero;
    BIGINT one;
    BIGINT even;
    BIGINT modulus;
    BIGINT output;
    MONT_WIDE invalid_wide;
    MONT_CTX context;
    MONT_CTX saved;

    memset(&context, 0x5a, sizeof(context));
    memcpy(&saved, &context, sizeof(saved));
    expect_int("error zero", bigint_zero(&zero), BIGINT_OK);
    expect_int("error one", bigint_from_ulong(&one, 1UL), BIGINT_OK);
    expect_int("error even", bigint_from_ulong(&even, 18UL), BIGINT_OK);
    expect_int("zero modulus", mont_init(&context, &zero),
               MONT_ERR_MODULUS);
    expect_true("zero modulus preserves context",
                memcmp(&context, &saved, sizeof(context)) == 0);
    expect_int("one modulus", mont_init(&context, &one),
               MONT_ERR_MODULUS);
    expect_int("even modulus", mont_init(&context, &even),
               MONT_ERR_MODULUS);

    load_hex("error valid modulus", &modulus, "1F1");
    expect_int("error valid context", mont_init(&context, &modulus),
               MONT_OK);
    load_hex("error output", &output, "55AA");
    expect_int("operand at modulus",
               mont_mul(&context, &modulus, &one, &output),
               MONT_ERR_RANGE);
    expect_hex("range output preserved", &output, "55AA");

    memset(&invalid_wide, 0, sizeof(invalid_wide));
    invalid_wide.used = 1U;
    expect_int("invalid wide",
               mont_reduce(&context, &invalid_wide, &output),
               MONT_ERR_INVALID);
    context.initialized = 0UL;
    expect_int("invalid context",
               mont_to(&context, &one, &output), MONT_ERR_CONTEXT);
    expect_hex("context output preserved", &output, "55AA");
    expect_int("null context", mont_init(NULL, &modulus), MONT_ERR_NULL);
}

int main(void)
{
    test_context();
    test_wide_and_reduce();
    test_conversion_and_multiplication();
    test_exponentiation();
    test_full_width_modulus();
    test_small_native_cross_checks();
    test_errors();

    if (failures != 0) {
        fprintf(stderr, "%d Week7 Montgomery test(s) failed\n", failures);
        return 1;
    }
    printf("Week7 Montgomery arithmetic tests passed\n");
    return 0;
}
