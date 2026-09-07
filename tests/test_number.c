#include <stdio.h>
#include <string.h>

#include "number.h"

static int failures = 0;

static const unsigned char test_key[8] = {
    0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1
};

static const unsigned char test_state[8] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
};

static const unsigned char test_counter[8] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

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

static void init_test_rng(const char *name, RNG_CTX *rng)
{
    expect_int(name,
               rng_init_deterministic(rng, test_key, test_state,
                                      test_counter), RNG_OK);
}

static void test_gcd(void)
{
    BIGINT left;
    BIGINT right;
    BIGINT result;

    expect_int("gcd left zero", bigint_zero(&left), BIGINT_OK);
    expect_int("gcd right zero", bigint_zero(&right), BIGINT_OK);
    expect_int("gcd zero zero", number_gcd(&left, &right, &result),
               NUMBER_OK);
    expect_hex("gcd zero result", &result, "0");

    load_hex("gcd load left", &left, "123456789ABCDEF0");
    expect_int("gcd with zero", number_gcd(&left, &right, &result),
               NUMBER_OK);
    expect_same("gcd zero identity", &result, &left);

    load_hex("gcd known left", &left, "BEEF1234");
    load_hex("gcd known right", &right, "1234");
    expect_int("gcd known", number_gcd(&left, &right, &result), NUMBER_OK);
    expect_hex("gcd known result", &result, "4");

    load_hex("gcd euclid left", &left, "30");
    load_hex("gcd euclid right", &right, "12");
    expect_int("gcd alias", number_gcd(&left, &right, &left), NUMBER_OK);
    expect_hex("gcd alias result", &left, "6");
}

static void test_modular_arithmetic(void)
{
    BIGINT left;
    BIGINT right;
    BIGINT modulus;
    BIGINT exponent;
    BIGINT result;
    BIGINT inverse;
    BIGINT one;

    load_hex("mod load left", &left, "123456789ABCDEF");
    load_hex("mod load right", &right, "FEDCBA987654321");
    load_hex("mod load modulus", &modulus, "FFFFFFFF00000001");
    expect_int("mod multiply",
               number_mod_multiply(&left, &right, &modulus, &result),
               NUMBER_OK);
    expect_hex("mod product", &result, "2CFAEAFCF36C7BBB");

    expect_int("mod exponent load",
               bigint_from_ulong(&exponent, 65537UL), BIGINT_OK);
    expect_int("mod pow",
               number_mod_pow(&left, &exponent, &modulus, &result),
               NUMBER_OK);
    expect_hex("mod pow result", &result, "9FDB4D09181F9480");

    load_hex("pow classic base", &left, "4");
    load_hex("pow classic exponent", &exponent, "D");
    load_hex("pow classic modulus", &modulus, "1F1");
    expect_int("classic mod pow",
               number_mod_pow(&left, &exponent, &modulus, &result),
               NUMBER_OK);
    expect_hex("classic mod pow result", &result, "1BD");

    expect_int("zero exponent", bigint_zero(&exponent), BIGINT_OK);
    expect_int("zero exponent pow",
               number_mod_pow(&left, &exponent, &modulus, &result),
               NUMBER_OK);
    expect_hex("zero exponent result", &result, "1");
    expect_int("modulus one", bigint_from_ulong(&modulus, 1UL), BIGINT_OK);
    expect_int("modulus one pow",
               number_mod_pow(&left, &exponent, &modulus, &result),
               NUMBER_OK);
    expect_hex("modulus one result", &result, "0");

    load_hex("inverse value", &left, "11");
    load_hex("inverse modulus", &modulus, "C30");
    expect_int("mod inverse",
               number_mod_inverse(&left, &modulus, &inverse), NUMBER_OK);
    expect_hex("mod inverse result", &inverse, "AC1");
    expect_int("inverse identity",
               number_mod_multiply(&left, &inverse, &modulus, &result),
               NUMBER_OK);
    expect_int("load one", bigint_from_ulong(&one, 1UL), BIGINT_OK);
    expect_same("inverse identity result", &result, &one);

    load_hex("small inverse value", &left, "3");
    load_hex("small inverse modulus", &modulus, "B");
    expect_int("small inverse",
               number_mod_inverse(&left, &modulus, &inverse), NUMBER_OK);
    expect_hex("small inverse result", &inverse, "4");

    load_hex("no inverse value", &left, "C");
    load_hex("no inverse modulus", &modulus, "12");
    load_hex("inverse sentinel", &inverse, "55AA");
    expect_int("no inverse",
               number_mod_inverse(&left, &modulus, &inverse),
               NUMBER_ERR_NO_INVERSE);
    expect_hex("no inverse preserves output", &inverse, "55AA");
}

static void make_maximum(BIGINT *value)
{
    char text[BIGINT_MAX_HEX_DIGITS + 1U];
    unsigned int index;

    for (index = 0U; index < BIGINT_MAX_HEX_DIGITS; ++index) {
        text[index] = 'F';
    }
    text[BIGINT_MAX_HEX_DIGITS] = '\0';
    load_hex("load number maximum", value, text);
}

static void test_full_width_modular_multiply(void)
{
    BIGINT maximum;
    BIGINT four;
    BIGINT one;
    BIGINT modulus;
    BIGINT operand;
    BIGINT result;

    make_maximum(&maximum);
    expect_int("fallback four", bigint_from_ulong(&four, 4UL), BIGINT_OK);
    expect_int("fallback one", bigint_from_ulong(&one, 1UL), BIGINT_OK);
    expect_int("fallback modulus",
               bigint_subtract(&maximum, &four, &modulus), BIGINT_OK);
    expect_int("fallback operand",
               bigint_subtract(&modulus, &one, &operand), BIGINT_OK);
    expect_int("fallback multiply",
               number_mod_multiply(&operand, &operand, &modulus, &result),
               NUMBER_OK);
    expect_hex("fallback result", &result, "1");
}

static void test_trial_division(void)
{
    BIGINT candidate;
    unsigned int factor;

    load_hex("trial small prime", &candidate, "3E5");
    factor = 0U;
    expect_int("trial prime table end",
               number_trial_division(&candidate, &factor), NUMBER_OK);
    expect_int("trial table factor", (int)factor, 997);

    load_hex("trial outside table", &candidate, "3F1");
    factor = 99U;
    expect_int("trial no factor",
               number_trial_division(&candidate, &factor), NUMBER_OK);
    expect_int("trial no factor result", (int)factor, 0);

    load_hex("trial composite", &candidate, "BD3");
    factor = 0U;
    expect_int("trial composite result",
               number_trial_division(&candidate, &factor), NUMBER_OK);
    expect_true("trial composite found", factor != 0U);
}

static void expect_primality(const char *name,
                             const char *hex_value,
                             const unsigned long *bases,
                             unsigned int rounds,
                             int expected)
{
    BIGINT candidate;
    int probable;

    load_hex(name, &candidate, hex_value);
    probable = -1;
    expect_int(name,
               number_miller_rabin_bases(&candidate, bases, rounds,
                                         &probable), NUMBER_OK);
    expect_int(name, probable, expected);
}

static void test_miller_rabin(void)
{
    static const unsigned long bases[] = {
        2UL, 3UL, 5UL, 7UL, 11UL, 13UL, 17UL, 19UL, 23UL
    };
    static const char *carmichael[] = {
        "231", "451", "6C1", "9A1", "B05", "19C9"
    };
    BIGINT candidate;
    RNG_CTX rng;
    unsigned int index;
    int probable;

    expect_primality("prime two", "2", bases, 9U, 1);
    expect_primality("prime three", "3", bases, 9U, 1);
    expect_primality("prime 1009", "3F1", bases, 9U, 1);
    expect_primality("large known prime", "78C27CE77", bases, 9U, 1);
    expect_primality("Mersenne prime 2^127-1",
                     "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", bases, 9U, 1);
    expect_primality("zero composite", "0", bases, 9U, 0);
    expect_primality("one composite", "1", bases, 9U, 0);
    expect_primality("even composite", "100", bases, 9U, 0);
    expect_primality("square above trial table", "F88E1", bases, 9U, 0);

    for (index = 0U; index < sizeof(carmichael) / sizeof(carmichael[0]);
         ++index) {
        expect_primality("Carmichael composite", carmichael[index],
                         bases, 9U, 0);
    }

    expect_primality("seven-base strong pseudoprime",
                     "136A352B2C8C1", bases, 7U, 1);
    expect_primality("additional bases reject pseudoprime",
                     "136A352B2C8C1", bases, 9U, 0);

    load_hex("random witness prime", &candidate, "78C27CE77");
    init_test_rng("random witness rng", &rng);
    probable = -1;
    expect_int("random witness Miller-Rabin",
               number_miller_rabin(&candidate, &rng, 8U, &probable),
               NUMBER_OK);
    expect_int("random witness prime result", probable, 1);

    memset(&rng, 0, sizeof(rng));
    probable = 77;
    expect_int("uninitialized witness rng",
               number_miller_rabin(&candidate, &rng, 1U, &probable),
               NUMBER_ERR_RNG);
    expect_int("rng error preserves result", probable, 77);

    probable = 88;
    expect_int("zero rounds",
               number_miller_rabin_bases(&candidate, bases, 0U,
                                         &probable), NUMBER_ERR_RANGE);
    expect_int("round error preserves result", probable, 88);
}

static void test_probable_prime_generation(void)
{
    BIGINT first;
    BIGINT second;
    BIGINT candidate;
    RNG_CTX first_rng;
    RNG_CTX second_rng;
    RNG_CTX limited_rng;
    unsigned long first_attempts;
    unsigned long second_attempts;
    unsigned long limited_attempts;
    unsigned long bases[8];
    unsigned int bits;
    unsigned int index;
    int odd;
    int probable;

    for (index = 0U; index < 8U; ++index) {
        bases[index] = (unsigned long)(2U + index);
    }
    init_test_rng("first prime rng", &first_rng);
    init_test_rng("second prime rng", &second_rng);
    first_attempts = 0UL;
    second_attempts = 0UL;
    expect_int("generate first prime",
               number_generate_probable_prime(&first_rng, 32U, 8U, 1000UL,
                                              &first, &first_attempts),
               NUMBER_OK);
    expect_int("generate second prime",
               number_generate_probable_prime(&second_rng, 32U, 8U, 1000UL,
                                              &second, &second_attempts),
               NUMBER_OK);
    expect_same("deterministic generated prime", &first, &second);
    expect_true("deterministic attempts",
                first_attempts == second_attempts);
    expect_int("generated bit length",
               bigint_bit_length(&first, &bits), BIGINT_OK);
    expect_int("exact generated bits", (int)bits, 32);
    expect_int("generated odd", bigint_is_odd(&first, &odd), BIGINT_OK);
    expect_int("generated is odd", odd, 1);
    probable = 0;
    expect_int("verify generated prime",
               number_miller_rabin_bases(&first, bases, 8U, &probable),
               NUMBER_OK);
    expect_int("generated probable result", probable, 1);
    expect_hex("stable generated prime", &first, "CB68CDF9");

    init_test_rng("limited prime rng", &limited_rng);
    load_hex("limited output sentinel", &candidate, "55AA");
    limited_attempts = 0UL;
    expect_int("attempt limit",
               number_generate_probable_prime(&limited_rng, 8U, 4U, 1UL,
                                              &candidate, &limited_attempts),
               NUMBER_ERR_ATTEMPTS);
    expect_int("attempt limit count", (int)limited_attempts, 1);
    expect_hex("attempt limit preserves prime", &candidate, "55AA");

    first_attempts = 99UL;
    expect_int("invalid generated bits",
               number_generate_probable_prime(&first_rng, 1U, 4U, 10UL,
                                              &candidate, &first_attempts),
               NUMBER_ERR_RANGE);
    expect_true("range error preserves attempts", first_attempts == 99UL);
}

static void test_errors(void)
{
    BIGINT value;
    BIGINT modulus;
    BIGINT output;
    unsigned long bases[1];
    int probable;

    bases[0] = 1UL;
    load_hex("error value", &value, "3F1");
    expect_int("error modulus zero", bigint_zero(&modulus), BIGINT_OK);
    load_hex("error output", &output, "55AA");
    expect_int("zero modulus multiply",
               number_mod_multiply(&value, &value, &modulus, &output),
               NUMBER_ERR_MODULUS);
    expect_hex("zero modulus output", &output, "55AA");
    expect_int("zero modulus inverse",
               number_mod_inverse(&value, &modulus, &output),
               NUMBER_ERR_MODULUS);

    probable = 55;
    expect_int("invalid deterministic base",
               number_miller_rabin_bases(&value, bases, 1U, &probable),
               NUMBER_ERR_INVALID);
    expect_int("invalid base preserves result", probable, 55);
    expect_int("null gcd", number_gcd(NULL, &value, &output),
               NUMBER_ERR_NULL);
}

int main(void)
{
    test_gcd();
    test_modular_arithmetic();
    test_full_width_modular_multiply();
    test_trial_division();
    test_miller_rabin();
    test_probable_prime_generation();
    test_errors();

    if (failures != 0) {
        fprintf(stderr, "%d Week6 number test(s) failed\n", failures);
        return 1;
    }
    printf("Week6 number theory and probable-prime tests passed\n");
    return 0;
}
