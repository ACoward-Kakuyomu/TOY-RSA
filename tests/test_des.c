#include <stdio.h>
#include <string.h>

#include "des.h"

static int failures = 0;

static void expect_int(const char *name, int actual, int expected)
{
    if (actual != expected) {
        fprintf(stderr, "%s: expected %d, got %d\n",
                name, expected, actual);
        ++failures;
    }
}

static void expect_bytes(const char *name,
                         const unsigned char *actual,
                         const unsigned char *expected,
                         unsigned int length)
{
    unsigned int index;

    if (memcmp(actual, expected, length) == 0) {
        return;
    }
    fprintf(stderr, "%s: byte sequence differs\n  expected:", name);
    for (index = 0U; index < length; ++index) {
        fprintf(stderr, " %02X", (unsigned int)expected[index]);
    }
    fprintf(stderr, "\n  actual:  ");
    for (index = 0U; index < length; ++index) {
        fprintf(stderr, " %02X", (unsigned int)actual[index]);
    }
    fprintf(stderr, "\n");
    ++failures;
}

static void test_initial_and_final_permutations(void)
{
    const unsigned char input[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const unsigned char expected_ip[8] = {
        0xcc, 0x00, 0xcc, 0xff, 0xf0, 0xaa, 0xf0, 0xaa
    };
    unsigned char permuted[8];
    unsigned char restored[8];

    expect_int("initial permutation status",
               des_initial_permutation(input, permuted), DES_OK);
    expect_bytes("initial permutation", permuted, expected_ip, 8U);
    expect_int("final permutation status",
               des_final_permutation(permuted, restored), DES_OK);
    expect_bytes("IP followed by FP", restored, input, 8U);

    memcpy(restored, input, sizeof(restored));
    expect_int("in-place initial permutation status",
               des_initial_permutation(restored, restored), DES_OK);
    expect_bytes("in-place initial permutation", restored, expected_ip, 8U);
}

static void test_expansion_and_p_permutation(void)
{
    const unsigned char right[4] = { 0xf0, 0xaa, 0xf0, 0xaa };
    const unsigned char expected_expanded[6] = {
        0x7a, 0x15, 0x55, 0x7a, 0x15, 0x55
    };
    const unsigned char sbox_output[4] = { 0x5c, 0x82, 0xb5, 0x97 };
    const unsigned char expected_p[4] = { 0x23, 0x4a, 0xa9, 0xbb };
    unsigned char expanded[6];
    unsigned char permuted[4];

    expect_int("expansion status", des_expand(right, expanded), DES_OK);
    expect_bytes("expansion", expanded, expected_expanded, 6U);
    expect_int("P permutation status",
               des_p_permute(sbox_output, permuted), DES_OK);
    expect_bytes("P permutation", permuted, expected_p, 4U);
}

static void test_sboxes(void)
{
    unsigned char value;

    expect_int("S1 zero status", des_sbox(0U, 0U, &value), DES_OK);
    expect_int("S1 zero value", (int)value, 14);
    expect_int("S1 all ones status", des_sbox(0U, 63U, &value), DES_OK);
    expect_int("S1 all ones value", (int)value, 13);
    expect_int("S8 zero status", des_sbox(7U, 0U, &value), DES_OK);
    expect_int("S8 zero value", (int)value, 13);
    expect_int("S-box number range", des_sbox(8U, 0U, &value),
               DES_ERR_RANGE);
    expect_int("S-box input range", des_sbox(0U, 64U, &value),
               DES_ERR_RANGE);
    expect_int("S-box NULL output", des_sbox(0U, 0U, NULL),
               DES_ERR_NULL);
}

static void test_key_half_rotation(void)
{
    unsigned char c[4] = { 0x0f, 0x0c, 0xca, 0xaf };
    unsigned char d[4] = { 0x05, 0x56, 0x67, 0x8f };
    const unsigned char expected_c[4] = { 0x0e, 0x19, 0x95, 0x5f };
    const unsigned char expected_d[4] = { 0x0a, 0xac, 0xcf, 0x1e };
    unsigned char invalid[4] = { 0x10, 0x00, 0x00, 0x00 };

    expect_int("C rotation status", des_rotate_key_half(c, 1U), DES_OK);
    expect_bytes("C rotation", c, expected_c, 4U);
    expect_int("D rotation status", des_rotate_key_half(d, 1U), DES_OK);
    expect_bytes("D rotation", d, expected_d, 4U);
    expect_int("rotation count range", des_rotate_key_half(c, 3U),
               DES_ERR_RANGE);
    expect_int("28-bit representation range",
               des_rotate_key_half(invalid, 1U), DES_ERR_RANGE);
}

static void test_key_schedule(void)
{
    const unsigned char key[8] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1
    };
    const unsigned char parity_flipped_key[8] = {
        0x12, 0x35, 0x56, 0x78, 0x9a, 0xbd, 0xde, 0xf0
    };
    const unsigned char expected_first[6] = {
        0x1b, 0x02, 0xef, 0xfc, 0x70, 0x72
    };
    const unsigned char expected_last[6] = {
        0xcb, 0x3d, 0x8b, 0x0e, 0x17, 0xf5
    };
    DES_KEY_SCHEDULE schedule;
    DES_KEY_SCHEDULE parity_schedule;

    expect_int("key schedule status",
               des_key_schedule(key, &schedule), DES_OK);
    expect_bytes("first subkey", schedule.subkeys[0], expected_first, 6U);
    expect_bytes("last subkey", schedule.subkeys[15], expected_last, 6U);

    expect_int("parity-flipped key schedule status",
               des_key_schedule(parity_flipped_key, &parity_schedule),
               DES_OK);
    expect_bytes("parity bits do not affect schedule",
                 &parity_schedule.subkeys[0][0],
                 &schedule.subkeys[0][0],
                 DES_ROUNDS * DES_SUBKEY_BYTES);
}

static void test_f_function_and_round(void)
{
    const unsigned char key[8] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1
    };
    const unsigned char expected_f[4] = { 0x23, 0x4a, 0xa9, 0xbb };
    const unsigned char expected_left[4] = { 0xf0, 0xaa, 0xf0, 0xaa };
    const unsigned char expected_right[4] = { 0xef, 0x4a, 0x65, 0x44 };
    unsigned char left[4] = { 0xcc, 0x00, 0xcc, 0xff };
    unsigned char right[4] = { 0xf0, 0xaa, 0xf0, 0xaa };
    unsigned char output[4];
    DES_KEY_SCHEDULE schedule;

    expect_int("schedule for F", des_key_schedule(key, &schedule), DES_OK);
    expect_int("F function status",
               des_f(right, schedule.subkeys[0], output), DES_OK);
    expect_bytes("F function", output, expected_f, 4U);
    expect_int("round status",
               des_round(left, right, schedule.subkeys[0]), DES_OK);
    expect_bytes("round left", left, expected_left, 4U);
    expect_bytes("round right", right, expected_right, 4U);
    expect_int("round alias rejection",
               des_round(left, left, schedule.subkeys[0]), DES_ERR_ALIAS);
}

static void test_error_paths(void)
{
    unsigned char input[8] = { 0 };
    unsigned char output[8] = { 0 };
    unsigned char bad_table[1] = { 9 };
    unsigned char good_table[1] = { 1 };
    DES_KEY_SCHEDULE schedule;

    expect_int("permutation NULL input",
               des_permute(NULL, 8U, output, 1U, good_table), DES_ERR_NULL);
    expect_int("permutation NULL output",
               des_permute(input, 8U, NULL, 1U, good_table), DES_ERR_NULL);
    expect_int("permutation zero input bits",
               des_permute(input, 0U, output, 1U, good_table),
               DES_ERR_RANGE);
    expect_int("permutation invalid table entry",
               des_permute(input, 8U, output, 1U, bad_table),
               DES_ERR_RANGE);
    expect_int("key schedule NULL key",
               des_key_schedule(NULL, &schedule), DES_ERR_NULL);
    expect_int("key schedule NULL output",
               des_key_schedule(input, NULL), DES_ERR_NULL);
}

int main(void)
{
    test_initial_and_final_permutations();
    test_expansion_and_p_permutation();
    test_sboxes();
    test_key_half_rotation();
    test_key_schedule();
    test_f_function_and_round();
    test_error_paths();

    if (failures != 0) {
        fprintf(stderr, "%d DES test(s) failed\n", failures);
        return 1;
    }
    printf("All Week1 DES internal tests passed.\n");
    return 0;
}
