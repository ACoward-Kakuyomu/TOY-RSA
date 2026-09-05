#include <stdio.h>
#include <string.h>

#include "rng.h"

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

static const unsigned char test_entropy[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const unsigned char test_timing[8] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
};

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

static void expect_different(const char *name,
                             const unsigned char *left,
                             const unsigned char *right,
                             unsigned int length)
{
    if (memcmp(left, right, length) == 0) {
        fprintf(stderr, "%s: byte sequences unexpectedly match\n", name);
        ++failures;
    }
}

static int byte_has_odd_parity(unsigned char value)
{
    unsigned int ones;
    unsigned int bit;

    ones = 0U;
    for (bit = 0U; bit < 8U; ++bit) {
        ones += (unsigned int)((value >> bit) & 1U);
    }
    return (ones & 1U) != 0U;
}

static void expect_odd_parity(const char *name,
                              const unsigned char key[8])
{
    unsigned int index;

    for (index = 0U; index < 8U; ++index) {
        if (!byte_has_odd_parity(key[index])) {
            fprintf(stderr, "%s: byte %u lacks odd parity\n", name, index);
            ++failures;
        }
    }
}

static void test_deterministic_vector(void)
{
    static const unsigned char expected[24] = {
        0xce, 0xf0, 0x94, 0x03, 0x45, 0x91, 0xb1, 0x82,
        0xbc, 0x37, 0x9a, 0x10, 0x4b, 0x68, 0xcd, 0xf8,
        0xd1, 0x47, 0x63, 0xd3, 0xbe, 0xe4, 0x8e, 0x3a
    };
    unsigned char output[24];
    RNG_CTX context;

    expect_int("deterministic init",
               rng_init_deterministic(&context, test_key, test_state,
                                      test_counter), RNG_OK);
    expect_odd_parity("stored deterministic key", context.key);
    expect_int("deterministic generate",
               rng_generate(&context, output, 24UL), RNG_OK);
    expect_bytes("deterministic vector", output, expected, 24U);
}

static void test_split_generation(void)
{
    unsigned char whole[24];
    unsigned char split[24];
    RNG_CTX first;
    RNG_CTX second;

    expect_int("whole init",
               rng_init_deterministic(&first, test_key, test_state,
                                      test_counter), RNG_OK);
    expect_int("split init",
               rng_init_deterministic(&second, test_key, test_state,
                                      test_counter), RNG_OK);
    expect_int("whole generate", rng_generate(&first, whole, 24UL), RNG_OK);
    expect_int("split one", rng_generate(&second, split, 1UL), RNG_OK);
    expect_int("split three", rng_generate(&second, split + 1, 3UL), RNG_OK);
    expect_int("split twelve",
               rng_generate(&second, split + 4, 12UL), RNG_OK);
    expect_int("split eight",
               rng_generate(&second, split + 16, 8UL), RNG_OK);
    expect_bytes("split output equality", split, whole, 24U);
    expect_bytes("split state equality", second.state_vector,
                 first.state_vector, 8U);
    expect_bytes("split counter equality", second.counter,
                 first.counter, 8U);
    expect_int("split output index equality",
               (int)second.output_index, (int)first.output_index);
}

static void test_parity_independence(void)
{
    unsigned char parity_flipped[8];
    unsigned char first_output[16];
    unsigned char second_output[16];
    unsigned int index;
    RNG_CTX first;
    RNG_CTX second;

    for (index = 0U; index < 8U; ++index) {
        parity_flipped[index] = (unsigned char)(test_key[index] ^ 1U);
    }
    expect_int("parity first init",
               rng_init_deterministic(&first, test_key, test_state,
                                      test_counter), RNG_OK);
    expect_int("parity second init",
               rng_init_deterministic(&second, parity_flipped, test_state,
                                      test_counter), RNG_OK);
    expect_int("parity first output",
               rng_generate(&first, first_output, 16UL), RNG_OK);
    expect_int("parity second output",
               rng_generate(&second, second_output, 16UL), RNG_OK);
    expect_bytes("parity does not alter stream",
                 second_output, first_output, 16U);
    expect_bytes("normalized keys match", second.key, first.key, 8U);
}

static void test_seed_vector(void)
{
    static const unsigned char expected[24] = {
        0x5c, 0xd5, 0xdd, 0x19, 0x28, 0x13, 0x21, 0xa8,
        0x1a, 0xec, 0xcb, 0x73, 0x96, 0xa4, 0xa4, 0x69,
        0x2c, 0xe1, 0x96, 0xa8, 0xb6, 0xc2, 0xe3, 0xab
    };
    static const unsigned char expected_key[8] = {
        0x46, 0x64, 0x2f, 0x1c, 0x73, 0x75, 0x2c, 0xb5
    };
    unsigned char output[24];
    unsigned char des_key[8];
    int weak;
    RNG_CTX context;

    expect_int("fixed seed init",
               rng_seed(&context, test_entropy, 16UL, test_timing), RNG_OK);
    expect_odd_parity("derived internal key", context.key);
    expect_int("fixed seed generate",
               rng_generate(&context, output, 24UL), RNG_OK);
    expect_bytes("fixed seed vector", output, expected, 24U);
    expect_int("generated DES key status",
               rng_generate_des_key(&context, des_key), RNG_OK);
    expect_bytes("generated DES key vector", des_key, expected_key, 8U);
    expect_odd_parity("generated DES key parity", des_key);
    expect_int("generated DES weak check",
               rng_des_key_is_weak(des_key, &weak), RNG_OK);
    expect_int("generated DES key is not weak", weak, 0);
}

static void test_seed_diversification(void)
{
    unsigned char changed_timing[8];
    unsigned char first_output[8];
    unsigned char second_output[8];
    RNG_CTX first;
    RNG_CTX second;

    memcpy(changed_timing, test_timing, sizeof(changed_timing));
    changed_timing[7] ^= 1U;
    expect_int("diversification first seed",
               rng_seed(&first, test_entropy, 16UL, test_timing), RNG_OK);
    expect_int("diversification second seed",
               rng_seed(&second, test_entropy, 16UL, changed_timing), RNG_OK);
    expect_int("diversification first output",
               rng_generate(&first, first_output, 8UL), RNG_OK);
    expect_int("diversification second output",
               rng_generate(&second, second_output, 8UL), RNG_OK);
    expect_different("timing diversifies seed", first_output,
                     second_output, 8U);
}

static void test_normal_initialization(void)
{
    unsigned char output[8];
    RNG_CTX context;

    expect_int("normal init",
               rng_init(&context, test_entropy, 16UL), RNG_OK);
    expect_int("normal init state", context.status, RNG_STATE_ACTIVE);
    expect_int("normal output",
               rng_generate(&context, output, 8UL), RNG_OK);
}

static void test_weak_keys(void)
{
    static const unsigned char weak_keys[16][8] = {
        { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
        { 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe },
        { 0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1 },
        { 0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e },
        { 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe },
        { 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01 },
        { 0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1 },
        { 0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e },
        { 0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1 },
        { 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01 },
        { 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe },
        { 0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e },
        { 0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e },
        { 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01 },
        { 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe },
        { 0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1 }
    };
    unsigned char no_parity[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    unsigned char normalized[8];
    unsigned int index;
    int weak;
    RNG_CTX context;

    for (index = 0U; index < 16U; ++index) {
        expect_int("known weak key check",
                   rng_des_key_is_weak(weak_keys[index], &weak), RNG_OK);
        expect_int("known weak key result", weak, 1);
    }
    expect_int("parity-free weak key check",
               rng_des_key_is_weak(no_parity, &weak), RNG_OK);
    expect_int("parity-free weak key result", weak, 1);
    expect_int("in-place parity",
               rng_des_key_set_odd_parity(no_parity, no_parity), RNG_OK);
    memset(normalized, 0x01, sizeof(normalized));
    expect_bytes("zero material parity normalization",
                 no_parity, normalized, 8U);
    expect_odd_parity("normalized weak key parity", no_parity);
    expect_int("deterministic weak key rejection",
               rng_init_deterministic(&context, weak_keys[0], test_state,
                                      test_counter), RNG_ERR_WEAK_KEY);
}

static void test_errors_and_limit(void)
{
    unsigned char all_ones[8];
    unsigned char output[8];
    unsigned char short_entropy[7] = { 0, 1, 2, 3, 4, 5, 6 };
    int weak;
    RNG_CTX context;

    memset(&context, 0, sizeof(context));
    memset(all_ones, 0xff, sizeof(all_ones));
    expect_int("uninitialized generate",
               rng_generate(&context, output, 1UL), RNG_ERR_STATE);
    expect_int("NULL deterministic context",
               rng_init_deterministic(NULL, test_key, test_state,
                                      test_counter), RNG_ERR_NULL);
    expect_int("short seed entropy",
               rng_seed(&context, short_entropy, 7UL, test_timing),
               RNG_ERR_ENTROPY);
    expect_int("short normal entropy",
               rng_init(&context, short_entropy, 7UL), RNG_ERR_ENTROPY);
    expect_int("NULL parity input",
               rng_des_key_set_odd_parity(NULL, output), RNG_ERR_NULL);
    expect_int("NULL weak output",
               rng_des_key_is_weak(test_key, NULL), RNG_ERR_NULL);
    expect_int("NULL weak key",
               rng_des_key_is_weak(NULL, &weak), RNG_ERR_NULL);

    expect_int("limit init",
               rng_init_deterministic(&context, test_key, test_state,
                                      all_ones), RNG_OK);
    expect_int("zero-length NULL output",
               rng_generate(&context, NULL, 0UL), RNG_OK);
    expect_int("counter limit",
               rng_generate(&context, output, 1UL), RNG_ERR_LIMIT);
    expect_int("counter limit state", context.status, RNG_STATE_ERROR);
    expect_int("generate after limit",
               rng_generate(&context, output, 1UL), RNG_ERR_STATE);
}

int main(void)
{
    test_deterministic_vector();
    test_split_generation();
    test_parity_independence();
    test_seed_vector();
    test_seed_diversification();
    test_normal_initialization();
    test_weak_keys();
    test_errors_and_limit();

    if (failures != 0) {
        fprintf(stderr, "%d Week4 RNG test(s) failed\n", failures);
        return 1;
    }
    printf("All Week4 DES-based RNG tests passed.\n");
    return 0;
}
