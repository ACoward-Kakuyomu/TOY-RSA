#include <stdio.h>
#include <string.h>

#include "rsa.h"

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
    if (status != BIGINT_OK || strcmp(actual, expected) != 0) {
        fprintf(stderr, "%s: expected %s, got %s (status %d)\n",
                name, expected, actual, status);
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

static void expect_bytes(const char *name,
                         const unsigned char *actual,
                         const unsigned char *expected,
                         unsigned int length)
{
    if (memcmp(actual, expected, length) != 0) {
        fprintf(stderr, "%s: byte strings differ\n", name);
        ++failures;
    }
}

static void init_test_rng(const char *name, RNG_CTX *rng)
{
    expect_int(name,
               rng_init_deterministic(rng, test_key, test_state,
                                      test_counter),
               RNG_OK);
}

static void make_small_key(RSA_PRIVATE_KEY *key)
{
    BIGINT p;
    BIGINT q;

    load_hex("small p", &p, "3D");
    load_hex("small q", &q, "35");
    expect_int("small key", rsa_private_key_from_primes(&p, &q, key),
               RSA_OK);
}

static void test_known_key_and_operations(void)
{
    RSA_PRIVATE_KEY key;
    RSA_PUBLIC_KEY public_key;
    BIGINT message;
    BIGINT ciphertext;
    BIGINT recovered;
    BIGINT standard;
    BIGINT sentinel;
    int valid;

    make_small_key(&key);
    expect_hex("known n", &key.public_key.n, "CA1");
    expect_hex("known e", &key.public_key.e, "10001");
    expect_hex("known d", &key.d, "AC1");
    expect_hex("known dp", &key.dp, "35");
    expect_hex("known dq", &key.dq, "31");
    expect_hex("known q inverse", &key.q_inverse, "26");
    expect_true("known modulus bits", key.public_key.modulus_bits == 12U);

    valid = 0;
    expect_int("validate private", rsa_validate_private_key(&key, &valid),
               RSA_OK);
    expect_true("private valid", valid != 0);
    expect_int("extract public", rsa_public_from_private(&key, &public_key),
               RSA_OK);
    valid = 0;
    expect_int("validate public",
               rsa_validate_public_key(&public_key, &valid), RSA_OK);
    expect_true("public valid", valid != 0);

    load_hex("message 65", &message, "41");
    expect_int("public operation",
               rsa_public_operation(&public_key, &message, &ciphertext),
               RSA_OK);
    expect_hex("known ciphertext", &ciphertext, "AE6");
    expect_int("standard private",
               rsa_private_operation_standard(&key, &ciphertext, &standard),
               RSA_OK);
    expect_int("CRT private",
               rsa_private_operation(&key, &ciphertext, &recovered), RSA_OK);
    expect_same("standard result", &standard, &message);
    expect_same("CRT result", &recovered, &message);

    load_hex("zero message", &message, "0");
    expect_int("zero public",
               rsa_public_operation(&public_key, &message, &ciphertext),
               RSA_OK);
    expect_int("zero private",
               rsa_private_operation(&key, &ciphertext, &recovered), RSA_OK);
    expect_hex("zero round trip", &recovered, "0");

    load_hex("one message", &message, "1");
    expect_int("one public",
               rsa_public_operation(&public_key, &message, &ciphertext),
               RSA_OK);
    expect_int("one private",
               rsa_private_operation(&key, &ciphertext, &recovered), RSA_OK);
    expect_hex("one round trip", &recovered, "1");

    load_hex("n minus one", &message, "CA0");
    expect_int("n-1 public alias",
               rsa_public_operation(&public_key, &message, &message), RSA_OK);
    expect_int("n-1 private alias",
               rsa_private_operation(&key, &message, &message), RSA_OK);
    expect_hex("n-1 round trip", &message, "CA0");

    load_hex("out of range", &message, "CA1");
    load_hex("sentinel", &sentinel, "1234");
    recovered = sentinel;
    expect_int("public range",
               rsa_public_operation(&public_key, &message, &recovered),
               RSA_ERR_RANGE);
    expect_same("range preserves output", &recovered, &sentinel);
}

static void test_validation_failures(void)
{
    RSA_PRIVATE_KEY key;
    RSA_PRIVATE_KEY changed;
    BIGINT p;
    BIGINT q;
    int valid;

    make_small_key(&key);
    changed = key;
    load_hex("changed dp", &changed.dp, "34");
    valid = 1;
    expect_int("invalid CRT status",
               rsa_validate_private_key(&changed, &valid), RSA_OK);
    expect_true("invalid CRT detected", valid == 0);

    changed = key;
    changed.dp.used = BIGINT_MAX_LIMBS + 1U;
    valid = 7;
    expect_int("invalid representation status",
               rsa_validate_private_key(&changed, &valid), RSA_ERR_INVALID);
    expect_true("invalid representation preserves valid", valid == 7);

    load_hex("same prime", &p, "3D");
    q = p;
    expect_int("same primes rejected",
               rsa_private_key_from_primes(&p, &q, &changed), RSA_ERR_KEY);
    load_hex("composite p", &p, "3F");
    load_hex("prime q", &q, "35");
    expect_int("composite rejected",
               rsa_private_key_from_primes(&p, &q, &changed), RSA_ERR_KEY);
}

static void test_serialization(void)
{
    static const unsigned char expected_public[12] = {
        0x54, 0x52, 0x50, 0x38, 0x00, 0x02,
        0x0c, 0xa1, 0x00, 0x01, 0x00, 0x01
    };
    static const unsigned char expected_private[22] = {
        0x54, 0x52, 0x53, 0x38, 0x00, 0x02, 0x0c, 0xa1,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x0a, 0xc1,
        0x00, 0x01, 0x3d, 0x00, 0x01, 0x35
    };
    RSA_PRIVATE_KEY key;
    RSA_PRIVATE_KEY private_copy;
    RSA_PUBLIC_KEY public_copy;
    unsigned char output[RSA_PRIVATE_KEY_MAX_SERIALIZED];
    unsigned char changed_public[13];
    unsigned char changed[22];
    unsigned int length;
    unsigned int size;
    int valid;

    make_small_key(&key);
    length = 0U;
    expect_int("public size",
               rsa_public_key_serialized_size(&key.public_key, &size),
               RSA_OK);
    expect_true("public size value", size == sizeof(expected_public));
    expect_int("serialize public",
               rsa_serialize_public_key(&key.public_key, output,
                                        sizeof(output), &length), RSA_OK);
    expect_true("public length", length == sizeof(expected_public));
    expect_bytes("public bytes", output, expected_public, length);
    expect_int("deserialize public",
               rsa_deserialize_public_key(output, length, &public_copy),
               RSA_OK);
    expect_same("public round trip n", &public_copy.n, &key.public_key.n);

    memcpy(changed_public, expected_public, sizeof(expected_public));
    changed_public[11] ^= 1U;
    expect_int("bad public exponent",
               rsa_deserialize_public_key(changed_public,
                                          sizeof(expected_public),
                                          &public_copy), RSA_ERR_FORMAT);
    memcpy(changed_public, expected_public, sizeof(expected_public));
    changed_public[6] = 0U;
    expect_int("non-minimal public integer",
               rsa_deserialize_public_key(changed_public,
                                          sizeof(expected_public),
                                          &public_copy), RSA_ERR_FORMAT);
    memcpy(changed_public, expected_public, sizeof(expected_public));
    changed_public[12] = 0U;
    expect_int("trailing public data",
               rsa_deserialize_public_key(changed_public,
                                          sizeof(changed_public),
                                          &public_copy), RSA_ERR_FORMAT);

    memset(output, 0xa5, sizeof(output));
    length = 0U;
    expect_int("public capacity",
               rsa_serialize_public_key(&key.public_key, output, 11U,
                                        &length), RSA_ERR_CAPACITY);
    expect_true("public required length", length == 12U);
    expect_true("capacity preserves output", output[0] == 0xa5U);

    expect_int("private size",
               rsa_private_key_serialized_size(&key, &size), RSA_OK);
    expect_true("private size value", size == sizeof(expected_private));
    expect_int("serialize private",
               rsa_serialize_private_key(&key, output, sizeof(output),
                                         &length), RSA_OK);
    expect_true("private length", length == sizeof(expected_private));
    expect_bytes("private bytes", output, expected_private, length);
    expect_int("deserialize private",
               rsa_deserialize_private_key(output, length, &private_copy),
               RSA_OK);
    valid = 0;
    expect_int("validate private copy",
               rsa_validate_private_key(&private_copy, &valid), RSA_OK);
    expect_true("private copy valid", valid != 0);
    expect_same("private round trip d", &private_copy.d, &key.d);

    memcpy(changed, expected_private, sizeof(changed));
    changed[0] = 'X';
    expect_int("bad private magic",
               rsa_deserialize_private_key(changed, sizeof(changed),
                                           &private_copy), RSA_ERR_FORMAT);
    memcpy(changed, expected_private, sizeof(changed));
    changed[7] ^= 1U;
    expect_int("bad serialized n",
               rsa_deserialize_private_key(changed, sizeof(changed),
                                           &private_copy), RSA_ERR_FORMAT);
    memcpy(changed, expected_private, sizeof(changed));
    changed[15] ^= 1U;
    expect_int("bad serialized d",
               rsa_deserialize_private_key(changed, sizeof(changed),
                                           &private_copy), RSA_ERR_FORMAT);
    memcpy(changed, expected_private, sizeof(changed));
    changed[11] ^= 1U;
    expect_int("bad private exponent",
               rsa_deserialize_private_key(changed, sizeof(changed),
                                           &private_copy), RSA_ERR_FORMAT);
    memcpy(changed, expected_private, sizeof(changed));
    changed[18] ^= 2U;
    expect_int("bad serialized p",
               rsa_deserialize_private_key(changed, sizeof(changed),
                                           &private_copy), RSA_ERR_FORMAT);
    memcpy(changed, expected_private, sizeof(changed));
    changed[21] ^= 2U;
    expect_int("bad serialized q",
               rsa_deserialize_private_key(changed, sizeof(changed),
                                           &private_copy), RSA_ERR_FORMAT);
    memcpy(changed, expected_private, sizeof(changed));
    changed[5] = 3U;
    expect_int("bad private length",
               rsa_deserialize_private_key(changed, sizeof(changed),
                                           &private_copy), RSA_ERR_FORMAT);
    memcpy(changed, expected_private, sizeof(changed));
    changed[6] = 0U;
    expect_int("non-minimal private integer",
               rsa_deserialize_private_key(changed, sizeof(changed),
                                           &private_copy), RSA_ERR_FORMAT);
    expect_int("trailing private data",
               rsa_deserialize_private_key(expected_private,
                                           sizeof(expected_private) - 1U,
                                           &private_copy), RSA_ERR_FORMAT);
}

static void test_deterministic_generation(void)
{
    RNG_CTX first_rng;
    RNG_CTX second_rng;
    RSA_PRIVATE_KEY first;
    RSA_PRIVATE_KEY second;
    RSA_KEYGEN_STATS first_stats;
    RSA_KEYGEN_STATS second_stats;
    BIGINT message;
    BIGINT ciphertext;
    BIGINT recovered;
    RSA_PRIVATE_KEY restored;
    unsigned char serialized[RSA_PRIVATE_KEY_MAX_SERIALIZED];
    unsigned int serialized_length;
    unsigned int bits;
    int valid;

    init_test_rng("first RNG", &first_rng);
    init_test_rng("second RNG", &second_rng);
    expect_int("first keygen",
               rsa_generate_key(&first_rng, 64U, 8U, 10000UL, 64U,
                                &first, &first_stats), RSA_OK);
    expect_int("second keygen",
               rsa_generate_key(&second_rng, 64U, 8U, 10000UL, 64U,
                                &second, &second_stats), RSA_OK);
    expect_same("deterministic n", &first.public_key.n,
                &second.public_key.n);
    expect_same("deterministic d", &first.d, &second.d);
    expect_true("deterministic stats",
                first_stats.p_candidates == second_stats.p_candidates &&
                first_stats.q_candidates == second_stats.q_candidates &&
                first_stats.restarts == second_stats.restarts);
    bits = 0U;
    expect_int("generated bit length",
               bigint_bit_length(&first.public_key.n, &bits), BIGINT_OK);
    expect_true("exact generated bits", bits == 64U);
    valid = 0;
    expect_int("generated validation",
               rsa_validate_private_key(&first, &valid), RSA_OK);
    expect_true("generated key valid", valid != 0);
    serialized_length = 0U;
    expect_int("generated serialization",
               rsa_serialize_private_key(&first, serialized,
                                         sizeof(serialized),
                                         &serialized_length), RSA_OK);
    expect_int("generated deserialization",
               rsa_deserialize_private_key(serialized, serialized_length,
                                           &restored), RSA_OK);
    expect_same("generated serialized n", &restored.public_key.n,
                &first.public_key.n);
    expect_same("generated serialized d", &restored.d, &first.d);

    load_hex("generated message", &message, "12345678");
    expect_int("generated public",
               rsa_public_operation(&first.public_key, &message, &ciphertext),
               RSA_OK);
    expect_int("generated private",
               rsa_private_operation(&first, &ciphertext, &recovered),
               RSA_OK);
    expect_same("generated round trip", &recovered, &message);
}

int main(void)
{
    test_known_key_and_operations();
    test_validation_failures();
    test_serialization();
    test_deterministic_generation();

    if (failures != 0) {
        fprintf(stderr, "RSA tests failed: %d\n", failures);
        return 1;
    }
    printf("RSA tests passed\n");
    return 0;
}
