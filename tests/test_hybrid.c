#include <stdio.h>
#include <string.h>

#include "cbc.h"
#include "hybrid.h"
#include "mmo.h"

#define TEST_BUFFER_BYTES 512U

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

static const unsigned char zero_iv[8] = {
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U
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

static void init_test_rng(const char *name, RNG_CTX *rng)
{
    expect_int(name,
               rng_init_deterministic(rng, test_key, test_state,
                                      test_counter), RNG_OK);
}

static void make_story_key(RSA_PRIVATE_KEY *private_key)
{
    RNG_CTX rng;
    RSA_KEYGEN_STATS statistics;

    init_test_rng("key RNG", &rng);
    expect_int("story key generation",
               rsa_generate_key(&rng, RSA_STORY_MODULUS_BITS, 10U,
                                100000UL, 256U, private_key,
                                &statistics), RSA_OK);
}

static unsigned long get_u32(const unsigned char *input)
{
    unsigned long value;

    value = (unsigned long)input[0] << 24U;
    value |= (unsigned long)input[1] << 16U;
    value |= (unsigned long)input[2] << 8U;
    value |= (unsigned long)input[3];
    return value;
}

static void put_u32(unsigned char *output, unsigned long value)
{
    output[0] = (unsigned char)((value >> 24U) & 0xffUL);
    output[1] = (unsigned char)((value >> 16U) & 0xffUL);
    output[2] = (unsigned char)((value >> 8U) & 0xffUL);
    output[3] = (unsigned char)(value & 0xffUL);
}

static int extract_ms(const RSA_PRIVATE_KEY *key,
                      const unsigned char *ciphertext,
                      unsigned long ciphertext_length,
                      unsigned char *ms,
                      unsigned long *ms_length)
{
    BIGINT rc;
    BIGINT mt;
    unsigned int modulus_bytes;
    unsigned long remainder_length;
    int status;

    modulus_bytes = (key->public_key.modulus_bits + 7U) / 8U;
    if (ciphertext_length < 8UL + (unsigned long)modulus_bytes) {
        return 0;
    }
    remainder_length = ciphertext_length - 8UL -
        (unsigned long)modulus_bytes;
    *ms_length = (unsigned long)(modulus_bytes - 1U) +
        remainder_length;
    status = bigint_from_bytes(&rc, ciphertext + 8U, modulus_bytes);
    if (status != BIGINT_OK) {
        return 0;
    }
    status = rsa_private_operation(key, &rc, &mt);
    if (status != RSA_OK) {
        return 0;
    }
    status = bigint_to_bytes_fixed(&mt, ms, modulus_bytes - 1U);
    if (status != BIGINT_OK) {
        return 0;
    }
    if (remainder_length != 0UL) {
        memcpy(ms + modulus_bytes - 1U,
               ciphertext + 8U + modulus_bytes,
               (size_t)remainder_length);
    }
    return 1;
}

static int rebuild_from_ms(const RSA_PUBLIC_KEY *key,
                           const unsigned char *ms,
                           unsigned long ms_length,
                           unsigned char *ciphertext,
                           unsigned long *ciphertext_length)
{
    BIGINT mt;
    BIGINT rc;
    unsigned int modulus_bytes;
    unsigned long rsa_input_length;
    unsigned long remainder_length;
    int status;

    modulus_bytes = (key->modulus_bits + 7U) / 8U;
    rsa_input_length = (unsigned long)(modulus_bytes - 1U);
    if (ms_length < rsa_input_length) {
        return 0;
    }
    remainder_length = ms_length - rsa_input_length;
    status = bigint_from_bytes(&mt, ms, modulus_bytes - 1U);
    if (status != BIGINT_OK) {
        return 0;
    }
    status = rsa_public_operation(key, &mt, &rc);
    if (status != RSA_OK) {
        return 0;
    }
    status = bigint_to_bytes_fixed(&rc, ciphertext + 8U,
                                   modulus_bytes);
    if (status != BIGINT_OK) {
        return 0;
    }
    if (remainder_length != 0UL) {
        memcpy(ciphertext + 8U + modulus_bytes,
               ms + rsa_input_length, (size_t)remainder_length);
    }
    *ciphertext_length = 8UL + (unsigned long)modulus_bytes +
        remainder_length;
    status = mmo_hash(ciphertext + 8U, *ciphertext_length - 8UL,
                      ciphertext);
    return status == MMO_OK;
}

static void refresh_m3(unsigned char *ciphertext,
                       unsigned long ciphertext_length)
{
    expect_int("refresh M3",
               mmo_hash(ciphertext + 8U, ciphertext_length - 8UL,
                        ciphertext), MMO_OK);
}

static void fill_plaintext(unsigned char *plaintext,
                           unsigned long length)
{
    unsigned long index;

    for (index = 0UL; index < length; ++index) {
        plaintext[index] = (unsigned char)(index * 37UL + 11UL);
    }
}

static void round_trip_case(const char *name,
                            const RSA_PRIVATE_KEY *key,
                            unsigned long plaintext_length,
                            int expect_remainder)
{
    RNG_CTX rng;
    unsigned char plaintext[TEST_BUFFER_BYTES];
    unsigned char ciphertext[TEST_BUFFER_BYTES];
    unsigned char restored[TEST_BUFFER_BYTES];
    unsigned long predicted;
    unsigned long ciphertext_length;
    unsigned long restored_length;
    unsigned int modulus_bytes;

    fill_plaintext(plaintext, plaintext_length);
    init_test_rng(name, &rng);
    predicted = 0UL;
    expect_int(name,
               hybrid_ciphertext_size(&key->public_key, plaintext_length,
                                      &predicted), HYBRID_OK);
    expect_true("predicted fits test buffer",
                predicted <= TEST_BUFFER_BYTES);
    ciphertext_length = 0UL;
    expect_int(name,
               hybrid_encrypt(&key->public_key, &rng,
                              plaintext_length == 0UL ? NULL : plaintext,
                              plaintext_length, ciphertext,
                              sizeof(ciphertext), &ciphertext_length),
               HYBRID_OK);
    expect_true("predicted length matches",
                ciphertext_length == predicted);
    modulus_bytes = (key->public_key.modulus_bits + 7U) / 8U;
    if (expect_remainder != 0) {
        expect_true("mb is non-empty",
                    ciphertext_length > 8UL + modulus_bytes);
    } else {
        expect_true("mb is empty",
                    ciphertext_length == 8UL + modulus_bytes);
    }
    memset(restored, 0xa5, sizeof(restored));
    restored_length = 999UL;
    expect_int(name,
               hybrid_decrypt(key, ciphertext, ciphertext_length,
                              plaintext_length == 0UL ? NULL : restored,
                              sizeof(restored), &restored_length),
               HYBRID_OK);
    expect_true("restored length", restored_length == plaintext_length);
    expect_true("restored data",
                plaintext_length == 0UL ||
                memcmp(restored, plaintext, (size_t)plaintext_length) == 0);
}

static void test_round_trips(const RSA_PRIVATE_KEY *key)
{
    round_trip_case("empty", key, 0UL, 0);
    round_trip_case("sub-block", key, 3UL, 0);
    round_trip_case("one block", key, 8UL, 0);
    round_trip_case("multiple blocks", key, 40UL, 1);
    round_trip_case("larger remainder", key, 128UL, 1);
}

static void test_rng_and_capacity(const RSA_PRIVATE_KEY *key)
{
    RNG_CTX first_rng;
    RNG_CTX second_rng;
    unsigned char plaintext[40];
    unsigned char first[TEST_BUFFER_BYTES];
    unsigned char second[TEST_BUFFER_BYTES];
    unsigned char third[TEST_BUFFER_BYTES];
    unsigned char restored[40];
    unsigned long first_length;
    unsigned long second_length;
    unsigned long third_length;
    unsigned long needed;
    unsigned long restored_length;

    fill_plaintext(plaintext, sizeof(plaintext));
    init_test_rng("first encryption RNG", &first_rng);
    init_test_rng("second encryption RNG", &second_rng);
    expect_int("first deterministic encryption",
               hybrid_encrypt(&key->public_key, &first_rng,
                              plaintext, sizeof(plaintext), first,
                              sizeof(first), &first_length), HYBRID_OK);
    expect_int("same deterministic encryption",
               hybrid_encrypt(&key->public_key, &second_rng,
                              plaintext, sizeof(plaintext), second,
                              sizeof(second), &second_length), HYBRID_OK);
    expect_true("deterministic ciphertext",
                first_length == second_length &&
                memcmp(first, second, (size_t)first_length) == 0);
    expect_int("advanced RNG encryption",
               hybrid_encrypt(&key->public_key, &first_rng,
                              plaintext, sizeof(plaintext), third,
                              sizeof(third), &third_length), HYBRID_OK);
    expect_true("fresh session changes ciphertext",
                third_length == first_length &&
                memcmp(first, third, (size_t)first_length) != 0);

    memset(third, 0xa5, sizeof(third));
    needed = 0UL;
    init_test_rng("capacity RNG", &second_rng);
    expect_int("encrypt capacity",
               hybrid_encrypt(&key->public_key, &second_rng,
                              plaintext, sizeof(plaintext), third,
                              first_length - 1UL, &needed),
               HYBRID_ERR_CAPACITY);
    expect_true("encrypt needed length", needed == first_length);
    expect_true("encrypt output preserved", third[0] == 0xa5U);

    memset(restored, 0xa5, sizeof(restored));
    restored_length = 777UL;
    expect_int("decrypt capacity",
               hybrid_decrypt(key, first, first_length, restored,
                              sizeof(restored) - 1UL, &restored_length),
               HYBRID_ERR_CAPACITY);
    expect_true("decrypt needed length",
                restored_length == sizeof(restored));
    expect_true("decrypt output preserved", restored[0] == 0xa5U);
}

static void test_short_ms_padding(const RSA_PRIVATE_KEY *key)
{
    RNG_CTX rng;
    unsigned char plaintext[3] = { 0x61U, 0x62U, 0x63U };
    unsigned char ciphertext[TEST_BUFFER_BYTES];
    unsigned char rebuilt[TEST_BUFFER_BYTES];
    unsigned char ms[TEST_BUFFER_BYTES];
    unsigned char restored[TEST_BUFFER_BYTES];
    unsigned long ciphertext_length;
    unsigned long rebuilt_length;
    unsigned long ms_length;
    unsigned long core_length;
    unsigned long restored_length;
    unsigned int modulus_bytes;

    init_test_rng("padding RNG", &rng);
    expect_int("padding source",
               hybrid_encrypt(&key->public_key, &rng, plaintext,
                              sizeof(plaintext), ciphertext,
                              sizeof(ciphertext), &ciphertext_length),
               HYBRID_OK);
    expect_true("extract padded ms",
                extract_ms(key, ciphertext, ciphertext_length,
                           ms, &ms_length));
    modulus_bytes = (key->public_key.modulus_bits + 7U) / 8U;
    core_length = 20UL + get_u32(ms + 16U);
    expect_true("ms has modulus-minus-one width",
                ms_length == (unsigned long)(modulus_bytes - 1U));
    expect_true("random padding is present", core_length < ms_length);

    ms[core_length] ^= 0x80U;
    expect_true("rebuild changed random padding",
                rebuild_from_ms(&key->public_key, ms, ms_length,
                                rebuilt, &rebuilt_length));
    restored_length = 0UL;
    expect_int("changed padding is discarded",
               hybrid_decrypt(key, rebuilt, rebuilt_length,
                              restored, sizeof(restored),
                              &restored_length), HYBRID_OK);
    expect_true("padding-discard length",
                restored_length == sizeof(plaintext));
    expect_true("padding-discard data",
                memcmp(restored, plaintext, sizeof(plaintext)) == 0);
}

static void test_outer_and_rsa_corruption(const RSA_PRIVATE_KEY *key)
{
    RNG_CTX rng;
    unsigned char plaintext[40];
    unsigned char ciphertext[TEST_BUFFER_BYTES];
    unsigned char changed[TEST_BUFFER_BYTES];
    unsigned char output[TEST_BUFFER_BYTES];
    unsigned long ciphertext_length;
    unsigned long output_length;
    unsigned int modulus_bytes;
    int status;

    fill_plaintext(plaintext, sizeof(plaintext));
    init_test_rng("corruption RNG", &rng);
    expect_int("corruption source",
               hybrid_encrypt(&key->public_key, &rng, plaintext,
                              sizeof(plaintext), ciphertext,
                              sizeof(ciphertext), &ciphertext_length),
               HYBRID_OK);
    memcpy(changed, ciphertext, (size_t)ciphertext_length);
    changed[0] ^= 1U;
    output_length = 333UL;
    expect_int("M3 corruption",
               hybrid_decrypt(key, changed, ciphertext_length,
                              output, sizeof(output), &output_length),
               HYBRID_ERR_M3);
    expect_true("M3 preserves length", output_length == 333UL);

    memcpy(changed, ciphertext, (size_t)ciphertext_length);
    modulus_bytes = (key->public_key.modulus_bits + 7U) / 8U;
    changed[8U + modulus_bytes - 1U] ^= 1U;
    refresh_m3(changed, ciphertext_length);
    status = hybrid_decrypt(key, changed, ciphertext_length,
                            output, sizeof(output), &output_length);
    expect_true("RSA block corruption detected",
                status == HYBRID_ERR_RSA || status == HYBRID_ERR_FORMAT ||
                status == HYBRID_ERR_M2);

    memcpy(changed, ciphertext, (size_t)ciphertext_length);
    changed[ciphertext_length] = 0x5aU;
    refresh_m3(changed, ciphertext_length + 1UL);
    expect_int("authenticated trailing data",
               hybrid_decrypt(key, changed, ciphertext_length + 1UL,
                              output, sizeof(output), &output_length),
               HYBRID_ERR_FORMAT);

    memcpy(changed, ciphertext, (size_t)(ciphertext_length - 1UL));
    refresh_m3(changed, ciphertext_length - 1UL);
    expect_int("authenticated truncation",
               hybrid_decrypt(key, changed, ciphertext_length - 1UL,
                              output, sizeof(output), &output_length),
               HYBRID_ERR_FORMAT);
}

static void test_inner_corruption(const RSA_PRIVATE_KEY *key)
{
    RNG_CTX rng;
    DES_KEY_SCHEDULE schedule;
    unsigned char plaintext[40];
    unsigned char ciphertext[TEST_BUFFER_BYTES];
    unsigned char rebuilt[TEST_BUFFER_BYTES];
    unsigned char ms[TEST_BUFFER_BYTES];
    unsigned char des_plain[TEST_BUFFER_BYTES];
    unsigned char new_dc[TEST_BUFFER_BYTES];
    unsigned char output[TEST_BUFFER_BYTES];
    unsigned long ciphertext_length;
    unsigned long rebuilt_length;
    unsigned long ms_length;
    unsigned long dc_length;
    unsigned long des_plain_length;
    unsigned long new_dc_length;
    unsigned long output_length;
    int status;

    fill_plaintext(plaintext, sizeof(plaintext));
    init_test_rng("inner corruption RNG", &rng);
    expect_int("inner corruption source",
               hybrid_encrypt(&key->public_key, &rng, plaintext,
                              sizeof(plaintext), ciphertext,
                              sizeof(ciphertext), &ciphertext_length),
               HYBRID_OK);
    expect_true("extract M2 ms",
                extract_ms(key, ciphertext, ciphertext_length,
                           ms, &ms_length));
    ms[0] ^= 1U;
    expect_true("rebuild M2 corruption",
                rebuild_from_ms(&key->public_key, ms, ms_length,
                                rebuilt, &rebuilt_length));
    expect_int("M2 corruption",
               hybrid_decrypt(key, rebuilt, rebuilt_length,
                              output, sizeof(output), &output_length),
               HYBRID_ERR_M2);

    expect_true("extract DES ms",
                extract_ms(key, ciphertext, ciphertext_length,
                           ms, &ms_length));
    dc_length = get_u32(ms + 16U);
    expect_true("dc lies in ms", 20UL + dc_length <= ms_length);
    ms[20U + dc_length / 2UL] ^= 1U;
    expect_int("refresh M2 for DES corruption",
               mmo_hash(ms + 8U, 12UL + dc_length, ms), MMO_OK);
    expect_true("rebuild DES corruption",
                rebuild_from_ms(&key->public_key, ms, ms_length,
                                rebuilt, &rebuilt_length));
    status = hybrid_decrypt(key, rebuilt, rebuilt_length,
                            output, sizeof(output), &output_length);
    expect_true("DES corruption reaches inner checks",
                status == HYBRID_ERR_FORMAT || status == HYBRID_ERR_M1);

    expect_true("extract M1 ms",
                extract_ms(key, ciphertext, ciphertext_length,
                           ms, &ms_length));
    dc_length = get_u32(ms + 16U);
    expect_int("M1 schedule", des_key_schedule(ms + 8U, &schedule), DES_OK);
    des_plain_length = 0UL;
    expect_int("decrypt for M1 mutation",
               des_cbc_decrypt(ms + 20U, dc_length,
                               des_plain, sizeof(des_plain),
                               &des_plain_length, &schedule, zero_iv), DES_OK);
    expect_true("M1 structure length", des_plain_length >= 12UL);
    des_plain[0] ^= 1U;
    new_dc_length = 0UL;
    expect_int("reencrypt M1 mutation",
               des_cbc_encrypt(des_plain, des_plain_length,
                               new_dc, sizeof(new_dc), &new_dc_length,
                               &schedule, zero_iv), DES_OK);
    expect_true("same dc length", new_dc_length == dc_length);
    memcpy(ms + 20U, new_dc, (size_t)dc_length);
    expect_int("refresh M2 for M1 corruption",
               mmo_hash(ms + 8U, 12UL + dc_length, ms), MMO_OK);
    expect_true("rebuild M1 corruption",
                rebuild_from_ms(&key->public_key, ms, ms_length,
                                rebuilt, &rebuilt_length));
    expect_int("M1 corruption",
               hybrid_decrypt(key, rebuilt, rebuilt_length,
                              output, sizeof(output), &output_length),
               HYBRID_ERR_M1);

    expect_true("extract length ms",
                extract_ms(key, ciphertext, ciphertext_length,
                           ms, &ms_length));
    put_u32(ms + 16U, 15UL);
    expect_true("rebuild invalid dc length",
                rebuild_from_ms(&key->public_key, ms, ms_length,
                                rebuilt, &rebuilt_length));
    expect_int("invalid dc length",
               hybrid_decrypt(key, rebuilt, rebuilt_length,
                              output, sizeof(output), &output_length),
               HYBRID_ERR_FORMAT);
}

static void test_key_and_range_errors(const RSA_PRIVATE_KEY *key)
{
    RSA_PUBLIC_KEY short_key;
    BIGINT p;
    BIGINT q;
    RSA_PRIVATE_KEY small_private;
    unsigned long length;

    expect_int("plaintext too long",
               hybrid_ciphertext_size(&key->public_key,
                                      HYBRID_MAX_PLAINTEXT + 1UL,
                                      &length), HYBRID_ERR_RANGE);
    expect_int("small p", bigint_from_ulong(&p, 61UL), BIGINT_OK);
    expect_int("small q", bigint_from_ulong(&q, 53UL), BIGINT_OK);
    expect_int("small RSA key",
               rsa_private_key_from_primes(&p, &q, &small_private), RSA_OK);
    expect_int("extract small public",
               rsa_public_from_private(&small_private, &short_key), RSA_OK);
    expect_int("short modulus rejected",
               hybrid_ciphertext_size(&short_key, 0UL, &length),
               HYBRID_ERR_KEY);
}

int main(void)
{
    RSA_PRIVATE_KEY key;

    make_story_key(&key);
    test_round_trips(&key);
    test_rng_and_capacity(&key);
    test_short_ms_padding(&key);
    test_outer_and_rsa_corruption(&key);
    test_inner_corruption(&key);
    test_key_and_range_errors(&key);

    if (failures != 0) {
        fprintf(stderr, "hybrid tests failed: %d\n", failures);
        return 1;
    }
    printf("hybrid tests passed\n");
    return 0;
}
