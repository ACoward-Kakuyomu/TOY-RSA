#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "cbc.h"
#include "hybrid.h"
#include "mmo.h"

/*
 * Week9 applies RSA exactly once to the first modulus-width-minus-one
 * bytes.  The remaining bytes are already protected by the fresh DES
 * session key and are carried after the fixed-width RSA ciphertext.
 */
#define HYBRID_DES_PLAIN_OVERHEAD 12UL
#define HYBRID_SD_OVERHEAD 12UL
#define HYBRID_MS_OVERHEAD 20UL
#define HYBRID_OUTER_OVERHEAD 8UL

static const unsigned char hybrid_zero_iv[DES_BLOCK_BYTES] = {
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U
};

static int hybrid_length_fits_size_t(unsigned long length)
{
    size_t converted;

    converted = (size_t)length;
    return (unsigned long)converted == length;
}

static void hybrid_put_u32(unsigned char output[HYBRID_LENGTH_BYTES],
                           unsigned long value)
{
    output[0] = (unsigned char)((value >> 24U) & 0xffUL);
    output[1] = (unsigned char)((value >> 16U) & 0xffUL);
    output[2] = (unsigned char)((value >> 8U) & 0xffUL);
    output[3] = (unsigned char)(value & 0xffUL);
}

static unsigned long hybrid_get_u32(
    const unsigned char input[HYBRID_LENGTH_BYTES])
{
    unsigned long value;

    value = (unsigned long)input[0] << 24U;
    value |= (unsigned long)input[1] << 16U;
    value |= (unsigned long)input[2] << 8U;
    value |= (unsigned long)input[3];
    return value;
}

static int hybrid_digest_equal(const unsigned char *left,
                               const unsigned char *right)
{
    unsigned int difference;
    unsigned int index;

    difference = 0U;
    for (index = 0U; index < HYBRID_DIGEST_BYTES; ++index) {
        difference |= (unsigned int)(left[index] ^ right[index]);
    }
    return difference == 0U;
}

static int hybrid_public_modulus_bytes(const RSA_PUBLIC_KEY *public_key,
                                       unsigned int *modulus_bytes)
{
    int valid;
    int status;

    if (public_key == NULL || modulus_bytes == NULL) {
        return HYBRID_ERR_NULL;
    }
    status = rsa_validate_public_key(public_key, &valid);
    if (status != RSA_OK || valid == 0) {
        return HYBRID_ERR_KEY;
    }
    *modulus_bytes = (public_key->modulus_bits + 7U) / 8U;
    if (*modulus_bytes < HYBRID_MIN_MODULUS_BYTES ||
        *modulus_bytes > BIGINT_MAX_BYTES) {
        return HYBRID_ERR_KEY;
    }
    return HYBRID_OK;
}

static int hybrid_size_parts(const RSA_PUBLIC_KEY *public_key,
                             unsigned long plaintext_length,
                             unsigned int *modulus_bytes,
                             unsigned long *des_ciphertext_length,
                             unsigned long *ms_length,
                             unsigned long *ciphertext_length)
{
    unsigned long des_plain_length;
    unsigned long core_length;
    unsigned long rsa_input_length;
    unsigned long remainder_length;
    int status;

    if (modulus_bytes == NULL || des_ciphertext_length == NULL ||
        ms_length == NULL || ciphertext_length == NULL) {
        return HYBRID_ERR_NULL;
    }
    status = hybrid_public_modulus_bytes(public_key, modulus_bytes);
    if (status != HYBRID_OK) {
        return status;
    }
    if (plaintext_length > HYBRID_MAX_PLAINTEXT) {
        return HYBRID_ERR_RANGE;
    }
    des_plain_length = HYBRID_DES_PLAIN_OVERHEAD + plaintext_length;
    status = des_cbc_framed_size(des_plain_length,
                                 des_ciphertext_length);
    if (status != DES_OK) {
        return HYBRID_ERR_RANGE;
    }
    if (*des_ciphertext_length > 0xffffffffUL - HYBRID_MS_OVERHEAD) {
        return HYBRID_ERR_RANGE;
    }
    core_length = HYBRID_MS_OVERHEAD + *des_ciphertext_length;
    rsa_input_length = (unsigned long)(*modulus_bytes - 1U);
    if (core_length < rsa_input_length) {
        *ms_length = rsa_input_length;
    } else {
        *ms_length = core_length;
    }
    remainder_length = *ms_length - rsa_input_length;
    if (remainder_length >
        0xffffffffUL - HYBRID_OUTER_OVERHEAD -
        (unsigned long)*modulus_bytes) {
        return HYBRID_ERR_RANGE;
    }
    *ciphertext_length = HYBRID_OUTER_OVERHEAD +
        (unsigned long)*modulus_bytes + remainder_length;
    return HYBRID_OK;
}

int hybrid_ciphertext_size(const RSA_PUBLIC_KEY *public_key,
                           unsigned long plaintext_length,
                           unsigned long *ciphertext_length)
{
    unsigned int modulus_bytes;
    unsigned long des_ciphertext_length;
    unsigned long ms_length;
    unsigned long result_length;
    int status;

    if (ciphertext_length == NULL) {
        return HYBRID_ERR_NULL;
    }
    status = hybrid_size_parts(public_key, plaintext_length,
                               &modulus_bytes, &des_ciphertext_length,
                               &ms_length, &result_length);
    if (status != HYBRID_OK) {
        return status;
    }
    *ciphertext_length = result_length;
    return HYBRID_OK;
}

static void hybrid_clear_free(unsigned char *buffer, unsigned long length)
{
    if (buffer != NULL) {
        memset(buffer, 0, (size_t)length);
        free(buffer);
    }
}

int hybrid_encrypt(const RSA_PUBLIC_KEY *public_key,
                   RNG_CTX *rng,
                   const unsigned char *plaintext,
                   unsigned long plaintext_length,
                   unsigned char *ciphertext,
                   unsigned long ciphertext_capacity,
                   unsigned long *ciphertext_length)
{
    DES_KEY_SCHEDULE schedule;
    BIGINT mt_integer;
    BIGINT rc_integer;
    unsigned char session_key[HYBRID_SESSION_KEY_BYTES];
    unsigned char *des_plain;
    unsigned char *des_ciphertext;
    unsigned char *ms;
    unsigned char *result_buffer;
    unsigned int modulus_bytes;
    unsigned long des_plain_length;
    unsigned long des_ciphertext_length;
    unsigned long actual_des_length;
    unsigned long ms_length;
    unsigned long core_length;
    unsigned long rsa_input_length;
    unsigned long remainder_length;
    unsigned long required;
    int status;
    int result;

    if (public_key == NULL || rng == NULL || ciphertext_length == NULL) {
        return HYBRID_ERR_NULL;
    }
    if (plaintext_length != 0UL && plaintext == NULL) {
        return HYBRID_ERR_NULL;
    }
    status = hybrid_size_parts(public_key, plaintext_length,
                               &modulus_bytes, &des_ciphertext_length,
                               &ms_length, &required);
    if (status != HYBRID_OK) {
        return status;
    }
    if (ciphertext_capacity < required) {
        *ciphertext_length = required;
        return HYBRID_ERR_CAPACITY;
    }
    if (ciphertext == NULL) {
        return HYBRID_ERR_NULL;
    }
    des_plain_length = HYBRID_DES_PLAIN_OVERHEAD + plaintext_length;
    core_length = HYBRID_MS_OVERHEAD + des_ciphertext_length;
    if (!hybrid_length_fits_size_t(des_plain_length) ||
        !hybrid_length_fits_size_t(des_ciphertext_length) ||
        !hybrid_length_fits_size_t(ms_length) ||
        !hybrid_length_fits_size_t(required)) {
        return HYBRID_ERR_RANGE;
    }

    des_plain = NULL;
    des_ciphertext = NULL;
    ms = NULL;
    result_buffer = NULL;
    memset(session_key, 0, sizeof(session_key));
    result = HYBRID_ERR_ARITHMETIC;

    des_plain = (unsigned char *)malloc((size_t)des_plain_length);
    des_ciphertext = (unsigned char *)malloc(
        (size_t)des_ciphertext_length);
    ms = (unsigned char *)malloc((size_t)ms_length);
    result_buffer = (unsigned char *)malloc((size_t)required);
    if (des_plain == NULL || des_ciphertext == NULL || ms == NULL ||
        result_buffer == NULL) {
        result = HYBRID_ERR_MEMORY;
        goto cleanup;
    }

    hybrid_put_u32(des_plain + HYBRID_DIGEST_BYTES, plaintext_length);
    if (plaintext_length != 0UL) {
        memcpy(des_plain + HYBRID_DES_PLAIN_OVERHEAD, plaintext,
               (size_t)plaintext_length);
    }
    status = mmo_hash(des_plain + HYBRID_DIGEST_BYTES,
                      HYBRID_LENGTH_BYTES + plaintext_length,
                      des_plain);
    if (status != MMO_OK) {
        goto cleanup;
    }
    status = rng_generate_des_key(rng, session_key);
    if (status != RNG_OK) {
        result = HYBRID_ERR_RNG;
        goto cleanup;
    }
    status = des_key_schedule(session_key, &schedule);
    if (status != DES_OK) {
        goto cleanup;
    }
    actual_des_length = 0UL;
    status = des_cbc_encrypt(des_plain, des_plain_length,
                             des_ciphertext, des_ciphertext_length,
                             &actual_des_length, &schedule,
                             hybrid_zero_iv);
    if (status != DES_OK || actual_des_length != des_ciphertext_length) {
        goto cleanup;
    }

    memcpy(ms + HYBRID_DIGEST_BYTES, session_key,
           HYBRID_SESSION_KEY_BYTES);
    hybrid_put_u32(ms + HYBRID_DIGEST_BYTES +
                   HYBRID_SESSION_KEY_BYTES,
                   des_ciphertext_length);
    memcpy(ms + HYBRID_MS_OVERHEAD, des_ciphertext,
           (size_t)des_ciphertext_length);
    status = mmo_hash(ms + HYBRID_DIGEST_BYTES,
                      HYBRID_SD_OVERHEAD + des_ciphertext_length, ms);
    if (status != MMO_OK) {
        goto cleanup;
    }
    if (ms_length > core_length) {
        status = rng_generate(rng, ms + core_length,
                              ms_length - core_length);
        if (status != RNG_OK) {
            result = HYBRID_ERR_RNG;
            goto cleanup;
        }
    }

    rsa_input_length = (unsigned long)(modulus_bytes - 1U);
    status = bigint_from_bytes(&mt_integer, ms,
                               (unsigned int)rsa_input_length);
    if (status != BIGINT_OK) {
        goto cleanup;
    }
    status = rsa_public_operation(public_key, &mt_integer, &rc_integer);
    if (status != RSA_OK) {
        result = HYBRID_ERR_RSA;
        goto cleanup;
    }
    status = bigint_to_bytes_fixed(&rc_integer,
                                   result_buffer + HYBRID_DIGEST_BYTES,
                                   modulus_bytes);
    if (status != BIGINT_OK) {
        goto cleanup;
    }
    remainder_length = ms_length - rsa_input_length;
    if (remainder_length != 0UL) {
        memcpy(result_buffer + HYBRID_DIGEST_BYTES + modulus_bytes,
               ms + rsa_input_length, (size_t)remainder_length);
    }
    status = mmo_hash(result_buffer + HYBRID_DIGEST_BYTES,
                      (unsigned long)modulus_bytes + remainder_length,
                      result_buffer);
    if (status != MMO_OK) {
        goto cleanup;
    }
    memcpy(ciphertext, result_buffer, (size_t)required);
    *ciphertext_length = required;
    result = HYBRID_OK;

cleanup:
    memset(&schedule, 0, sizeof(schedule));
    memset(&mt_integer, 0, sizeof(mt_integer));
    memset(&rc_integer, 0, sizeof(rc_integer));
    memset(session_key, 0, sizeof(session_key));
    hybrid_clear_free(des_plain, des_plain_length);
    hybrid_clear_free(des_ciphertext, des_ciphertext_length);
    hybrid_clear_free(ms, ms_length);
    hybrid_clear_free(result_buffer, required);
    return result;
}

int hybrid_decrypt(const RSA_PRIVATE_KEY *private_key,
                   const unsigned char *ciphertext,
                   unsigned long ciphertext_length,
                   unsigned char *plaintext,
                   unsigned long plaintext_capacity,
                   unsigned long *plaintext_length)
{
    RSA_PUBLIC_KEY public_key;
    DES_KEY_SCHEDULE schedule;
    BIGINT rc_integer;
    BIGINT mt_integer;
    unsigned char digest[HYBRID_DIGEST_BYTES];
    unsigned char *ms;
    unsigned char *des_plain;
    unsigned int modulus_bytes;
    unsigned long rsa_input_length;
    unsigned long remainder_length;
    unsigned long ms_length;
    unsigned long des_ciphertext_length;
    unsigned long core_length;
    unsigned long des_plain_capacity;
    unsigned long des_plain_length;
    unsigned long decoded_plaintext_length;
    int status;
    int result;

    if (private_key == NULL || ciphertext == NULL ||
        plaintext_length == NULL) {
        return HYBRID_ERR_NULL;
    }
    status = rsa_public_from_private(private_key, &public_key);
    if (status != RSA_OK) {
        return HYBRID_ERR_KEY;
    }
    status = hybrid_public_modulus_bytes(&public_key, &modulus_bytes);
    if (status != HYBRID_OK) {
        return status;
    }
    if (ciphertext_length < HYBRID_OUTER_OVERHEAD +
        (unsigned long)modulus_bytes) {
        return HYBRID_ERR_FORMAT;
    }
    if (!hybrid_length_fits_size_t(ciphertext_length)) {
        return HYBRID_ERR_RANGE;
    }
    status = mmo_hash(ciphertext + HYBRID_DIGEST_BYTES,
                      ciphertext_length - HYBRID_DIGEST_BYTES, digest);
    if (status != MMO_OK) {
        return HYBRID_ERR_ARITHMETIC;
    }
    if (!hybrid_digest_equal(ciphertext, digest)) {
        return HYBRID_ERR_M3;
    }

    rsa_input_length = (unsigned long)(modulus_bytes - 1U);
    remainder_length = ciphertext_length - HYBRID_OUTER_OVERHEAD -
        (unsigned long)modulus_bytes;
    if (remainder_length > 0xffffffffUL - rsa_input_length) {
        return HYBRID_ERR_RANGE;
    }
    ms_length = rsa_input_length + remainder_length;
    if (!hybrid_length_fits_size_t(ms_length)) {
        return HYBRID_ERR_RANGE;
    }
    ms = (unsigned char *)malloc((size_t)ms_length);
    des_plain = NULL;
    des_plain_capacity = 0UL;
    if (ms == NULL) {
        return HYBRID_ERR_MEMORY;
    }
    memset(&schedule, 0, sizeof(schedule));
    result = HYBRID_ERR_ARITHMETIC;

    status = bigint_from_bytes(&rc_integer,
                               ciphertext + HYBRID_DIGEST_BYTES,
                               modulus_bytes);
    if (status != BIGINT_OK) {
        result = HYBRID_ERR_RSA;
        goto cleanup;
    }
    status = rsa_private_operation(private_key, &rc_integer, &mt_integer);
    if (status != RSA_OK) {
        result = HYBRID_ERR_RSA;
        goto cleanup;
    }
    status = bigint_to_bytes_fixed(&mt_integer, ms,
                                   (unsigned int)rsa_input_length);
    if (status != BIGINT_OK) {
        result = HYBRID_ERR_RSA;
        goto cleanup;
    }
    if (remainder_length != 0UL) {
        memcpy(ms + rsa_input_length,
               ciphertext + HYBRID_DIGEST_BYTES + modulus_bytes,
               (size_t)remainder_length);
    }

    des_ciphertext_length = hybrid_get_u32(
        ms + HYBRID_DIGEST_BYTES + HYBRID_SESSION_KEY_BYTES);
    if (des_ciphertext_length < 16UL ||
        (des_ciphertext_length % DES_BLOCK_BYTES) != 0UL ||
        des_ciphertext_length > DES_CBC_MAX_CIPHERTEXT ||
        des_ciphertext_length > 0xffffffffUL - HYBRID_MS_OVERHEAD) {
        result = HYBRID_ERR_FORMAT;
        goto cleanup;
    }
    core_length = HYBRID_MS_OVERHEAD + des_ciphertext_length;
    if ((core_length <= rsa_input_length &&
         ms_length != rsa_input_length) ||
        (core_length > rsa_input_length && ms_length != core_length)) {
        result = HYBRID_ERR_FORMAT;
        goto cleanup;
    }
    status = mmo_hash(ms + HYBRID_DIGEST_BYTES,
                      HYBRID_SD_OVERHEAD + des_ciphertext_length,
                      digest);
    if (status != MMO_OK) {
        goto cleanup;
    }
    if (!hybrid_digest_equal(ms, digest)) {
        result = HYBRID_ERR_M2;
        goto cleanup;
    }

    status = des_key_schedule(ms + HYBRID_DIGEST_BYTES, &schedule);
    if (status != DES_OK) {
        goto cleanup;
    }
    des_plain_capacity = des_ciphertext_length - DES_CBC_LENGTH_BYTES;
    if (!hybrid_length_fits_size_t(des_plain_capacity)) {
        result = HYBRID_ERR_RANGE;
        goto cleanup;
    }
    des_plain = (unsigned char *)malloc((size_t)des_plain_capacity);
    if (des_plain == NULL) {
        result = HYBRID_ERR_MEMORY;
        goto cleanup;
    }
    des_plain_length = 0UL;
    status = des_cbc_decrypt(ms + HYBRID_MS_OVERHEAD,
                             des_ciphertext_length,
                             des_plain, des_plain_capacity,
                             &des_plain_length, &schedule,
                             hybrid_zero_iv);
    if (status == DES_ERR_FORMAT || status == DES_ERR_LENGTH) {
        result = HYBRID_ERR_FORMAT;
        goto cleanup;
    }
    if (status != DES_OK) {
        goto cleanup;
    }
    if (des_plain_length < HYBRID_DES_PLAIN_OVERHEAD) {
        result = HYBRID_ERR_FORMAT;
        goto cleanup;
    }
    decoded_plaintext_length = hybrid_get_u32(
        des_plain + HYBRID_DIGEST_BYTES);
    if (decoded_plaintext_length !=
        des_plain_length - HYBRID_DES_PLAIN_OVERHEAD ||
        decoded_plaintext_length > HYBRID_MAX_PLAINTEXT) {
        result = HYBRID_ERR_FORMAT;
        goto cleanup;
    }
    status = mmo_hash(des_plain + HYBRID_DIGEST_BYTES,
                      HYBRID_LENGTH_BYTES + decoded_plaintext_length,
                      digest);
    if (status != MMO_OK) {
        goto cleanup;
    }
    if (!hybrid_digest_equal(des_plain, digest)) {
        result = HYBRID_ERR_M1;
        goto cleanup;
    }
    if (plaintext_capacity < decoded_plaintext_length) {
        *plaintext_length = decoded_plaintext_length;
        result = HYBRID_ERR_CAPACITY;
        goto cleanup;
    }
    if (decoded_plaintext_length != 0UL && plaintext == NULL) {
        result = HYBRID_ERR_NULL;
        goto cleanup;
    }
    if (decoded_plaintext_length != 0UL) {
        memcpy(plaintext,
               des_plain + HYBRID_DES_PLAIN_OVERHEAD,
               (size_t)decoded_plaintext_length);
    }
    *plaintext_length = decoded_plaintext_length;
    result = HYBRID_OK;

cleanup:
    memset(&schedule, 0, sizeof(schedule));
    memset(&rc_integer, 0, sizeof(rc_integer));
    memset(&mt_integer, 0, sizeof(mt_integer));
    memset(digest, 0, sizeof(digest));
    hybrid_clear_free(ms, ms_length);
    hybrid_clear_free(des_plain,
                      des_plain == NULL ? 0UL : des_plain_capacity);
    return result;
}
