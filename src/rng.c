#include <stddef.h>
#include <string.h>
#include <time.h>

#include "mmo.h"
#include "rng.h"

#define RNG_WORD_MASK 0xffffffffUL

static const unsigned char rng_weak_keys[16][RNG_DES_KEY_BYTES] = {
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

static unsigned char rng_set_byte_odd_parity(unsigned char value)
{
    unsigned char data;
    unsigned char work;
    unsigned int ones;

    data = (unsigned char)(value & 0xfeU);
    work = data;
    ones = 0U;
    while (work != 0U) {
        ones += (unsigned int)(work & 1U);
        work = (unsigned char)(work >> 1U);
    }
    if ((ones & 1U) == 0U) {
        data = (unsigned char)(data | 1U);
    }
    return data;
}

int rng_des_key_set_odd_parity(
    const unsigned char input[RNG_DES_KEY_BYTES],
    unsigned char output[RNG_DES_KEY_BYTES])
{
    unsigned int index;

    if (input == NULL || output == NULL) {
        return RNG_ERR_NULL;
    }
    for (index = 0U; index < RNG_DES_KEY_BYTES; ++index) {
        output[index] = rng_set_byte_odd_parity(input[index]);
    }
    return RNG_OK;
}

int rng_des_key_is_weak(const unsigned char key[RNG_DES_KEY_BYTES],
                        int *is_weak)
{
    unsigned char normalized[RNG_DES_KEY_BYTES];
    unsigned int index;
    int result;

    if (key == NULL || is_weak == NULL) {
        return RNG_ERR_NULL;
    }
    result = rng_des_key_set_odd_parity(key, normalized);
    if (result != RNG_OK) {
        return result;
    }
    *is_weak = 0;
    for (index = 0U; index < 16U; ++index) {
        if (memcmp(normalized, rng_weak_keys[index],
                   RNG_DES_KEY_BYTES) == 0) {
            *is_weak = 1;
            break;
        }
    }
    return RNG_OK;
}

static int rng_activate(RNG_CTX *context,
                        const unsigned char key[RNG_DES_KEY_BYTES],
                        const unsigned char state[RNG_BLOCK_BYTES],
                        const unsigned char counter[RNG_BLOCK_BYTES])
{
    int result;

    memcpy(context->key, key, RNG_DES_KEY_BYTES);
    memcpy(context->state_vector, state, RNG_BLOCK_BYTES);
    memcpy(context->counter, counter, RNG_BLOCK_BYTES);
    memset(context->output_buffer, 0, RNG_BLOCK_BYTES);
    context->output_index = RNG_BLOCK_BYTES;
    result = des_key_schedule(context->key, &context->schedule);
    if (result != DES_OK) {
        context->status = RNG_STATE_ERROR;
        return RNG_ERR_DES;
    }
    context->status = RNG_STATE_ACTIVE;
    return RNG_OK;
}

int rng_init_deterministic(RNG_CTX *context,
                           const unsigned char key[RNG_DES_KEY_BYTES],
                           const unsigned char state[RNG_BLOCK_BYTES],
                           const unsigned char counter[RNG_BLOCK_BYTES])
{
    unsigned char normalized[RNG_DES_KEY_BYTES];
    int weak;
    int result;

    if (context == NULL || key == NULL || state == NULL || counter == NULL) {
        return RNG_ERR_NULL;
    }
    context->status = RNG_STATE_UNINITIALIZED;
    result = rng_des_key_set_odd_parity(key, normalized);
    if (result != RNG_OK) {
        return result;
    }
    result = rng_des_key_is_weak(normalized, &weak);
    if (result != RNG_OK) {
        return result;
    }
    if (weak != 0) {
        return RNG_ERR_WEAK_KEY;
    }
    return rng_activate(context, normalized, state, counter);
}

static int rng_mmo_derive(const unsigned char domain[8],
                          const unsigned char timing[RNG_BLOCK_BYTES],
                          const unsigned char *entropy,
                          unsigned long entropy_length,
                          const unsigned char *extra,
                          unsigned long extra_length,
                          unsigned char output[MMO_DIGEST_BYTES])
{
    MMO_CTX mmo;
    int result;

    result = mmo_init(&mmo);
    if (result != MMO_OK) {
        return RNG_ERR_DES;
    }
    result = mmo_update(&mmo, domain, 8UL);
    if (result == MMO_OK) {
        result = mmo_update(&mmo, timing, RNG_BLOCK_BYTES);
    }
    if (result == MMO_OK) {
        result = mmo_update(&mmo, entropy, entropy_length);
    }
    if (result == MMO_OK && extra_length != 0UL) {
        result = mmo_update(&mmo, extra, extra_length);
    }
    if (result == MMO_OK) {
        result = mmo_final(&mmo, output);
    }
    if (result == MMO_ERR_LENGTH) {
        return RNG_ERR_LENGTH;
    }
    if (result != MMO_OK) {
        return RNG_ERR_DES;
    }
    return RNG_OK;
}

static int rng_avoid_weak_derived_key(unsigned char key[RNG_DES_KEY_BYTES])
{
    unsigned int attempt;
    int weak;
    int result;

    result = rng_des_key_set_odd_parity(key, key);
    if (result != RNG_OK) {
        return result;
    }
    for (attempt = 0U; attempt <= RNG_DES_KEY_BYTES; ++attempt) {
        result = rng_des_key_is_weak(key, &weak);
        if (result != RNG_OK) {
            return result;
        }
        if (weak == 0) {
            return RNG_OK;
        }
        if (attempt < RNG_DES_KEY_BYTES) {
            key[RNG_DES_KEY_BYTES - 1U - attempt] =
                (unsigned char)(key[RNG_DES_KEY_BYTES - 1U - attempt] ^
                                0x02U);
            key[RNG_DES_KEY_BYTES - 1U - attempt] =
                rng_set_byte_odd_parity(
                    key[RNG_DES_KEY_BYTES - 1U - attempt]);
        }
    }
    return RNG_ERR_WEAK_KEY;
}

int rng_seed(RNG_CTX *context,
             const unsigned char *entropy,
             unsigned long entropy_length,
             const unsigned char timing[RNG_BLOCK_BYTES])
{
    static const unsigned char key_domain[8] = {
        'R', 'N', 'G', 'K', 'E', 'Y', '8', '5'
    };
    static const unsigned char state_domain[8] = {
        'R', 'N', 'G', 'S', 'T', 'A', '8', '5'
    };
    static const unsigned char counter_domain[8] = {
        'R', 'N', 'G', 'C', 'T', 'R', '8', '5'
    };
    unsigned char key[RNG_DES_KEY_BYTES];
    unsigned char state[RNG_BLOCK_BYTES];
    unsigned char counter[RNG_BLOCK_BYTES];
    int result;

    if (context == NULL || entropy == NULL || timing == NULL) {
        return RNG_ERR_NULL;
    }
    context->status = RNG_STATE_UNINITIALIZED;
    if (entropy_length < RNG_MIN_ENTROPY_BYTES) {
        return RNG_ERR_ENTROPY;
    }
    if ((unsigned long)(size_t)entropy_length != entropy_length) {
        return RNG_ERR_LENGTH;
    }

    result = rng_mmo_derive(key_domain, timing, entropy, entropy_length,
                            NULL, 0UL, key);
    if (result != RNG_OK) {
        return result;
    }
    result = rng_avoid_weak_derived_key(key);
    if (result != RNG_OK) {
        return result;
    }
    result = rng_mmo_derive(state_domain, timing, entropy, entropy_length,
                            key, RNG_DES_KEY_BYTES, state);
    if (result != RNG_OK) {
        return result;
    }
    result = rng_mmo_derive(counter_domain, timing, entropy,
                            entropy_length, state, RNG_BLOCK_BYTES,
                            counter);
    if (result != RNG_OK) {
        return result;
    }
    return rng_activate(context, key, state, counter);
}

static void rng_store_word(unsigned char output[4], unsigned long value)
{
    output[0] = (unsigned char)((value >> 24U) & 0xffUL);
    output[1] = (unsigned char)((value >> 16U) & 0xffUL);
    output[2] = (unsigned char)((value >> 8U) & 0xffUL);
    output[3] = (unsigned char)(value & 0xffUL);
}

int rng_init(RNG_CTX *context,
             const unsigned char *entropy,
             unsigned long entropy_length)
{
    unsigned char timing[RNG_BLOCK_BYTES];
    time_t wall_time;
    clock_t processor_time;
    unsigned long wall_word;
    unsigned long processor_word;

    if (context == NULL || entropy == NULL) {
        return RNG_ERR_NULL;
    }
    wall_time = time(NULL);
    processor_time = clock();
    wall_word = ((unsigned long)wall_time) & RNG_WORD_MASK;
    processor_word = ((unsigned long)processor_time) & RNG_WORD_MASK;
    rng_store_word(timing, wall_word);
    rng_store_word(timing + 4, processor_word);
    return rng_seed(context, entropy, entropy_length, timing);
}

static int rng_counter_is_maximum(
    const unsigned char counter[RNG_BLOCK_BYTES])
{
    unsigned int index;

    for (index = 0U; index < RNG_BLOCK_BYTES; ++index) {
        if (counter[index] != 0xffU) {
            return 0;
        }
    }
    return 1;
}

static void rng_increment_counter(unsigned char counter[RNG_BLOCK_BYTES])
{
    unsigned int index;

    index = RNG_BLOCK_BYTES;
    while (index != 0U) {
        --index;
        counter[index] = (unsigned char)(counter[index] + 1U);
        if (counter[index] != 0U) {
            break;
        }
    }
}

static int rng_generate_block(RNG_CTX *context)
{
    unsigned char intermediate[RNG_BLOCK_BYTES];
    unsigned char mixed[RNG_BLOCK_BYTES];
    unsigned char random_block[RNG_BLOCK_BYTES];
    unsigned int index;
    int result;

    if (rng_counter_is_maximum(context->counter)) {
        context->status = RNG_STATE_ERROR;
        return RNG_ERR_LIMIT;
    }
    result = des_encrypt_block(context->counter, intermediate,
                               &context->schedule);
    if (result != DES_OK) {
        context->status = RNG_STATE_ERROR;
        return RNG_ERR_DES;
    }
    for (index = 0U; index < RNG_BLOCK_BYTES; ++index) {
        mixed[index] = (unsigned char)(intermediate[index] ^
                                      context->state_vector[index]);
    }
    result = des_encrypt_block(mixed, random_block, &context->schedule);
    if (result != DES_OK) {
        context->status = RNG_STATE_ERROR;
        return RNG_ERR_DES;
    }
    for (index = 0U; index < RNG_BLOCK_BYTES; ++index) {
        mixed[index] = (unsigned char)(random_block[index] ^
                                      intermediate[index]);
    }
    result = des_encrypt_block(mixed, context->state_vector,
                               &context->schedule);
    if (result != DES_OK) {
        context->status = RNG_STATE_ERROR;
        return RNG_ERR_DES;
    }
    memcpy(context->output_buffer, random_block, RNG_BLOCK_BYTES);
    context->output_index = 0U;
    rng_increment_counter(context->counter);
    return RNG_OK;
}

int rng_generate(RNG_CTX *context,
                 unsigned char *output,
                 unsigned long length)
{
    unsigned long index;
    int result;

    if (context == NULL) {
        return RNG_ERR_NULL;
    }
    if (context->status != RNG_STATE_ACTIVE ||
        context->output_index > RNG_BLOCK_BYTES) {
        return RNG_ERR_STATE;
    }
    if (length != 0UL && output == NULL) {
        return RNG_ERR_NULL;
    }
    if ((unsigned long)(size_t)length != length) {
        return RNG_ERR_LENGTH;
    }

    for (index = 0UL; index < length; ++index) {
        if (context->output_index == RNG_BLOCK_BYTES) {
            result = rng_generate_block(context);
            if (result != RNG_OK) {
                return result;
            }
        }
        output[(size_t)index] =
            context->output_buffer[context->output_index];
        ++context->output_index;
    }
    return RNG_OK;
}

int rng_generate_des_key(RNG_CTX *context,
                         unsigned char key[RNG_DES_KEY_BYTES])
{
    unsigned char material[RNG_DES_KEY_BYTES];
    unsigned int attempt;
    int weak;
    int result;

    if (context == NULL || key == NULL) {
        return RNG_ERR_NULL;
    }
    for (attempt = 0U; attempt < 16U; ++attempt) {
        result = rng_generate(context, material, RNG_DES_KEY_BYTES);
        if (result != RNG_OK) {
            return result;
        }
        result = rng_des_key_set_odd_parity(material, key);
        if (result != RNG_OK) {
            return result;
        }
        result = rng_des_key_is_weak(key, &weak);
        if (result != RNG_OK) {
            return result;
        }
        if (weak == 0) {
            return RNG_OK;
        }
    }
    return RNG_ERR_WEAK_KEY;
}
