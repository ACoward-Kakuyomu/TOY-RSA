#include <stddef.h>
#include <string.h>

#include "des.h"
#include "mmo.h"

#define MMO_WORD_MASK 0xffffffffUL

static int mmo_compress(MMO_CTX *context,
                        const unsigned char block[MMO_BLOCK_BYTES])
{
    unsigned char encrypted[MMO_BLOCK_BYTES];
    DES_KEY_SCHEDULE schedule;
    unsigned int index;
    int result;

    result = des_key_schedule(context->chaining, &schedule);
    if (result != DES_OK) {
        return MMO_ERR_DES;
    }
    result = des_encrypt_block(block, encrypted, &schedule);
    if (result != DES_OK) {
        return MMO_ERR_DES;
    }
    for (index = 0U; index < MMO_DIGEST_BYTES; ++index) {
        context->chaining[index] =
            (unsigned char)(encrypted[index] ^ block[index]);
    }
    return MMO_OK;
}

static int mmo_increment_length(MMO_CTX *context)
{
    if (context->length_low == MMO_WORD_MASK) {
        if (context->length_high == MMO_WORD_MASK) {
            return MMO_ERR_LENGTH;
        }
        context->length_low = 0UL;
        context->length_high =
            (context->length_high + 1UL) & MMO_WORD_MASK;
    } else {
        context->length_low =
            (context->length_low + 1UL) & MMO_WORD_MASK;
    }
    return MMO_OK;
}

static void mmo_store_word(unsigned char output[4], unsigned long value)
{
    output[0] = (unsigned char)((value >> 24U) & 0xffUL);
    output[1] = (unsigned char)((value >> 16U) & 0xffUL);
    output[2] = (unsigned char)((value >> 8U) & 0xffUL);
    output[3] = (unsigned char)(value & 0xffUL);
}

int mmo_init(MMO_CTX *context)
{
    if (context == NULL) {
        return MMO_ERR_NULL;
    }
    memset(context->chaining, 0, sizeof(context->chaining));
    memset(context->buffer, 0, sizeof(context->buffer));
    context->buffer_used = 0U;
    context->length_high = 0UL;
    context->length_low = 0UL;
    context->state = MMO_STATE_ACTIVE;
    return MMO_OK;
}

int mmo_update(MMO_CTX *context,
               const unsigned char *data,
               unsigned long length)
{
    unsigned long index;
    int result;

    if (context == NULL) {
        return MMO_ERR_NULL;
    }
    if (context->state != MMO_STATE_ACTIVE) {
        return MMO_ERR_STATE;
    }
    if (length != 0UL && data == NULL) {
        return MMO_ERR_NULL;
    }
    if ((unsigned long)(size_t)length != length) {
        context->state = MMO_STATE_ERROR;
        return MMO_ERR_LENGTH;
    }

    for (index = 0UL; index < length; ++index) {
        result = mmo_increment_length(context);
        if (result != MMO_OK) {
            context->state = MMO_STATE_ERROR;
            return result;
        }
        context->buffer[context->buffer_used] = data[(size_t)index];
        ++context->buffer_used;
        if (context->buffer_used == MMO_BLOCK_BYTES) {
            result = mmo_compress(context, context->buffer);
            if (result != MMO_OK) {
                context->state = MMO_STATE_ERROR;
                return result;
            }
            context->buffer_used = 0U;
        }
    }
    return MMO_OK;
}

int mmo_final(MMO_CTX *context,
              unsigned char digest[MMO_DIGEST_BYTES])
{
    unsigned char length_block[MMO_BLOCK_BYTES];
    int result;

    if (context == NULL || digest == NULL) {
        return MMO_ERR_NULL;
    }
    if (context->state != MMO_STATE_ACTIVE) {
        return MMO_ERR_STATE;
    }

    context->buffer[context->buffer_used] = 0x80U;
    ++context->buffer_used;
    while (context->buffer_used < MMO_BLOCK_BYTES) {
        context->buffer[context->buffer_used] = 0U;
        ++context->buffer_used;
    }
    result = mmo_compress(context, context->buffer);
    if (result != MMO_OK) {
        context->state = MMO_STATE_ERROR;
        return result;
    }

    mmo_store_word(length_block, context->length_high);
    mmo_store_word(length_block + 4, context->length_low);
    result = mmo_compress(context, length_block);
    if (result != MMO_OK) {
        context->state = MMO_STATE_ERROR;
        return result;
    }

    memcpy(digest, context->chaining, MMO_DIGEST_BYTES);
    memset(context->buffer, 0, sizeof(context->buffer));
    context->buffer_used = 0U;
    context->state = MMO_STATE_FINAL;
    return MMO_OK;
}

int mmo_hash(const unsigned char *data,
             unsigned long length,
             unsigned char digest[MMO_DIGEST_BYTES])
{
    MMO_CTX context;
    int result;

    if (digest == NULL) {
        return MMO_ERR_NULL;
    }
    if (length != 0UL && data == NULL) {
        return MMO_ERR_NULL;
    }

    result = mmo_init(&context);
    if (result != MMO_OK) {
        return result;
    }
    result = mmo_update(&context, data, length);
    if (result != MMO_OK) {
        return result;
    }
    return mmo_final(&context, digest);
}
