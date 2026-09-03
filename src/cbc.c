#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "cbc.h"

static int des_cbc_buffer_length_valid(unsigned long length)
{
    return (unsigned long)(size_t)length == length;
}

static unsigned char des_cbc_length_byte(unsigned long length,
                                         unsigned int index)
{
    unsigned int shift;

    shift = (3U - index) * 8U;
    return (unsigned char)((length >> shift) & 0xffUL);
}

static unsigned long des_cbc_read_length(const unsigned char block[8])
{
    unsigned long value;

    value = ((unsigned long)block[0] << 24U);
    value |= ((unsigned long)block[1] << 16U);
    value |= ((unsigned long)block[2] << 8U);
    value |= (unsigned long)block[3];
    return value;
}

static void des_cbc_xor_block(unsigned char output[DES_BLOCK_BYTES],
                              const unsigned char left[DES_BLOCK_BYTES],
                              const unsigned char right[DES_BLOCK_BYTES])
{
    unsigned int index;

    for (index = 0U; index < DES_BLOCK_BYTES; ++index) {
        output[index] = (unsigned char)(left[index] ^ right[index]);
    }
}

int des_cbc_encrypt_blocks(const unsigned char *input,
                           unsigned long length,
                           unsigned char *output,
                           const DES_KEY_SCHEDULE *schedule,
                           const unsigned char iv[DES_BLOCK_BYTES])
{
    unsigned char chain[DES_BLOCK_BYTES];
    unsigned char plaintext[DES_BLOCK_BYTES];
    unsigned char mixed[DES_BLOCK_BYTES];
    unsigned char ciphertext[DES_BLOCK_BYTES];
    unsigned long offset;
    int result;

    if (schedule == NULL || iv == NULL) {
        return DES_ERR_NULL;
    }
    if ((length % DES_BLOCK_BYTES) != 0UL ||
        !des_cbc_buffer_length_valid(length)) {
        return DES_ERR_LENGTH;
    }
    if (length == 0UL) {
        return DES_OK;
    }
    if (input == NULL || output == NULL) {
        return DES_ERR_NULL;
    }

    memcpy(chain, iv, DES_BLOCK_BYTES);
    for (offset = 0UL; offset < length; offset += DES_BLOCK_BYTES) {
        memcpy(plaintext, input + (size_t)offset, DES_BLOCK_BYTES);
        des_cbc_xor_block(mixed, plaintext, chain);
        result = des_encrypt_block(mixed, ciphertext, schedule);
        if (result != DES_OK) {
            return result;
        }
        memcpy(output + (size_t)offset, ciphertext, DES_BLOCK_BYTES);
        memcpy(chain, ciphertext, DES_BLOCK_BYTES);
    }
    return DES_OK;
}

int des_cbc_decrypt_blocks(const unsigned char *input,
                           unsigned long length,
                           unsigned char *output,
                           const DES_KEY_SCHEDULE *schedule,
                           const unsigned char iv[DES_BLOCK_BYTES])
{
    unsigned char chain[DES_BLOCK_BYTES];
    unsigned char ciphertext[DES_BLOCK_BYTES];
    unsigned char decrypted[DES_BLOCK_BYTES];
    unsigned char plaintext[DES_BLOCK_BYTES];
    unsigned long offset;
    int result;

    if (schedule == NULL || iv == NULL) {
        return DES_ERR_NULL;
    }
    if ((length % DES_BLOCK_BYTES) != 0UL ||
        !des_cbc_buffer_length_valid(length)) {
        return DES_ERR_LENGTH;
    }
    if (length == 0UL) {
        return DES_OK;
    }
    if (input == NULL || output == NULL) {
        return DES_ERR_NULL;
    }

    memcpy(chain, iv, DES_BLOCK_BYTES);
    for (offset = 0UL; offset < length; offset += DES_BLOCK_BYTES) {
        memcpy(ciphertext, input + (size_t)offset, DES_BLOCK_BYTES);
        result = des_decrypt_block(ciphertext, decrypted, schedule);
        if (result != DES_OK) {
            return result;
        }
        des_cbc_xor_block(plaintext, decrypted, chain);
        memcpy(output + (size_t)offset, plaintext, DES_BLOCK_BYTES);
        memcpy(chain, ciphertext, DES_BLOCK_BYTES);
    }
    return DES_OK;
}

int des_cbc_framed_size(unsigned long plaintext_length,
                        unsigned long *ciphertext_length)
{
    unsigned long unrounded;

    if (ciphertext_length == NULL) {
        return DES_ERR_NULL;
    }
    if (plaintext_length > DES_CBC_MAX_PLAINTEXT) {
        return DES_ERR_LENGTH;
    }
    unrounded = DES_CBC_LENGTH_BYTES + plaintext_length;
    *ciphertext_length = (unrounded + 7UL) & ~7UL;
    return DES_OK;
}

int des_cbc_encrypt(const unsigned char *input,
                    unsigned long plaintext_length,
                    unsigned char *output,
                    unsigned long output_capacity,
                    unsigned long *ciphertext_length,
                    const DES_KEY_SCHEDULE *schedule,
                    const unsigned char iv[DES_BLOCK_BYTES])
{
    unsigned char chain[DES_BLOCK_BYTES];
    unsigned char block[DES_BLOCK_BYTES];
    unsigned char mixed[DES_BLOCK_BYTES];
    unsigned char encrypted[DES_BLOCK_BYTES];
    unsigned long required;
    unsigned long offset;
    unsigned long position;
    unsigned long plaintext_index;
    unsigned int index;
    int result;

    if (output == NULL || ciphertext_length == NULL ||
        schedule == NULL || iv == NULL) {
        return DES_ERR_NULL;
    }
    if (plaintext_length != 0UL && input == NULL) {
        return DES_ERR_NULL;
    }
    if (plaintext_length != 0UL && input == output) {
        return DES_ERR_ALIAS;
    }
    result = des_cbc_framed_size(plaintext_length, &required);
    if (result != DES_OK) {
        return result;
    }
    if (!des_cbc_buffer_length_valid(plaintext_length) ||
        !des_cbc_buffer_length_valid(required)) {
        return DES_ERR_LENGTH;
    }
    if (output_capacity < required) {
        return DES_ERR_CAPACITY;
    }

    memcpy(chain, iv, DES_BLOCK_BYTES);
    for (offset = 0UL; offset < required; offset += DES_BLOCK_BYTES) {
        for (index = 0U; index < DES_BLOCK_BYTES; ++index) {
            position = offset + (unsigned long)index;
            if (position < DES_CBC_LENGTH_BYTES) {
                block[index] = des_cbc_length_byte(
                    plaintext_length, (unsigned int)position);
            } else {
                plaintext_index = position - DES_CBC_LENGTH_BYTES;
                if (plaintext_index < plaintext_length) {
                    block[index] = input[(size_t)plaintext_index];
                } else {
                    block[index] = 0U;
                }
            }
        }
        des_cbc_xor_block(mixed, block, chain);
        result = des_encrypt_block(mixed, encrypted, schedule);
        if (result != DES_OK) {
            return result;
        }
        memcpy(output + (size_t)offset, encrypted, DES_BLOCK_BYTES);
        memcpy(chain, encrypted, DES_BLOCK_BYTES);
    }
    *ciphertext_length = required;
    return DES_OK;
}

int des_cbc_decrypt(const unsigned char *input,
                    unsigned long ciphertext_length,
                    unsigned char *output,
                    unsigned long output_capacity,
                    unsigned long *plaintext_length,
                    const DES_KEY_SCHEDULE *schedule,
                    const unsigned char iv[DES_BLOCK_BYTES])
{
    unsigned char chain[DES_BLOCK_BYTES];
    unsigned char ciphertext[DES_BLOCK_BYTES];
    unsigned char decrypted[DES_BLOCK_BYTES];
    unsigned char block[DES_BLOCK_BYTES];
    unsigned long decoded_length;
    unsigned long expected_length;
    unsigned long data_end;
    unsigned long offset;
    unsigned long position;
    unsigned int index;
    int result;

    if (input == NULL || plaintext_length == NULL ||
        schedule == NULL || iv == NULL) {
        return DES_ERR_NULL;
    }
    if (ciphertext_length < DES_BLOCK_BYTES ||
        (ciphertext_length % DES_BLOCK_BYTES) != 0UL ||
        !des_cbc_buffer_length_valid(ciphertext_length)) {
        return DES_ERR_LENGTH;
    }

    memcpy(chain, iv, DES_BLOCK_BYTES);
    decoded_length = 0UL;
    data_end = 0UL;
    for (offset = 0UL; offset < ciphertext_length;
         offset += DES_BLOCK_BYTES) {
        memcpy(ciphertext, input + (size_t)offset, DES_BLOCK_BYTES);
        result = des_decrypt_block(ciphertext, decrypted, schedule);
        if (result != DES_OK) {
            return result;
        }
        des_cbc_xor_block(block, decrypted, chain);
        memcpy(chain, ciphertext, DES_BLOCK_BYTES);

        if (offset == 0UL) {
            decoded_length = des_cbc_read_length(block);
            result = des_cbc_framed_size(decoded_length, &expected_length);
            if (result != DES_OK || expected_length != ciphertext_length) {
                return DES_ERR_FORMAT;
            }
            if (!des_cbc_buffer_length_valid(decoded_length)) {
                return DES_ERR_LENGTH;
            }
            if (output_capacity < decoded_length) {
                return DES_ERR_CAPACITY;
            }
            if (decoded_length != 0UL && output == NULL) {
                return DES_ERR_NULL;
            }
            data_end = DES_CBC_LENGTH_BYTES + decoded_length;
        }

        for (index = 0U; index < DES_BLOCK_BYTES; ++index) {
            position = offset + (unsigned long)index;
            if (position >= DES_CBC_LENGTH_BYTES && position < data_end) {
                output[(size_t)(position - DES_CBC_LENGTH_BYTES)] =
                    block[index];
            } else if (position >= data_end && block[index] != 0U) {
                return DES_ERR_FORMAT;
            }
        }
    }
    *plaintext_length = decoded_length;
    return DES_OK;
}

int des_cbc_encrypt_file(FILE *input,
                         FILE *output,
                         unsigned long plaintext_length,
                         const DES_KEY_SCHEDULE *schedule,
                         const unsigned char iv[DES_BLOCK_BYTES])
{
    unsigned char chain[DES_BLOCK_BYTES];
    unsigned char block[DES_BLOCK_BYTES];
    unsigned char mixed[DES_BLOCK_BYTES];
    unsigned char encrypted[DES_BLOCK_BYTES];
    unsigned long ciphertext_length;
    unsigned long offset;
    unsigned long position;
    unsigned long plaintext_index;
    unsigned int index;
    int byte_value;
    int result;

    if (input == NULL || output == NULL || schedule == NULL || iv == NULL) {
        return DES_ERR_NULL;
    }
    if (input == output) {
        return DES_ERR_ALIAS;
    }
    result = des_cbc_framed_size(plaintext_length, &ciphertext_length);
    if (result != DES_OK) {
        return result;
    }

    memcpy(chain, iv, DES_BLOCK_BYTES);
    for (offset = 0UL; offset < ciphertext_length;
         offset += DES_BLOCK_BYTES) {
        for (index = 0U; index < DES_BLOCK_BYTES; ++index) {
            position = offset + (unsigned long)index;
            if (position < DES_CBC_LENGTH_BYTES) {
                block[index] = des_cbc_length_byte(
                    plaintext_length, (unsigned int)position);
            } else {
                plaintext_index = position - DES_CBC_LENGTH_BYTES;
                if (plaintext_index < plaintext_length) {
                    byte_value = fgetc(input);
                    if (byte_value == EOF) {
                        return DES_ERR_IO;
                    }
                    block[index] = (unsigned char)byte_value;
                } else {
                    block[index] = 0U;
                }
            }
        }
        des_cbc_xor_block(mixed, block, chain);
        result = des_encrypt_block(mixed, encrypted, schedule);
        if (result != DES_OK) {
            return result;
        }
        if (fwrite(encrypted, 1U, DES_BLOCK_BYTES, output) !=
            DES_BLOCK_BYTES) {
            return DES_ERR_IO;
        }
        memcpy(chain, encrypted, DES_BLOCK_BYTES);
    }
    return DES_OK;
}

int des_cbc_decrypt_file(FILE *input,
                         FILE *output,
                         unsigned long ciphertext_length,
                         unsigned long *plaintext_length,
                         const DES_KEY_SCHEDULE *schedule,
                         const unsigned char iv[DES_BLOCK_BYTES])
{
    unsigned char chain[DES_BLOCK_BYTES];
    unsigned char ciphertext[DES_BLOCK_BYTES];
    unsigned char decrypted[DES_BLOCK_BYTES];
    unsigned char block[DES_BLOCK_BYTES];
    unsigned long decoded_length;
    unsigned long expected_length;
    unsigned long data_end;
    unsigned long offset;
    unsigned long position;
    unsigned int index;
    int result;

    if (input == NULL || output == NULL || plaintext_length == NULL ||
        schedule == NULL || iv == NULL) {
        return DES_ERR_NULL;
    }
    if (input == output) {
        return DES_ERR_ALIAS;
    }
    if (ciphertext_length < DES_BLOCK_BYTES ||
        (ciphertext_length % DES_BLOCK_BYTES) != 0UL) {
        return DES_ERR_LENGTH;
    }

    memcpy(chain, iv, DES_BLOCK_BYTES);
    decoded_length = 0UL;
    data_end = 0UL;
    for (offset = 0UL; offset < ciphertext_length;
         offset += DES_BLOCK_BYTES) {
        if (fread(ciphertext, 1U, DES_BLOCK_BYTES, input) !=
            DES_BLOCK_BYTES) {
            return DES_ERR_IO;
        }
        result = des_decrypt_block(ciphertext, decrypted, schedule);
        if (result != DES_OK) {
            return result;
        }
        des_cbc_xor_block(block, decrypted, chain);
        memcpy(chain, ciphertext, DES_BLOCK_BYTES);

        if (offset == 0UL) {
            decoded_length = des_cbc_read_length(block);
            result = des_cbc_framed_size(decoded_length, &expected_length);
            if (result != DES_OK || expected_length != ciphertext_length) {
                return DES_ERR_FORMAT;
            }
            data_end = DES_CBC_LENGTH_BYTES + decoded_length;
        }

        for (index = 0U; index < DES_BLOCK_BYTES; ++index) {
            position = offset + (unsigned long)index;
            if (position >= DES_CBC_LENGTH_BYTES && position < data_end) {
                if (fputc((int)block[index], output) == EOF) {
                    return DES_ERR_IO;
                }
            } else if (position >= data_end && block[index] != 0U) {
                return DES_ERR_FORMAT;
            }
        }
    }
    *plaintext_length = decoded_length;
    return DES_OK;
}
