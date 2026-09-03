#include <string.h>

#include "des.h"
#include "des_internal.h"

static unsigned char des_get_bit(const unsigned char *data,
                                 unsigned int position)
{
    unsigned int byte_index;
    unsigned int bit_index;

    byte_index = position / 8U;
    bit_index = position % 8U;
    return (unsigned char)((data[byte_index] >> (7U - bit_index)) & 1U);
}

static void des_set_bit(unsigned char *data,
                        unsigned int position,
                        unsigned char value)
{
    unsigned int byte_index;
    unsigned int bit_index;
    unsigned char mask;

    byte_index = position / 8U;
    bit_index = position % 8U;
    mask = (unsigned char)(1U << (7U - bit_index));
    if (value != 0U) {
        data[byte_index] = (unsigned char)(data[byte_index] | mask);
    }
}

int des_permute(const unsigned char *input,
                unsigned int input_bits,
                unsigned char *output,
                unsigned int output_bits,
                const unsigned char *table)
{
    unsigned char temporary[DES_BLOCK_BYTES];
    unsigned int output_bytes;
    unsigned int index;
    unsigned int source_position;

    if (input == NULL || output == NULL || table == NULL) {
        return DES_ERR_NULL;
    }
    if (input_bits == 0U || input_bits > 64U ||
        output_bits == 0U || output_bits > 64U) {
        return DES_ERR_RANGE;
    }
    for (index = 0U; index < output_bits; ++index) {
        if (table[index] == 0U || table[index] > input_bits) {
            return DES_ERR_RANGE;
        }
    }

    memset(temporary, 0, sizeof(temporary));
    for (index = 0U; index < output_bits; ++index) {
        source_position = (unsigned int)table[index] - 1U;
        des_set_bit(temporary, index, des_get_bit(input, source_position));
    }
    output_bytes = (output_bits + 7U) / 8U;
    memcpy(output, temporary, output_bytes);
    return DES_OK;
}

int des_initial_permutation(const unsigned char input[DES_BLOCK_BYTES],
                            unsigned char output[DES_BLOCK_BYTES])
{
    return des_permute(input, 64U, output, 64U, des_ip_table);
}

int des_final_permutation(const unsigned char input[DES_BLOCK_BYTES],
                          unsigned char output[DES_BLOCK_BYTES])
{
    return des_permute(input, 64U, output, 64U, des_fp_table);
}

int des_expand(const unsigned char right[DES_HALF_BYTES],
               unsigned char output[DES_SUBKEY_BYTES])
{
    return des_permute(right, 32U, output, 48U, des_e_table);
}

int des_p_permute(const unsigned char input[DES_HALF_BYTES],
                  unsigned char output[DES_HALF_BYTES])
{
    return des_permute(input, 32U, output, 32U, des_p_table);
}

int des_sbox(unsigned int box,
             unsigned char six_bits,
             unsigned char *value)
{
    unsigned int row;
    unsigned int column;

    if (value == NULL) {
        return DES_ERR_NULL;
    }
    if (box >= 8U || six_bits >= 64U) {
        return DES_ERR_RANGE;
    }
    row = (unsigned int)(((six_bits & 0x20U) >> 4U) |
                         (six_bits & 0x01U));
    column = (unsigned int)((six_bits >> 1U) & 0x0fU);
    *value = des_sboxes[box][row * 16U + column];
    return DES_OK;
}

int des_rotate_key_half(unsigned char half[DES_HALF_BYTES],
                        unsigned int shifts)
{
    unsigned int count;
    unsigned char first_bit;

    if (half == NULL) {
        return DES_ERR_NULL;
    }
    if ((half[0] & 0xf0U) != 0U || (shifts != 1U && shifts != 2U)) {
        return DES_ERR_RANGE;
    }

    for (count = 0U; count < shifts; ++count) {
        first_bit = (unsigned char)((half[0] >> 3U) & 1U);
        half[0] = (unsigned char)(((half[0] << 1U) & 0x0fU) |
                                  ((half[1] >> 7U) & 1U));
        half[1] = (unsigned char)((half[1] << 1U) |
                                  ((half[2] >> 7U) & 1U));
        half[2] = (unsigned char)((half[2] << 1U) |
                                  ((half[3] >> 7U) & 1U));
        half[3] = (unsigned char)((half[3] << 1U) | first_bit);
    }
    return DES_OK;
}

static void des_split_key_halves(const unsigned char combined[7],
                                 unsigned char c[DES_HALF_BYTES],
                                 unsigned char d[DES_HALF_BYTES])
{
    c[0] = (unsigned char)(combined[0] >> 4U);
    c[1] = (unsigned char)((combined[0] << 4U) | (combined[1] >> 4U));
    c[2] = (unsigned char)((combined[1] << 4U) | (combined[2] >> 4U));
    c[3] = (unsigned char)((combined[2] << 4U) | (combined[3] >> 4U));

    d[0] = (unsigned char)(combined[3] & 0x0fU);
    d[1] = combined[4];
    d[2] = combined[5];
    d[3] = combined[6];
}

static void des_join_key_halves(const unsigned char c[DES_HALF_BYTES],
                                const unsigned char d[DES_HALF_BYTES],
                                unsigned char combined[7])
{
    combined[0] = (unsigned char)((c[0] << 4U) | (c[1] >> 4U));
    combined[1] = (unsigned char)((c[1] << 4U) | (c[2] >> 4U));
    combined[2] = (unsigned char)((c[2] << 4U) | (c[3] >> 4U));
    combined[3] = (unsigned char)((c[3] << 4U) | d[0]);
    combined[4] = d[1];
    combined[5] = d[2];
    combined[6] = d[3];
}

int des_key_schedule(const unsigned char key[DES_BLOCK_BYTES],
                     DES_KEY_SCHEDULE *schedule)
{
    unsigned char combined[7];
    unsigned char c[DES_HALF_BYTES];
    unsigned char d[DES_HALF_BYTES];
    unsigned int round;
    int result;

    if (key == NULL || schedule == NULL) {
        return DES_ERR_NULL;
    }

    result = des_permute(key, 64U, combined, 56U, des_pc1_table);
    if (result != DES_OK) {
        return result;
    }
    des_split_key_halves(combined, c, d);

    for (round = 0U; round < DES_ROUNDS; ++round) {
        result = des_rotate_key_half(c, des_key_shifts[round]);
        if (result != DES_OK) {
            return result;
        }
        result = des_rotate_key_half(d, des_key_shifts[round]);
        if (result != DES_OK) {
            return result;
        }
        des_join_key_halves(c, d, combined);
        result = des_permute(combined, 56U,
                             schedule->subkeys[round], 48U,
                             des_pc2_table);
        if (result != DES_OK) {
            return result;
        }
    }
    return DES_OK;
}

static unsigned char des_extract_six_bits(const unsigned char data[6],
                                          unsigned int group)
{
    unsigned char value;
    unsigned int bit;
    unsigned int position;

    value = 0U;
    for (bit = 0U; bit < 6U; ++bit) {
        position = group * 6U + bit;
        value = (unsigned char)((value << 1U) |
                                des_get_bit(data, position));
    }
    return value;
}

int des_f(const unsigned char right[DES_HALF_BYTES],
          const unsigned char subkey[DES_SUBKEY_BYTES],
          unsigned char output[DES_HALF_BYTES])
{
    unsigned char expanded[DES_SUBKEY_BYTES];
    unsigned char substituted[DES_HALF_BYTES];
    unsigned char six_bits;
    unsigned char four_bits;
    unsigned int index;
    int result;

    if (right == NULL || subkey == NULL || output == NULL) {
        return DES_ERR_NULL;
    }

    result = des_expand(right, expanded);
    if (result != DES_OK) {
        return result;
    }
    for (index = 0U; index < DES_SUBKEY_BYTES; ++index) {
        expanded[index] = (unsigned char)(expanded[index] ^ subkey[index]);
    }

    memset(substituted, 0, sizeof(substituted));
    for (index = 0U; index < 8U; ++index) {
        six_bits = des_extract_six_bits(expanded, index);
        result = des_sbox(index, six_bits, &four_bits);
        if (result != DES_OK) {
            return result;
        }
        if ((index & 1U) == 0U) {
            substituted[index / 2U] = (unsigned char)(four_bits << 4U);
        } else {
            substituted[index / 2U] = (unsigned char)(
                substituted[index / 2U] | four_bits);
        }
    }
    return des_p_permute(substituted, output);
}

int des_round(unsigned char left[DES_HALF_BYTES],
              unsigned char right[DES_HALF_BYTES],
              const unsigned char subkey[DES_SUBKEY_BYTES])
{
    unsigned char old_left[DES_HALF_BYTES];
    unsigned char old_right[DES_HALF_BYTES];
    unsigned char f_output[DES_HALF_BYTES];
    unsigned int index;
    int result;

    if (left == NULL || right == NULL || subkey == NULL) {
        return DES_ERR_NULL;
    }
    if (left == right) {
        return DES_ERR_ALIAS;
    }

    memcpy(old_left, left, sizeof(old_left));
    memcpy(old_right, right, sizeof(old_right));
    result = des_f(old_right, subkey, f_output);
    if (result != DES_OK) {
        return result;
    }
    for (index = 0U; index < DES_HALF_BYTES; ++index) {
        left[index] = old_right[index];
        right[index] = (unsigned char)(old_left[index] ^ f_output[index]);
    }
    return DES_OK;
}

static int des_crypt_block(const unsigned char input[DES_BLOCK_BYTES],
                           unsigned char output[DES_BLOCK_BYTES],
                           const DES_KEY_SCHEDULE *schedule,
                           int decrypt)
{
    unsigned char state[DES_BLOCK_BYTES];
    unsigned char left[DES_HALF_BYTES];
    unsigned char right[DES_HALF_BYTES];
    unsigned char preoutput[DES_BLOCK_BYTES];
    unsigned int round;
    unsigned int subkey_index;
    int result;

    if (input == NULL || output == NULL || schedule == NULL) {
        return DES_ERR_NULL;
    }

    result = des_initial_permutation(input, state);
    if (result != DES_OK) {
        return result;
    }
    memcpy(left, state, DES_HALF_BYTES);
    memcpy(right, state + DES_HALF_BYTES, DES_HALF_BYTES);

    for (round = 0U; round < DES_ROUNDS; ++round) {
        if (decrypt != 0) {
            subkey_index = DES_ROUNDS - 1U - round;
        } else {
            subkey_index = round;
        }
        result = des_round(left, right, schedule->subkeys[subkey_index]);
        if (result != DES_OK) {
            return result;
        }
    }

    memcpy(preoutput, right, DES_HALF_BYTES);
    memcpy(preoutput + DES_HALF_BYTES, left, DES_HALF_BYTES);
    return des_final_permutation(preoutput, output);
}

int des_encrypt_block(const unsigned char input[DES_BLOCK_BYTES],
                      unsigned char output[DES_BLOCK_BYTES],
                      const DES_KEY_SCHEDULE *schedule)
{
    return des_crypt_block(input, output, schedule, 0);
}

int des_decrypt_block(const unsigned char input[DES_BLOCK_BYTES],
                      unsigned char output[DES_BLOCK_BYTES],
                      const DES_KEY_SCHEDULE *schedule)
{
    return des_crypt_block(input, output, schedule, 1);
}
