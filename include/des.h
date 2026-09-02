#ifndef TOY_RSA_DES_H
#define TOY_RSA_DES_H

#define DES_BLOCK_BYTES 8U
#define DES_HALF_BYTES 4U
#define DES_SUBKEY_BYTES 6U
#define DES_ROUNDS 16U

#define DES_OK 0
#define DES_ERR_NULL (-1)
#define DES_ERR_RANGE (-2)
#define DES_ERR_ALIAS (-3)

typedef struct des_key_schedule_tag {
    unsigned char subkeys[DES_ROUNDS][DES_SUBKEY_BYTES];
} DES_KEY_SCHEDULE;

int des_permute(const unsigned char *input,
                unsigned int input_bits,
                unsigned char *output,
                unsigned int output_bits,
                const unsigned char *table);

int des_initial_permutation(const unsigned char input[DES_BLOCK_BYTES],
                            unsigned char output[DES_BLOCK_BYTES]);

int des_final_permutation(const unsigned char input[DES_BLOCK_BYTES],
                          unsigned char output[DES_BLOCK_BYTES]);

int des_expand(const unsigned char right[DES_HALF_BYTES],
               unsigned char output[DES_SUBKEY_BYTES]);

int des_p_permute(const unsigned char input[DES_HALF_BYTES],
                  unsigned char output[DES_HALF_BYTES]);

int des_sbox(unsigned int box,
             unsigned char six_bits,
             unsigned char *value);

int des_rotate_key_half(unsigned char half[DES_HALF_BYTES],
                        unsigned int shifts);

int des_key_schedule(const unsigned char key[DES_BLOCK_BYTES],
                     DES_KEY_SCHEDULE *schedule);

int des_f(const unsigned char right[DES_HALF_BYTES],
          const unsigned char subkey[DES_SUBKEY_BYTES],
          unsigned char output[DES_HALF_BYTES]);

int des_round(unsigned char left[DES_HALF_BYTES],
              unsigned char right[DES_HALF_BYTES],
              const unsigned char subkey[DES_SUBKEY_BYTES]);

#endif
