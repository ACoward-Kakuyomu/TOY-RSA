#ifndef TOY_RSA_CBC_H
#define TOY_RSA_CBC_H

#include <stdio.h>

#include "des.h"

#define DES_CBC_LENGTH_BYTES 4UL
#define DES_CBC_MAX_PLAINTEXT 0xfffffff4UL
#define DES_CBC_MAX_CIPHERTEXT 0xfffffff8UL

int des_cbc_encrypt_blocks(const unsigned char *input,
                           unsigned long length,
                           unsigned char *output,
                           const DES_KEY_SCHEDULE *schedule,
                           const unsigned char iv[DES_BLOCK_BYTES]);

int des_cbc_decrypt_blocks(const unsigned char *input,
                           unsigned long length,
                           unsigned char *output,
                           const DES_KEY_SCHEDULE *schedule,
                           const unsigned char iv[DES_BLOCK_BYTES]);

int des_cbc_framed_size(unsigned long plaintext_length,
                        unsigned long *ciphertext_length);

int des_cbc_encrypt(const unsigned char *input,
                    unsigned long plaintext_length,
                    unsigned char *output,
                    unsigned long output_capacity,
                    unsigned long *ciphertext_length,
                    const DES_KEY_SCHEDULE *schedule,
                    const unsigned char iv[DES_BLOCK_BYTES]);

int des_cbc_decrypt(const unsigned char *input,
                    unsigned long ciphertext_length,
                    unsigned char *output,
                    unsigned long output_capacity,
                    unsigned long *plaintext_length,
                    const DES_KEY_SCHEDULE *schedule,
                    const unsigned char iv[DES_BLOCK_BYTES]);

int des_cbc_encrypt_file(FILE *input,
                         FILE *output,
                         unsigned long plaintext_length,
                         const DES_KEY_SCHEDULE *schedule,
                         const unsigned char iv[DES_BLOCK_BYTES]);

int des_cbc_decrypt_file(FILE *input,
                         FILE *output,
                         unsigned long ciphertext_length,
                         unsigned long *plaintext_length,
                         const DES_KEY_SCHEDULE *schedule,
                         const unsigned char iv[DES_BLOCK_BYTES]);

#endif
