#ifndef TOY_RSA_RNG_H
#define TOY_RSA_RNG_H

#include "des.h"

#define RNG_BLOCK_BYTES 8U
#define RNG_DES_KEY_BYTES 8U
#define RNG_MIN_ENTROPY_BYTES 8UL

#define RNG_OK 0
#define RNG_ERR_NULL (-1)
#define RNG_ERR_STATE (-2)
#define RNG_ERR_LENGTH (-3)
#define RNG_ERR_WEAK_KEY (-4)
#define RNG_ERR_ENTROPY (-5)
#define RNG_ERR_LIMIT (-6)
#define RNG_ERR_DES (-7)

#define RNG_STATE_UNINITIALIZED 0
#define RNG_STATE_ACTIVE 1
#define RNG_STATE_ERROR 2

typedef struct rng_context_tag {
    unsigned char key[RNG_DES_KEY_BYTES];
    DES_KEY_SCHEDULE schedule;
    unsigned char state_vector[RNG_BLOCK_BYTES];
    unsigned char counter[RNG_BLOCK_BYTES];
    unsigned char output_buffer[RNG_BLOCK_BYTES];
    unsigned int output_index;
    int status;
} RNG_CTX;

int rng_init_deterministic(RNG_CTX *context,
                           const unsigned char key[RNG_DES_KEY_BYTES],
                           const unsigned char state[RNG_BLOCK_BYTES],
                           const unsigned char counter[RNG_BLOCK_BYTES]);

int rng_seed(RNG_CTX *context,
             const unsigned char *entropy,
             unsigned long entropy_length,
             const unsigned char timing[RNG_BLOCK_BYTES]);

int rng_init(RNG_CTX *context,
             const unsigned char *entropy,
             unsigned long entropy_length);

int rng_generate(RNG_CTX *context,
                 unsigned char *output,
                 unsigned long length);

int rng_generate_des_key(RNG_CTX *context,
                         unsigned char key[RNG_DES_KEY_BYTES]);

int rng_des_key_set_odd_parity(
    const unsigned char input[RNG_DES_KEY_BYTES],
    unsigned char output[RNG_DES_KEY_BYTES]);

int rng_des_key_is_weak(const unsigned char key[RNG_DES_KEY_BYTES],
                        int *is_weak);

#endif
