#ifndef TOY_RSA_MMO_H
#define TOY_RSA_MMO_H

#define MMO_BLOCK_BYTES 8U
#define MMO_DIGEST_BYTES 8U

#define MMO_OK 0
#define MMO_ERR_NULL (-1)
#define MMO_ERR_STATE (-2)
#define MMO_ERR_LENGTH (-3)
#define MMO_ERR_DES (-4)

#define MMO_STATE_UNINITIALIZED 0
#define MMO_STATE_ACTIVE 1
#define MMO_STATE_FINAL 2
#define MMO_STATE_ERROR 3

typedef struct mmo_context_tag {
    unsigned char chaining[MMO_DIGEST_BYTES];
    unsigned char buffer[MMO_BLOCK_BYTES];
    unsigned int buffer_used;
    unsigned long length_high;
    unsigned long length_low;
    int state;
} MMO_CTX;

int mmo_init(MMO_CTX *context);

int mmo_update(MMO_CTX *context,
               const unsigned char *data,
               unsigned long length);

int mmo_final(MMO_CTX *context,
              unsigned char digest[MMO_DIGEST_BYTES]);

int mmo_hash(const unsigned char *data,
             unsigned long length,
             unsigned char digest[MMO_DIGEST_BYTES]);

#endif
