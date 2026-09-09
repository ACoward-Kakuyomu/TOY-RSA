#include <stdio.h>

#include "demo_common.h"
#include "rsa.h"

static void usage(const char *program)
{
    fprintf(stderr,
            "usage: %s ENTROPY PUBLIC_KEY PRIVATE_KEY [BITS]\n",
            program);
}

int main(int argc, char **argv)
{
    unsigned int bits;

    if (argc != 4 && argc != 5) {
        usage(argv[0]);
        return 2;
    }
    bits = RSA_STORY_MODULUS_BITS;
    if (argc == 5 && !demo_parse_bits(argv[4], &bits)) {
        fprintf(stderr, "invalid RSA bit count: %s\n", argv[4]);
        return 2;
    }
    return demo_run_rsa_keygen(argv[1], argv[2], argv[3], bits) ? 0 : 1;
}
