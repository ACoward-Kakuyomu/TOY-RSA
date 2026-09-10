#include <stdio.h>
#include <string.h>

#include "demo_common.h"

static void usage(const char *program)
{
    fprintf(stderr,
            "usage:\n"
            "  %s encrypt PUBLIC_KEY ENTROPY INPUT OUTPUT\n"
            "  %s decrypt PRIVATE_KEY INPUT OUTPUT\n",
            program, program);
}

int main(int argc, char **argv)
{
    if (argc == 6 && strcmp(argv[1], "encrypt") == 0) {
        return demo_run_hybrid_encrypt(argv[2], argv[3], argv[4],
                                       argv[5]) ? 0 : 1;
    }
    if (argc == 5 && strcmp(argv[1], "decrypt") == 0) {
        return demo_run_hybrid_decrypt(argv[2], argv[3], argv[4]) ? 0 : 1;
    }
    usage(argv[0]);
    return 2;
}
