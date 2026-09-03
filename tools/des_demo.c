#include <stdio.h>
#include <string.h>

#include "demo_common.h"

static void usage(const char *program)
{
    fprintf(stderr,
            "usage:\n"
            "  %s encrypt KEY_HEX IV_HEX INPUT OUTPUT\n"
            "  %s decrypt KEY_HEX IV_HEX INPUT OUTPUT\n",
            program, program);
}

int main(int argc, char **argv)
{
    int encrypting;

    if (argc != 6) {
        usage(argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "encrypt") == 0) {
        encrypting = 1;
    } else if (strcmp(argv[1], "decrypt") == 0) {
        encrypting = 0;
    } else {
        usage(argv[0]);
        return 2;
    }
    return demo_run_des_file(encrypting, argv[2], argv[3],
                             argv[4], argv[5]) ? 0 : 1;
}
