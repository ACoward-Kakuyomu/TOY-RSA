#include <limits.h>
#include <stdio.h>
#include <time.h>

#include "rsa.h"

#define PUBLIC_REPETITIONS 100U
#define PRIVATE_REPETITIONS 3U

static const unsigned char benchmark_key[8] = {
    0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1
};

static const unsigned char benchmark_state[8] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
};

static const unsigned char benchmark_counter[8] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static const char *compiler_name(void)
{
#if defined(_MSC_VER)
    return "MSVC";
#elif defined(__clang__)
    return "Clang";
#elif defined(__GNUC__)
    return "GCC";
#else
    return "unknown C compiler";
#endif
}

static const char *platform_name(void)
{
#if defined(_WIN32)
    return "Windows";
#elif defined(__linux__)
    return "Linux";
#else
    return "unknown platform";
#endif
}

static int same_bigint(const BIGINT *left, const BIGINT *right)
{
    int comparison;

    comparison = 1;
    if (bigint_compare(left, right, &comparison) != BIGINT_OK) {
        return 0;
    }
    return comparison == 0;
}

static double elapsed_seconds(clock_t start, clock_t finish)
{
    return (double)(finish - start) / (double)CLOCKS_PER_SEC;
}

int main(void)
{
    RNG_CTX rng;
    RSA_PRIVATE_KEY key;
    RSA_KEYGEN_STATS statistics;
    BIGINT message;
    BIGINT ciphertext;
    BIGINT standard_result;
    BIGINT crt_result;
    unsigned int actual_bits;
    unsigned int repetition;
    clock_t start;
    clock_t finish;
    double keygen_seconds;
    double public_seconds;
    double standard_seconds;
    double crt_seconds;
    int status;

    printf("Week8 RSA benchmark (measured, no expected speedup)\n");
    printf("compiler: %s\n", compiler_name());
    printf("platform: %s\n", platform_name());
    printf("limits: pointer %u bits, unsigned short %u bits, "
           "unsigned long %u bits\n",
           (unsigned int)(sizeof(void *) * CHAR_BIT),
           (unsigned int)(sizeof(unsigned short) * CHAR_BIT),
           (unsigned int)(sizeof(unsigned long) * CHAR_BIT));
    printf("CLOCKS_PER_SEC: %lu\n", (unsigned long)CLOCKS_PER_SEC);
    printf("BIGINT_MAX_BITS: %u\n", (unsigned int)BIGINT_MAX_BITS);
    printf("requested RSA modulus: %u bits\n",
           (unsigned int)RSA_STORY_MODULUS_BITS);

    status = rng_init_deterministic(&rng, benchmark_key, benchmark_state,
                                    benchmark_counter);
    if (status != RNG_OK) {
        fprintf(stderr, "RNG initialization failed: %d\n", status);
        return 1;
    }

    start = clock();
    status = rsa_generate_key(&rng, RSA_STORY_MODULUS_BITS, 12U,
                              100000UL, 256U, &key, &statistics);
    finish = clock();
    if (status != RSA_OK) {
        fprintf(stderr, "RSA key generation failed: %d\n", status);
        return 1;
    }
    keygen_seconds = elapsed_seconds(start, finish);
    status = bigint_bit_length(&key.public_key.n, &actual_bits);
    if (status != BIGINT_OK) {
        fprintf(stderr, "modulus bit length failed: %d\n", status);
        return 1;
    }
    printf("actual RSA modulus: %u bits\n", actual_bits);
    printf("prime candidates: p=%lu, q=%lu, modulus restarts=%u\n",
           statistics.p_candidates, statistics.q_candidates,
           statistics.restarts);
    printf("key generation: %.6f s\n", keygen_seconds);

    status = bigint_from_ulong(&message, 42UL);
    if (status != BIGINT_OK) {
        fprintf(stderr, "message setup failed: %d\n", status);
        return 1;
    }
    start = clock();
    for (repetition = 0U; repetition < PUBLIC_REPETITIONS;
         ++repetition) {
        status = rsa_public_operation(&key.public_key, &message,
                                      &ciphertext);
        if (status != RSA_OK) {
            fprintf(stderr, "public operation failed: %d\n", status);
            return 1;
        }
    }
    finish = clock();
    public_seconds = elapsed_seconds(start, finish);

    start = clock();
    for (repetition = 0U; repetition < PRIVATE_REPETITIONS;
         ++repetition) {
        status = rsa_private_operation_standard(&key, &ciphertext,
                                                &standard_result);
        if (status != RSA_OK) {
            fprintf(stderr, "standard private operation failed: %d\n",
                    status);
            return 1;
        }
    }
    finish = clock();
    standard_seconds = elapsed_seconds(start, finish);

    start = clock();
    for (repetition = 0U; repetition < PRIVATE_REPETITIONS;
         ++repetition) {
        status = rsa_private_operation(&key, &ciphertext, &crt_result);
        if (status != RSA_OK) {
            fprintf(stderr, "CRT private operation failed: %d\n", status);
            return 1;
        }
    }
    finish = clock();
    crt_seconds = elapsed_seconds(start, finish);

    if (!same_bigint(&standard_result, &message) ||
        !same_bigint(&crt_result, &message)) {
        fprintf(stderr, "benchmark result verification failed\n");
        return 1;
    }
    printf("public: %u operations, %.6f s total, %.6f s/op\n",
           PUBLIC_REPETITIONS, public_seconds,
           public_seconds / (double)PUBLIC_REPETITIONS);
    printf("private standard: %u operations, %.6f s total, %.6f s/op\n",
           PRIVATE_REPETITIONS, standard_seconds,
           standard_seconds / (double)PRIVATE_REPETITIONS);
    printf("private CRT: %u operations, %.6f s total, %.6f s/op\n",
           PRIVATE_REPETITIONS, crt_seconds,
           crt_seconds / (double)PRIVATE_REPETITIONS);
    if (crt_seconds > 0.0) {
        printf("measured standard/CRT time ratio: %.3f\n",
               standard_seconds / crt_seconds);
    }
    return 0;
}
