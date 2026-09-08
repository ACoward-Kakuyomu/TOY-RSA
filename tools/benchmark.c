#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "montgomery.h"
#include "number.h"

#define BENCHMARK_DEFAULT_REPETITIONS 20UL
#define BENCHMARK_MAX_REPETITIONS 1000000UL
#define BENCHMARK_MILLER_RABIN_ROUNDS 9U

static int load_value(BIGINT *value, const char *text)
{
    int status;

    status = bigint_from_hex(value, text);
    if (status != BIGINT_OK) {
        fprintf(stderr, "cannot parse benchmark value: %s (%d)\n",
                text, status);
        return 0;
    }
    return 1;
}

static int parse_repetitions(const char *text, unsigned long *repetitions)
{
    char *end;
    unsigned long value;

    errno = 0;
    end = NULL;
    value = strtoul(text, &end, 10);
    if (text[0] == '-' || errno != 0 || end == text || *end != '\0' ||
        value == 0UL || value > BENCHMARK_MAX_REPETITIONS) {
        return 0;
    }
    *repetitions = value;
    return 1;
}

static int compare_results(const BIGINT *left, const BIGINT *right)
{
    int comparison;
    int status;

    status = bigint_compare(left, right, &comparison);
    return status == BIGINT_OK && comparison == 0;
}

int main(int argc, char **argv)
{
    static const char modulus_text[] =
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC5";
    static const char base_text[] =
        "123456789ABCDEF00112233445566778899AABBCCDDEEFF";
    static const char exponent_text[] =
        "123456789ABCDEF0011223344556677889ABCDEF";
    static const char prime_candidate_text[] =
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    static const unsigned long miller_rabin_bases[] = {
        2UL, 3UL, 5UL, 7UL, 11UL, 13UL, 17UL, 19UL, 23UL
    };
    BIGINT modulus;
    BIGINT base;
    BIGINT exponent;
    BIGINT prime_candidate;
    BIGINT ordinary_result;
    BIGINT montgomery_result;
    MONT_CTX context;
    unsigned long repetitions;
    unsigned long iteration;
    unsigned int modulus_bits;
    unsigned int candidate_bits;
    clock_t setup_start;
    clock_t setup_end;
    clock_t ordinary_start;
    clock_t ordinary_end;
    clock_t montgomery_start;
    clock_t montgomery_end;
    clock_t conventional_mr_start;
    clock_t conventional_mr_end;
    clock_t montgomery_mr_start;
    clock_t montgomery_mr_end;
    double setup_seconds;
    double ordinary_seconds;
    double montgomery_seconds;
    double conventional_mr_seconds;
    double montgomery_mr_seconds;
    int conventional_probable;
    int montgomery_probable;
    int status;

    repetitions = BENCHMARK_DEFAULT_REPETITIONS;
    conventional_probable = 0;
    montgomery_probable = 0;
    if (argc > 2) {
        fprintf(stderr, "usage: benchmark_montgomery [repetitions]\n");
        return 2;
    }
    if (argc == 2 && !parse_repetitions(argv[1], &repetitions)) {
        fprintf(stderr, "repetitions must be an integer from 1 to %lu\n",
                BENCHMARK_MAX_REPETITIONS);
        return 2;
    }
    if (!load_value(&modulus, modulus_text) ||
        !load_value(&base, base_text) ||
        !load_value(&exponent, exponent_text) ||
        !load_value(&prime_candidate, prime_candidate_text)) {
        return 1;
    }
    status = bigint_bit_length(&modulus, &modulus_bits);
    if (status != BIGINT_OK) {
        fprintf(stderr, "cannot obtain modulus width (%d)\n", status);
        return 1;
    }
    status = bigint_bit_length(&prime_candidate, &candidate_bits);
    if (status != BIGINT_OK) {
        fprintf(stderr, "cannot obtain candidate width (%d)\n", status);
        return 1;
    }

    setup_start = clock();
    status = mont_init(&context, &modulus);
    setup_end = clock();
    if (status != MONT_OK) {
        fprintf(stderr, "Montgomery setup failed (%d)\n", status);
        return 1;
    }

    ordinary_start = clock();
    for (iteration = 0UL; iteration < repetitions; ++iteration) {
        status = number_mod_pow(&base, &exponent, &modulus,
                                &ordinary_result);
        if (status != NUMBER_OK) {
            fprintf(stderr, "ordinary exponentiation failed (%d)\n",
                    status);
            return 1;
        }
    }
    ordinary_end = clock();

    montgomery_start = clock();
    for (iteration = 0UL; iteration < repetitions; ++iteration) {
        status = mont_pow(&context, &base, &exponent,
                          &montgomery_result);
        if (status != MONT_OK) {
            fprintf(stderr, "Montgomery exponentiation failed (%d)\n",
                    status);
            return 1;
        }
    }
    montgomery_end = clock();

    if (!compare_results(&ordinary_result, &montgomery_result)) {
        fprintf(stderr, "benchmark implementations returned different values\n");
        return 1;
    }

    conventional_mr_start = clock();
    for (iteration = 0UL; iteration < repetitions; ++iteration) {
        status = number_miller_rabin_bases_conventional(
            &prime_candidate, miller_rabin_bases,
            BENCHMARK_MILLER_RABIN_ROUNDS, &conventional_probable);
        if (status != NUMBER_OK) {
            fprintf(stderr, "conventional Miller-Rabin failed (%d)\n",
                    status);
            return 1;
        }
    }
    conventional_mr_end = clock();

    montgomery_mr_start = clock();
    for (iteration = 0UL; iteration < repetitions; ++iteration) {
        status = number_miller_rabin_bases(
            &prime_candidate, miller_rabin_bases,
            BENCHMARK_MILLER_RABIN_ROUNDS, &montgomery_probable);
        if (status != NUMBER_OK) {
            fprintf(stderr, "Montgomery Miller-Rabin failed (%d)\n",
                    status);
            return 1;
        }
    }
    montgomery_mr_end = clock();
    if (conventional_probable != montgomery_probable ||
        conventional_probable == 0) {
        fprintf(stderr, "Miller-Rabin implementations disagree\n");
        return 1;
    }

    setup_seconds = (double)(setup_end - setup_start) /
                    (double)CLOCKS_PER_SEC;
    ordinary_seconds = (double)(ordinary_end - ordinary_start) /
                       (double)CLOCKS_PER_SEC;
    montgomery_seconds = (double)(montgomery_end - montgomery_start) /
                         (double)CLOCKS_PER_SEC;
    conventional_mr_seconds =
        (double)(conventional_mr_end - conventional_mr_start) /
        (double)CLOCKS_PER_SEC;
    montgomery_mr_seconds =
        (double)(montgomery_mr_end - montgomery_mr_start) /
        (double)CLOCKS_PER_SEC;

    printf("Week7 Montgomery benchmark\n");
    printf("BIGINT_MAX_BITS: %u\n", (unsigned int)BIGINT_MAX_BITS);
    printf("modulus bits: %u\n", modulus_bits);
    printf("repetitions: %lu\n", repetitions);
    printf("CLOCKS_PER_SEC: %lu\n", (unsigned long)CLOCKS_PER_SEC);
    printf("Montgomery setup seconds: %.6f\n", setup_seconds);
    printf("ordinary total seconds: %.6f\n", ordinary_seconds);
    printf("ordinary seconds per operation: %.9f\n",
           ordinary_seconds / (double)repetitions);
    printf("Montgomery total seconds: %.6f\n", montgomery_seconds);
    printf("Montgomery seconds per operation: %.9f\n",
           montgomery_seconds / (double)repetitions);
    if (montgomery_seconds > 0.0) {
        printf("measured ordinary/Montgomery ratio: %.3f\n",
               ordinary_seconds / montgomery_seconds);
    } else {
        printf("measured ordinary/Montgomery ratio: timer resolution too low\n");
    }
    printf("\nMiller-Rabin candidate bits: %u\n", candidate_bits);
    printf("Miller-Rabin rounds: %u\n",
           (unsigned int)BENCHMARK_MILLER_RABIN_ROUNDS);
    printf("conventional Miller-Rabin total seconds: %.6f\n",
           conventional_mr_seconds);
    printf("conventional Miller-Rabin seconds per operation: %.9f\n",
           conventional_mr_seconds / (double)repetitions);
    printf("Montgomery Miller-Rabin total seconds: %.6f\n",
           montgomery_mr_seconds);
    printf("Montgomery Miller-Rabin seconds per operation: %.9f\n",
           montgomery_mr_seconds / (double)repetitions);
    if (montgomery_mr_seconds > 0.0) {
        printf("measured Miller-Rabin conventional/Montgomery ratio: %.3f\n",
               conventional_mr_seconds / montgomery_mr_seconds);
    } else {
        printf("measured Miller-Rabin conventional/Montgomery ratio: "
               "timer resolution too low\n");
    }
    return 0;
}
