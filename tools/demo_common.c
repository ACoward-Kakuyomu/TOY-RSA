#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbc.h"
#include "demo_common.h"
#include "hybrid.h"

#define DEMO_ENTROPY_MIN 8UL
#define DEMO_ENTROPY_MAX 4096UL
#define DEMO_COPY_BUFFER 4096U

static int same_path(const char *left, const char *right)
{
    return strcmp(left, right) == 0;
}

static int file_length(FILE *file, unsigned long *length)
{
    long position;

    if (fseek(file, 0L, SEEK_END) != 0) {
        return 0;
    }
    position = ftell(file);
    if (position < 0L || fseek(file, 0L, SEEK_SET) != 0) {
        return 0;
    }
    *length = (unsigned long)position;
    return 1;
}

static int load_file(const char *path,
                     unsigned long maximum_length,
                     unsigned char **data,
                     unsigned long *length)
{
    FILE *file;
    unsigned char *buffer;
    unsigned long file_size;

    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "cannot open input file: %s\n", path);
        return 0;
    }
    if (!file_length(file, &file_size) || file_size > maximum_length ||
        (unsigned long)(size_t)file_size != file_size) {
        fprintf(stderr, "input file is too large or unreadable: %s\n",
                path);
        fclose(file);
        return 0;
    }
    buffer = NULL;
    if (file_size != 0UL) {
        buffer = (unsigned char *)malloc((size_t)file_size);
        if (buffer == NULL) {
            fprintf(stderr, "not enough memory for: %s\n", path);
            fclose(file);
            return 0;
        }
        if (fread(buffer, 1U, (size_t)file_size, file) !=
            (size_t)file_size) {
            fprintf(stderr, "cannot read input file: %s\n", path);
            memset(buffer, 0, (size_t)file_size);
            free(buffer);
            fclose(file);
            return 0;
        }
    }
    if (fclose(file) != 0) {
        fprintf(stderr, "cannot close input file: %s\n", path);
        if (buffer != NULL) {
            memset(buffer, 0, (size_t)file_size);
            free(buffer);
        }
        return 0;
    }
    *data = buffer;
    *length = file_size;
    return 1;
}

static int write_file(const char *path,
                      const unsigned char *data,
                      unsigned long length)
{
    FILE *file;
    int ok;

    file = fopen(path, "wb");
    if (file == NULL) {
        fprintf(stderr, "cannot open output file: %s\n", path);
        return 0;
    }
    ok = length == 0UL ||
        fwrite(data, 1U, (size_t)length, file) == (size_t)length;
    if (fclose(file) != 0) {
        ok = 0;
    }
    if (!ok) {
        fprintf(stderr, "cannot write output file: %s\n", path);
    }
    return ok;
}

static int copy_temporary_file(FILE *temporary, const char *output_path)
{
    FILE *output;
    unsigned char buffer[DEMO_COPY_BUFFER];
    size_t count;
    int ok;

    if (fseek(temporary, 0L, SEEK_SET) != 0) {
        fprintf(stderr, "cannot rewind temporary output\n");
        return 0;
    }
    output = fopen(output_path, "wb");
    if (output == NULL) {
        fprintf(stderr, "cannot open output file: %s\n", output_path);
        return 0;
    }
    ok = 1;
    for (;;) {
        count = fread(buffer, 1U, sizeof(buffer), temporary);
        if (count != 0U && fwrite(buffer, 1U, count, output) != count) {
            ok = 0;
            break;
        }
        if (count < sizeof(buffer)) {
            if (ferror(temporary)) {
                ok = 0;
            }
            break;
        }
    }
    if (fclose(output) != 0) {
        ok = 0;
    }
    if (!ok) {
        fprintf(stderr, "cannot write output file: %s\n", output_path);
    }
    return ok;
}

static int hex_value(char character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

static int parse_hex_block(const char *text,
                           unsigned char output[DES_BLOCK_BYTES])
{
    unsigned int index;
    int high;
    int low;

    if (strlen(text) != DES_BLOCK_BYTES * 2U) {
        return 0;
    }
    for (index = 0U; index < DES_BLOCK_BYTES; ++index) {
        high = hex_value(text[index * 2U]);
        low = hex_value(text[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return 0;
        }
        output[index] = (unsigned char)((high << 4) | low);
    }
    return 1;
}

int demo_run_des_file(int encrypting,
                      const char *key_text,
                      const char *iv_text,
                      const char *input_path,
                      const char *output_path)
{
    FILE *input;
    FILE *temporary;
    DES_KEY_SCHEDULE schedule;
    unsigned char key[DES_BLOCK_BYTES];
    unsigned char iv[DES_BLOCK_BYTES];
    unsigned long input_length;
    unsigned long output_length;
    int status;
    int ok;

    if (same_path(input_path, output_path)) {
        fprintf(stderr, "input and output paths must differ\n");
        return 0;
    }
    if (!parse_hex_block(key_text, key) ||
        !parse_hex_block(iv_text, iv)) {
        fprintf(stderr, "DES key and IV must each be 16 hex digits\n");
        return 0;
    }
    status = des_key_schedule(key, &schedule);
    if (status != DES_OK) {
        fprintf(stderr, "DES key schedule failed: %d\n", status);
        return 0;
    }
    input = fopen(input_path, "rb");
    if (input == NULL) {
        fprintf(stderr, "cannot open input file: %s\n", input_path);
        return 0;
    }
    if (!file_length(input, &input_length)) {
        fprintf(stderr, "cannot determine input length: %s\n", input_path);
        fclose(input);
        return 0;
    }
    temporary = tmpfile();
    if (temporary == NULL) {
        fprintf(stderr, "cannot create temporary output\n");
        fclose(input);
        return 0;
    }
    output_length = 0UL;
    if (encrypting) {
        status = des_cbc_encrypt_file(input, temporary, input_length,
                                      &schedule, iv);
        if (status == DES_OK) {
            status = des_cbc_framed_size(input_length, &output_length);
        }
    } else {
        status = des_cbc_decrypt_file(input, temporary, input_length,
                                      &output_length, &schedule, iv);
    }
    ok = status == DES_OK;
    if (!ok) {
        fprintf(stderr, "DES-CBC %s failed: %d\n",
                encrypting ? "encryption" : "decryption", status);
    }
    if (fclose(input) != 0) {
        ok = 0;
    }
    if (ok) {
        ok = copy_temporary_file(temporary, output_path);
    }
    fclose(temporary);
    memset(&schedule, 0, sizeof(schedule));
    memset(key, 0, sizeof(key));
    if (ok) {
        printf("DES-CBC %s: %lu -> %lu bytes\n",
               encrypting ? "encrypted" : "decrypted",
               input_length, output_length);
    }
    return ok;
}

int demo_parse_bits(const char *text, unsigned int *bits)
{
    char *end;
    unsigned long value;

    errno = 0;
    end = NULL;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > UINT_MAX) {
        return 0;
    }
    *bits = (unsigned int)value;
    return 1;
}

static int init_rng_from_file(const char *path,
                              RNG_CTX *rng,
                              unsigned char **entropy,
                              unsigned long *entropy_length)
{
    int status;

    if (!load_file(path, DEMO_ENTROPY_MAX, entropy, entropy_length)) {
        return 0;
    }
    if (*entropy_length < DEMO_ENTROPY_MIN) {
        fprintf(stderr, "entropy file must contain at least 8 bytes\n");
        if (*entropy != NULL) {
            memset(*entropy, 0, (size_t)*entropy_length);
            free(*entropy);
            *entropy = NULL;
        }
        return 0;
    }
    status = rng_init(rng, *entropy, *entropy_length);
    if (status != RNG_OK) {
        fprintf(stderr, "RNG initialization failed: %d\n", status);
        memset(*entropy, 0, (size_t)*entropy_length);
        free(*entropy);
        *entropy = NULL;
        return 0;
    }
    return 1;
}

int demo_run_rsa_keygen(const char *entropy_path,
                        const char *public_path,
                        const char *private_path,
                        unsigned int bits)
{
    RNG_CTX rng;
    RSA_PRIVATE_KEY private_key;
    RSA_KEYGEN_STATS statistics;
    unsigned char *entropy;
    unsigned long entropy_length;
    unsigned char public_data[RSA_PUBLIC_KEY_MAX_SERIALIZED];
    unsigned char private_data[RSA_PRIVATE_KEY_MAX_SERIALIZED];
    unsigned int public_length;
    unsigned int private_length;
    int status;
    int ok;

    if (same_path(public_path, private_path) ||
        same_path(entropy_path, public_path) ||
        same_path(entropy_path, private_path)) {
        fprintf(stderr, "entropy, public, and private paths must differ\n");
        return 0;
    }
    entropy = NULL;
    entropy_length = 0UL;
    if (!init_rng_from_file(entropy_path, &rng, &entropy,
                            &entropy_length)) {
        return 0;
    }
    status = rsa_generate_key(&rng, bits, 12U, 100000UL, 256U,
                              &private_key, &statistics);
    if (status != RSA_OK) {
        fprintf(stderr, "RSA key generation failed: %d\n", status);
        ok = 0;
        goto cleanup;
    }
    public_length = 0U;
    status = rsa_serialize_public_key(&private_key.public_key,
                                      public_data, sizeof(public_data),
                                      &public_length);
    if (status != RSA_OK) {
        fprintf(stderr, "public key serialization failed: %d\n", status);
        ok = 0;
        goto cleanup;
    }
    private_length = 0U;
    status = rsa_serialize_private_key(&private_key,
                                       private_data, sizeof(private_data),
                                       &private_length);
    if (status != RSA_OK) {
        fprintf(stderr, "private key serialization failed: %d\n", status);
        ok = 0;
        goto cleanup;
    }
    ok = write_file(public_path, public_data,
                    (unsigned long)public_length) &&
        write_file(private_path, private_data,
                   (unsigned long)private_length);
    if (ok) {
        printf("RSA key generated: %u bits\n", bits);
        printf("prime candidates: p=%lu, q=%lu, restarts=%u\n",
               statistics.p_candidates, statistics.q_candidates,
               statistics.restarts);
        printf("public key: %s\nprivate key: %s\n",
               public_path, private_path);
    }

cleanup:
    if (entropy != NULL) {
        memset(entropy, 0, (size_t)entropy_length);
        free(entropy);
    }
    memset(&rng, 0, sizeof(rng));
    memset(&private_key, 0, sizeof(private_key));
    memset(private_data, 0, sizeof(private_data));
    return ok;
}

static int load_public_key(const char *path, RSA_PUBLIC_KEY *key)
{
    unsigned char *data;
    unsigned long length;
    int status;

    data = NULL;
    if (!load_file(path, RSA_PUBLIC_KEY_MAX_SERIALIZED, &data, &length)) {
        return 0;
    }
    status = rsa_deserialize_public_key(data, (unsigned int)length, key);
    if (data != NULL) {
        free(data);
    }
    if (status != RSA_OK) {
        fprintf(stderr, "invalid public key file: %s (status %d)\n",
                path, status);
        return 0;
    }
    return 1;
}

static int load_private_key(const char *path, RSA_PRIVATE_KEY *key)
{
    unsigned char *data;
    unsigned long length;
    int status;

    data = NULL;
    if (!load_file(path, RSA_PRIVATE_KEY_MAX_SERIALIZED, &data, &length)) {
        return 0;
    }
    status = rsa_deserialize_private_key(data, (unsigned int)length, key);
    if (data != NULL) {
        memset(data, 0, (size_t)length);
        free(data);
    }
    if (status != RSA_OK) {
        fprintf(stderr, "invalid private key file: %s (status %d)\n",
                path, status);
        return 0;
    }
    return 1;
}

int demo_run_hybrid_encrypt(const char *public_path,
                            const char *entropy_path,
                            const char *input_path,
                            const char *output_path)
{
    RSA_PUBLIC_KEY public_key;
    RNG_CTX rng;
    unsigned char *entropy;
    unsigned char *plaintext;
    unsigned char *ciphertext;
    unsigned long entropy_length;
    unsigned long plaintext_length;
    unsigned long required;
    unsigned long actual;
    int status;
    int ok;

    if (same_path(output_path, public_path) ||
        same_path(output_path, entropy_path) ||
        same_path(output_path, input_path)) {
        fprintf(stderr, "output path must differ from all input paths\n");
        return 0;
    }
    if (!load_public_key(public_path, &public_key)) {
        return 0;
    }
    entropy = NULL;
    entropy_length = 0UL;
    if (!init_rng_from_file(entropy_path, &rng, &entropy,
                            &entropy_length)) {
        return 0;
    }
    plaintext = NULL;
    plaintext_length = 0UL;
    ciphertext = NULL;
    required = 0UL;
    ok = 0;
    if (!load_file(input_path, HYBRID_MAX_PLAINTEXT,
                   &plaintext, &plaintext_length)) {
        goto cleanup;
    }
    status = hybrid_ciphertext_size(&public_key, plaintext_length,
                                    &required);
    if (status != HYBRID_OK ||
        (unsigned long)(size_t)required != required) {
        fprintf(stderr, "hybrid ciphertext sizing failed: %d\n", status);
        goto cleanup;
    }
    ciphertext = (unsigned char *)malloc((size_t)required);
    if (ciphertext == NULL) {
        fprintf(stderr, "not enough memory for hybrid ciphertext\n");
        goto cleanup;
    }
    actual = 0UL;
    status = hybrid_encrypt(&public_key, &rng, plaintext, plaintext_length,
                            ciphertext, required, &actual);
    if (status != HYBRID_OK) {
        fprintf(stderr, "hybrid encryption failed: %d\n", status);
        goto cleanup;
    }
    ok = write_file(output_path, ciphertext, actual);
    if (ok) {
        printf("hybrid encrypted: %lu -> %lu bytes\n",
               plaintext_length, actual);
    }

cleanup:
    if (entropy != NULL) {
        memset(entropy, 0, (size_t)entropy_length);
        free(entropy);
    }
    if (plaintext != NULL) {
        free(plaintext);
    }
    if (ciphertext != NULL) {
        memset(ciphertext, 0, (size_t)required);
        free(ciphertext);
    }
    memset(&rng, 0, sizeof(rng));
    return ok;
}

int demo_run_hybrid_decrypt(const char *private_path,
                            const char *input_path,
                            const char *output_path)
{
    RSA_PRIVATE_KEY private_key;
    unsigned char *ciphertext;
    unsigned char *plaintext;
    unsigned long ciphertext_length;
    unsigned long plaintext_capacity;
    unsigned long plaintext_length;
    int status;
    int ok;

    if (same_path(output_path, private_path) ||
        same_path(output_path, input_path)) {
        fprintf(stderr, "output path must differ from all input paths\n");
        return 0;
    }
    if (!load_private_key(private_path, &private_key)) {
        return 0;
    }
    ciphertext = NULL;
    ciphertext_length = 0UL;
    plaintext = NULL;
    plaintext_capacity = 0UL;
    ok = 0;
    if (!load_file(input_path, 0xffffffffUL,
                   &ciphertext, &ciphertext_length)) {
        goto cleanup;
    }
    plaintext_capacity = ciphertext_length;
    if (plaintext_capacity != 0UL) {
        plaintext = (unsigned char *)malloc((size_t)plaintext_capacity);
        if (plaintext == NULL) {
            fprintf(stderr, "not enough memory for hybrid plaintext\n");
            goto cleanup;
        }
    }
    plaintext_length = 0UL;
    status = hybrid_decrypt(&private_key, ciphertext, ciphertext_length,
                            plaintext, plaintext_capacity,
                            &plaintext_length);
    if (status != HYBRID_OK) {
        fprintf(stderr, "hybrid decryption failed: %d\n", status);
        goto cleanup;
    }
    ok = write_file(output_path, plaintext, plaintext_length);
    if (ok) {
        printf("hybrid decrypted: %lu -> %lu bytes\n",
               ciphertext_length, plaintext_length);
    }

cleanup:
    if (ciphertext != NULL) {
        free(ciphertext);
    }
    if (plaintext != NULL) {
        memset(plaintext, 0, (size_t)plaintext_capacity);
        free(plaintext);
    }
    memset(&private_key, 0, sizeof(private_key));
    return ok;
}
