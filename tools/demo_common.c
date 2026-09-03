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
