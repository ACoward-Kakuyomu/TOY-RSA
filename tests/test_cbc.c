#if defined(_MSC_VER)
#define _CRT_SECURE_NO_WARNINGS 1
#endif

#include <stdio.h>
#include <string.h>

#include "cbc.h"
#include "des.h"

static int failures = 0;

static void expect_int(const char *name, int actual, int expected)
{
    if (actual != expected) {
        fprintf(stderr, "%s: expected %d, got %d\n",
                name, expected, actual);
        ++failures;
    }
}

static void expect_ulong(const char *name,
                         unsigned long actual,
                         unsigned long expected)
{
    if (actual != expected) {
        fprintf(stderr, "%s: expected %lu, got %lu\n",
                name, expected, actual);
        ++failures;
    }
}

static void expect_bytes(const char *name,
                         const unsigned char *actual,
                         const unsigned char *expected,
                         unsigned long length)
{
    unsigned long index;

    if (memcmp(actual, expected, (size_t)length) == 0) {
        return;
    }
    fprintf(stderr, "%s: byte sequence differs\n  expected:", name);
    for (index = 0UL; index < length; ++index) {
        fprintf(stderr, " %02X", (unsigned int)expected[index]);
    }
    fprintf(stderr, "\n  actual:  ");
    for (index = 0UL; index < length; ++index) {
        fprintf(stderr, " %02X", (unsigned int)actual[index]);
    }
    fprintf(stderr, "\n");
    ++failures;
}

static void make_schedule(DES_KEY_SCHEDULE *schedule)
{
    const unsigned char key[8] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1
    };

    expect_int("common key schedule", des_key_schedule(key, schedule),
               DES_OK);
}

static void test_des_block_vectors(void)
{
    const unsigned char key[8] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1
    };
    const unsigned char plaintext[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const unsigned char expected[8] = {
        0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05
    };
    const unsigned char zero[8] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    const unsigned char expected_zero[8] = {
        0x8c, 0xa6, 0x4d, 0xe9, 0xc1, 0xb1, 0x23, 0xa7
    };
    unsigned char output[8];
    unsigned char restored[8];
    unsigned char in_place[8];
    DES_KEY_SCHEDULE schedule;
    DES_KEY_SCHEDULE zero_schedule;

    expect_int("block key schedule", des_key_schedule(key, &schedule),
               DES_OK);
    expect_int("block encryption status",
               des_encrypt_block(plaintext, output, &schedule), DES_OK);
    expect_bytes("block encryption vector", output, expected, 8UL);
    expect_int("block decryption status",
               des_decrypt_block(output, restored, &schedule), DES_OK);
    expect_bytes("block decryption vector", restored, plaintext, 8UL);

    memcpy(in_place, plaintext, sizeof(in_place));
    expect_int("in-place encryption status",
               des_encrypt_block(in_place, in_place, &schedule), DES_OK);
    expect_bytes("in-place encryption", in_place, expected, 8UL);
    expect_int("in-place decryption status",
               des_decrypt_block(in_place, in_place, &schedule), DES_OK);
    expect_bytes("in-place decryption", in_place, plaintext, 8UL);

    expect_int("zero key schedule",
               des_key_schedule(zero, &zero_schedule), DES_OK);
    expect_int("zero block encryption status",
               des_encrypt_block(zero, output, &zero_schedule), DES_OK);
    expect_bytes("zero block encryption vector",
                 output, expected_zero, 8UL);

    expect_int("block encryption NULL input",
               des_encrypt_block(NULL, output, &schedule), DES_ERR_NULL);
    expect_int("block decryption NULL schedule",
               des_decrypt_block(output, restored, NULL), DES_ERR_NULL);
}

static void test_cbc_known_vector(void)
{
    const unsigned char key[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const unsigned char iv[8] = {
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
    };
    const unsigned char plaintext[24] = {
        0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20,
        0x66, 0x6f, 0x72, 0x20, 0x61, 0x6c, 0x6c, 0x20
    };
    const unsigned char expected[24] = {
        0xe5, 0xc7, 0xcd, 0xde, 0x87, 0x2b, 0xf2, 0x7c,
        0x43, 0xe9, 0x34, 0x00, 0x8c, 0x38, 0x9c, 0x0f,
        0x68, 0x37, 0x88, 0x49, 0x9a, 0x7c, 0x05, 0xf6
    };
    unsigned char ciphertext[24];
    unsigned char restored[24];
    unsigned char in_place[24];
    DES_KEY_SCHEDULE schedule;

    expect_int("CBC vector schedule", des_key_schedule(key, &schedule),
               DES_OK);
    expect_int("CBC vector encryption status",
               des_cbc_encrypt_blocks(plaintext, 24UL, ciphertext,
                                      &schedule, iv), DES_OK);
    expect_bytes("CBC vector encryption", ciphertext, expected, 24UL);
    expect_int("CBC vector decryption status",
               des_cbc_decrypt_blocks(ciphertext, 24UL, restored,
                                      &schedule, iv), DES_OK);
    expect_bytes("CBC vector decryption", restored, plaintext, 24UL);

    memcpy(in_place, plaintext, sizeof(in_place));
    expect_int("CBC in-place encryption status",
               des_cbc_encrypt_blocks(in_place, 24UL, in_place,
                                      &schedule, iv), DES_OK);
    expect_bytes("CBC in-place encryption", in_place, expected, 24UL);
    expect_int("CBC in-place decryption status",
               des_cbc_decrypt_blocks(in_place, 24UL, in_place,
                                      &schedule, iv), DES_OK);
    expect_bytes("CBC in-place decryption", in_place, plaintext, 24UL);

    expect_int("CBC empty blocks",
               des_cbc_encrypt_blocks(NULL, 0UL, NULL, &schedule, iv),
               DES_OK);
    expect_int("CBC non-block length",
               des_cbc_encrypt_blocks(plaintext, 7UL, ciphertext,
                                      &schedule, iv), DES_ERR_LENGTH);
}

static void test_framed_length(unsigned long length)
{
    const unsigned char iv[8] = {
        0xa5, 0x5a, 0xc3, 0x3c, 0x96, 0x69, 0xf0, 0x0f
    };
    unsigned char plaintext[64];
    unsigned char ciphertext[72];
    unsigned char restored[64];
    unsigned long ciphertext_length;
    unsigned long restored_length;
    unsigned long expected_length;
    unsigned long index;
    DES_KEY_SCHEDULE schedule;

    make_schedule(&schedule);
    for (index = 0UL; index < length; ++index) {
        plaintext[index] = (unsigned char)(index * 29UL + 7UL);
    }

    expect_int("framed size status",
               des_cbc_framed_size(length, &expected_length), DES_OK);
    expect_int("framed encryption status",
               des_cbc_encrypt(length == 0UL ? NULL : plaintext,
                               length, ciphertext, sizeof(ciphertext),
                               &ciphertext_length, &schedule, iv), DES_OK);
    expect_ulong("framed ciphertext length",
                 ciphertext_length, expected_length);
    memset(restored, 0x5a, sizeof(restored));
    expect_int("framed decryption status",
               des_cbc_decrypt(ciphertext, ciphertext_length,
                               length == 0UL ? NULL : restored,
                               sizeof(restored), &restored_length,
                               &schedule, iv), DES_OK);
    expect_ulong("framed plaintext length", restored_length, length);
    if (length != 0UL) {
        expect_bytes("framed plaintext", restored, plaintext, length);
    }
}

static void test_framed_buffers(void)
{
    const unsigned char iv[8] = {
        0xa5, 0x5a, 0xc3, 0x3c, 0x96, 0x69, 0xf0, 0x0f
    };
    const unsigned char plaintext[5] = { 1, 2, 3, 4, 5 };
    unsigned char ciphertext[16];
    unsigned char malformed_frame[16];
    unsigned char malformed_ciphertext[16];
    unsigned char output[16];
    unsigned long ciphertext_length;
    unsigned long output_length;
    DES_KEY_SCHEDULE schedule;

    test_framed_length(0UL);
    test_framed_length(1UL);
    test_framed_length(4UL);
    test_framed_length(5UL);
    test_framed_length(8UL);
    test_framed_length(31UL);
    test_framed_length(64UL);

    make_schedule(&schedule);
    expect_int("framed size NULL output",
               des_cbc_framed_size(1UL, NULL), DES_ERR_NULL);
    expect_int("framed size maximum",
               des_cbc_framed_size(DES_CBC_MAX_PLAINTEXT,
                                   &ciphertext_length), DES_OK);
    expect_ulong("maximum framed size", ciphertext_length,
                 DES_CBC_MAX_CIPHERTEXT);
    expect_int("framed size over maximum",
               des_cbc_framed_size(DES_CBC_MAX_PLAINTEXT + 1UL,
                                   &ciphertext_length), DES_ERR_LENGTH);
    expect_int("framed output capacity",
               des_cbc_encrypt(plaintext, 5UL, ciphertext, 8UL,
                               &ciphertext_length, &schedule, iv),
               DES_ERR_CAPACITY);
    expect_int("framed encryption alias",
               des_cbc_encrypt(ciphertext, 5UL, ciphertext,
                               sizeof(ciphertext), &ciphertext_length,
                               &schedule, iv), DES_ERR_ALIAS);
    expect_int("framed invalid ciphertext length",
               des_cbc_decrypt(ciphertext, 7UL, output, sizeof(output),
                               &output_length, &schedule, iv),
               DES_ERR_LENGTH);

    memset(malformed_frame, 0, sizeof(malformed_frame));
    malformed_frame[3] = 1U;
    malformed_frame[4] = 0x41U;
    malformed_frame[5] = 1U;
    expect_int("encrypt malformed padding frame",
               des_cbc_encrypt_blocks(malformed_frame, 8UL,
                                      malformed_ciphertext,
                                      &schedule, iv), DES_OK);
    expect_int("reject nonzero frame padding",
               des_cbc_decrypt(malformed_ciphertext, 8UL,
                               output, sizeof(output), &output_length,
                               &schedule, iv), DES_ERR_FORMAT);

    memset(malformed_frame, 0, sizeof(malformed_frame));
    expect_int("encrypt mismatched frame length",
               des_cbc_encrypt_blocks(malformed_frame, 16UL,
                                      malformed_ciphertext,
                                      &schedule, iv), DES_OK);
    expect_int("reject mismatched stored length",
               des_cbc_decrypt(malformed_ciphertext, 16UL,
                               output, sizeof(output), &output_length,
                               &schedule, iv), DES_ERR_FORMAT);

    expect_int("valid framed encryption for capacity test",
               des_cbc_encrypt(plaintext, 5UL, ciphertext,
                               sizeof(ciphertext), &ciphertext_length,
                               &schedule, iv), DES_OK);
    expect_int("framed decrypt capacity",
               des_cbc_decrypt(ciphertext, ciphertext_length,
                               output, 4UL, &output_length,
                               &schedule, iv), DES_ERR_CAPACITY);
}

static int write_bytes(FILE *file,
                       const unsigned char *data,
                       unsigned long length)
{
    if (length != 0UL &&
        fwrite(data, 1U, (size_t)length, file) != (size_t)length) {
        return 0;
    }
    return fflush(file) == 0;
}

static void test_file_length(unsigned long length)
{
    const unsigned char iv[8] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe
    };
    unsigned char plaintext[48];
    unsigned char restored[48];
    unsigned long ciphertext_length;
    unsigned long restored_length;
    unsigned long index;
    FILE *plain_file;
    FILE *cipher_file;
    FILE *restored_file;
    DES_KEY_SCHEDULE schedule;

    plain_file = tmpfile();
    cipher_file = tmpfile();
    restored_file = tmpfile();
    if (plain_file == NULL || cipher_file == NULL || restored_file == NULL) {
        fprintf(stderr, "tmpfile creation failed\n");
        ++failures;
        if (plain_file != NULL) {
            fclose(plain_file);
        }
        if (cipher_file != NULL) {
            fclose(cipher_file);
        }
        if (restored_file != NULL) {
            fclose(restored_file);
        }
        return;
    }

    for (index = 0UL; index < length; ++index) {
        plaintext[index] = (unsigned char)(0xd3UL - index * 3UL);
    }
    if (!write_bytes(plain_file, plaintext, length)) {
        fprintf(stderr, "plain file setup failed\n");
        ++failures;
    }
    rewind(plain_file);
    make_schedule(&schedule);
    expect_int("file encryption status",
               des_cbc_encrypt_file(plain_file, cipher_file, length,
                                    &schedule, iv), DES_OK);
    expect_int("file cipher flush", fflush(cipher_file), 0);
    expect_int("file cipher seek", fseek(cipher_file, 0L, SEEK_END), 0);
    ciphertext_length = (unsigned long)ftell(cipher_file);
    expect_int("file framed size status",
               des_cbc_framed_size(length, &restored_length), DES_OK);
    expect_ulong("file ciphertext length",
                 ciphertext_length, restored_length);

    rewind(cipher_file);
    expect_int("file decryption status",
               des_cbc_decrypt_file(cipher_file, restored_file,
                                    ciphertext_length, &restored_length,
                                    &schedule, iv), DES_OK);
    expect_ulong("file plaintext length", restored_length, length);
    expect_int("restored file flush", fflush(restored_file), 0);
    rewind(restored_file);
    memset(restored, 0, sizeof(restored));
    if (length != 0UL &&
        fread(restored, 1U, (size_t)length, restored_file) !=
        (size_t)length) {
        fprintf(stderr, "restored file read failed\n");
        ++failures;
    }
    if (length != 0UL) {
        expect_bytes("file plaintext", restored, plaintext, length);
    }

    fclose(plain_file);
    fclose(cipher_file);
    fclose(restored_file);
}

static void test_file_interfaces(void)
{
    const unsigned char iv[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    const unsigned char short_data[2] = { 1, 2 };
    FILE *input;
    FILE *output;
    DES_KEY_SCHEDULE schedule;

    test_file_length(0UL);
    test_file_length(3UL);
    test_file_length(8UL);
    test_file_length(37UL);

    input = tmpfile();
    output = tmpfile();
    if (input == NULL || output == NULL) {
        fprintf(stderr, "tmpfile creation for short input failed\n");
        ++failures;
        if (input != NULL) {
            fclose(input);
        }
        if (output != NULL) {
            fclose(output);
        }
        return;
    }
    make_schedule(&schedule);
    if (!write_bytes(input, short_data, 2UL)) {
        fprintf(stderr, "short file setup failed\n");
        ++failures;
    }
    rewind(input);
    expect_int("short file input rejection",
               des_cbc_encrypt_file(input, output, 3UL, &schedule, iv),
               DES_ERR_IO);
    expect_int("same file rejection",
               des_cbc_encrypt_file(input, input, 0UL, &schedule, iv),
               DES_ERR_ALIAS);
    fclose(input);
    fclose(output);
}

int main(void)
{
    test_des_block_vectors();
    test_cbc_known_vector();
    test_framed_buffers();
    test_file_interfaces();

    if (failures != 0) {
        fprintf(stderr, "%d Week2 test(s) failed\n", failures);
        return 1;
    }
    printf("All Week2 DES and CBC tests passed.\n");
    return 0;
}
