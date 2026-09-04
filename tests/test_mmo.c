#include <stdio.h>
#include <string.h>

#include "mmo.h"

static int failures = 0;

static void expect_int(const char *name, int actual, int expected)
{
    if (actual != expected) {
        fprintf(stderr, "%s: expected %d, got %d\n",
                name, expected, actual);
        ++failures;
    }
}

static void expect_bytes(const char *name,
                         const unsigned char *actual,
                         const unsigned char *expected,
                         unsigned int length)
{
    unsigned int index;

    if (memcmp(actual, expected, length) == 0) {
        return;
    }
    fprintf(stderr, "%s: byte sequence differs\n  expected:", name);
    for (index = 0U; index < length; ++index) {
        fprintf(stderr, " %02X", (unsigned int)expected[index]);
    }
    fprintf(stderr, "\n  actual:  ");
    for (index = 0U; index < length; ++index) {
        fprintf(stderr, " %02X", (unsigned int)actual[index]);
    }
    fprintf(stderr, "\n");
    ++failures;
}

static void expect_different(const char *name,
                             const unsigned char *left,
                             const unsigned char *right,
                             unsigned int length)
{
    if (memcmp(left, right, length) == 0) {
        fprintf(stderr, "%s: digests unexpectedly match\n", name);
        ++failures;
    }
}

static void test_vector(const char *name,
                        const unsigned char *message,
                        unsigned long length,
                        const unsigned char expected[MMO_DIGEST_BYTES])
{
    unsigned char digest[MMO_DIGEST_BYTES];

    expect_int(name, mmo_hash(message, length, digest), MMO_OK);
    expect_bytes(name, digest, expected, MMO_DIGEST_BYTES);
}

static void test_stable_vectors(void)
{
    static const unsigned char binary[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const unsigned char quick[] =
        "The quick brown fox jumps over the lazy dog";
    static const unsigned char empty_digest[8] = {
        0x5a, 0xf4, 0x78, 0x9a, 0x3f, 0x93, 0xd6, 0xeb
    };
    static const unsigned char a_digest[8] = {
        0x92, 0x91, 0xdc, 0x55, 0x8e, 0x92, 0x81, 0x26
    };
    static const unsigned char abc_digest[8] = {
        0x76, 0xea, 0x4b, 0xef, 0x6b, 0x36, 0x51, 0xfb
    };
    static const unsigned char quick_digest[8] = {
        0x55, 0xfb, 0x1f, 0xf0, 0x68, 0xc2, 0x9c, 0xa2
    };
    static const unsigned char binary_digest[8] = {
        0x6c, 0x21, 0xa9, 0xe2, 0x1f, 0x66, 0xff, 0x22
    };

    test_vector("empty vector", NULL, 0UL, empty_digest);
    test_vector("a vector", (const unsigned char *)"a", 1UL, a_digest);
    test_vector("abc vector", (const unsigned char *)"abc", 3UL,
                abc_digest);
    test_vector("quick vector", quick,
                (unsigned long)sizeof(quick) - 1UL, quick_digest);
    test_vector("binary vector", binary, 16UL, binary_digest);
}

static void test_streaming_splits(void)
{
    unsigned char message[37];
    unsigned char one_shot[MMO_DIGEST_BYTES];
    unsigned char split[MMO_DIGEST_BYTES];
    unsigned char bytewise[MMO_DIGEST_BYTES];
    unsigned long index;
    MMO_CTX context;

    for (index = 0UL; index < (unsigned long)sizeof(message); ++index) {
        message[index] = (unsigned char)(index * 17UL + 3UL);
    }
    expect_int("one-shot split reference",
               mmo_hash(message, (unsigned long)sizeof(message), one_shot),
               MMO_OK);

    expect_int("split init", mmo_init(&context), MMO_OK);
    expect_int("split first", mmo_update(&context, message, 3UL), MMO_OK);
    expect_int("split empty NULL",
               mmo_update(&context, NULL, 0UL), MMO_OK);
    expect_int("split second",
               mmo_update(&context, message + 3, 8UL), MMO_OK);
    expect_int("split third",
               mmo_update(&context, message + 11, 1UL), MMO_OK);
    expect_int("split remainder",
               mmo_update(&context, message + 12,
                          (unsigned long)sizeof(message) - 12UL), MMO_OK);
    expect_int("split final", mmo_final(&context, split), MMO_OK);
    expect_bytes("split equals one-shot", split, one_shot,
                 MMO_DIGEST_BYTES);

    expect_int("bytewise init", mmo_init(&context), MMO_OK);
    for (index = 0UL; index < (unsigned long)sizeof(message); ++index) {
        expect_int("bytewise update",
                   mmo_update(&context, message + index, 1UL), MMO_OK);
    }
    expect_int("bytewise final", mmo_final(&context, bytewise), MMO_OK);
    expect_bytes("bytewise equals one-shot", bytewise, one_shot,
                 MMO_DIGEST_BYTES);
}

static void test_boundary_length(unsigned long length)
{
    unsigned char message[16];
    unsigned char one_shot[MMO_DIGEST_BYTES];
    unsigned char split[MMO_DIGEST_BYTES];
    unsigned long first;
    unsigned long index;
    MMO_CTX context;

    for (index = 0UL; index < length; ++index) {
        message[index] = (unsigned char)(0xa0UL + index);
    }
    expect_int("boundary one-shot",
               mmo_hash(message, length, one_shot), MMO_OK);
    expect_int("boundary init", mmo_init(&context), MMO_OK);
    first = length / 2UL;
    expect_int("boundary first update",
               mmo_update(&context, message, first), MMO_OK);
    expect_int("boundary second update",
               mmo_update(&context, message + first, length - first),
               MMO_OK);
    expect_int("boundary final", mmo_final(&context, split), MMO_OK);
    expect_bytes("boundary split equality", split, one_shot,
                 MMO_DIGEST_BYTES);
}

static void test_block_boundaries(void)
{
    test_boundary_length(7UL);
    test_boundary_length(8UL);
    test_boundary_length(9UL);
    test_boundary_length(16UL);
}

static void test_message_changes(void)
{
    const unsigned char first[8] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80
    };
    const unsigned char changed[8] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x81
    };
    const unsigned char with_zero[9] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x00
    };
    unsigned char first_digest[MMO_DIGEST_BYTES];
    unsigned char changed_digest[MMO_DIGEST_BYTES];
    unsigned char zero_digest[MMO_DIGEST_BYTES];

    expect_int("change first hash",
               mmo_hash(first, 8UL, first_digest), MMO_OK);
    expect_int("change bit hash",
               mmo_hash(changed, 8UL, changed_digest), MMO_OK);
    expect_int("trailing zero hash",
               mmo_hash(with_zero, 9UL, zero_digest), MMO_OK);
    expect_different("one-bit message change", first_digest,
                     changed_digest, MMO_DIGEST_BYTES);
    expect_different("trailing zero framing", first_digest,
                     zero_digest, MMO_DIGEST_BYTES);
}

static void test_state_and_errors(void)
{
    const unsigned char byte = 0x42U;
    unsigned char digest[MMO_DIGEST_BYTES];
    MMO_CTX context;

    memset(&context, 0, sizeof(context));
    expect_int("uninitialized update",
               mmo_update(&context, &byte, 1UL), MMO_ERR_STATE);
    expect_int("uninitialized final",
               mmo_final(&context, digest), MMO_ERR_STATE);
    expect_int("NULL init", mmo_init(NULL), MMO_ERR_NULL);
    expect_int("NULL one-shot digest",
               mmo_hash(&byte, 1UL, NULL), MMO_ERR_NULL);
    expect_int("NULL one-shot data",
               mmo_hash(NULL, 1UL, digest), MMO_ERR_NULL);

    expect_int("state init", mmo_init(&context), MMO_OK);
    expect_int("nonempty NULL update",
               mmo_update(&context, NULL, 1UL), MMO_ERR_NULL);
    expect_int("state valid update",
               mmo_update(&context, &byte, 1UL), MMO_OK);
    expect_int("NULL final digest",
               mmo_final(&context, NULL), MMO_ERR_NULL);
    expect_int("state final", mmo_final(&context, digest), MMO_OK);
    expect_int("double final",
               mmo_final(&context, digest), MMO_ERR_STATE);
    expect_int("update after final",
               mmo_update(&context, &byte, 1UL), MMO_ERR_STATE);

    expect_int("overflow init", mmo_init(&context), MMO_OK);
    context.length_high = 0xffffffffUL;
    context.length_low = 0xffffffffUL;
    expect_int("length overflow",
               mmo_update(&context, &byte, 1UL), MMO_ERR_LENGTH);
    expect_int("overflow state", context.state, MMO_STATE_ERROR);
    expect_int("update after overflow",
               mmo_update(&context, &byte, 1UL), MMO_ERR_STATE);
}

int main(void)
{
    test_stable_vectors();
    test_streaming_splits();
    test_block_boundaries();
    test_message_changes();
    test_state_and_errors();
    if (failures != 0) {
        fprintf(stderr, "%d MMO test(s) failed\n", failures);
        return 1;
    }
    printf("All Week3 MMO digest tests passed.\n");
    return 0;
}
