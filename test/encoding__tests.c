/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>
#include <string.h>

#include "../src/base/encoding/compress.h"
#include "../src/base/encoding/encoding.h"
#include "../src/base/errors.h" /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* a caesar mock encoding shifts every byte by a key held in ctx; it is order-sensitive when stacked
 * with the prefix mock, so a wrong decode order corrupts the result and the round-trip test catches
 * it */
#define TEST_ENCODING_ID_CAESAR       16
#define TEST_ENCODING_ID_PREFIX       17
#define TEST_ENCODING_ID_UNREGISTERED 200
#define TEST_PREFIX_BYTE              0xAB

static int caesar_encode(void *ctx, const uint8_t *src, size_t n, uint8_t **dst, size_t *dn)
{
    const uint8_t key = *(const uint8_t *)ctx;
    uint8_t *out = malloc(n ? n : 1);
    if (!out) return TDB_ERR_MEMORY;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(src[i] + key);
    *dst = out;
    *dn = n;
    return TDB_SUCCESS;
}

static int caesar_decode(void *ctx, const uint8_t *src, size_t n, uint8_t **dst, size_t *dn)
{
    const uint8_t key = *(const uint8_t *)ctx;
    uint8_t *out = malloc(n ? n : 1);
    if (!out) return TDB_ERR_MEMORY;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(src[i] - key);
    *dst = out;
    *dn = n;
    return TDB_SUCCESS;
}

/* the prefix mock prepends a marker byte on encode and strips it on decode, changing the length so
 * a mis-ordered pipeline is detectable both in the bytes and in the size */
static int prefix_encode(void *ctx, const uint8_t *src, size_t n, uint8_t **dst, size_t *dn)
{
    (void)ctx;
    uint8_t *out = malloc(n + 1);
    if (!out) return TDB_ERR_MEMORY;
    out[0] = TEST_PREFIX_BYTE;
    if (n) memcpy(out + 1, src, n);
    *dst = out;
    *dn = n + 1;
    return TDB_SUCCESS;
}

static int prefix_decode(void *ctx, const uint8_t *src, size_t n, uint8_t **dst, size_t *dn)
{
    (void)ctx;
    if (n < 1 || src[0] != TEST_PREFIX_BYTE) return TDB_ERR_CORRUPTION;
    uint8_t *out = malloc(n - 1 ? n - 1 : 1);
    if (!out) return TDB_ERR_MEMORY;
    if (n - 1) memcpy(out, src + 1, n - 1);
    *dst = out;
    *dn = n - 1;
    return TDB_SUCCESS;
}

/* init registers "none" and every compiled-in compression backend, each resolvable by name and id
 */
void test_registry_builtins(void)
{
    tidesdb_encoding_registry_t reg;
    ASSERT_EQ(tidesdb_encoding_registry_init(&reg), TDB_SUCCESS);

    const tidesdb_encoding_t *none = tidesdb_encoding_find_by_name(&reg, TDB_ENCODING_NAME_NONE);
    ASSERT_TRUE(none != NULL);
    ASSERT_EQ(none->id, TDB_COMPRESS_NONE);
    ASSERT_TRUE(tidesdb_encoding_find_by_id(&reg, TDB_COMPRESS_NONE) == none);

    /* whatever the build compiled in must round-trip name and id resolution to the same entry */
    if (tidesdb_compression_available(TDB_COMPRESS_ZSTD))
    {
        const tidesdb_encoding_t *z = tidesdb_encoding_find_by_name(&reg, TDB_ENCODING_NAME_ZSTD);
        ASSERT_TRUE(z != NULL);
        ASSERT_EQ(z->id, TDB_COMPRESS_ZSTD);
        ASSERT_TRUE(tidesdb_encoding_find_by_id(&reg, TDB_COMPRESS_ZSTD) == z);
    }

    ASSERT_TRUE(tidesdb_encoding_find_by_name(&reg, "does_not_exist") == NULL);
    ASSERT_TRUE(tidesdb_encoding_find_by_id(&reg, TEST_ENCODING_ID_UNREGISTERED) == NULL);
}

/* register rejects bad arguments, a duplicate name, a duplicate id, and a full registry */
void test_register_validation(void)
{
    tidesdb_encoding_registry_t reg;
    ASSERT_EQ(tidesdb_encoding_registry_init(&reg), TDB_SUCCESS);
    uint8_t key = 3;

    ASSERT_EQ(tidesdb_encoding_register(NULL, "x", TEST_ENCODING_ID_CAESAR, caesar_encode,
                                        caesar_decode, &key),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_encoding_register(&reg, NULL, TEST_ENCODING_ID_CAESAR, caesar_encode,
                                        caesar_decode, &key),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_encoding_register(&reg, "", TEST_ENCODING_ID_CAESAR, caesar_encode,
                                        caesar_decode, &key),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_encoding_register(&reg, "caesar", TEST_ENCODING_ID_CAESAR, NULL,
                                        caesar_decode, &key),
              TDB_ERR_INVALID_ARGS);

    ASSERT_EQ(tidesdb_encoding_register(&reg, "caesar", TEST_ENCODING_ID_CAESAR, caesar_encode,
                                        caesar_decode, &key),
              TDB_SUCCESS);
    /* a second registration under the same name is rejected */
    ASSERT_EQ(tidesdb_encoding_register(&reg, "caesar", TEST_ENCODING_ID_PREFIX, caesar_encode,
                                        caesar_decode, &key),
              TDB_ERR_EXISTS);
    /* a different name reusing the same id is rejected */
    ASSERT_EQ(tidesdb_encoding_register(&reg, "caesar2", TEST_ENCODING_ID_CAESAR, caesar_encode,
                                        caesar_decode, &key),
              TDB_ERR_EXISTS);

    /* filling the registry past capacity reports the limit rather than overrunning */
    int rc = TDB_SUCCESS;
    char name[TDB_ENCODING_NAME_MAX];
    for (int i = 0; i < TDB_ENCODING_REGISTRY_MAX + 5; i++)
    {
        snprintf(name, sizeof(name), "filler_%d", i);
        rc = tidesdb_encoding_register(&reg, name, (uint8_t)(50 + i), caesar_encode, caesar_decode,
                                       &key);
        if (rc != TDB_SUCCESS) break;
    }
    ASSERT_EQ(rc, TDB_ERR_MEMORY_LIMIT);
}

/* an empty pipeline and a single "none" both hand back an owned verbatim copy */
void test_pipeline_passthrough(void)
{
    tidesdb_encoding_registry_t reg;
    ASSERT_EQ(tidesdb_encoding_registry_init(&reg), TDB_SUCCESS);

    const uint8_t src[] = {1, 2, 3, 4, 5, 0, 7, 8};
    uint8_t *out = NULL;
    size_t out_size = 0;

    ASSERT_EQ(tidesdb_encoding_pipeline_encode(&reg, NULL, 0, src, sizeof(src), &out, &out_size),
              TDB_SUCCESS);
    ASSERT_EQ(out_size, sizeof(src));
    ASSERT_TRUE(out != (const uint8_t *)src); /* a copy, not a borrow */
    ASSERT_TRUE(memcmp(out, src, sizeof(src)) == 0);
    free(out);

    const uint8_t ids[] = {TDB_COMPRESS_NONE};
    out = NULL;
    ASSERT_EQ(tidesdb_encoding_pipeline_encode(&reg, ids, 1, src, sizeof(src), &out, &out_size),
              TDB_SUCCESS);
    ASSERT_EQ(out_size, sizeof(src));
    ASSERT_TRUE(memcmp(out, src, sizeof(src)) == 0);
    free(out);
}

/* a single compression encoding round-trips through the pipeline; the encoded form differs from the
 * input on compressible data, and decode restores it exactly */
void test_pipeline_single_compress(void)
{
    if (!tidesdb_compression_available(TDB_COMPRESS_ZSTD))
    {
        tests_skipped++;
        return;
    }
    tidesdb_encoding_registry_t reg;
    ASSERT_EQ(tidesdb_encoding_registry_init(&reg), TDB_SUCCESS);

    uint8_t src[512];
    for (size_t i = 0; i < sizeof(src); i++) src[i] = (uint8_t)(i / 8); /* highly compressible */

    const uint8_t ids[] = {TDB_COMPRESS_ZSTD};
    uint8_t *enc = NULL;
    size_t enc_size = 0;
    ASSERT_EQ(tidesdb_encoding_pipeline_encode(&reg, ids, 1, src, sizeof(src), &enc, &enc_size),
              TDB_SUCCESS);

    uint8_t *dec = NULL;
    size_t dec_size = 0;
    ASSERT_EQ(tidesdb_encoding_pipeline_decode(&reg, ids, 1, enc, enc_size, &dec, &dec_size),
              TDB_SUCCESS);
    ASSERT_EQ(dec_size, sizeof(src));
    ASSERT_TRUE(memcmp(dec, src, sizeof(src)) == 0);

    free(enc);
    free(dec);
}

/* a stacked pipeline decodes in reverse order; caesar-then-prefix on encode must strip the prefix
 * then unshift on decode, and the order-sensitive mocks fail the round-trip if the direction is
 * wrong */
void test_pipeline_stacked_reverse_order(void)
{
    tidesdb_encoding_registry_t reg;
    ASSERT_EQ(tidesdb_encoding_registry_init(&reg), TDB_SUCCESS);
    uint8_t key = 7;
    ASSERT_EQ(tidesdb_encoding_register(&reg, "caesar", TEST_ENCODING_ID_CAESAR, caesar_encode,
                                        caesar_decode, &key),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_encoding_register(&reg, "prefix", TEST_ENCODING_ID_PREFIX, prefix_encode,
                                        prefix_decode, NULL),
              TDB_SUCCESS);

    const uint8_t src[] = {10, 20, 30, 40, 250, 251, 252};
    const uint8_t ids[] = {TEST_ENCODING_ID_CAESAR, TEST_ENCODING_ID_PREFIX};

    uint8_t *enc = NULL;
    size_t enc_size = 0;
    ASSERT_EQ(tidesdb_encoding_pipeline_encode(&reg, ids, 2, src, sizeof(src), &enc, &enc_size),
              TDB_SUCCESS);
    /* prefix ran last on encode, so the first byte is its marker and the length grew by one */
    ASSERT_EQ(enc_size, sizeof(src) + 1);
    ASSERT_EQ(enc[0], TEST_PREFIX_BYTE);

    uint8_t *dec = NULL;
    size_t dec_size = 0;
    ASSERT_EQ(tidesdb_encoding_pipeline_decode(&reg, ids, 2, enc, enc_size, &dec, &dec_size),
              TDB_SUCCESS);
    ASSERT_EQ(dec_size, sizeof(src));
    ASSERT_TRUE(memcmp(dec, src, sizeof(src)) == 0);

    free(enc);
    free(dec);
}

/* decoding bytes whose pipeline names an id this registry does not have is a hard corruption error,
 * never a silent wrong result */
void test_pipeline_unresolved_id(void)
{
    tidesdb_encoding_registry_t reg;
    ASSERT_EQ(tidesdb_encoding_registry_init(&reg), TDB_SUCCESS);

    const uint8_t src[] = {1, 2, 3};
    const uint8_t ids[] = {TEST_ENCODING_ID_UNREGISTERED};
    uint8_t *out = NULL;
    size_t out_size = 0;

    ASSERT_EQ(tidesdb_encoding_pipeline_decode(&reg, ids, 1, src, sizeof(src), &out, &out_size),
              TDB_ERR_CORRUPTION);
    /* the encode side reports the same as a configuration error */
    ASSERT_EQ(tidesdb_encoding_pipeline_encode(&reg, ids, 1, src, sizeof(src), &out, &out_size),
              TDB_ERR_INVALID_ARGS);
}

/* argument and bound checks on the pipeline entry points */
void test_pipeline_bad_args(void)
{
    tidesdb_encoding_registry_t reg;
    ASSERT_EQ(tidesdb_encoding_registry_init(&reg), TDB_SUCCESS);

    const uint8_t src[] = {1, 2, 3};
    const uint8_t ids[] = {TDB_COMPRESS_NONE};
    uint8_t *out = NULL;
    size_t out_size = 0;

    ASSERT_EQ(tidesdb_encoding_pipeline_encode(&reg, ids, 1, src, sizeof(src), NULL, &out_size),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_encoding_pipeline_encode(&reg, ids, -1, src, sizeof(src), &out, &out_size),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_encoding_pipeline_encode(&reg, ids, TDB_ENCODING_PIPELINE_MAX + 1, src,
                                               sizeof(src), &out, &out_size),
              TDB_ERR_INVALID_ARGS);
    /* a positive count with no id list is rejected before any transform runs */
    ASSERT_EQ(tidesdb_encoding_pipeline_encode(&reg, NULL, 1, src, sizeof(src), &out, &out_size),
              TDB_ERR_INVALID_ARGS);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_registry_builtins, tests_passed);
    RUN_TEST(test_register_validation, tests_passed);
    RUN_TEST(test_pipeline_passthrough, tests_passed);
    RUN_TEST(test_pipeline_single_compress, tests_passed);
    RUN_TEST(test_pipeline_stacked_reverse_order, tests_passed);
    RUN_TEST(test_pipeline_unresolved_id, tests_passed);
    RUN_TEST(test_pipeline_bad_args, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
