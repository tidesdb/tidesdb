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

#include "../src/sstable/bloom_filter.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* build a filter, add each key, and return its serialized form; the in-memory filter is freed since
 * the engine only ever queries the serialized bytes */
static uint8_t *build_serialized(double p, int n, const char *const *keys, int key_count,
                                 size_t *out_size)
{
    bloom_filter_t *bf = NULL;
    ASSERT_EQ(bloom_filter_new(&bf, p, n), 0);
    ASSERT_TRUE(bf != NULL);
    ASSERT_TRUE(bf->m > 0 && bf->h > 0);
    for (int i = 0; i < key_count; i++)
        bloom_filter_add(bf, (const uint8_t *)keys[i], strlen(keys[i]));
    uint8_t *blob = bloom_filter_serialize(bf, out_size);
    bloom_filter_free(bf);
    return blob;
}

/* new rejects a bad rate or count without leaking */
void test_bloom_filter_new_invalid_args(void)
{
    bloom_filter_t *bf = NULL;
    ASSERT_EQ(bloom_filter_new(&bf, 0.0, 100), -1);
    ASSERT_EQ(bloom_filter_new(&bf, 1.0, 100), -1);
    ASSERT_EQ(bloom_filter_new(&bf, -0.5, 100), -1);
    ASSERT_EQ(bloom_filter_new(&bf, 0.01, 0), -1);
    ASSERT_EQ(bloom_filter_new(&bf, 0.01, -5), -1);
    ASSERT_EQ(bloom_filter_new(NULL, 0.01, 100), -1);
}

/* every added key is reported present through the serialized form */
void test_bloom_filter_present_keys(void)
{
    const char *keys[] = {"alpha", "beta", "gamma", "delta", "epsilon"};
    const int n = (int)(sizeof(keys) / sizeof(keys[0]));
    size_t size = 0;
    uint8_t *blob = build_serialized(0.01, n, keys, n, &size);
    ASSERT_TRUE(blob != NULL);

    for (int i = 0; i < n; i++)
        ASSERT_EQ(
            bloom_filter_contains_serialized(blob, size, (const uint8_t *)keys[i], strlen(keys[i])),
            1);
    free(blob);
}

/* absent keys stay near the target false-positive rate */
void test_bloom_filter_false_positive_rate(void)
{
    const int n = 1000;
    char(*keys)[16] = malloc((size_t)n * sizeof(*keys));
    const char *kptrs[1000];
    for (int i = 0; i < n; i++)
    {
        snprintf(keys[i], sizeof(keys[i]), "key-%d", i);
        kptrs[i] = keys[i];
    }

    size_t size = 0;
    uint8_t *blob = build_serialized(0.01, n, kptrs, n, &size);
    ASSERT_TRUE(blob != NULL);

    int false_positives = 0;
    const int probes = 10000;
    for (int i = 0; i < probes; i++)
    {
        char absent[24];
        snprintf(absent, sizeof(absent), "absent-%d", i);
        if (bloom_filter_contains_serialized(blob, size, (const uint8_t *)absent, strlen(absent)) ==
            1)
            false_positives++;
    }
    /* target is 1%, allow generous slack for a finite sample */
    ASSERT_TRUE(false_positives < probes / 20); /* under 5% */

    free(blob);
    free(keys);
}

/* binary keys with embedded NULs round-trip */
void test_bloom_filter_binary_keys(void)
{
    bloom_filter_t *bf = NULL;
    ASSERT_EQ(bloom_filter_new(&bf, 0.01, 8), 0);
    const uint8_t key1[] = {0x00, 0x01, 0x00, 0xFF, 0x00};
    const uint8_t key2[] = {0xFF, 0x00, 0xAB, 0x00, 0xCD};
    bloom_filter_add(bf, key1, sizeof(key1));
    bloom_filter_add(bf, key2, sizeof(key2));

    size_t size = 0;
    uint8_t *blob = bloom_filter_serialize(bf, &size);
    bloom_filter_free(bf);
    ASSERT_TRUE(blob != NULL);

    ASSERT_EQ(bloom_filter_contains_serialized(blob, size, key1, sizeof(key1)), 1);
    ASSERT_EQ(bloom_filter_contains_serialized(blob, size, key2, sizeof(key2)), 1);
    free(blob);
}

/* contains_serialized rejects bad arguments and malformed buffers rather than over-reading */
void test_bloom_filter_contains_serialized_guards(void)
{
    const char *keys[] = {"one", "two"};
    size_t size = 0;
    uint8_t *blob = build_serialized(0.01, 2, keys, 2, &size);
    ASSERT_TRUE(blob != NULL && size > 8);

    /* null/empty entry */
    ASSERT_EQ(bloom_filter_contains_serialized(blob, size, NULL, 3), -1);
    ASSERT_EQ(bloom_filter_contains_serialized(blob, size, (const uint8_t *)"x", 0), -1);
    /* null data */
    ASSERT_EQ(bloom_filter_contains_serialized(NULL, size, (const uint8_t *)"x", 1), -1);
    /* a buffer shorter than the header */
    ASSERT_EQ(bloom_filter_contains_serialized(blob, 4, (const uint8_t *)"one", 3), -1);
    /* a truncated bitset body */
    ASSERT_EQ(bloom_filter_contains_serialized(blob, size - 1, (const uint8_t *)"one", 3), -1);
    /* a corrupt header (m = 0) */
    uint8_t corrupt[16] = {0};
    ASSERT_EQ(bloom_filter_contains_serialized(corrupt, sizeof(corrupt), (const uint8_t *)"x", 1),
              -1);

    free(blob);
}

/* a filter holding many keys reports them all present after serialization */
void test_bloom_filter_many_keys(void)
{
    const int n = 5000;
    char(*keys)[16] = malloc((size_t)n * sizeof(*keys));
    const char *kptrs[5000];
    for (int i = 0; i < n; i++)
    {
        snprintf(keys[i], sizeof(keys[i]), "k%d", i);
        kptrs[i] = keys[i];
    }

    size_t size = 0;
    uint8_t *blob = build_serialized(0.001, n, kptrs, n, &size);
    ASSERT_TRUE(blob != NULL);

    for (int i = 0; i < n; i++)
        ASSERT_EQ(bloom_filter_contains_serialized(blob, size, (const uint8_t *)kptrs[i],
                                                   strlen(kptrs[i])),
                  1);

    free(blob);
    free(keys);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_bloom_filter_new_invalid_args, tests_passed);
    RUN_TEST(test_bloom_filter_present_keys, tests_passed);
    RUN_TEST(test_bloom_filter_false_positive_rate, tests_passed);
    RUN_TEST(test_bloom_filter_binary_keys, tests_passed);
    RUN_TEST(test_bloom_filter_contains_serialized_guards, tests_passed);
    RUN_TEST(test_bloom_filter_many_keys, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
