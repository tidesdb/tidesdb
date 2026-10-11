/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/base/errors.h"
#include "../src/base/keycmp.h"
#include "../src/range_filter/range_filter_codec.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* keys the model is built from and probed with */
#define RFC_KEYS 4000

/* the longest key any test makes */
#define RFC_MAX_KEY 64

/* random pairs the order tests compare */
#define RFC_PAIRS 200000

/* contexts the tests let a model keep */
#define RFC_CONTEXTS 512

typedef struct
{
    uint8_t bytes[RFC_MAX_KEY];
    size_t len;
} rfc_key_t;

static uint64_t rfc_next(uint64_t *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    return *s;
}

/* keys shaped like the ones a range filter struggles with -- urls, emails and composite index
 * entries -- long shared prefixes, a narrow alphabet, and runs of near-identical neighbours */
static void rfc_make_skewed(rfc_key_t *keys, int n, uint64_t seed)
{
    static const char *const shapes[] = {"https://www.example%d.com/products/item-%d",
                                         "user%d@mail%d.example.org", "idx:customer:%08d:%04d"};
    for (int i = 0; i < n; i++)
    {
        const char *shape = shapes[rfc_next(&seed) % 3];
        const int a = (int)(rfc_next(&seed) % 97), b = (int)(rfc_next(&seed) % 100000);
        keys[i].len = (size_t)snprintf((char *)keys[i].bytes, RFC_MAX_KEY, shape, a, b);
    }
}

/* keys of any byte value and any length up to RFC_MAX_KEY, most of them sharing a prefix with an
 * earlier key so the comparisons exercise long common runs as well as unseen bytes */
static void rfc_make_wild(rfc_key_t *keys, int n, uint64_t seed)
{
    for (int i = 0; i < n; i++)
    {
        size_t len = (size_t)(rfc_next(&seed) % RFC_MAX_KEY);
        size_t shared = 0;
        if (i > 0 && rfc_next(&seed) % 4 != 0)
        {
            const rfc_key_t *base = &keys[rfc_next(&seed) % (uint64_t)i];
            shared = (size_t)(rfc_next(&seed) % (base->len + 1));
            memcpy(keys[i].bytes, base->bytes, shared);
            if (len < shared) len = shared;
        }
        for (size_t j = shared; j < len; j++) keys[i].bytes[j] = (uint8_t)rfc_next(&seed);
        keys[i].len = len;
    }
}

static range_filter_codec_t *rfc_build(const rfc_key_t *keys, int n, int order, int contexts)
{
    range_filter_codec_counts_t *counts = NULL;
    ASSERT_EQ(range_filter_codec_counts_new(&counts), TDB_SUCCESS);
    for (int i = 0; i < n; i++) range_filter_codec_counts_add(counts, keys[i].bytes, keys[i].len);
    range_filter_codec_t *codec = NULL;
    ASSERT_EQ(range_filter_codec_build(counts, order, contexts, &codec), TDB_SUCCESS);
    range_filter_codec_counts_free(counts);
    return codec;
}

static void rfc_encode(const range_filter_codec_t *codec, const rfc_key_t *k,
                       range_filter_bits_t *out)
{
    range_filter_bits_reset(out);
    ASSERT_EQ(range_filter_codec_encode(codec, k->bytes, k->len, out), TDB_SUCCESS);
}

static int rfc_sign(int v)
{
    return v < 0 ? -1 : (v > 0 ? 1 : 0);
}

/* for many random pairs, the encodings compare exactly as the keys do under the engine's order */
static void rfc_assert_order(const range_filter_codec_t *codec, const rfc_key_t *keys, int n,
                             uint64_t seed)
{
    range_filter_bits_t a, b;
    range_filter_bits_init(&a);
    range_filter_bits_init(&b);
    for (int i = 0; i < RFC_PAIRS; i++)
    {
        const rfc_key_t *x = &keys[rfc_next(&seed) % (uint64_t)n];
        const rfc_key_t *y = &keys[rfc_next(&seed) % (uint64_t)n];
        rfc_encode(codec, x, &a);
        rfc_encode(codec, y, &b);
        const int raw = rfc_sign(tdb_key_cmp(x->bytes, x->len, y->bytes, y->len));
        ASSERT_EQ(rfc_sign(range_filter_bits_compare(&a, &b)), raw);
    }
    range_filter_bits_free(&a);
    range_filter_bits_free(&b);
}

/* encodings order exactly as the keys do, at every order the model may be built to */
void test_range_filter_codec_preserves_order(void)
{
    rfc_key_t *keys = malloc(RFC_KEYS * sizeof(*keys));
    ASSERT_TRUE(keys != NULL);
    rfc_make_skewed(keys, RFC_KEYS, 1);
    for (int order = 0; order <= RANGE_FILTER_CODEC_MAX_ORDER; order++)
    {
        range_filter_codec_t *codec = rfc_build(keys, RFC_KEYS, order, RFC_CONTEXTS);
        ASSERT_EQ(range_filter_codec_order(codec), order);
        rfc_assert_order(codec, keys, RFC_KEYS, 7 + (uint64_t)order);
        range_filter_codec_free(codec);
    }
    free(keys);
}

/* a model built from narrow keys still codes every byte value, in order. a query endpoint can hold
 * bytes the build never saw, and a byte with no code, or one coded out of order, would be a false
 * negative waiting to happen */
void test_range_filter_codec_codes_bytes_it_never_saw(void)
{
    rfc_key_t *train = malloc(RFC_KEYS * sizeof(*train));
    rfc_key_t *probe = malloc(RFC_KEYS * sizeof(*probe));
    ASSERT_TRUE(train && probe);
    rfc_make_skewed(train, RFC_KEYS, 2);
    rfc_make_wild(probe, RFC_KEYS, 3);
    range_filter_codec_t *codec = rfc_build(train, RFC_KEYS, 2, RFC_CONTEXTS);
    rfc_assert_order(codec, probe, RFC_KEYS, 11);

    /* every single byte value, as a one-byte key, sorts exactly where it should */
    range_filter_bits_t prev, cur;
    range_filter_bits_init(&prev);
    range_filter_bits_init(&cur);
    for (int v = 0; v < 256; v++)
    {
        const uint8_t byte = (uint8_t)v;
        range_filter_bits_reset(&cur);
        ASSERT_EQ(range_filter_codec_encode(codec, &byte, 1, &cur), TDB_SUCCESS);
        ASSERT_TRUE(cur.nbits >= 1 && cur.nbits <= RANGE_FILTER_CODEC_MAX_CODE_BITS);
        if (v > 0) ASSERT_TRUE(range_filter_bits_compare(&prev, &cur) < 0);
        range_filter_bits_reset(&prev);
        ASSERT_EQ(range_filter_codec_encode(codec, &byte, 1, &prev), TDB_SUCCESS);
    }
    range_filter_bits_free(&prev);
    range_filter_bits_free(&cur);
    range_filter_codec_free(codec);
    free(train);
    free(probe);
}

/* a key that is a proper prefix of another encodes to a proper prefix of it, which is what keeps
 * the shorter key first */
void test_range_filter_codec_prefix_encodes_to_prefix(void)
{
    rfc_key_t *keys = malloc(RFC_KEYS * sizeof(*keys));
    ASSERT_TRUE(keys != NULL);
    rfc_make_skewed(keys, RFC_KEYS, 4);
    range_filter_codec_t *codec = rfc_build(keys, RFC_KEYS, 2, RFC_CONTEXTS);
    range_filter_bits_t whole, part;
    range_filter_bits_init(&whole);
    range_filter_bits_init(&part);
    for (int i = 0; i < RFC_KEYS; i++)
    {
        rfc_key_t cut = keys[i];
        cut.len = keys[i].len / 2;
        rfc_encode(codec, &keys[i], &whole);
        rfc_encode(codec, &cut, &part);
        ASSERT_TRUE(part.nbits <= whole.nbits);
        ASSERT_EQ(range_filter_bits_common_prefix(&part, &whole), part.nbits);
    }
    range_filter_bits_free(&whole);
    range_filter_bits_free(&part);
    range_filter_codec_free(codec);
    free(keys);
}

/* on the skewed keys the coder exists for, the encoding is shorter than the bytes, and the order-2
 * model is no longer than the order-0 one */
void test_range_filter_codec_shortens_skewed_keys(void)
{
    rfc_key_t *keys = malloc(RFC_KEYS * sizeof(*keys));
    ASSERT_TRUE(keys != NULL);
    rfc_make_skewed(keys, RFC_KEYS, 5);
    size_t raw_bits = 0, bits_by_order[RANGE_FILTER_CODEC_MAX_ORDER + 1] = {0};
    range_filter_bits_t out;
    range_filter_bits_init(&out);
    for (int order = 0; order <= RANGE_FILTER_CODEC_MAX_ORDER; order++)
    {
        range_filter_codec_t *codec = rfc_build(keys, RFC_KEYS, order, RFC_CONTEXTS);
        for (int i = 0; i < RFC_KEYS; i++)
        {
            rfc_encode(codec, &keys[i], &out);
            bits_by_order[order] += out.nbits;
            if (order == 0) raw_bits += keys[i].len * 8;
        }
        range_filter_codec_free(codec);
    }
    ASSERT_TRUE(bits_by_order[0] < raw_bits);
    ASSERT_TRUE(bits_by_order[2] <= bits_by_order[0]);
    range_filter_bits_free(&out);
    free(keys);
}

/* however skewed the counts, no code exceeds the bound the bisection guarantees */
void test_range_filter_codec_code_length_is_bounded(void)
{
    range_filter_codec_counts_t *counts = NULL;
    ASSERT_EQ(range_filter_codec_counts_new(&counts), TDB_SUCCESS);
    /* one byte overwhelmingly common, then a geometric tail, the shape that drives a bisection
     * deepest */
    uint8_t key[1];
    for (int v = 0; v < 20; v++)
    {
        key[0] = (uint8_t)(v * 7);
        const int reps = 1 << (20 - v);
        for (int r = 0; r < reps; r++) range_filter_codec_counts_add(counts, key, 1);
    }
    range_filter_codec_t *codec = NULL;
    ASSERT_EQ(range_filter_codec_build(counts, 0, 0, &codec), TDB_SUCCESS);
    range_filter_bits_t out;
    range_filter_bits_init(&out);
    for (int v = 0; v < 256; v++)
    {
        key[0] = (uint8_t)v;
        range_filter_bits_reset(&out);
        ASSERT_EQ(range_filter_codec_encode(codec, key, 1, &out), TDB_SUCCESS);
        ASSERT_TRUE(out.nbits <= RANGE_FILTER_CODEC_MAX_CODE_BITS);
    }
    range_filter_bits_free(&out);
    range_filter_codec_free(codec);
    range_filter_codec_counts_free(counts);
}

/* a model read back encodes every key exactly as the one written did */
void test_range_filter_codec_round_trips(void)
{
    rfc_key_t *keys = malloc(RFC_KEYS * sizeof(*keys));
    ASSERT_TRUE(keys != NULL);
    rfc_make_skewed(keys, RFC_KEYS, 6);
    range_filter_codec_t *codec = rfc_build(keys, RFC_KEYS, 2, RFC_CONTEXTS);
    uint8_t *blob = NULL;
    size_t size = 0;
    ASSERT_EQ(range_filter_codec_serialize(codec, &blob, &size), TDB_SUCCESS);
    range_filter_codec_t *back = NULL;
    ASSERT_EQ(range_filter_codec_deserialize(blob, size, &back), TDB_SUCCESS);
    ASSERT_EQ(range_filter_codec_order(back), range_filter_codec_order(codec));
    ASSERT_EQ(range_filter_codec_context_count(back), range_filter_codec_context_count(codec));
    /* the loaded model kept its code tables and dropped the weights, at well under half the size,
     * and having no weights it cannot be written again */
    ASSERT_TRUE(range_filter_codec_resident_bytes(back) * 2 <
                range_filter_codec_resident_bytes(codec));
    uint8_t *again = NULL;
    size_t again_size = 0;
    ASSERT_EQ(range_filter_codec_serialize(back, &again, &again_size), TDB_ERR_INVALID_ARGS);
    ASSERT_TRUE(again == NULL);

    range_filter_bits_t a, b;
    range_filter_bits_init(&a);
    range_filter_bits_init(&b);
    for (int i = 0; i < RFC_KEYS; i++)
    {
        rfc_encode(codec, &keys[i], &a);
        rfc_encode(back, &keys[i], &b);
        ASSERT_EQ(range_filter_bits_compare(&a, &b), 0);
    }
    range_filter_bits_free(&a);
    range_filter_bits_free(&b);
    range_filter_codec_free(back);
    range_filter_codec_free(codec);
    free(blob);
    free(keys);
}

/* every way a model can be damaged is refused rather than read into codes the writer never had */
void test_range_filter_codec_rejects_damage(void)
{
    rfc_key_t *keys = malloc(RFC_KEYS * sizeof(*keys));
    ASSERT_TRUE(keys != NULL);
    rfc_make_skewed(keys, RFC_KEYS, 8);
    range_filter_codec_t *codec = rfc_build(keys, RFC_KEYS, 2, RFC_CONTEXTS);
    uint8_t *blob = NULL;
    size_t size = 0;
    ASSERT_EQ(range_filter_codec_serialize(codec, &blob, &size), TDB_SUCCESS);
    uint8_t *copy = malloc(size + 1);
    ASSERT_TRUE(copy != NULL);
    range_filter_codec_t *back = NULL;

    /* every truncation */
    for (size_t cut = 0; cut < size; cut++)
    {
        ASSERT_TRUE(range_filter_codec_deserialize(blob, cut, &back) != TDB_SUCCESS);
        ASSERT_TRUE(back == NULL);
    }
    /* a trailing byte */
    memcpy(copy, blob, size);
    copy[size] = 0;
    ASSERT_EQ(range_filter_codec_deserialize(copy, size + 1, &back), TDB_ERR_CORRUPTION);
    /* a version it does not know */
    memcpy(copy, blob, size);
    copy[0] ^= 0xFF;
    ASSERT_EQ(range_filter_codec_deserialize(copy, size, &back), TDB_ERR_CORRUPTION);
    /* an order deeper than any model has */
    memcpy(copy, blob, size);
    copy[1] = RANGE_FILTER_CODEC_MAX_ORDER + 1;
    ASSERT_EQ(range_filter_codec_deserialize(copy, size, &back), TDB_ERR_CORRUPTION);
    /* an order the trees do not match */
    memcpy(copy, blob, size);
    copy[1] = 1;
    ASSERT_EQ(range_filter_codec_deserialize(copy, size, &back), TDB_ERR_CORRUPTION);

    free(copy);
    free(blob);
    range_filter_codec_free(codec);
    free(keys);
}

/* the context budget caps how many trees a model keeps, and order 0 keeps none */
void test_range_filter_codec_respects_the_context_budget(void)
{
    rfc_key_t *keys = malloc(RFC_KEYS * sizeof(*keys));
    ASSERT_TRUE(keys != NULL);
    rfc_make_skewed(keys, RFC_KEYS, 9);
    range_filter_codec_t *none = rfc_build(keys, RFC_KEYS, 0, RFC_CONTEXTS);
    ASSERT_EQ(range_filter_codec_context_count(none), 0);
    range_filter_codec_t *few = rfc_build(keys, RFC_KEYS, 2, 16);
    ASSERT_TRUE(range_filter_codec_context_count(few) <= 16);
    ASSERT_TRUE(range_filter_codec_context_count(few) > 0);
    rfc_assert_order(few, keys, RFC_KEYS, 13);
    range_filter_codec_free(none);
    range_filter_codec_free(few);
    free(keys);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_range_filter_codec_preserves_order, tests_passed);
    RUN_TEST(test_range_filter_codec_codes_bytes_it_never_saw, tests_passed);
    RUN_TEST(test_range_filter_codec_prefix_encodes_to_prefix, tests_passed);
    RUN_TEST(test_range_filter_codec_shortens_skewed_keys, tests_passed);
    RUN_TEST(test_range_filter_codec_code_length_is_bounded, tests_passed);
    RUN_TEST(test_range_filter_codec_round_trips, tests_passed);
    RUN_TEST(test_range_filter_codec_rejects_damage, tests_passed);
    RUN_TEST(test_range_filter_codec_respects_the_context_budget, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
