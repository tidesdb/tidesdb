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
#include "../src/range_filter/range_filter.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* the longest key any test makes */
#define RFT_MAX_KEY 48

/* the remainder width the tests build with, about a 0.8% false positive rate */
#define RFT_R_BITS 8

/* contexts the tests' coders keep */
#define RFT_CONTEXTS 512

/* random ranges each no-false-negative pass checks */
#define RFT_RANGES 4000

/* keys in the false positive and size measurements */
#define RFT_BIG 50000

/* the bytes of an index entry's value and of its row id */
#define RFT_INDEX_HALF 8

/* index values, and entries under each */
#define RFT_INDEX_VALUES 2048
#define RFT_INDEX_ROWS   16

/* the remainder width of the shared infix test. the tries live in the slots the repeated
 * remainders gave up, so wider remainders leave them room for longer trailing strings */
#define RFT_SHARED_INFIX_R_BITS 12

/* the false positive rate the tries hold absent rows under present values to at that width, about
 * 0.05 measured, where infixes alone pass nearly every one */
#define RFT_SHARED_INFIX_MAX_FPR 0.1

typedef struct
{
    uint8_t b[RFT_MAX_KEY];
    size_t n;
} rft_key_t;

/* splitmix64. a weaker generator taking the low byte of consecutive xorshift outputs made probes
 * land near keys about half again as often as independent draws would, which read as a false
 * positive rate three times the filter's real one */
static uint64_t rft_next(uint64_t *s)
{
    uint64_t z = (*s += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static int rft_cmp(const void *pa, const void *pb)
{
    const rft_key_t *a = pa, *b = pb;
    return tdb_key_cmp(a->b, a->n, b->b, b->n);
}

/* sort the keys in the engine's order and drop repeats, returning how many are left */
static int rft_sort_unique(rft_key_t *k, int n)
{
    qsort(k, (size_t)n, sizeof(*k), rft_cmp);
    int out = 0;
    for (int i = 0; i < n; i++)
        if (out == 0 || rft_cmp(&k[out - 1], &k[i]) != 0) k[out++] = k[i];
    return out;
}

static void rft_uniform(rft_key_t *k, int n, uint64_t seed)
{
    for (int i = 0; i < n; i++)
    {
        k[i].n = 16;
        for (int j = 0; j < 16; j++) k[i].b[j] = (uint8_t)rft_next(&seed);
    }
}

static void rft_skewed(rft_key_t *k, int n, uint64_t seed)
{
    static const char *const shapes[] = {"https://www.example%d.com/item-%d", "u%d@mail%d.org",
                                         "idx:cust:%08d:%04d"};
    for (int i = 0; i < n; i++)
    {
        const int a = (int)(rft_next(&seed) % 97), b = (int)(rft_next(&seed) % 1000000);
        k[i].n = (size_t)snprintf((char *)k[i].b, RFT_MAX_KEY, shapes[rft_next(&seed) % 3], a, b);
    }
}

/* any byte, any length, much of it sharing prefixes with earlier keys */
static void rft_wild(rft_key_t *k, int n, uint64_t seed)
{
    for (int i = 0; i < n; i++)
    {
        size_t len = (size_t)(rft_next(&seed) % RFT_MAX_KEY), shared = 0;
        if (i > 0 && rft_next(&seed) % 3 != 0)
        {
            const rft_key_t *base = &k[rft_next(&seed) % (uint64_t)i];
            shared = (size_t)(rft_next(&seed) % (base->n + 1));
            memcpy(k[i].b, base->b, shared);
            if (len < shared) len = shared;
        }
        for (size_t j = shared; j < len; j++) k[i].b[j] = (uint8_t)rft_next(&seed);
        k[i].n = len;
    }
}

/* "a", "a\0", "a\0\0", ... and the same under "b" -- keys that are equal once padded with zeros,
 * which is where two samples can leave no room between them */
static int rft_prefix_chains(rft_key_t *k)
{
    int n = 0;
    for (int base = 'a'; base <= 'b'; base++)
        for (size_t len = 1; len <= 20; len++)
        {
            memset(k[n].b, 0, len);
            k[n].b[0] = (uint8_t)base;
            k[n].n = len;
            n++;
        }
    return n;
}

static range_filter_codec_t *rft_codec(const rft_key_t *k, int n)
{
    range_filter_codec_counts_t *c = NULL;
    ASSERT_EQ(range_filter_codec_counts_new(&c), TDB_SUCCESS);
    for (int i = 0; i < n; i++) range_filter_codec_counts_add(c, k[i].b, k[i].n);
    range_filter_codec_t *codec = NULL;
    ASSERT_EQ(range_filter_codec_build(c, 2, RFT_CONTEXTS, &codec), TDB_SUCCESS);
    range_filter_codec_counts_free(c);
    return codec;
}

static range_filter_t *rft_build_width(const range_filter_codec_t *codec, const rft_key_t *k, int n,
                                       unsigned sample_bits, unsigned r_bits)
{
    range_filter_builder_t *b = NULL;
    ASSERT_EQ(range_filter_builder_new(codec, sample_bits, r_bits, &b), TDB_SUCCESS);
    for (int i = 0; i < n; i++) ASSERT_EQ(range_filter_builder_add(b, k[i].b, k[i].n), TDB_SUCCESS);
    range_filter_t *f = NULL;
    ASSERT_EQ(range_filter_builder_finish(b, &f), TDB_SUCCESS);
    ASSERT_EQ(range_filter_key_count(f), (uint64_t)n);
    return f;
}

static range_filter_t *rft_build(const range_filter_codec_t *codec, const rft_key_t *k, int n,
                                 unsigned sample_bits)
{
    return rft_build_width(codec, k, n, sample_bits, RFT_R_BITS);
}

/* every key answers yes as a point, and every range between two keys answers yes */
static void rft_assert_no_false_negatives(const range_filter_t *f, const rft_key_t *k, int n,
                                          uint64_t seed)
{
    for (int i = 0; i < n; i++)
        ASSERT_EQ(range_filter_may_contain(f, k[i].b, k[i].n, k[i].b, k[i].n), 1);
    for (int r = 0; r < RFT_RANGES && n > 0; r++)
    {
        int a = (int)(rft_next(&seed) % (uint64_t)n), b = (int)(rft_next(&seed) % (uint64_t)n);
        if (a > b)
        {
            const int t = a;
            a = b;
            b = t;
        }
        ASSERT_EQ(range_filter_may_contain(f, k[a].b, k[a].n, k[b].b, k[b].n), 1);
        /* ends that are not keys, pulled below the low key and pushed above the high one, so a
         * trie is searched against endpoints that differ from every key it holds */
        rft_key_t lo = k[a], hi = k[b];
        if (lo.n > 0 && lo.b[lo.n - 1] > 0) lo.b[lo.n - 1]--;
        if (hi.n < RFT_MAX_KEY) hi.b[hi.n++] = (uint8_t)rft_next(&seed);
        ASSERT_EQ(range_filter_may_contain(f, lo.b, lo.n, hi.b, hi.n), 1);
    }
}

/* no key is ever missed, across key shapes and across every size around the sample interval */
void test_range_filter_has_no_false_negatives(void)
{
    static const int sizes[] = {1, 2, 3, 7, 8, 9, 1023, 1024, 1025, 5 * 1024 + 3, 12000};
    rft_key_t *k = malloc(12000 * sizeof(*k));
    ASSERT_TRUE(k != NULL);
    for (int shape = 0; shape < 3; shape++)
        for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
        {
            int n = sizes[s];
            const uint64_t seed = 100 + (uint64_t)shape * 31 + s;
            if (shape == 0) rft_uniform(k, n, seed);
            if (shape == 1) rft_skewed(k, n, seed);
            if (shape == 2) rft_wild(k, n, seed);
            n = rft_sort_unique(k, n);
            range_filter_codec_t *codec = rft_codec(k, n);
            /* a small interval as well as the default, so gaps of every size are covered */
            for (unsigned sb = 3; sb <= RANGE_FILTER_DEFAULT_SAMPLE_BITS; sb += 7)
            {
                range_filter_t *f = rft_build(codec, k, n, sb);
                rft_assert_no_false_negatives(f, k, n, seed + sb);
                range_filter_free(f);
            }
            range_filter_codec_free(codec);
        }
    free(k);
}

/* keys equal once padded leave samples with no room between them, and still nothing is missed */
void test_range_filter_keys_equal_once_padded(void)
{
    rft_key_t k[64];
    int n = rft_prefix_chains(k);
    n = rft_sort_unique(k, n);
    range_filter_codec_t *codec = rft_codec(k, n);
    for (unsigned sb = 1; sb <= 3; sb++)
    {
        range_filter_t *f = rft_build(codec, k, n, sb);
        rft_assert_no_false_negatives(f, k, n, sb);
        range_filter_free(f);
    }
    range_filter_codec_free(codec);
}

/* ranges outside every key, inverted ranges and an empty filter all answer no */
void test_range_filter_answers_no_outside_the_keys(void)
{
    rft_key_t k[3] = {{"m", 1}, {"n", 1}, {"p", 1}};
    range_filter_codec_t *codec = rft_codec(k, 3);
    range_filter_t *f = rft_build(codec, k, 3, 1);
    ASSERT_EQ(range_filter_may_contain(f, (const uint8_t *)"a", 1, (const uint8_t *)"l", 1), 0);
    ASSERT_EQ(range_filter_may_contain(f, (const uint8_t *)"q", 1, (const uint8_t *)"z", 1), 0);
    ASSERT_EQ(range_filter_may_contain(f, (const uint8_t *)"p", 1, (const uint8_t *)"m", 1), 0);
    ASSERT_EQ(range_filter_may_contain(f, (const uint8_t *)"a", 1, (const uint8_t *)"m", 1), 1);
    range_filter_free(f);

    range_filter_t *empty = rft_build(codec, k, 0, 1);
    ASSERT_EQ(range_filter_may_contain(empty, (const uint8_t *)"a", 1, (const uint8_t *)"z", 1), 0);
    range_filter_free(empty);
    range_filter_codec_free(codec);
}

/* keys out of order, or repeated, are refused */
void test_range_filter_rejects_keys_out_of_order(void)
{
    rft_key_t k[2] = {{"b", 1}, {"a", 1}};
    range_filter_codec_t *codec = rft_codec(k, 2);
    range_filter_builder_t *b = NULL;
    ASSERT_EQ(range_filter_builder_new(codec, 2, RFT_R_BITS, &b), TDB_SUCCESS);
    ASSERT_EQ(range_filter_builder_add(b, k[0].b, k[0].n), TDB_SUCCESS);
    ASSERT_EQ(range_filter_builder_add(b, k[0].b, k[0].n), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_filter_builder_add(b, k[1].b, k[1].n), TDB_ERR_INVALID_ARGS);
    range_filter_builder_free(b);
    range_filter_codec_free(codec);
}

/* whether any key lies in [lo, hi], by binary search over the sorted keys */
static int rft_truth(const rft_key_t *k, int n, const rft_key_t *lo, const rft_key_t *hi)
{
    int a = 0, b = n;
    while (a < b)
    {
        const int m = a + (b - a) / 2;
        if (rft_cmp(&k[m], lo) < 0)
            a = m + 1;
        else
            b = m;
    }
    return a < n && rft_cmp(&k[a], hi) <= 0;
}

/* on uniform keys the false positive rate for empty points and short empty ranges stays near the
 * 2 / 2^r the infix width is chosen for, and the filter costs about r + 2 bits a key */
void test_range_filter_false_positive_rate_and_size(void)
{
    rft_key_t *k = malloc(RFT_BIG * sizeof(*k));
    ASSERT_TRUE(k != NULL);
    rft_uniform(k, RFT_BIG, 77);
    const int n = rft_sort_unique(k, RFT_BIG);
    range_filter_codec_t *codec = rft_codec(k, n);
    range_filter_t *f = rft_build(codec, k, n, RANGE_FILTER_DEFAULT_SAMPLE_BITS);

    uint64_t seed = 99;
    int probes = 0, positives = 0, point_pos = 0, range_pos = 0;
    while (probes < RFT_BIG)
    {
        rft_key_t lo, hi;
        rft_uniform(&lo, 1, rft_next(&seed));
        hi = lo;
        /* half points, half ranges a few values wide in the last byte */
        const int is_range = probes % 2 == 1 && hi.b[15] < 0xF0;
        if (is_range) hi.b[15] = (uint8_t)(hi.b[15] + 8);
        if (rft_truth(k, n, &lo, &hi)) continue;
        probes++;
        const int pos = range_filter_may_contain(f, lo.b, lo.n, hi.b, hi.n);
        positives += pos;
        if (is_range)
            range_pos += pos;
        else
            point_pos += pos;
    }
    fprintf(stderr, "  points positive %d, ranges positive %d, of %d probes\n", point_pos,
            range_pos, probes);
    const double fpr = (double)positives / probes;
    const double target = 2.0 / (double)(1u << RFT_R_BITS);
    const double bpk = (double)range_filter_size_bits(f) / n;
    fprintf(stderr, "  fpr %.4f against a target of %.4f, %.2f bits per key\n", fpr, target, bpk);
    ASSERT_TRUE(fpr < 3 * target);
    ASSERT_TRUE(bpk < RFT_R_BITS + 4);

    range_filter_free(f);
    range_filter_codec_free(codec);
    free(k);
}

/* index entries, a few thousand values each followed by several row ids, both random */
static void rft_index_entries(rft_key_t *k, int values, int rows, uint64_t seed)
{
    for (int v = 0; v < values; v++)
    {
        const uint64_t value = rft_next(&seed);
        for (int r = 0; r < rows; r++)
        {
            rft_key_t *e = &k[v * rows + r];
            const uint64_t row = rft_next(&seed);
            for (int j = 0; j < RFT_INDEX_HALF; j++)
            {
                e->b[j] = (uint8_t)(value >> (8 * (RFT_INDEX_HALF - 1 - j)));
                e->b[RFT_INDEX_HALF + j] = (uint8_t)(row >> (8 * (RFT_INDEX_HALF - 1 - j)));
            }
            e->n = 2 * RFT_INDEX_HALF;
        }
    }
}

/* the entries of one value agree past where samples part, so they cut down to the same infix and
 * only the tries tell them apart. a probe for a row a value does not have stays rare to pass */
void test_range_filter_tells_apart_keys_sharing_an_infix(void)
{
    const int total = RFT_INDEX_VALUES * RFT_INDEX_ROWS;
    rft_key_t *k = malloc((size_t)total * sizeof(*k));
    ASSERT_TRUE(k != NULL);
    rft_index_entries(k, RFT_INDEX_VALUES, RFT_INDEX_ROWS, 5);
    const int n = rft_sort_unique(k, total);
    range_filter_codec_t *codec = rft_codec(k, n);
    range_filter_t *f =
        rft_build_width(codec, k, n, RANGE_FILTER_DEFAULT_SAMPLE_BITS, RFT_SHARED_INFIX_R_BITS);
    rft_assert_no_false_negatives(f, k, n, 6);

    uint64_t seed = 7;
    int probes = 0, positives = 0;
    while (probes < RFT_BIG)
    {
        /* a value that is there, with a row that is not */
        rft_key_t lo = k[rft_next(&seed) % (uint64_t)n];
        for (int j = RFT_INDEX_HALF; j < 2 * RFT_INDEX_HALF; j++)
            lo.b[j] = (uint8_t)rft_next(&seed);
        rft_key_t hi = lo;
        if (probes % 2 == 1 && hi.b[lo.n - 1] < 0xF0)
            hi.b[lo.n - 1] = (uint8_t)(hi.b[lo.n - 1] + 8);
        if (rft_truth(k, n, &lo, &hi)) continue;
        probes++;
        positives += range_filter_may_contain(f, lo.b, lo.n, hi.b, hi.n);
    }
    const double fpr = (double)positives / probes;
    fprintf(stderr, "  absent rows under present values, fpr %.4f, %.2f bits per key\n", fpr,
            (double)range_filter_size_bits(f) / n);
    ASSERT_TRUE(fpr < RFT_SHARED_INFIX_MAX_FPR);

    range_filter_free(f);
    range_filter_codec_free(codec);
    free(k);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_range_filter_has_no_false_negatives, tests_passed);
    RUN_TEST(test_range_filter_keys_equal_once_padded, tests_passed);
    RUN_TEST(test_range_filter_answers_no_outside_the_keys, tests_passed);
    RUN_TEST(test_range_filter_rejects_keys_out_of_order, tests_passed);
    RUN_TEST(test_range_filter_false_positive_rate_and_size, tests_passed);
    RUN_TEST(test_range_filter_tells_apart_keys_sharing_an_infix, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
