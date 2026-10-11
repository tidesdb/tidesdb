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
#include "../src/range_filter/range_filter_infix.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* infixes per store in the exactness tests, a full gap at the default sample interval */
#define RFI_N 1023

/* ranges probed against each store */
#define RFI_PROBES 20000

static uint64_t rfi_next(uint64_t *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    return *s;
}

static int rfi_cmp_u64(const void *a, const void *b)
{
    const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

/* whether any infix lies in [lo, hi], by looking at every one */
static int rfi_brute(const uint64_t *v, size_t n, uint64_t lo, uint64_t hi)
{
    for (size_t i = 0; i < n; i++)
        if (v[i] >= lo && v[i] <= hi) return 1;
    return 0;
}

/* the store answers exactly as a scan of its infixes does, across quotient and remainder widths
 * that make runs short, long, and the whole store one run */
void test_range_filter_infix_store_is_exact(void)
{
    static const unsigned widths[][2] = {{10, 8}, {4, 12}, {0, 16}, {12, 1}, {10, 20}};
    uint64_t *v = malloc(RFI_N * sizeof(*v));
    ASSERT_TRUE(v != NULL);
    uint64_t seed = 0x243f6a8885a308d3ULL;
    for (size_t w = 0; w < sizeof(widths) / sizeof(widths[0]); w++)
    {
        const unsigned q = widths[w][0], r = widths[w][1];
        const uint64_t limit = UINT64_C(1) << (q + r);
        for (size_t i = 0; i < RFI_N; i++) v[i] = rfi_next(&seed) % limit;
        qsort(v, RFI_N, sizeof(*v), rfi_cmp_u64);
        range_filter_infix_store_t s;
        ASSERT_EQ(range_filter_infix_store_build(v, NULL, 0, RFI_N, q, r, &s), TDB_SUCCESS);
        for (int p = 0; p < RFI_PROBES; p++)
        {
            uint64_t lo = rfi_next(&seed) % limit, hi;
            /* most probes are short, so they land between neighbours as well as across them */
            if (p % 2 == 0)
                hi = lo + rfi_next(&seed) % 4;
            else
                hi = rfi_next(&seed) % limit;
            if (p % 5 == 0) lo = hi = v[rfi_next(&seed) % RFI_N]; /* exactly on a held infix */
            ASSERT_EQ(range_filter_infix_store_may_contain(&s, lo, hi, NULL, NULL),
                      rfi_brute(v, RFI_N, lo, hi));
        }
        range_filter_infix_store_free(&s);
    }
    free(v);
}

/* duplicates share a run, and an empty store holds nothing */
void test_range_filter_infix_store_duplicates_and_empty(void)
{
    const uint64_t v[] = {5, 5, 5, 6, 300, 300, 1023};
    range_filter_infix_store_t s;
    ASSERT_EQ(range_filter_infix_store_build(v, NULL, 0, 7, 4, 6, &s), TDB_SUCCESS);
    ASSERT_EQ(range_filter_infix_store_may_contain(&s, 5, 5, NULL, NULL), 1);
    ASSERT_EQ(range_filter_infix_store_may_contain(&s, 7, 299, NULL, NULL), 0);
    ASSERT_EQ(range_filter_infix_store_may_contain(&s, 1023, 1023, NULL, NULL), 1);
    ASSERT_EQ(range_filter_infix_store_may_contain(&s, 301, 1022, NULL, NULL), 0);
    ASSERT_EQ(range_filter_infix_store_may_contain(&s, 9, 4, NULL, NULL), 0); /* inverted */
    range_filter_infix_store_free(&s);

    ASSERT_EQ(range_filter_infix_store_build(NULL, NULL, 0, 0, 10, 8, &s), TDB_SUCCESS);
    ASSERT_EQ(range_filter_infix_store_may_contain(&s, 0, ~UINT64_C(0), NULL, NULL), 0);
    range_filter_infix_store_free(&s);
}

/* infixes out of order or wider than the store are refused */
void test_range_filter_infix_store_rejects_bad_input(void)
{
    range_filter_infix_store_t s;
    const uint64_t unsorted[] = {3, 2};
    ASSERT_EQ(range_filter_infix_store_build(unsorted, NULL, 0, 2, 4, 4, &s), TDB_ERR_INVALID_ARGS);
    const uint64_t wide[] = {UINT64_C(1) << 8};
    ASSERT_EQ(range_filter_infix_store_build(wide, NULL, 0, 1, 4, 4, &s), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_filter_infix_store_build(wide, NULL, 0, 1, 4, 0, &s), TDB_ERR_INVALID_ARGS);
    range_filter_infix_store_free(&s);
}

/* distinct infixes in the collision test, few so that many keys share each */
#define RFI_GROUPS 40

/* the most keys under one infix, past the most a trie holds so large groups stay plain */
#define RFI_MAX_GROUP 80

/* the longest tail after the infix, in bits */
#define RFI_MAX_TAIL 48

/* one group in this many sits on the widest remainder of its quotient */
#define RFI_EDGE_SHARE 4

/* stores the collision test builds, and probes each answers */
#define RFI_COLLISION_STORES 60
#define RFI_COLLISION_PROBES 4000

static int rfi_cmp_bits(const void *a, const void *b)
{
    return range_filter_bits_compare(a, b);
}

/* a key under the given infix with a random tail, or one stretched past a key or cut short */
static void rfi_make_key(range_filter_bits_t *k, uint64_t infix, unsigned width, uint64_t *seed)
{
    range_filter_bits_init(k);
    ASSERT_EQ(range_filter_bits_append(k, infix, width), 0);
    const unsigned tail = (unsigned)(rfi_next(seed) % RFI_MAX_TAIL);
    if (tail > 0) ASSERT_EQ(range_filter_bits_append(k, rfi_next(seed), tail), 0);
}

/* whether any key lies in [lo, hi] */
static int rfi_brute_keys(const range_filter_bits_t *k, size_t n, const range_filter_bits_t *lo,
                          const range_filter_bits_t *hi)
{
    for (size_t i = 0; i < n; i++)
        if (range_filter_bits_compare(lo, &k[i]) <= 0 && range_filter_bits_compare(&k[i], hi) <= 0)
            return 1;
    return 0;
}

/* keys piled onto few infixes, so most groups carry a trie, and endpoints on those infixes that are
 * rarely keys themselves. no range holding a key is answered no, and the tries do answer no for
 * many ranges whose infixes alone would pass */
void test_range_filter_infix_store_tries_miss_no_key(void)
{
    /* among them quotients so few that the two ends' runs are often adjacent, where nothing
     * between them answers and each end's run must */
    static const unsigned widths[][2] = {{4, 6}, {6, 8}, {0, 12}, {8, 3}, {1, 8}, {2, 10}};
    uint64_t seed = 0x13198a2e03707344ULL;
    int infix_only = 0, refused = 0;
    for (int st = 0; st < RFI_COLLISION_STORES; st++)
    {
        const size_t kind = (size_t)st % (sizeof(widths) / sizeof(widths[0]));
        const unsigned q = widths[kind][0], r = widths[kind][1], w = q + r;
        uint64_t inf[RFI_GROUPS];
        const uint64_t r_mask = (UINT64_C(1) << r) - 1;
        for (int g = 0; g < RFI_GROUPS; g++)
        {
            inf[g] = rfi_next(&seed) % (UINT64_C(1) << w);
            /* a share of the groups on the widest remainder, the one a run's far end is cut to */
            if (g % RFI_EDGE_SHARE == 0) inf[g] |= r_mask;
        }
        size_t n = 0;
        range_filter_bits_t *k = malloc(RFI_GROUPS * RFI_MAX_GROUP * sizeof(*k));
        uint64_t *v = malloc(RFI_GROUPS * RFI_MAX_GROUP * sizeof(*v));
        ASSERT_TRUE(k != NULL && v != NULL);
        for (int g = 0; g < RFI_GROUPS; g++)
        {
            const size_t c = 1 + (size_t)(rfi_next(&seed) % RFI_MAX_GROUP);
            for (size_t i = 0; i < c; i++) rfi_make_key(&k[n++], inf[g], w, &seed);
        }
        qsort(k, n, sizeof(*k), rfi_cmp_bits);
        size_t u = 0;
        for (size_t i = 0; i < n; i++)
        {
            /* the store's keys are distinct and, cut to infixes, in order */
            if (u > 0 && range_filter_bits_compare(&k[u - 1], &k[i]) == 0)
            {
                range_filter_bits_free(&k[i]);
                continue;
            }
            k[u++] = k[i];
        }
        n = u;
        for (size_t i = 0; i < n; i++) v[i] = range_filter_bits_get(&k[i], 0, w);
        range_filter_infix_store_t s;
        ASSERT_EQ(range_filter_infix_store_build(v, k, w, (uint32_t)n, q, r, &s), TDB_SUCCESS);
        for (int p = 0; p < RFI_COLLISION_PROBES; p++)
        {
            range_filter_bits_t lo, hi;
            rfi_make_key(&lo, inf[rfi_next(&seed) % RFI_GROUPS], w, &seed);
            /* the high end on the same infix half the time, so both ends can search one trie */
            rfi_make_key(
                &hi, p % 2 ? range_filter_bits_get(&lo, 0, w) : inf[rfi_next(&seed) % RFI_GROUPS],
                w, &seed);
            if (range_filter_bits_compare(&lo, &hi) > 0)
            {
                const range_filter_bits_t t = lo;
                lo = hi;
                hi = t;
            }
            const uint64_t li = range_filter_bits_get(&lo, 0, w),
                           hi_i = range_filter_bits_get(&hi, 0, w);
            const range_filter_dtrie_probe_t plo = {&lo, w}, phi = {&hi, w};
            const int truth = rfi_brute_keys(k, n, &lo, &hi);
            const int got = range_filter_infix_store_may_contain(&s, li, hi_i, &plo, &phi);
            if (truth) ASSERT_EQ(got, 1);
            /* a high end past every infix is cut back to the widest, and its key stops counting */
            if (n > 0 && range_filter_bits_compare(&lo, &k[n - 1]) <= 0)
                ASSERT_EQ(range_filter_infix_store_may_contain(&s, li, ~UINT64_C(0), &plo, &phi),
                          1);
            if (!truth && rfi_brute(v, n, li, hi_i))
            {
                infix_only++;
                refused += got == 0;
            }
            range_filter_bits_free(&lo);
            range_filter_bits_free(&hi);
        }
        range_filter_infix_store_free(&s);
        for (size_t i = 0; i < n; i++) range_filter_bits_free(&k[i]);
        free(k);
        free(v);
    }
    fprintf(stderr, "  tries refused %d of %d empty ranges the infixes alone would pass\n", refused,
            infix_only);
    ASSERT_TRUE(refused > infix_only / 4);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_range_filter_infix_store_is_exact, tests_passed);
    RUN_TEST(test_range_filter_infix_store_duplicates_and_empty, tests_passed);
    RUN_TEST(test_range_filter_infix_store_rejects_bad_input, tests_passed);
    RUN_TEST(test_range_filter_infix_store_tries_miss_no_key, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
