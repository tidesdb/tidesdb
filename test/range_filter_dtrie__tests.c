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
#include "../src/range_filter/range_filter_dtrie.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* groups each property test builds */
#define RFD_TRIALS 3000

/* probes each group answers */
#define RFD_PROBES 200

/* the longest shared prefix and the longest tail the generator makes, in bits */
#define RFD_MAX_PREFIX 70
#define RFD_MAX_TAIL   150

/* a budget no group here can fill, so every trailing string runs past its key's end */
#define RFD_AMPLE 8192

/* the tail width of the exactness test, every key and probe the same length */
#define RFD_FIXED_TAIL 40

/* bits one random draw supplies */
#define RFD_WORD_BITS 64

/* random strings the damage test feeds the parser */
#define RFD_GARBAGE 20000

/* the most bits one garbage string holds */
#define RFD_GARBAGE_BITS 600

static uint64_t rfd_next(uint64_t *s)
{
    uint64_t z = (*s += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

/* append n random bits */
static void rfd_random_bits(range_filter_bits_t *b, size_t n, uint64_t *seed)
{
    while (n > 0)
    {
        const unsigned take = n < RFD_WORD_BITS ? (unsigned)n : RFD_WORD_BITS;
        ASSERT_EQ(range_filter_bits_append(b, rfd_next(seed), take), 0);
        n -= take;
    }
}

static int rfd_cmp(const void *a, const void *b)
{
    return range_filter_bits_compare(a, b);
}

/* a key made of the shared prefix and a tail of tail_len bits */
static void rfd_key(range_filter_bits_t *k, const range_filter_bits_t *prefix, size_t tail_len,
                    uint64_t *seed)
{
    range_filter_bits_init(k);
    ASSERT_EQ(range_filter_bits_append_range(k, prefix, 0, prefix->nbits), 0);
    rfd_random_bits(k, tail_len, seed);
}

/* n distinct keys under one prefix in increasing order, returning how many survive dropping
 * repeats */
static size_t rfd_group(range_filter_bits_t *keys, size_t n, const range_filter_bits_t *prefix,
                        size_t fixed_tail, uint64_t *seed)
{
    for (size_t i = 0; i < n; i++)
    {
        const size_t len = fixed_tail ? fixed_tail : (size_t)(rfd_next(seed) % RFD_MAX_TAIL);
        rfd_key(&keys[i], prefix, len, seed);
    }
    qsort(keys, n, sizeof(*keys), rfd_cmp);
    size_t out = 0;
    for (size_t i = 0; i < n; i++)
    {
        if (out > 0 && range_filter_bits_compare(&keys[out - 1], &keys[i]) == 0)
        {
            range_filter_bits_free(&keys[i]);
            continue;
        }
        keys[out++] = keys[i];
    }
    return out;
}

/* a probe under the prefix, usually near a key so the trie's paths are exercised */
static void rfd_probe(range_filter_bits_t *p, const range_filter_bits_t *keys, size_t n,
                      const range_filter_bits_t *prefix, size_t fixed_tail, uint64_t *seed)
{
    const uint64_t kind = rfd_next(seed) % 3;
    if (kind == 0)
    {
        rfd_key(p, prefix, fixed_tail ? fixed_tail : (size_t)(rfd_next(seed) % RFD_MAX_TAIL), seed);
        return;
    }
    const range_filter_bits_t *k = &keys[rfd_next(seed) % n];
    range_filter_bits_init(p);
    ASSERT_EQ(range_filter_bits_append_range(p, k, 0, k->nbits), 0);
    if (kind == 2 && k->nbits > prefix->nbits)
    {
        /* keep a random part of the key's tail and redraw the rest */
        const size_t keep = prefix->nbits + (size_t)(rfd_next(seed) % (k->nbits - prefix->nbits));
        range_filter_bits_truncate(p, keep);
        const size_t want = fixed_tail ? prefix->nbits + fixed_tail : keep + rfd_next(seed) % 16;
        rfd_random_bits(p, want > keep ? want - keep : 0, seed);
    }
}

/* whether a key lies at or above lo and at or below hi, a NULL end holding for every key */
static int rfd_truth(const range_filter_bits_t *keys, size_t n, const range_filter_bits_t *lo,
                     const range_filter_bits_t *hi)
{
    for (size_t i = 0; i < n; i++)
        if ((!lo || range_filter_bits_compare(lo, &keys[i]) <= 0) &&
            (!hi || range_filter_bits_compare(&keys[i], hi) <= 0))
            return 1;
    return 0;
}

/* encode, then parse back the shape the encoder wrote and check it fills the budget exactly */
static int rfd_encode_and_parse(const range_filter_bits_t *keys, size_t n, size_t tail_off,
                                size_t budget, range_filter_bits_t *out, range_filter_dtrie_t *t)
{
    int fitted = 0;
    ASSERT_EQ(range_filter_dtrie_encode(keys, n, tail_off, budget, out, &fitted), TDB_SUCCESS);
    if (!fitted)
    {
        ASSERT_EQ(out->nbits, (size_t)0);
        return 0;
    }
    ASSERT_EQ(out->nbits, budget);
    ASSERT_EQ(range_filter_dtrie_parse(out, 0, budget, t), TDB_SUCCESS);
    ASSERT_EQ(t->keys, n);
    ASSERT_EQ(range_filter_dtrie_set_budget(t, budget), TDB_SUCCESS);
    return 1;
}

/* one group's probes, checked against a scan of its keys, exact when the tails all fit whole */
static void rfd_check_probes(const range_filter_bits_t *src, const range_filter_dtrie_t *t,
                             const range_filter_bits_t *keys, size_t n,
                             const range_filter_bits_t *prefix, size_t fixed_tail, int exact,
                             uint64_t *seed)
{
    for (int p = 0; p < RFD_PROBES; p++)
    {
        range_filter_bits_t a, b;
        rfd_probe(&a, keys, n, prefix, fixed_tail, seed);
        rfd_probe(&b, keys, n, prefix, fixed_tail, seed);
        if (range_filter_bits_compare(&a, &b) > 0)
        {
            const range_filter_bits_t swap = a;
            a = b;
            b = swap;
        }
        /* both ends, then each alone as the store tests an end lying on the group's infix */
        const int side = p % 3;
        const range_filter_bits_t *lo = side == 2 ? NULL : &a;
        const range_filter_bits_t *hi = side == 1 ? NULL : &b;
        const range_filter_dtrie_probe_t plo = {lo, prefix->nbits}, phi = {hi, prefix->nbits};
        const int truth = rfd_truth(keys, n, lo, hi);
        const int got = range_filter_dtrie_may_contain(src, t, &plo, &phi);
        if (truth) ASSERT_EQ(got, 1);
        if (exact) ASSERT_EQ(got, truth);
        range_filter_bits_free(&a);
        range_filter_bits_free(&b);
    }
}

/* a trie answers yes for every range holding one of its keys, across group sizes, tail lengths and
 * budgets from barely enough to more than the tails need */
void test_range_filter_dtrie_misses_no_key(void)
{
    uint64_t seed = 0x1234;
    range_filter_bits_t keys[RANGE_FILTER_DTRIE_MAX_KEYS];
    int built = 0;
    for (int trial = 0; trial < RFD_TRIALS; trial++)
    {
        range_filter_bits_t prefix;
        range_filter_bits_init(&prefix);
        rfd_random_bits(&prefix, (size_t)(rfd_next(&seed) % RFD_MAX_PREFIX), &seed);
        const size_t want = 2 + (size_t)(rfd_next(&seed) % (RANGE_FILTER_DTRIE_MAX_KEYS - 1));
        const size_t n = rfd_group(keys, want, &prefix, 0, &seed);
        const size_t budget = trial % 2 ? RFD_AMPLE : (size_t)(rfd_next(&seed) % (n * 40));
        range_filter_bits_t out;
        range_filter_bits_init(&out);
        range_filter_dtrie_t t;
        if (n >= 2 && rfd_encode_and_parse(keys, n, prefix.nbits, budget, &out, &t))
        {
            built++;
            rfd_check_probes(&out, &t, keys, n, &prefix, 0, 0, &seed);
        }
        range_filter_bits_free(&out);
        for (size_t i = 0; i < n; i++) range_filter_bits_free(&keys[i]);
        range_filter_bits_free(&prefix);
    }
    fprintf(stderr, "  %d of %d groups fit a trie\n", built, RFD_TRIALS);
    ASSERT_TRUE(built > RFD_TRIALS / 2);
}

/* with tails of one length and room for every tail whole, a trie answers exactly as its keys do */
void test_range_filter_dtrie_is_exact_with_whole_tails(void)
{
    uint64_t seed = 0x5678;
    range_filter_bits_t keys[RANGE_FILTER_DTRIE_MAX_KEYS];
    for (int trial = 0; trial < RFD_TRIALS / 4; trial++)
    {
        range_filter_bits_t prefix;
        range_filter_bits_init(&prefix);
        rfd_random_bits(&prefix, (size_t)(rfd_next(&seed) % RFD_MAX_PREFIX), &seed);
        const size_t want = 2 + (size_t)(rfd_next(&seed) % (RANGE_FILTER_DTRIE_MAX_KEYS - 1));
        const size_t n = rfd_group(keys, want, &prefix, RFD_FIXED_TAIL, &seed);
        range_filter_bits_t out;
        range_filter_bits_init(&out);
        range_filter_dtrie_t t;
        if (n >= 2)
        {
            ASSERT_EQ(rfd_encode_and_parse(keys, n, prefix.nbits, RFD_AMPLE, &out, &t), 1);
            ASSERT_TRUE(t.trail >= RFD_FIXED_TAIL);
            rfd_check_probes(&out, &t, keys, n, &prefix, RFD_FIXED_TAIL, 1, &seed);
        }
        range_filter_bits_free(&out);
        for (size_t i = 0; i < n; i++) range_filter_bits_free(&keys[i]);
        range_filter_bits_free(&prefix);
    }
}

/* path lengths go in unary when the paths are short and in elias-gamma when they are long */
void test_range_filter_dtrie_picks_the_smaller_format(void)
{
    range_filter_bits_t keys[2], out;
    range_filter_bits_init(&out);
    range_filter_dtrie_t t;
    /* tails 0... and 1... part at once, a path of length 0 */
    for (int i = 0; i < 2; i++)
    {
        range_filter_bits_init(&keys[i]);
        ASSERT_EQ(range_filter_bits_append(&keys[i], (uint64_t)i, 1), 0);
    }
    ASSERT_EQ(rfd_encode_and_parse(keys, 2, 0, RFD_AMPLE, &out, &t), 1);
    ASSERT_EQ(range_filter_bits_get(&out, 0, 1), (uint64_t)0);
    ASSERT_EQ(t.trie_bits, (size_t)(1 + 1 + 1 + 2)); /* format, branch, unary 0, two leaves */
    range_filter_bits_free(&out);
    range_filter_bits_init(&out);
    for (int i = 0; i < 2; i++) range_filter_bits_free(&keys[i]);

    /* tails sharing 40 bits before they part, which unary spends 41 bits on and gamma 11 */
    for (int i = 0; i < 2; i++)
    {
        range_filter_bits_init(&keys[i]);
        ASSERT_EQ(range_filter_bits_append(&keys[i], UINT64_C(0xABCDEF0123), 40), 0);
        ASSERT_EQ(range_filter_bits_append(&keys[i], (uint64_t)i, 1), 0);
    }
    ASSERT_EQ(rfd_encode_and_parse(keys, 2, 0, RFD_AMPLE, &out, &t), 1);
    ASSERT_EQ(range_filter_bits_get(&out, 0, 1), (uint64_t)1);
    ASSERT_EQ(t.trie_bits, (size_t)(1 + 1 + 11 + 40 + 2));
    range_filter_bits_free(&out);
    for (int i = 0; i < 2; i++) range_filter_bits_free(&keys[i]);
}

/* tails equal once padded, or a trie larger than its budget, append nothing */
void test_range_filter_dtrie_declines_what_it_cannot_hold(void)
{
    range_filter_bits_t keys[2], out;
    range_filter_bits_init(&out);
    range_filter_bits_init(&keys[0]);
    range_filter_bits_init(&keys[1]);
    ASSERT_EQ(range_filter_bits_append(&keys[0], 1, 1), 0);
    ASSERT_EQ(range_filter_bits_append(&keys[1], 2, 2), 0); /* "1" and "10" */
    int fitted = 1;
    ASSERT_EQ(range_filter_dtrie_encode(keys, 2, 0, RFD_AMPLE, &out, &fitted), TDB_SUCCESS);
    ASSERT_EQ(fitted, 0);
    ASSERT_EQ(out.nbits, (size_t)0);

    range_filter_bits_free(&keys[1]);
    range_filter_bits_init(&keys[1]);
    ASSERT_EQ(range_filter_bits_append(&keys[1], 3, 2), 0); /* "1" and "11" part at bit 1 */
    ASSERT_EQ(range_filter_dtrie_encode(keys, 2, 0, 6, &out, &fitted), TDB_SUCCESS);
    ASSERT_EQ(fitted, 0); /* format, branch, a unary 1 in two bits, its label, two leaves need 7 */
    ASSERT_EQ(out.nbits, (size_t)0);
    ASSERT_EQ(range_filter_dtrie_encode(keys, 2, 0, 7, &out, &fitted), TDB_SUCCESS);
    ASSERT_EQ(fitted, 1);
    ASSERT_EQ(out.nbits, (size_t)7);
    ASSERT_EQ(range_filter_dtrie_encode(keys, 1, 0, 7, &out, &fitted), TDB_ERR_INVALID_ARGS);
    range_filter_bits_free(&out);
    range_filter_bits_free(&keys[0]);
    range_filter_bits_free(&keys[1]);
}

/* bits that are not a whole trie inside their limit are refused, and whatever the parser accepts
 * can be searched without reading outside it */
void test_range_filter_dtrie_parse_refuses_damage(void)
{
    range_filter_bits_t b;
    range_filter_bits_init(&b);
    range_filter_dtrie_t t;
    ASSERT_EQ(range_filter_bits_append(&b, 0x3, 2), 0); /* format, then a lone leaf */
    ASSERT_EQ(range_filter_dtrie_parse(&b, 0, 2, &t), TDB_ERR_CORRUPTION);
    range_filter_bits_reset(&b);
    /* format, a branch with a one-bit path, one leaf, and the second leaf missing */
    ASSERT_EQ(range_filter_bits_append(&b, 0x05, 5), 0);
    ASSERT_EQ(range_filter_bits_append(&b, 1, 1), 0);
    ASSERT_EQ(range_filter_dtrie_parse(&b, 0, 5, &t), TDB_ERR_CORRUPTION);
    ASSERT_EQ(range_filter_dtrie_parse(&b, 0, 6, &t), TDB_ERR_CORRUPTION);
    ASSERT_EQ(range_filter_dtrie_parse(&b, 3, 3, &t), TDB_ERR_CORRUPTION);
    range_filter_bits_reset(&b);

    uint64_t seed = 0x9abc;
    int accepted = 0;
    for (int i = 0; i < RFD_GARBAGE; i++)
    {
        const size_t len = 1 + (size_t)(rfd_next(&seed) % RFD_GARBAGE_BITS);
        rfd_random_bits(&b, len, &seed);
        if (range_filter_dtrie_parse(&b, 0, len, &t) == TDB_SUCCESS)
        {
            accepted++;
            ASSERT_TRUE(t.keys >= 2 && t.keys <= RANGE_FILTER_DTRIE_MAX_KEYS);
            ASSERT_TRUE(t.trie_bits <= len);
            if (range_filter_dtrie_set_budget(&t, len) == TDB_SUCCESS)
            {
                range_filter_bits_t probe;
                range_filter_bits_init(&probe);
                rfd_random_bits(&probe, (size_t)(rfd_next(&seed) % RFD_WORD_BITS), &seed);
                const range_filter_dtrie_probe_t p = {&probe, 0};
                const int got = range_filter_dtrie_may_contain(&b, &t, &p, &p);
                ASSERT_TRUE(got == 0 || got == 1);
                range_filter_bits_free(&probe);
            }
        }
        range_filter_bits_reset(&b);
    }
    fprintf(stderr, "  %d of %d random strings parsed as tries\n", accepted, RFD_GARBAGE);
    range_filter_bits_free(&b);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_range_filter_dtrie_misses_no_key, tests_passed);
    RUN_TEST(test_range_filter_dtrie_is_exact_with_whole_tails, tests_passed);
    RUN_TEST(test_range_filter_dtrie_picks_the_smaller_format, tests_passed);
    RUN_TEST(test_range_filter_dtrie_declines_what_it_cannot_hold, tests_passed);
    RUN_TEST(test_range_filter_dtrie_parse_refuses_damage, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
