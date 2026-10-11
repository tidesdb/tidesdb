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

#include "../src/range_filter/range_filter_bits.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* fields this many bits wide or narrower are appended in the random round trip */
#define RFB_MAX_FIELD 64

/* how many random fields the round trip appends, enough to cross many word boundaries */
#define RFB_FIELDS 4096

/* a fixed-seed xorshift, so a failure reproduces */
static uint64_t rfb_next(uint64_t *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    return *s;
}

/* every field appended reads back where it was put, whatever word boundaries it straddles */
void test_range_filter_bits_round_trip(void)
{
    range_filter_bits_t b;
    range_filter_bits_init(&b);
    uint64_t *vals = malloc(RFB_FIELDS * sizeof(*vals));
    unsigned *lens = malloc(RFB_FIELDS * sizeof(*lens));
    ASSERT_TRUE(vals && lens);
    uint64_t seed = 0x9e3779b97f4a7c15ULL;
    for (int i = 0; i < RFB_FIELDS; i++)
    {
        lens[i] = (unsigned)(rfb_next(&seed) % RFB_MAX_FIELD) + 1;
        const uint64_t mask = lens[i] == 64 ? ~UINT64_C(0) : (UINT64_C(1) << lens[i]) - 1;
        vals[i] = rfb_next(&seed) & mask;
        ASSERT_EQ(range_filter_bits_append(&b, vals[i], lens[i]), 0);
    }
    size_t off = 0;
    for (int i = 0; i < RFB_FIELDS; i++)
    {
        ASSERT_TRUE(range_filter_bits_get(&b, off, lens[i]) == vals[i]);
        off += lens[i];
    }
    ASSERT_EQ(b.nbits, off);
    free(vals);
    free(lens);
    range_filter_bits_free(&b);
}

/* bits past the end read as zero, which is how a short key is padded to a window */
void test_range_filter_bits_pads_past_the_end_with_zero(void)
{
    range_filter_bits_t b;
    range_filter_bits_init(&b);
    ASSERT_EQ(range_filter_bits_append(&b, 0x7, 3), 0);
    ASSERT_TRUE(range_filter_bits_get(&b, 0, 8) == 0xE0);
    ASSERT_TRUE(range_filter_bits_get(&b, 2, 4) == 0x8);
    ASSERT_TRUE(range_filter_bits_get(&b, 3, 16) == 0);
    ASSERT_TRUE(range_filter_bits_get(&b, 1000, 64) == 0);
    range_filter_bits_free(&b);
}

/* comparison is lexicographic over bits, with a proper prefix sorting first */
void test_range_filter_bits_compare(void)
{
    range_filter_bits_t a, b;
    range_filter_bits_init(&a);
    range_filter_bits_init(&b);
    ASSERT_EQ(range_filter_bits_compare(&a, &b), 0);

    ASSERT_EQ(range_filter_bits_append(&a, 0x5, 3), 0); /* 101 */
    ASSERT_TRUE(range_filter_bits_compare(&b, &a) < 0); /* empty is a prefix of everything */
    ASSERT_EQ(range_filter_bits_append(&b, 0x5, 3), 0); /* 101 */
    ASSERT_EQ(range_filter_bits_compare(&a, &b), 0);
    ASSERT_EQ(range_filter_bits_append(&b, 0x0, 1), 0); /* 1010 */
    ASSERT_TRUE(range_filter_bits_compare(&a, &b) < 0);
    ASSERT_TRUE(range_filter_bits_compare(&b, &a) > 0);
    ASSERT_EQ(range_filter_bits_common_prefix(&a, &b), 3);

    /* a difference in a later word, past a full shared word */
    range_filter_bits_reset(&a);
    range_filter_bits_reset(&b);
    ASSERT_EQ(range_filter_bits_append(&a, ~UINT64_C(0), 64), 0);
    ASSERT_EQ(range_filter_bits_append(&b, ~UINT64_C(0), 64), 0);
    ASSERT_EQ(range_filter_bits_append(&a, 0x2, 2), 0); /* 10 */
    ASSERT_EQ(range_filter_bits_append(&b, 0x3, 2), 0); /* 11 */
    ASSERT_EQ(range_filter_bits_common_prefix(&a, &b), 65);
    ASSERT_TRUE(range_filter_bits_compare(&a, &b) < 0);
    range_filter_bits_free(&a);
    range_filter_bits_free(&b);
}

/* a reset string is empty and appends as if new, with no stale bits showing through */
void test_range_filter_bits_reset_leaves_no_stale_bits(void)
{
    range_filter_bits_t b;
    range_filter_bits_init(&b);
    ASSERT_EQ(range_filter_bits_append(&b, ~UINT64_C(0), 64), 0);
    ASSERT_EQ(range_filter_bits_append(&b, ~UINT64_C(0), 40), 0);
    range_filter_bits_reset(&b);
    ASSERT_EQ(b.nbits, 0);
    ASSERT_EQ(range_filter_bits_append(&b, 0x1, 2), 0); /* 01 */
    ASSERT_TRUE(range_filter_bits_get(&b, 0, 64) == (UINT64_C(1) << 62));
    range_filter_bits_free(&b);
}

/* an oversized field is refused rather than truncated */
void test_range_filter_bits_rejects_an_oversized_field(void)
{
    range_filter_bits_t b;
    range_filter_bits_init(&b);
    ASSERT_EQ(range_filter_bits_append(&b, 0, 65), -1);
    ASSERT_EQ(range_filter_bits_append(NULL, 0, 1), -1);
    ASSERT_EQ(b.nbits, 0);
    range_filter_bits_free(&b);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_range_filter_bits_round_trip, tests_passed);
    RUN_TEST(test_range_filter_bits_pads_past_the_end_with_zero, tests_passed);
    RUN_TEST(test_range_filter_bits_compare, tests_passed);
    RUN_TEST(test_range_filter_bits_reset_leaves_no_stale_bits, tests_passed);
    RUN_TEST(test_range_filter_bits_rejects_an_oversized_field, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
