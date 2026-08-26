/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/compat.h"
#include "../src/range_tombstone/range_tombstone.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* the differential round lays this many tombstones over a small alphabet, so the intervals overlap
 * often enough that fragmentation is what is actually under test */
#define RT_ORACLE_ROUNDS      200
#define RT_ORACLE_ADDS        12
#define RT_ORACLE_ALPHABET    4
#define RT_ORACLE_MAX_KEY_LEN 3

/* roughly one interval in this many is left unbounded above, to keep that arm of the merge covered
 * without letting it swallow every round */
#define RT_ORACLE_UNBOUNDED_ONE_IN 7

/* a fixed seed so a failing round is the same round on the next run */
#define RT_ORACLE_SEED 0x9e3779b97f4a7c15ULL

typedef struct
{
    uint8_t lo[RT_ORACLE_MAX_KEY_LEN];
    size_t lo_size;
    uint8_t hi[RT_ORACLE_MAX_KEY_LEN];
    size_t hi_size;
    uint64_t seq;
} rt_oracle_interval_t;

static uint64_t rt_rand_state = RT_ORACLE_SEED;

/* xorshift64, for a generator that repeats exactly across platforms and runs where rand() does not
 */
static uint64_t rt_rand(void)
{
    rt_rand_state ^= rt_rand_state << 13;
    rt_rand_state ^= rt_rand_state >> 7;
    rt_rand_state ^= rt_rand_state << 17;
    return rt_rand_state;
}

/* the same byte-wise order the set sorts in, written out again here so the oracle agrees with the
 * implementation only where the implementation is right */
static int rt_test_key_cmp(const uint8_t *key1, const size_t key1_size, const uint8_t *key2,
                           const size_t key2_size)
{
    const size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    const int c = min_size > 0 ? memcmp(key1, key2, min_size) : 0;
    if (c != 0) return c < 0 ? -1 : 1;
    if (key1_size < key2_size) return -1;
    if (key1_size > key2_size) return 1;
    return 0;
}

static void add_interval(range_tombstone_set_t *set, const char *lo, const char *hi,
                         const uint64_t seq)
{
    const size_t hi_size = hi ? strlen(hi) : RT_UNBOUNDED_ABOVE;
    ASSERT_EQ(range_tombstone_set_add(set, (const uint8_t *)lo, strlen(lo), (const uint8_t *)hi,
                                      hi_size, seq),
              TDB_SUCCESS);
}

static int covering(const range_tombstone_set_t *set, const char *key, const uint64_t snapshot_seq,
                    uint64_t *out_seq)
{
    return range_tombstone_max_covering(set, (const uint8_t *)key, strlen(key), snapshot_seq,
                                        out_seq);
}

/* every property the set claims to hold, checked after each mutation -- sorted, non-overlapping,
 * each fragment a real interval, each sequence list descending and free of repeats */
static void assert_set_invariants(const range_tombstone_set_t *set)
{
    const rt_fragment_t *prev = NULL;
    for (size_t i = 0; i < range_tombstone_set_count(set); i++)
    {
        const rt_fragment_t *frag = NULL;
        ASSERT_EQ(range_tombstone_set_fragment_at(set, i, &frag), TDB_SUCCESS);
        ASSERT_TRUE(frag->seq_count >= 1);
        ASSERT_TRUE(frag->hi_size == RT_UNBOUNDED_ABOVE ||
                    rt_test_key_cmp(frag->lo, frag->lo_size, frag->hi, frag->hi_size) < 0);

        for (size_t s = 1; s < frag->seq_count; s++) ASSERT_TRUE(frag->seqs[s - 1] > frag->seqs[s]);

        if (prev)
        {
            ASSERT_TRUE(prev->hi_size != RT_UNBOUNDED_ABOVE);
            ASSERT_TRUE(rt_test_key_cmp(prev->hi, prev->hi_size, frag->lo, frag->lo_size) <= 0);
        }
        prev = frag;
    }
}

void test_range_tombstone_empty_set_covers_nothing(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    ASSERT_EQ(range_tombstone_set_count(set), 0);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "anything", UINT64_MAX, &seq), 0);
    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_interval_is_half_open(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    add_interval(set, "c", "f", 10);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "b", 10, &seq), 0);
    ASSERT_EQ(covering(set, "c", 10, &seq), 1);
    ASSERT_EQ(seq, 10);
    ASSERT_EQ(covering(set, "e", 10, &seq), 1);
    ASSERT_EQ(covering(set, "f", 10, &seq), 0);
    ASSERT_EQ(covering(set, "g", 10, &seq), 0);

    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_snapshot_below_the_tombstone_sees_nothing(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    add_interval(set, "c", "f", 10);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "d", 9, &seq), 0);
    ASSERT_EQ(covering(set, "d", 10, &seq), 1);
    ASSERT_EQ(seq, 10);

    range_tombstone_set_free(set);
}

void test_range_tombstone_overlap_keeps_the_older_sequence_visible(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    add_interval(set, "a", "z", 10);
    add_interval(set, "c", "e", 20);

    /* the interval splits at both of the inner bounds and nowhere else */
    ASSERT_EQ(range_tombstone_set_count(set), 3);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "d", 25, &seq), 1);
    ASSERT_EQ(seq, 20);

    /* a read between the two sequences still sees the older tombstone, which is the version a
     * single newest-sequence per fragment would have hidden */
    ASSERT_EQ(covering(set, "d", 15, &seq), 1);
    ASSERT_EQ(seq, 10);

    ASSERT_EQ(covering(set, "b", 25, &seq), 1);
    ASSERT_EQ(seq, 10);

    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_disjoint_intervals_do_not_fragment(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    add_interval(set, "a", "c", 10);
    add_interval(set, "m", "p", 20);
    ASSERT_EQ(range_tombstone_set_count(set), 2);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "b", 30, &seq), 1);
    ASSERT_EQ(seq, 10);
    ASSERT_EQ(covering(set, "g", 30, &seq), 0);
    ASSERT_EQ(covering(set, "n", 30, &seq), 1);
    ASSERT_EQ(seq, 20);

    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_adjacent_intervals_stay_separate(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    add_interval(set, "a", "c", 10);
    add_interval(set, "c", "e", 20);
    ASSERT_EQ(range_tombstone_set_count(set), 2);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "b", 30, &seq), 1);
    ASSERT_EQ(seq, 10);
    ASSERT_EQ(covering(set, "c", 30, &seq), 1);
    ASSERT_EQ(seq, 20);

    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_added_out_of_order_still_sorts(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    add_interval(set, "m", "p", 10);
    add_interval(set, "a", "c", 20);
    add_interval(set, "e", "g", 30);
    ASSERT_EQ(range_tombstone_set_count(set), 3);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "b", 40, &seq), 1);
    ASSERT_EQ(seq, 20);
    ASSERT_EQ(covering(set, "f", 40, &seq), 1);
    ASSERT_EQ(seq, 30);
    ASSERT_EQ(covering(set, "n", 40, &seq), 1);
    ASSERT_EQ(seq, 10);

    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_spanning_interval_absorbs_the_gaps(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    add_interval(set, "b", "d", 10);
    add_interval(set, "f", "h", 20);

    /* one interval reaching across both and the gap between them splits into five */
    add_interval(set, "a", "z", 30);
    ASSERT_EQ(range_tombstone_set_count(set), 5);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "e", 30, &seq), 1);
    ASSERT_EQ(seq, 30);
    ASSERT_EQ(covering(set, "e", 25, &seq), 0);
    ASSERT_EQ(covering(set, "c", 25, &seq), 1);
    ASSERT_EQ(seq, 10);
    ASSERT_EQ(covering(set, "g", 25, &seq), 1);
    ASSERT_EQ(seq, 20);

    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_repeated_sequence_is_not_stored_twice(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);

    /* two tombstones committed together at one sequence, overlapping each other */
    add_interval(set, "a", "z", 10);
    add_interval(set, "c", "e", 10);

    for (size_t i = 0; i < range_tombstone_set_count(set); i++)
    {
        const rt_fragment_t *frag = NULL;
        ASSERT_EQ(range_tombstone_set_fragment_at(set, i, &frag), TDB_SUCCESS);
        ASSERT_EQ(frag->seq_count, 1);
    }

    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_unbounded_above_covers_the_tail(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    add_interval(set, "m", NULL, 10);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "l", 20, &seq), 0);
    ASSERT_EQ(covering(set, "m", 20, &seq), 1);
    ASSERT_EQ(covering(set, "zzzzzzzz", 20, &seq), 1);
    ASSERT_EQ(seq, 10);

    /* a bounded interval laid inside it splits the tail without losing it */
    add_interval(set, "p", "r", 20);
    ASSERT_EQ(covering(set, "q", 25, &seq), 1);
    ASSERT_EQ(seq, 20);
    ASSERT_EQ(covering(set, "zzzzzzzz", 25, &seq), 1);
    ASSERT_EQ(seq, 10);

    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_unbounded_over_unbounded_stays_one_tail(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    add_interval(set, "m", NULL, 10);
    add_interval(set, "p", NULL, 20);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "n", 25, &seq), 1);
    ASSERT_EQ(seq, 10);
    ASSERT_EQ(covering(set, "zzzz", 25, &seq), 1);
    ASSERT_EQ(seq, 20);
    ASSERT_EQ(covering(set, "zzzz", 15, &seq), 1);
    ASSERT_EQ(seq, 10);

    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_prefix_successor_increments_the_last_byte(void)
{
    const uint8_t prefix[] = {'a', 'b', 'c'};
    uint8_t *hi = NULL;
    size_t hi_size = 0;

    ASSERT_EQ(range_tombstone_prefix_successor(prefix, sizeof(prefix), &hi, &hi_size), TDB_SUCCESS);
    ASSERT_EQ(hi_size, 3);
    ASSERT_EQ(hi[0], 'a');
    ASSERT_EQ(hi[1], 'b');
    ASSERT_EQ(hi[2], 'd');
    free(hi);
}

void test_range_tombstone_prefix_successor_strips_trailing_max_bytes(void)
{
    const uint8_t prefix[] = {'a', 0xff, 0xff};
    uint8_t *hi = NULL;
    size_t hi_size = 0;

    ASSERT_EQ(range_tombstone_prefix_successor(prefix, sizeof(prefix), &hi, &hi_size), TDB_SUCCESS);
    ASSERT_EQ(hi_size, 1);
    ASSERT_EQ(hi[0], 'b');
    free(hi);
}

void test_range_tombstone_prefix_successor_of_all_max_bytes_is_unbounded(void)
{
    const uint8_t prefix[] = {0xff, 0xff};
    uint8_t *hi = NULL;
    size_t hi_size = 1;

    ASSERT_EQ(range_tombstone_prefix_successor(prefix, sizeof(prefix), &hi, &hi_size), TDB_SUCCESS);
    ASSERT_TRUE(hi == NULL);
    ASSERT_EQ(hi_size, RT_UNBOUNDED_ABOVE);

    /* the empty prefix is the same case and covers every key there is */
    hi_size = 1;
    ASSERT_EQ(range_tombstone_prefix_successor(NULL, 0, &hi, &hi_size), TDB_SUCCESS);
    ASSERT_TRUE(hi == NULL);
    ASSERT_EQ(hi_size, RT_UNBOUNDED_ABOVE);
}

void test_range_tombstone_prefix_covers_every_key_under_it(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);

    const uint8_t prefix[] = {'u', 's', 'e', 'r', ':'};
    ASSERT_EQ(range_tombstone_set_add_prefix(set, prefix, sizeof(prefix), 10), TDB_SUCCESS);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "user:", 10, &seq), 1);
    ASSERT_EQ(covering(set, "user:0", 10, &seq), 1);
    ASSERT_EQ(covering(set, "user:zzzzzz", 10, &seq), 1);
    ASSERT_EQ(seq, 10);

    /* the neighbours the successor has to exclude */
    ASSERT_EQ(covering(set, "user9", 10, &seq), 0);
    ASSERT_EQ(covering(set, "user", 10, &seq), 0);
    ASSERT_EQ(covering(set, "usef", 10, &seq), 0);

    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_max_byte_prefix_covers_its_own_keys(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);

    const uint8_t prefix[] = {'a', 0xff};
    ASSERT_EQ(range_tombstone_set_add_prefix(set, prefix, sizeof(prefix), 10), TDB_SUCCESS);

    const uint8_t under[] = {'a', 0xff, 0x00};
    const uint8_t outside[] = {'a', 0xfe};
    uint64_t seq = 0;

    ASSERT_EQ(range_tombstone_max_covering(set, prefix, sizeof(prefix), 10, &seq), 1);
    ASSERT_EQ(range_tombstone_max_covering(set, under, sizeof(under), 10, &seq), 1);
    ASSERT_EQ(range_tombstone_max_covering(set, outside, sizeof(outside), 10, &seq), 0);

    /* stripping the trailing 0xff must not widen the interval onto the next key up */
    const uint8_t next[] = {'b'};
    ASSERT_EQ(range_tombstone_max_covering(set, next, sizeof(next), 10, &seq), 0);

    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_empty_prefix_covers_every_key(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    ASSERT_EQ(range_tombstone_set_add_prefix(set, NULL, 0, 10), TDB_SUCCESS);
    ASSERT_EQ(range_tombstone_set_count(set), 1);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "", 10, &seq), 1);
    ASSERT_EQ(covering(set, "a", 10, &seq), 1);
    ASSERT_EQ(covering(set, "zzzzzzzzzz", 10, &seq), 1);
    ASSERT_EQ(seq, 10);

    assert_set_invariants(set);
    range_tombstone_set_free(set);
}

void test_range_tombstone_empty_interval_is_refused(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);

    ASSERT_EQ(range_tombstone_set_add(set, (const uint8_t *)"c", 1, (const uint8_t *)"c", 1, 10),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_set_add(set, (const uint8_t *)"f", 1, (const uint8_t *)"c", 1, 10),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_set_count(set), 0);

    range_tombstone_set_free(set);
}

void test_range_tombstone_null_arguments_are_refused(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    uint64_t seq = 0;
    const rt_fragment_t *frag = NULL;

    ASSERT_EQ(range_tombstone_set_add(NULL, (const uint8_t *)"a", 1, (const uint8_t *)"b", 1, 1),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_set_add(set, NULL, 1, (const uint8_t *)"b", 1, 1),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_set_add(set, (const uint8_t *)"a", 1, NULL, 1, 1),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_set_add_prefix(NULL, (const uint8_t *)"a", 1, 1),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_max_covering(NULL, (const uint8_t *)"a", 1, 1, &seq),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_max_covering(set, NULL, 1, 1, &seq), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_max_covering(set, (const uint8_t *)"a", 1, 1, NULL),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_set_fragment_at(set, 0, &frag), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_prefix_successor((const uint8_t *)"a", 1, NULL, NULL),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_set_count(NULL), 0);
    ASSERT_TRUE(range_tombstone_set_clone(NULL) == NULL);

    range_tombstone_set_free(NULL);
    range_tombstone_set_free(set);
}

void test_range_tombstone_clone_is_independent(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    add_interval(set, "a", "z", 10);

    range_tombstone_set_t *copy = range_tombstone_set_clone(set);
    ASSERT_TRUE(copy != NULL);
    ASSERT_EQ(range_tombstone_set_count(copy), 1);

    /* the original moving on must leave the copy where it was */
    add_interval(set, "c", "e", 20);
    ASSERT_EQ(range_tombstone_set_count(set), 3);
    ASSERT_EQ(range_tombstone_set_count(copy), 1);

    uint64_t seq = 0;
    ASSERT_EQ(covering(copy, "d", 30, &seq), 1);
    ASSERT_EQ(seq, 10);
    ASSERT_EQ(covering(set, "d", 30, &seq), 1);
    ASSERT_EQ(seq, 20);

    assert_set_invariants(copy);
    range_tombstone_set_free(copy);
    range_tombstone_set_free(set);
}

void test_range_tombstone_clone_of_an_empty_set_is_empty(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);

    range_tombstone_set_t *copy = range_tombstone_set_clone(set);
    ASSERT_TRUE(copy != NULL);
    ASSERT_EQ(range_tombstone_set_count(copy), 0);

    uint64_t seq = 0;
    ASSERT_EQ(covering(copy, "a", UINT64_MAX, &seq), 0);

    range_tombstone_set_free(copy);
    range_tombstone_set_free(set);
}

/* the fragment query hands back every sequence covering the key, so a caller filtering on more than
 * a ceiling -- an abandoned commit's sequence, say -- can walk them itself */
void test_range_tombstone_covering_fragment_carries_every_sequence(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    add_interval(set, "a", "z", 10);
    add_interval(set, "c", "e", 20);

    const rt_fragment_t *frag = NULL;
    ASSERT_EQ(range_tombstone_covering_fragment(set, (const uint8_t *)"d", 1, &frag), 1);
    ASSERT_EQ(frag->seq_count, 2);
    ASSERT_EQ(frag->seqs[0], 20);
    ASSERT_EQ(frag->seqs[1], 10);

    /* outside the overlap only one tombstone ever applied */
    ASSERT_EQ(range_tombstone_covering_fragment(set, (const uint8_t *)"b", 1, &frag), 1);
    ASSERT_EQ(frag->seq_count, 1);
    ASSERT_EQ(frag->seqs[0], 10);

    /* a key no fragment covers, and the argument guards */
    ASSERT_EQ(range_tombstone_covering_fragment(set, (const uint8_t *)"zz", 2, &frag), 0);
    ASSERT_EQ(range_tombstone_covering_fragment(NULL, (const uint8_t *)"d", 1, &frag),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_covering_fragment(set, NULL, 1, &frag), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(range_tombstone_covering_fragment(set, (const uint8_t *)"d", 1, NULL),
              TDB_ERR_INVALID_ARGS);

    range_tombstone_set_free(set);
}

/* forgetting through a sequence drops it from every fragment and takes with it any fragment left
 * covered by nothing, which is how a spent tombstone leaves the set */
void test_range_tombstone_forget_through_retires_spent_sequences(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    add_interval(set, "a", "z", 10);
    add_interval(set, "c", "e", 20);
    ASSERT_EQ(range_tombstone_set_count(set), 3);

    /* below every sequence, nothing goes */
    ASSERT_EQ(range_tombstone_set_forget_through(set, 9), 0);
    ASSERT_EQ(range_tombstone_set_count(set), 3);

    /* forgetting the older one leaves only the overlap, still covered by the newer */
    ASSERT_EQ(range_tombstone_set_forget_through(set, 10), 3);
    ASSERT_EQ(range_tombstone_set_count(set), 1);

    uint64_t seq = 0;
    ASSERT_EQ(covering(set, "d", UINT64_MAX, &seq), 1);
    ASSERT_EQ(seq, 20);
    ASSERT_EQ(covering(set, "b", UINT64_MAX, &seq), 0);
    assert_set_invariants(set);

    /* and forgetting the last of them empties the set */
    ASSERT_EQ(range_tombstone_set_forget_through(set, 20), 1);
    ASSERT_EQ(range_tombstone_set_count(set), 0);
    ASSERT_EQ(covering(set, "d", UINT64_MAX, &seq), 0);

    ASSERT_EQ(range_tombstone_set_forget_through(NULL, 1), 0);
    range_tombstone_set_free(set);
}

/* the watermark a build records is the newest sequence it could actually see at or below its
 * ceiling, never the ceiling itself */
void test_range_tombstone_max_seq_through_reports_what_is_there(void)
{
    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);

    /* an empty set has applied nothing, whatever ceiling it is asked about */
    ASSERT_EQ(range_tombstone_set_max_seq_through(set, UINT64_MAX), 0);
    ASSERT_EQ(range_tombstone_set_max_seq_through(NULL, UINT64_MAX), 0);

    add_interval(set, "a", "z", 10);
    add_interval(set, "c", "e", 20);
    add_interval(set, "m", "p", 30);

    ASSERT_EQ(range_tombstone_set_max_seq_through(set, UINT64_MAX), 30);
    ASSERT_EQ(range_tombstone_set_max_seq_through(set, 25), 20);
    ASSERT_EQ(range_tombstone_set_max_seq_through(set, 10), 10);
    ASSERT_EQ(range_tombstone_set_max_seq_through(set, 9), 0);

    range_tombstone_set_free(set);
}

/* the newest sequence at or below the snapshot covering the key, found by looking at every
 * tombstone ever added -- what fragmentation has to reproduce without the linear scan */
static int rt_oracle_covering(const rt_oracle_interval_t *ivs, const size_t n, const uint8_t *key,
                              const size_t key_size, const uint64_t snapshot_seq, uint64_t *out_seq)
{
    int found = 0;
    uint64_t best = 0;
    for (size_t i = 0; i < n; i++)
    {
        if (ivs[i].seq > snapshot_seq) continue;
        if (rt_test_key_cmp(key, key_size, ivs[i].lo, ivs[i].lo_size) < 0) continue;
        if (ivs[i].hi_size != RT_UNBOUNDED_ABOVE &&
            rt_test_key_cmp(key, key_size, ivs[i].hi, ivs[i].hi_size) >= 0)
            continue;
        if (!found || ivs[i].seq > best)
        {
            best = ivs[i].seq;
            found = 1;
        }
    }
    if (found) *out_seq = best;
    return found;
}

static size_t rt_rand_key(uint8_t *buf)
{
    const size_t len = (size_t)(rt_rand() % RT_ORACLE_MAX_KEY_LEN) + 1;
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)('a' + (rt_rand() % RT_ORACLE_ALPHABET));
    return len;
}

/* a random half-open interval, with the bounds ordered rather than resampled so the generator
 * always terminates, and an occasional unbounded upper bound */
static void rt_rand_interval(rt_oracle_interval_t *iv, const uint64_t seq)
{
    uint8_t a[RT_ORACLE_MAX_KEY_LEN];
    uint8_t b[RT_ORACLE_MAX_KEY_LEN];
    const size_t a_size = rt_rand_key(a);
    const size_t b_size = rt_rand_key(b);
    const int ordered = rt_test_key_cmp(a, a_size, b, b_size) < 0;

    iv->lo_size = ordered ? a_size : b_size;
    memcpy(iv->lo, ordered ? a : b, iv->lo_size);
    iv->hi_size = ordered ? b_size : a_size;
    memcpy(iv->hi, ordered ? b : a, iv->hi_size);
    iv->seq = seq;

    /* equal bounds describe nothing, so those rounds take the unbounded arm instead */
    if (rt_test_key_cmp(iv->lo, iv->lo_size, iv->hi, iv->hi_size) == 0 ||
        (rt_rand() % RT_ORACLE_UNBOUNDED_ONE_IN) == 0)
        iv->hi_size = RT_UNBOUNDED_ABOVE;
}

/* probe every key the alphabet can spell at every sequence the round used, comparing the set with
 * the oracle at each one */
static void rt_oracle_probe(const range_tombstone_set_t *set, const rt_oracle_interval_t *ivs,
                            const size_t n)
{
    for (size_t len = 1; len <= RT_ORACLE_MAX_KEY_LEN; len++)
    {
        size_t total = 1;
        for (size_t d = 0; d < len; d++) total *= RT_ORACLE_ALPHABET;

        for (size_t word = 0; word < total; word++)
        {
            uint8_t key[RT_ORACLE_MAX_KEY_LEN];
            size_t value = word;
            for (size_t d = 0; d < len; d++)
            {
                key[len - 1 - d] = (uint8_t)('a' + (value % RT_ORACLE_ALPHABET));
                value /= RT_ORACLE_ALPHABET;
            }

            for (uint64_t snapshot_seq = 0; snapshot_seq <= n + 1; snapshot_seq++)
            {
                uint64_t want = 0;
                uint64_t got = 0;
                const int expected = rt_oracle_covering(ivs, n, key, len, snapshot_seq, &want);
                ASSERT_EQ(range_tombstone_max_covering(set, key, len, snapshot_seq, &got),
                          expected);
                if (expected) ASSERT_EQ(got, want);
            }
        }
    }
}

void test_range_tombstone_matches_a_linear_scan_over_every_tombstone(void)
{
    rt_rand_state = RT_ORACLE_SEED;

    for (size_t round = 0; round < RT_ORACLE_ROUNDS; round++)
    {
        rt_oracle_interval_t ivs[RT_ORACLE_ADDS];
        range_tombstone_set_t *set = range_tombstone_set_new();
        ASSERT_TRUE(set != NULL);

        for (size_t i = 0; i < RT_ORACLE_ADDS; i++)
        {
            rt_rand_interval(&ivs[i], (uint64_t)i + 1);
            ASSERT_EQ(
                range_tombstone_set_add(set, ivs[i].lo, ivs[i].lo_size,
                                        ivs[i].hi_size == RT_UNBOUNDED_ABOVE ? NULL : ivs[i].hi,
                                        ivs[i].hi_size, ivs[i].seq),
                TDB_SUCCESS);
            assert_set_invariants(set);
            rt_oracle_probe(set, ivs, i + 1);
        }

        range_tombstone_set_free(set);
    }
}

int main(void)
{
    RUN_TEST(test_range_tombstone_empty_set_covers_nothing, tests_passed);
    RUN_TEST(test_range_tombstone_interval_is_half_open, tests_passed);
    RUN_TEST(test_range_tombstone_snapshot_below_the_tombstone_sees_nothing, tests_passed);
    RUN_TEST(test_range_tombstone_overlap_keeps_the_older_sequence_visible, tests_passed);
    RUN_TEST(test_range_tombstone_disjoint_intervals_do_not_fragment, tests_passed);
    RUN_TEST(test_range_tombstone_adjacent_intervals_stay_separate, tests_passed);
    RUN_TEST(test_range_tombstone_added_out_of_order_still_sorts, tests_passed);
    RUN_TEST(test_range_tombstone_spanning_interval_absorbs_the_gaps, tests_passed);
    RUN_TEST(test_range_tombstone_repeated_sequence_is_not_stored_twice, tests_passed);
    RUN_TEST(test_range_tombstone_unbounded_above_covers_the_tail, tests_passed);
    RUN_TEST(test_range_tombstone_unbounded_over_unbounded_stays_one_tail, tests_passed);
    RUN_TEST(test_range_tombstone_prefix_successor_increments_the_last_byte, tests_passed);
    RUN_TEST(test_range_tombstone_prefix_successor_strips_trailing_max_bytes, tests_passed);
    RUN_TEST(test_range_tombstone_prefix_successor_of_all_max_bytes_is_unbounded, tests_passed);
    RUN_TEST(test_range_tombstone_prefix_covers_every_key_under_it, tests_passed);
    RUN_TEST(test_range_tombstone_max_byte_prefix_covers_its_own_keys, tests_passed);
    RUN_TEST(test_range_tombstone_empty_prefix_covers_every_key, tests_passed);
    RUN_TEST(test_range_tombstone_empty_interval_is_refused, tests_passed);
    RUN_TEST(test_range_tombstone_null_arguments_are_refused, tests_passed);
    RUN_TEST(test_range_tombstone_clone_is_independent, tests_passed);
    RUN_TEST(test_range_tombstone_clone_of_an_empty_set_is_empty, tests_passed);
    RUN_TEST(test_range_tombstone_covering_fragment_carries_every_sequence, tests_passed);
    RUN_TEST(test_range_tombstone_forget_through_retires_spent_sequences, tests_passed);
    RUN_TEST(test_range_tombstone_max_seq_through_reports_what_is_there, tests_passed);
    RUN_TEST(test_range_tombstone_matches_a_linear_scan_over_every_tombstone, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
