/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "../src/txn/mvcc.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define CC_THREADS    8
#define CC_PER_THREAD 2000
#define CC_TOTAL_SEQS (CC_THREADS * CC_PER_THREAD)

/* two hashes landing in the same reservation slot but with different fingerprints, to exercise the
 * collision path; the low bits index the slot, the high 16 bits are the fingerprint */
#define HASH_SLOT       0x12345u
#define HASH_FP_A(slot) (((uint64_t)1 << TDB_MVCC_RES_SEQ_BITS) | (slot))
#define HASH_FP_B(slot) (((uint64_t)2 << TDB_MVCC_RES_SEQ_BITS) | (slot))

/* the sequence counter starts at 1 and hands out monotonically increasing seqs */
void test_mvcc_seq_counter(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    ASSERT_TRUE(tidesdb_mvcc_current_seq(m) == 1);
    ASSERT_TRUE(tidesdb_mvcc_next_seq(m) == 1);
    ASSERT_TRUE(tidesdb_mvcc_next_seq(m) == 2);
    ASSERT_TRUE(tidesdb_mvcc_next_seq(m) == 3);
    ASSERT_TRUE(tidesdb_mvcc_current_seq(m) == 4);
    tidesdb_mvcc_destroy(m);
}

/* mark records commit state in the ring; an unmarked or in-progress seq is not committed, seq 0
 * never */
void test_mvcc_mark_committed(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);

    ASSERT_EQ(tidesdb_mvcc_committed(m, 5), 0); /* never marked */
    tidesdb_mvcc_mark(m, 5, 1);
    ASSERT_EQ(tidesdb_mvcc_committed(m, 5), 1);
    tidesdb_mvcc_mark(m, 6, 0); /* explicitly in-progress */
    ASSERT_EQ(tidesdb_mvcc_committed(m, 6), 0);
    ASSERT_EQ(tidesdb_mvcc_committed(m, 0), 0);
    tidesdb_mvcc_destroy(m);
}

/* the visibility predicate combines nonzero, at-or-below-snapshot, and committed */
void test_mvcc_visible(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    tidesdb_mvcc_mark(m, 5, 1); /* committed */
    tidesdb_mvcc_mark(m, 6, 0); /* in-progress */

    ASSERT_EQ(tidesdb_mvcc_visible(m, 5, 10), 1); /* committed, below snapshot */
    ASSERT_EQ(tidesdb_mvcc_visible(m, 5, 5), 1);  /* committed, at snapshot */
    ASSERT_EQ(tidesdb_mvcc_visible(m, 5, 4), 0);  /* above snapshot */
    ASSERT_EQ(tidesdb_mvcc_visible(m, 6, 10), 0); /* in-progress */
    ASSERT_EQ(tidesdb_mvcc_visible(m, 0, 10), 0); /* zero seq */
    tidesdb_mvcc_destroy(m);
}

/* a seq more than a ring capacity behind the high-water mark is committed by the eviction rule even
 * though its ring slot was never marked */
void test_mvcc_eviction_rule(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);

    const uint64_t high = TDB_MVCC_COMMIT_RING_SIZE + 4464; /* > capacity so eviction can fire */
    tidesdb_mvcc_mark(m, high, 0); /* push the high-water mark; slot itself in-progress */

    const uint64_t evict_boundary = high - TDB_MVCC_COMMIT_RING_SIZE; /* seq <= this is evicted */
    ASSERT_EQ(tidesdb_mvcc_committed(m, evict_boundary), 1);          /* evicted -> committed */
    ASSERT_EQ(tidesdb_mvcc_committed(m, 1), 1);                       /* well past the window */
    ASSERT_EQ(tidesdb_mvcc_committed(m, evict_boundary + 1), 0);      /* inside window, unmarked */
    ASSERT_EQ(tidesdb_mvcc_committed(m, high), 0); /* the in-progress slot itself */
    tidesdb_mvcc_destroy(m);
}

/* a held sequence is exempt from the eviction rule, which is what keeps an undecided prepare in
 * flight after the ring has moved a whole capacity past it */
void test_mvcc_prepared_hold_survives_eviction(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);

    const uint64_t prepared = 7;
    const uint64_t high = prepared + TDB_MVCC_COMMIT_RING_SIZE + 1; /* prepared is evicted */

    /* without the hold the eviction rule calls it committed, which is the state the fix corrects */
    tidesdb_mvcc_mark(m, high, 0);
    ASSERT_EQ(tidesdb_mvcc_committed(m, prepared), 1);

    ASSERT_EQ(tidesdb_mvcc_prepared_hold(m, prepared), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_mvcc_committed(m, prepared), 0); /* held, so still in flight */

    /* the hold covers its own sequence and nothing else */
    ASSERT_EQ(tidesdb_mvcc_committed(m, prepared + 1), 1);

    /* and once phase two lets go, the rule governs it again */
    tidesdb_mvcc_prepared_release(m, prepared);
    ASSERT_EQ(tidesdb_mvcc_committed(m, prepared), 1);
    tidesdb_mvcc_destroy(m);
}

/* the table is fixed, so a prepare past its last slot is refused rather than left unprotected. a
 * release frees the slot it took and the next prepare gets it */
void test_mvcc_prepared_hold_table_is_bounded(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);

    const uint64_t first = 1;
    for (int i = 0; i < TDB_MVCC_MAX_PREPARED_HOLDS; i++)
        ASSERT_EQ(tidesdb_mvcc_prepared_hold(m, first + (uint64_t)i), TDB_SUCCESS);

    const uint64_t past_end = first + TDB_MVCC_MAX_PREPARED_HOLDS;
    ASSERT_EQ(tidesdb_mvcc_prepared_hold(m, past_end), TDB_ERR_CONFLICT);

    /* a sequence that never took a slot releases without disturbing one that did */
    tidesdb_mvcc_prepared_release(m, past_end);
    ASSERT_EQ(tidesdb_mvcc_prepared_hold(m, past_end), TDB_ERR_CONFLICT);

    tidesdb_mvcc_prepared_release(m, first);
    ASSERT_EQ(tidesdb_mvcc_prepared_hold(m, past_end), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_mvcc_prepared_hold(NULL, first), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_mvcc_prepared_hold(m, 0), TDB_ERR_INVALID_ARGS);
    tidesdb_mvcc_destroy(m);
}

/* a held sequence keeps its reservation refusing a later writer of the same key, which is the whole
 * point of the exemption -- the eviction rule alone would let that writer through */
void test_mvcc_prepared_hold_keeps_the_reservation_refusing(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);

    const uint64_t khash = 0x0123456789abcdefULL;
    const uint64_t prepared = tidesdb_mvcc_next_seq(m);
    ASSERT_EQ(tidesdb_mvcc_prepared_hold(m, prepared), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_mvcc_reserve(m, khash, prepared, prepared - 1, 0), 1);

    /* walk the ring clear past the prepare, as a database that keeps committing does */
    uint64_t seq = 0;
    for (int i = 0; i < TDB_MVCC_COMMIT_RING_SIZE + 1; i++)
    {
        seq = tidesdb_mvcc_next_seq(m);
        tidesdb_mvcc_mark(m, seq, 1);
    }

    const uint64_t later = tidesdb_mvcc_next_seq(m);
    ASSERT_EQ(tidesdb_mvcc_reserve(m, khash, later, later - 1, later - 1), 0);
    tidesdb_mvcc_destroy(m);
}

/* reseed advances the counter past the recovered max and backfills the trailing ring window so
 * every recovered seq reads committed, whether via the window or the eviction rule */
void test_mvcc_reseed(void)
{
    /* small db: recovered max below ring capacity -- backfill covers everything */
    tidesdb_mvcc_t *s = tidesdb_mvcc_create();
    ASSERT_TRUE(s != NULL);
    tidesdb_mvcc_reseed(s, 1000);
    ASSERT_TRUE(tidesdb_mvcc_current_seq(s) == 1001);
    ASSERT_EQ(tidesdb_mvcc_committed(s, 1), 1);
    ASSERT_EQ(tidesdb_mvcc_committed(s, 1000), 1);
    ASSERT_EQ(tidesdb_mvcc_committed(s, 1001), 0); /* not yet assigned */
    tidesdb_mvcc_destroy(s);

    /* large db: recovered max above capacity -- window backfilled, older seqs evicted */
    tidesdb_mvcc_t *l = tidesdb_mvcc_create();
    ASSERT_TRUE(l != NULL);
    const uint64_t big = TDB_MVCC_COMMIT_RING_SIZE + 34464;
    tidesdb_mvcc_reseed(l, big);
    ASSERT_TRUE(tidesdb_mvcc_current_seq(l) == big + 1);
    ASSERT_EQ(tidesdb_mvcc_committed(l, 1), 1); /* evicted */
    ASSERT_EQ(tidesdb_mvcc_committed(l, big / 2), 1);
    ASSERT_EQ(tidesdb_mvcc_committed(l, big), 1); /* top of the backfilled window */
    tidesdb_mvcc_destroy(l);
}

/* first-committer-wins: an empty slot is claimable, a re-claim by the same seq is idempotent, and
 * an in-flight occupant blocks a different committer until it commits under the read base */
void test_mvcc_reserve_basic(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    const uint64_t h = HASH_FP_A(HASH_SLOT);

    /* empty slot claims */
    ASSERT_EQ(tidesdb_mvcc_reserve(m, h, 10, 5, 0), 1);
    /* the same committer re-claiming is idempotent */
    ASSERT_EQ(tidesdb_mvcc_reserve(m, h, 10, 5, 0), 1);

    /* a different committer sees an in-flight occupant (seq 10 not marked committed) -> conflict */
    ASSERT_EQ(tidesdb_mvcc_reserve(m, h, 11, 5, 0), 0);

    /* once 10 commits, a committer whose read base is past 10 may claim; one whose base is behind
     * 10 (and same fingerprint) loses to the newer same-key writer */
    tidesdb_mvcc_mark(m, 10, 1);
    ASSERT_EQ(tidesdb_mvcc_reserve(m, h, 12, 5, 0), 0);  /* 10 > read_base 5, fp matches -> lose */
    ASSERT_EQ(tidesdb_mvcc_reserve(m, h, 12, 10, 0), 1); /* read_base 10 covers seq 10 -> win */
    tidesdb_mvcc_destroy(m);
}

/* release frees the slot only for its owner, so a later committer can claim it again */
void test_mvcc_release(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    const uint64_t h = HASH_FP_A(HASH_SLOT);

    ASSERT_EQ(tidesdb_mvcc_reserve(m, h, 20, 0, 0), 1);
    tidesdb_mvcc_release(m, h, 20);
    /* slot is unclaimed again -> a fresh committer claims cleanly */
    ASSERT_EQ(tidesdb_mvcc_reserve(m, h, 21, 0, 0), 1);

    /* releasing with a stale seq we no longer own is a no-op (slot stays owned by 21) */
    tidesdb_mvcc_release(m, h, 20);
    ASSERT_EQ(tidesdb_mvcc_reserve(m, h, 22, 0, 0), 0); /* 21 in-flight still holds it */
    tidesdb_mvcc_destroy(m);
}

/* a committed occupant of a different key colliding into the slot is suppressed when it is at or
 * below the oldest open snapshot, and kept conservative when it is newer */
void test_mvcc_reserve_collision(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    const uint64_t ha = HASH_FP_A(HASH_SLOT); /* same slot... */
    const uint64_t hb = HASH_FP_B(HASH_SLOT); /* ...different fingerprint */

    /* key A commits at seq 10 in the shared slot */
    ASSERT_EQ(tidesdb_mvcc_reserve(m, ha, 10, 0, 0), 1);
    tidesdb_mvcc_mark(m, 10, 1);

    /* key B (different fingerprint) with an old-enough occupant relative to min_snapshot ->
     * suppress the collision and claim (min_snapshot 100 means seq 10 is below every open snapshot)
     */
    ASSERT_EQ(tidesdb_mvcc_reserve(m, hb, 11, 5, 100), 1);

    /* reset the slot, replay, but now the occupant is newer than the oldest open snapshot -> stay
     * conservative and treat it as a conflict */
    tidesdb_mvcc_release(m, hb, 11);
    tidesdb_mvcc_release(m, ha, 10); /* not owner after B claimed; harmless */
    tidesdb_mvcc_t *m2 = tidesdb_mvcc_create();
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(tidesdb_mvcc_reserve(m2, ha, 10, 0, 0), 1);
    tidesdb_mvcc_mark(m2, 10, 1);
    ASSERT_EQ(tidesdb_mvcc_reserve(m2, hb, 11, 5, 5), 0); /* 10 > min_snapshot 5 -> conflict */
    tidesdb_mvcc_destroy(m2);
    tidesdb_mvcc_destroy(m);
}

/* per-seq occurrence counters, indexed by the drawn sequence number (1..CC_TOTAL_SEQS) */
static _Atomic(int) g_seq_hits[CC_TOTAL_SEQS + 2];

static void *cc_seq_worker(void *arg)
{
    tidesdb_mvcc_t *m = (tidesdb_mvcc_t *)arg;
    for (int i = 0; i < CC_PER_THREAD; i++)
    {
        const uint64_t s = tidesdb_mvcc_next_seq(m);
        if (s >= 1 && s <= CC_TOTAL_SEQS) atomic_fetch_add(&g_seq_hits[s], 1);
    }
    return NULL;
}

/* under contention the sequence counter hands out every seq in 1..N exactly once -- no duplicates,
 * no gaps. exercises the atomic fetch_add path (run under TSan) */
void test_mvcc_seq_concurrent_unique(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    for (int i = 0; i <= CC_TOTAL_SEQS + 1; i++) atomic_store(&g_seq_hits[i], 0);

    pthread_t threads[CC_THREADS];
    for (int t = 0; t < CC_THREADS; t++)
        ASSERT_EQ(pthread_create(&threads[t], NULL, cc_seq_worker, m), 0);
    for (int t = 0; t < CC_THREADS; t++) pthread_join(threads[t], NULL);

    int ok = 1;
    for (int s = 1; s <= CC_TOTAL_SEQS; s++)
        if (atomic_load(&g_seq_hits[s]) != 1) ok = 0;
    ASSERT_TRUE(ok);
    ASSERT_TRUE(tidesdb_mvcc_current_seq(m) == (uint64_t)CC_TOTAL_SEQS + 1);
    tidesdb_mvcc_destroy(m);
}

typedef struct
{
    tidesdb_mvcc_t *m;
    uint64_t key_hash;
    uint64_t commit_seq;
    int won;
} cc_reserve_arg;

static void *cc_reserve_worker(void *arg)
{
    cc_reserve_arg *a = (cc_reserve_arg *)arg;
    a->won = tidesdb_mvcc_reserve(a->m, a->key_hash, a->commit_seq, 0, 0);
    return NULL;
}

/* a thundering herd of committers racing to reserve the SAME key -- first-committer-wins means
 * exactly one claims the in-flight slot and every other loses. exercises the reservation CAS under
 * a real race (run under TSan) */
void test_mvcc_reserve_single_winner(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    const uint64_t h = HASH_FP_A(HASH_SLOT);

    pthread_t threads[CC_THREADS];
    cc_reserve_arg args[CC_THREADS];
    for (int t = 0; t < CC_THREADS; t++)
    {
        args[t].m = m;
        args[t].key_hash = h;
        args[t].commit_seq = (uint64_t)(t + 1); /* distinct seqs, none marked committed */
        args[t].won = -1;
        ASSERT_EQ(pthread_create(&threads[t], NULL, cc_reserve_worker, &args[t]), 0);
    }
    for (int t = 0; t < CC_THREADS; t++) pthread_join(threads[t], NULL);

    int winners = 0;
    for (int t = 0; t < CC_THREADS; t++)
        if (args[t].won == 1) winners++;
    ASSERT_EQ(winners, 1); /* exactly one first-committer wins the in-flight slot */
    tidesdb_mvcc_destroy(m);
}

/* the stats counters track seqs drawn, commits marked, and reservation wins vs losses */
void test_mvcc_stats(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);

    tidesdb_mvcc_stats_t st;
    tidesdb_mvcc_get_stats(m, &st);
    ASSERT_TRUE(st.seqs_assigned == 0 && st.commits_marked == 0);
    ASSERT_TRUE(st.reservations_won == 0 && st.reservations_lost == 0);

    (void)tidesdb_mvcc_next_seq(m);
    (void)tidesdb_mvcc_next_seq(m);
    tidesdb_mvcc_mark(m, 1, 1); /* committed */
    tidesdb_mvcc_mark(m, 2, 0); /* in-progress, not counted */

    const uint64_t h = HASH_FP_A(HASH_SLOT);
    ASSERT_EQ(tidesdb_mvcc_reserve(m, h, 1, 5, 0), 1); /* won */
    tidesdb_mvcc_mark(m, 1, 1);
    ASSERT_EQ(tidesdb_mvcc_reserve(m, h, 2, 0, 0),
              0); /* lost: 1 committed > read_base 0, fp match */

    tidesdb_mvcc_get_stats(m, &st);
    ASSERT_TRUE(st.seqs_assigned == 2);
    ASSERT_TRUE(st.commits_marked == 2); /* mark(1) committed twice */
    ASSERT_TRUE(st.reservations_won == 1);
    ASSERT_TRUE(st.reservations_lost == 1);

    /* null-safe stats zero the output */
    tidesdb_mvcc_get_stats(NULL, &st);
    ASSERT_TRUE(st.seqs_assigned == 0 && st.reservations_won == 0);
    tidesdb_mvcc_destroy(m);
}

/* the accessors tolerate a NULL clock */
void test_mvcc_null_safe(void)
{
    ASSERT_EQ(tidesdb_mvcc_committed(NULL, 5), 0);
    ASSERT_EQ(tidesdb_mvcc_visible(NULL, 5, 10), 0);
    ASSERT_EQ(tidesdb_mvcc_reserve(NULL, 1, 1, 0, 0), 1); /* no clock -> nothing to conflict with */
    tidesdb_mvcc_mark(NULL, 5, 1);
    tidesdb_mvcc_release(NULL, 1, 1);
    tidesdb_mvcc_reseed(NULL, 5);
    tidesdb_mvcc_destroy(NULL);
    ASSERT_TRUE(1);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_mvcc_seq_counter, tests_passed);
    RUN_TEST(test_mvcc_mark_committed, tests_passed);
    RUN_TEST(test_mvcc_visible, tests_passed);
    RUN_TEST(test_mvcc_eviction_rule, tests_passed);
    RUN_TEST(test_mvcc_prepared_hold_survives_eviction, tests_passed);
    RUN_TEST(test_mvcc_prepared_hold_table_is_bounded, tests_passed);
    RUN_TEST(test_mvcc_prepared_hold_keeps_the_reservation_refusing, tests_passed);
    RUN_TEST(test_mvcc_reseed, tests_passed);
    RUN_TEST(test_mvcc_reserve_basic, tests_passed);
    RUN_TEST(test_mvcc_release, tests_passed);
    RUN_TEST(test_mvcc_reserve_collision, tests_passed);
    RUN_TEST(test_mvcc_seq_concurrent_unique, tests_passed);
    RUN_TEST(test_mvcc_reserve_single_winner, tests_passed);
    RUN_TEST(test_mvcc_stats, tests_passed);
    RUN_TEST(test_mvcc_null_safe, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
