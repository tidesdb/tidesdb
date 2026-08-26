/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/txn/mvcc.h"
#include "../src/txn/registry.h"
#include "../src/txn/txn.h"
#include "db.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* begin a repeatable-read txn whose snapshot is `snap` by advancing the clock so current_seq is
 * snap + 1 (current_seq = n+1 after n next_seq calls) */
static tdb_txn_t *begin_at_snapshot(tidesdb_mvcc_t *clock, uint64_t snap)
{
    while (tidesdb_mvcc_current_seq(clock) <= snap) (void)tidesdb_mvcc_next_seq(clock);
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_REPEATABLE_READ, NULL, 0, NULL);
    return t;
}

/* an empty registry has no gc floor */
/* what the walk collects, so a test can assert on which transactions it reached */
typedef struct
{
    tdb_txn_t *a;
    tdb_txn_t *b;
    int saw_a;
    int saw_b;
    int seen;
} registry_walk_t;

static int registry_walk_visit(tdb_txn_t *txn, void *ctx)
{
    registry_walk_t *w = (registry_walk_t *)ctx;
    w->seen++;
    if (txn == w->a) w->saw_a = 1;
    if (txn == w->b) w->saw_b = 1;
    return 0;
}

/* counts every transaction the walk reaches, for the many-transaction case */
static int registry_count_visit(tdb_txn_t *txn, void *ctx)
{
    (void)txn;
    (*(int *)ctx)++;
    return 0;
}

/* stops the walk on the first transaction, to prove early exit works and still unlocks */
static int registry_stop_visit(tdb_txn_t *txn, void *ctx)
{
    (void)txn;
    (*(int *)ctx)++;
    return 1;
}

void test_registry_empty(void)
{
    tidesdb_txn_registry_t *reg = tidesdb_txn_registry_create();
    ASSERT_TRUE(reg != NULL);
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == UINT64_MAX);
    tidesdb_txn_registry_destroy(reg);
}

/* min_snapshot is the smallest snapshot among registered txns, and it rises as the holder leaves */
void test_registry_min_snapshot(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tidesdb_txn_registry_t *reg = tidesdb_txn_registry_create();

    tdb_txn_t *a = begin_at_snapshot(clock, 3);
    tdb_txn_t *b = begin_at_snapshot(clock, 5);
    tdb_txn_t *c = begin_at_snapshot(clock, 7);
    ASSERT_EQ(tidesdb_txn_registry_add(reg, a), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_registry_add(reg, b), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_registry_add(reg, c), TDB_SUCCESS);

    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == 3);

    tidesdb_txn_registry_remove(reg, a); /* oldest leaves -> floor rises */
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == 5);
    tidesdb_txn_registry_remove(reg, b);
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == 7);
    tidesdb_txn_registry_remove(reg, c);
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == UINT64_MAX);

    tdb_txn_free(a);
    tdb_txn_free(b);
    tdb_txn_free(c);
    tidesdb_txn_registry_destroy(reg);
    tidesdb_mvcc_destroy(clock);
}

/* the published minimum is what the commit path reads instead of running the scan, and it may only
 * ever be stale low. the case that could break that is the registry emptying and refilling: the
 * scan answers UINT64_MAX for an empty set, and publishing that sentinel would leave the cache
 * above the snapshot of the very next transaction */
void test_registry_published_min_never_exceeds_the_true_min(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tidesdb_txn_registry_t *reg = tidesdb_txn_registry_create();

    /* nothing published yet reads as zero, which constrains nothing wrongly */
    ASSERT_TRUE(tidesdb_txn_registry_published_min_snapshot(reg) == 0);

    tdb_txn_t *a = begin_at_snapshot(clock, 10);
    tdb_txn_t *b = begin_at_snapshot(clock, 20);
    ASSERT_EQ(tidesdb_txn_registry_add(reg, a), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_registry_add(reg, b), TDB_SUCCESS);
    tidesdb_txn_registry_publish_min_snapshot(reg);
    ASSERT_TRUE(tidesdb_txn_registry_published_min_snapshot(reg) == 10);

    /* the holder of the minimum leaves, so the true minimum rises above the published one. stale
     * low is the safe direction and the cache is allowed to sit there until the next publish */
    tidesdb_txn_registry_remove(reg, a);
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == 20);
    ASSERT_TRUE(tidesdb_txn_registry_published_min_snapshot(reg) == 10);

    /* empty publishes zero rather than the sentinel */
    tidesdb_txn_registry_remove(reg, b);
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == UINT64_MAX);
    tidesdb_txn_registry_publish_min_snapshot(reg);
    ASSERT_TRUE(tidesdb_txn_registry_published_min_snapshot(reg) == 0);

    /* and a transaction beginning after that empty publish is still above it, which is the
     * property the whole cache rests on */
    tdb_txn_t *c = begin_at_snapshot(clock, 30);
    ASSERT_EQ(tidesdb_txn_registry_add(reg, c), TDB_SUCCESS);
    ASSERT_TRUE(tidesdb_txn_registry_published_min_snapshot(reg) <=
                tidesdb_txn_registry_min_snapshot(reg));

    tidesdb_txn_registry_remove(reg, c);
    tdb_txn_free(a);
    tdb_txn_free(b);
    tdb_txn_free(c);
    tidesdb_txn_registry_destroy(reg);
    tidesdb_mvcc_destroy(clock);
}

/* the locked scan sees every registered txn */
void test_registry_scan(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tidesdb_txn_registry_t *reg = tidesdb_txn_registry_create();
    tdb_txn_t *a = begin_at_snapshot(clock, 2);
    tdb_txn_t *b = begin_at_snapshot(clock, 4);
    tidesdb_txn_registry_add(reg, a);
    tidesdb_txn_registry_add(reg, b);

    /* the walk reaches every live transaction wherever its shard placed it */
    registry_walk_t walk = {a, b, 0, 0, 0};
    ASSERT_EQ(tidesdb_txn_registry_for_each(reg, registry_walk_visit, &walk), 0);
    ASSERT_EQ(walk.seen, 2);
    ASSERT_TRUE(walk.saw_a && walk.saw_b);

    tidesdb_txn_registry_remove(reg, a);
    tidesdb_txn_registry_remove(reg, b);
    tdb_txn_free(a);
    tdb_txn_free(b);
    tidesdb_txn_registry_destroy(reg);
    tidesdb_mvcc_destroy(clock);
}

/* a txn begun with a registry joins it and leaves on free, so the gc floor tracks it automatically
 */
void test_registry_integration(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tidesdb_txn_registry_t *reg = tidesdb_txn_registry_create();
    while (tidesdb_mvcc_current_seq(clock) <= 4) (void)tidesdb_mvcc_next_seq(clock);

    /* repeatable-read joins */
    tdb_txn_t *rr = tdb_txn_begin(clock, TDB_ISOLATION_REPEATABLE_READ, NULL, 0, reg);
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == 4);

    /* read-committed does not join, so the floor is unaffected */
    tdb_txn_t *rc = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, reg);
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == 4);

    tdb_txn_free(rr); /* leaving removes it from the registry */
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == UINT64_MAX);
    tdb_txn_free(rc);

    tidesdb_txn_registry_destroy(reg);
    tidesdb_mvcc_destroy(clock);
}

/* bad args are handled */
void test_registry_null_safe(void)
{
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(NULL) == UINT64_MAX);
    ASSERT_EQ(tidesdb_txn_registry_add(NULL, NULL), TDB_ERR_INVALID_ARGS);
    int n = 0;
    ASSERT_EQ(tidesdb_txn_registry_for_each(NULL, registry_count_visit, &n), 0);
    ASSERT_EQ(n, 0);
    tidesdb_txn_registry_remove(NULL, NULL);
    tidesdb_txn_registry_destroy(NULL);
    ASSERT_TRUE(1);
}

/* enough transactions that they cannot all land in one shard, so the walk and the removal path are
 * exercised across shards rather than within a single array */
#define REGISTRY_TEST_MANY 64

void test_registry_spans_shards(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tidesdb_txn_registry_t *reg = tidesdb_txn_registry_create();
    tdb_txn_t *txns[REGISTRY_TEST_MANY];

    for (int i = 0; i < REGISTRY_TEST_MANY; i++)
    {
        txns[i] = begin_at_snapshot(clock, (uint64_t)(i + 1));
        ASSERT_EQ(tidesdb_txn_registry_add(reg, txns[i]), TDB_SUCCESS);
    }

    int seen = 0;
    ASSERT_EQ(tidesdb_txn_registry_for_each(reg, registry_count_visit, &seen), 0);
    ASSERT_EQ(seen, REGISTRY_TEST_MANY);

    /* the floor is the lowest live snapshot wherever it sits */
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == 1);

    /* stopping early still releases every shard, so a later walk works */
    int visited = 0;
    ASSERT_TRUE(tidesdb_txn_registry_for_each(reg, registry_stop_visit, &visited) != 0);
    ASSERT_EQ(visited, 1);
    seen = 0;
    ASSERT_EQ(tidesdb_txn_registry_for_each(reg, registry_count_visit, &seen), 0);
    ASSERT_EQ(seen, REGISTRY_TEST_MANY);

    /* removing the lowest raises the floor, which is the gc floor's whole contract */
    tidesdb_txn_registry_remove(reg, txns[0]);
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == 2);

    for (int i = 1; i < REGISTRY_TEST_MANY; i++) tidesdb_txn_registry_remove(reg, txns[i]);
    seen = 0;
    ASSERT_EQ(tidesdb_txn_registry_for_each(reg, registry_count_visit, &seen), 0);
    ASSERT_EQ(seen, 0);
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == UINT64_MAX);

    for (int i = 0; i < REGISTRY_TEST_MANY; i++) tdb_txn_free(txns[i]);
    tidesdb_txn_registry_destroy(reg);
    tidesdb_mvcc_destroy(clock);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_registry_empty, tests_passed);
    RUN_TEST(test_registry_min_snapshot, tests_passed);
    RUN_TEST(test_registry_published_min_never_exceeds_the_true_min, tests_passed);
    RUN_TEST(test_registry_scan, tests_passed);
    RUN_TEST(test_registry_integration, tests_passed);
    RUN_TEST(test_registry_spans_shards, tests_passed);
    RUN_TEST(test_registry_null_safe, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
