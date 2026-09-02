/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>

#include "../src/base/bg_pool.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

static _Atomic(int) g_processed = 0;
static _Atomic(long) g_sum = 0;

static void count_worker(void *item, void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&g_processed, 1);
    atomic_fetch_add(&g_sum, *(int *)item);
}

/* wait up to ~2s for the processed count to reach n */
static int wait_for(int n)
{
    for (int i = 0; i < 2000; i++)
    {
        if (atomic_load(&g_processed) >= n) return 1;
        usleep(1000);
    }
    return 0;
}

/* a single-thread pool processes every enqueued item exactly once */
void test_bg_pool_single_thread(void)
{
    atomic_store(&g_processed, 0);
    atomic_store(&g_sum, 0);
    queue_t *q = queue_new();
    ASSERT_TRUE(q != NULL);

    enum
    {
        N = 500
    };
    static int items[N];
    long expect_sum = 0;
    for (int i = 0; i < N; i++)
    {
        items[i] = i + 1;
        expect_sum += items[i];
        queue_enqueue(q, &items[i]);
    }

    bg_pool_t *pool = bg_pool_start(1, q, count_worker, NULL);
    ASSERT_TRUE(pool != NULL);
    ASSERT_EQ(bg_pool_live_threads(pool), 1);
    ASSERT_TRUE(wait_for(N));
    bg_pool_stop(pool);

    ASSERT_EQ(atomic_load(&g_processed), N);
    ASSERT_TRUE(atomic_load(&g_sum) == expect_sum);
    queue_free(q);
}

/* several worker threads drain the same queue, each item processed exactly once (sum is exact) */
void test_bg_pool_multi_thread(void)
{
    atomic_store(&g_processed, 0);
    atomic_store(&g_sum, 0);
    queue_t *q = queue_new();
    ASSERT_TRUE(q != NULL);

    enum
    {
        N = 4000
    };
    static int items[N];
    long expect_sum = 0;
    for (int i = 0; i < N; i++)
    {
        items[i] = i + 1;
        expect_sum += items[i];
        queue_enqueue(q, &items[i]);
    }

    bg_pool_t *pool = bg_pool_start(4, q, count_worker, NULL);
    ASSERT_TRUE(pool != NULL);
    ASSERT_EQ(bg_pool_live_threads(pool), 4);
    ASSERT_TRUE(wait_for(N));
    bg_pool_stop(pool);

    ASSERT_EQ(atomic_load(&g_processed), N);
    ASSERT_TRUE(atomic_load(&g_sum) == expect_sum);
    queue_free(q);
}

/* a named pool drains its queue exactly like an unnamed one; the naming and signal mask are
 * internal to the worker threads, so behavior is identical from the caller's view */
void test_bg_pool_named(void)
{
    atomic_store(&g_processed, 0);
    atomic_store(&g_sum, 0);
    queue_t *q = queue_new();
    ASSERT_TRUE(q != NULL);

    enum
    {
        N = 1000
    };
    static int items[N];
    long expect_sum = 0;
    for (int i = 0; i < N; i++)
    {
        items[i] = i + 1;
        expect_sum += items[i];
        queue_enqueue(q, &items[i]);
    }

    bg_pool_t *pool = bg_pool_start_named(3, q, "tdb.test", count_worker, NULL);
    ASSERT_TRUE(pool != NULL);
    ASSERT_EQ(bg_pool_live_threads(pool), 3);
    ASSERT_TRUE(wait_for(N));
    bg_pool_stop(pool);

    ASSERT_EQ(atomic_load(&g_processed), N);
    ASSERT_TRUE(atomic_load(&g_sum) == expect_sum);
    queue_free(q);
}

/* stopping a null pool and bad start args are handled */
void test_bg_pool_edge_cases(void)
{
    bg_pool_stop(NULL);
    queue_t *q = queue_new();
    ASSERT_TRUE(bg_pool_start(0, q, count_worker, NULL) == NULL);
    ASSERT_TRUE(bg_pool_start(1, NULL, count_worker, NULL) == NULL);
    ASSERT_TRUE(bg_pool_start(1, q, NULL, NULL) == NULL);
    ASSERT_EQ(bg_pool_live_threads(NULL), 0);
    queue_free(q);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_bg_pool_single_thread, tests_passed);
    RUN_TEST(test_bg_pool_multi_thread, tests_passed);
    RUN_TEST(test_bg_pool_named, tests_passed);
    RUN_TEST(test_bg_pool_edge_cases, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
