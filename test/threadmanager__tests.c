/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <string.h>

#include "../src/datastructures/queue.h"
#include "../src/threadmanager/threadmanager.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

static _Atomic(int) g_ticks = 0;
static void a_tick(void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&g_ticks, 1);
}
static void a_worker(void *item, void *ctx)
{
    (void)item;
    (void)ctx;
}

/* the manager holds a labeled pool and ticker, exposes them for introspection, and stops both */
void test_threadmanager_registers_pool_and_ticker(void)
{
    threadmanager_t *tm = threadmanager_new();
    ASSERT_TRUE(tm != NULL);
    ASSERT_EQ(threadmanager_count(tm), 0);

    queue_t *q = queue_new();
    bg_pool_t *pool = bg_pool_start(2, q, a_worker, NULL);
    bg_ticker_t *ticker = bg_ticker_start(100000000ULL, a_tick, NULL); /* long interval */
    ASSERT_TRUE(pool != NULL && ticker != NULL);

    ASSERT_EQ(threadmanager_add_pool(tm, "flush", pool), 0);
    ASSERT_EQ(threadmanager_add_ticker(tm, "reaper.deferred_free", ticker), 0);
    ASSERT_EQ(threadmanager_count(tm), 2);

    const threadmanager_proc_t *e0 = threadmanager_at(tm, 0);
    ASSERT_TRUE(e0 != NULL);
    ASSERT_TRUE(strcmp(e0->label, "flush") == 0);
    ASSERT_EQ(e0->kind, THREADMANAGER_POOL);

    const threadmanager_proc_t *e1 = threadmanager_at(tm, 1);
    ASSERT_TRUE(e1 != NULL);
    ASSERT_TRUE(strcmp(e1->label, "reaper.deferred_free") == 0);
    ASSERT_EQ(e1->kind, THREADMANAGER_TICKER);

    ASSERT_TRUE(threadmanager_at(tm, 2) == NULL);

    threadmanager_stop_all(tm); /* joins pool + ticker, frees the manager */
    queue_free(q);
}

/* waking a registered ticker by label drives an extra tick */
void test_threadmanager_wake_by_label(void)
{
    atomic_store(&g_ticks, 0);
    threadmanager_t *tm = threadmanager_new();
    bg_ticker_t *ticker = bg_ticker_start(100000000ULL, a_tick, NULL);
    ASSERT_EQ(threadmanager_add_ticker(tm, "sync", ticker), 0);

    usleep(20000); /* the immediate first tick lands */
    const int before = atomic_load(&g_ticks);

    threadmanager_wake(tm, "sync");
    usleep(20000);
    ASSERT_TRUE(atomic_load(&g_ticks) > before);

    /* waking an unknown or pool label is a no-op, not a crash */
    threadmanager_wake(tm, "nope");

    threadmanager_stop_all(tm);
}

/* stopping by label removes just that process and keeps the rest in order */
void test_threadmanager_stop_by_label(void)
{
    threadmanager_t *tm = threadmanager_new();
    queue_t *q = queue_new();
    bg_pool_t *pa = bg_pool_start(1, q, a_worker, NULL);
    bg_ticker_t *tb = bg_ticker_start(100000000ULL, a_tick, NULL);
    bg_pool_t *pc = bg_pool_start(1, q, a_worker, NULL);
    ASSERT_TRUE(pa && tb && pc);
    threadmanager_add_pool(tm, "a", pa);
    threadmanager_add_ticker(tm, "b", tb);
    threadmanager_add_pool(tm, "c", pc);
    ASSERT_EQ(threadmanager_count(tm), 3);

    ASSERT_EQ(threadmanager_stop(tm, "b"), 0); /* stop the middle one */
    ASSERT_EQ(threadmanager_count(tm), 2);
    ASSERT_TRUE(strcmp(threadmanager_at(tm, 0)->label, "a") == 0);
    ASSERT_TRUE(strcmp(threadmanager_at(tm, 1)->label, "c") == 0);

    ASSERT_EQ(threadmanager_stop(tm, "missing"), -1);

    threadmanager_stop_all(tm); /* stops the remaining a and c */
    queue_free(q);
}

/* the accessors tolerate a null manager */
void test_threadmanager_null_safe(void)
{
    ASSERT_EQ(threadmanager_count(NULL), 0);
    ASSERT_TRUE(threadmanager_at(NULL, 0) == NULL);
    threadmanager_wake(NULL, "x");
    threadmanager_stop_all(NULL);
    ASSERT_TRUE(1);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_threadmanager_registers_pool_and_ticker, tests_passed);
    RUN_TEST(test_threadmanager_wake_by_label, tests_passed);
    RUN_TEST(test_threadmanager_stop_by_label, tests_passed);
    RUN_TEST(test_threadmanager_null_safe, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
