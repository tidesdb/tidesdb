/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/bg_ticker.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

static _Atomic(int) g_ticks = 0;

static void count_tick(void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&g_ticks, 1);
}

/* a short-interval ticker fires repeatedly on its own */
void test_bg_ticker_runs_periodically(void)
{
    atomic_store(&g_ticks, 0);
    bg_ticker_t *t = bg_ticker_start(5000 /* 5ms */, count_tick, NULL);
    ASSERT_TRUE(t != NULL);
    usleep(80000); /* ~16 intervals; expect many ticks even under scheduling jitter */
    bg_ticker_stop(t);
    ASSERT_TRUE(atomic_load(&g_ticks) >= 3);
}

/* waking a long-interval ticker makes it tick now instead of waiting out the interval */
void test_bg_ticker_wake_triggers_tick(void)
{
    atomic_store(&g_ticks, 0);
    bg_ticker_t *t = bg_ticker_start(100000000ULL /* 100s */, count_tick, NULL);
    ASSERT_TRUE(t != NULL);
    usleep(20000); /* let the immediate first tick land */
    const int after_start = atomic_load(&g_ticks);
    ASSERT_TRUE(after_start >= 1);

    for (int i = 0; i < 3; i++)
    {
        bg_ticker_wake(t);
        usleep(20000);
    }
    bg_ticker_stop(t);
    /* each wake should have driven at least one more tick past the immediate one */
    ASSERT_TRUE(atomic_load(&g_ticks) > after_start);
}

/* stop and wake tolerate a null ticker */
void test_bg_ticker_null_safe(void)
{
    bg_ticker_wake(NULL);
    bg_ticker_stop(NULL);
    ASSERT_TRUE(1);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_bg_ticker_runs_periodically, tests_passed);
    RUN_TEST(test_bg_ticker_wake_triggers_tick, tests_passed);
    RUN_TEST(test_bg_ticker_null_safe, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
