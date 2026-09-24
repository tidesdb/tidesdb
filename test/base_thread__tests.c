/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "../src/base/thread.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* threads started at once, and how long a body lingers so the wait has something to wait for */
#define TEST_THREAD_COUNT     8
#define TEST_THREAD_LINGER_US 50000

/**
 * test_thread_body_t
 * what a started body records
 * @param entered set when the body starts
 * @param left set as the body's last act, after its linger
 */
typedef struct
{
    _Atomic(int) entered;
    _Atomic(int) left;
} test_thread_body_t;

/**
 * test_thread_body
 * note entry, linger, note exit
 * @param arg the test_thread_body_t
 * @return NULL
 */
static void *test_thread_body(void *arg)
{
    test_thread_body_t *b = arg;
    atomic_store(&b->entered, 1);
    usleep(TEST_THREAD_LINGER_US);
    atomic_store(&b->left, 1);
    return NULL;
}

/* every started thread runs its body, and finish returns only after the body has left */
void test_thread_finish_waits_for_the_body(void)
{
    tdb_thread_t threads[TEST_THREAD_COUNT];
    test_thread_body_t bodies[TEST_THREAD_COUNT];
    for (int i = 0; i < TEST_THREAD_COUNT; i++)
    {
        atomic_init(&bodies[i].entered, 0);
        atomic_init(&bodies[i].left, 0);
        ASSERT_EQ(tdb_thread_start(&threads[i], test_thread_body, &bodies[i]), 0);
    }
    for (int i = 0; i < TEST_THREAD_COUNT; i++)
    {
        tdb_thread_finish(&threads[i]);
        ASSERT_TRUE(atomic_load(&bodies[i].entered));
        ASSERT_TRUE(atomic_load(&bodies[i].left));
    }
}

/* a start refused for want of a body arms nothing, so there is nothing to finish */
void test_thread_start_rejects_a_missing_body(void)
{
    tdb_thread_t t;
    ASSERT_EQ(tdb_thread_start(&t, NULL, NULL), -1);
    ASSERT_EQ(tdb_thread_start(NULL, test_thread_body, NULL), -1);
    tdb_thread_finish(NULL);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_thread_finish_waits_for_the_body, tests_passed);
    RUN_TEST(test_thread_start_rejects_a_missing_body, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
