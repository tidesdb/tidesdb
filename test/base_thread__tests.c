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
/* how long a thread's teardown lingers after its body has returned */
#define TEST_THREAD_TEARDOWN_US 100000

/* set by the teardown below as its last act */
static _Atomic(int) test_thread_torn_down;

/* a thread-local destructor, which runs as the thread exits and after its body has returned */
static void test_thread_teardown(void *value)
{
    (void)value;
    usleep(TEST_THREAD_TEARDOWN_US);
    atomic_store(&test_thread_torn_down, 1);
}

static pthread_key_t test_thread_key;

/* give the thread a thread-local value, so its exit runs the destructor */
static void *test_thread_body_with_teardown(void *arg)
{
    (void)pthread_setspecific(test_thread_key, arg);
    return NULL;
}

/* finish returns only once the thread has exited, its teardown included, not merely once its body
 * has returned. a thread still tearing down holds whatever its exit takes, the allocator's locks
 * among them, and a process that forks in that window hands the child those locks held by a thread
 * the child does not have. the scheduler that cannot afford a join is the one place this is not
 * promised */
void test_thread_finish_waits_for_the_thread_to_exit(void)
{
#if !defined(__NetBSD__)
    ASSERT_EQ(pthread_key_create(&test_thread_key, test_thread_teardown), 0);
    atomic_store(&test_thread_torn_down, 0);
    tdb_thread_t t;
    static int value = 1;
    ASSERT_EQ(tdb_thread_start(&t, test_thread_body_with_teardown, &value), 0);
    tdb_thread_finish(&t);
    ASSERT_EQ(atomic_load(&test_thread_torn_down), 1);
#endif
}

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
    RUN_TEST(test_thread_finish_waits_for_the_thread_to_exit, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
