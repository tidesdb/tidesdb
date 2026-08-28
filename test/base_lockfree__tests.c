/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>

#include "../src/base/lockfree.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* a reclaim callback that counts calls and frees a malloc'd item, so a leak or double free shows up
 * as a wrong count under a normal run and as an error under ASan */
static _Atomic(int) g_reclaimed = 0;
static void reclaim_free_int(void *item, void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&g_reclaimed, 1);
    free(item);
}

/* an epoch brackets a reader and drains cleanly */
void test_epoch_enter_exit(void)
{
    tdb_epoch_t e = 0;
    ASSERT_EQ(tdb_epoch_active(&e), 0);
    tdb_epoch_enter(&e);
    tdb_epoch_enter(&e);
    ASSERT_EQ(tdb_epoch_active(&e), 2);
    tdb_epoch_exit(&e);
    ASSERT_EQ(tdb_epoch_active(&e), 1);
    tdb_epoch_exit(&e);
    ASSERT_EQ(tdb_epoch_active(&e), 0);
    tdb_epoch_wait_drained(&e); /* already 0, returns at once */
}

/* ref counts up, unref signals reclaim only on the last drop, try_ref refuses a dead object */
void test_refcount_basic(void)
{
    tdb_refcount_t rc = 1;
    tdb_ref(&rc);                   /* 2 */
    ASSERT_EQ(tdb_unref(&rc), 0);   /* 2 -> 1, not last */
    ASSERT_EQ(tdb_try_ref(&rc), 1); /* 1 -> 2 */
    ASSERT_EQ(tdb_unref(&rc), 0);   /* 2 -> 1 */
    ASSERT_EQ(tdb_unref(&rc), 1);   /* 1 -> 0, last drop, caller reclaims */

    tdb_refcount_t dead = 0;
    ASSERT_EQ(tdb_try_ref(&dead), 0); /* refuses a zero refcount */
}

/* begin_evict claims only from the exact baseline and end_evict restores it */
void test_refcount_evict_window(void)
{
    tdb_refcount_t rc = 2; /* baseline: one own ref plus one work ref */
    ASSERT_EQ(tdb_refcount_begin_evict(&rc, 2), 1);
    ASSERT_EQ(atomic_load(&rc), TDB_REFCOUNT_EVICTING);
    tdb_refcount_end_evict(&rc, 2);
    ASSERT_EQ(atomic_load(&rc), 2);

    /* a busy object (not at baseline) cannot be claimed */
    tdb_refcount_t busy = 3;
    ASSERT_EQ(tdb_refcount_begin_evict(&busy, 2), 0);
    ASSERT_EQ(atomic_load(&busy), 3);
}

/* a clear guard reclaims inline; a held guard defers until swept */
void test_retire_inline_and_deferred(void)
{
    atomic_store(&g_reclaimed, 0);
    tdb_retire_list_t list = {NULL};
    tdb_epoch_t guard = 0;

    /* guard clear -> reclaimed inline */
    tdb_retire(&list, malloc(8), &guard, reclaim_free_int, NULL);
    ASSERT_EQ(atomic_load(&g_reclaimed), 1);

    /* guard held -> deferred, a sweep while held reclaims nothing */
    tdb_epoch_enter(&guard);
    tdb_retire(&list, malloc(8), &guard, reclaim_free_int, NULL);
    tdb_retire_sweep(&list);
    ASSERT_EQ(atomic_load(&g_reclaimed), 1);

    /* guard drains -> the next sweep reclaims the deferred item */
    tdb_epoch_exit(&guard);
    tdb_retire_sweep(&list);
    ASSERT_EQ(atomic_load(&g_reclaimed), 2);
}

/* drain force-reclaims everything (NULL match) after spinning out the guard */
void test_retire_drain_all(void)
{
    atomic_store(&g_reclaimed, 0);
    tdb_retire_list_t list = {NULL};
    tdb_epoch_t guard = 0;

    tdb_epoch_enter(&guard); /* hold so items defer */
    for (int i = 0; i < 5; i++) tdb_retire(&list, malloc(8), &guard, reclaim_free_int, NULL);
    tdb_epoch_exit(&guard);

    tdb_retire_drain(&list, NULL, NULL);
    ASSERT_EQ(atomic_load(&g_reclaimed), 5);
}

/* drain with a match reclaims only the selected guard and leaves the rest deferred */
static int match_guard(void *item, const tdb_epoch_t *guard, void *ctx)
{
    (void)item;
    return guard == (const tdb_epoch_t *)ctx;
}
void test_retire_drain_match(void)
{
    atomic_store(&g_reclaimed, 0);
    tdb_retire_list_t list = {NULL};
    tdb_epoch_t guard_a = 0, guard_b = 0;

    tdb_epoch_enter(&guard_a);
    tdb_epoch_enter(&guard_b);
    tdb_retire(&list, malloc(8), &guard_a, reclaim_free_int, NULL);
    tdb_retire(&list, malloc(8), &guard_b, reclaim_free_int, NULL);
    tdb_epoch_exit(&guard_a);
    tdb_epoch_exit(&guard_b);

    tdb_retire_drain(&list, match_guard, &guard_a); /* only A */
    ASSERT_EQ(atomic_load(&g_reclaimed), 1);
    tdb_retire_drain(&list, NULL, NULL); /* the rest */
    ASSERT_EQ(atomic_load(&g_reclaimed), 2);
}

/* ===== concurrency stress ===== */

#define STRESS_READERS   4
#define STRESS_ITEMS     20000
#define STRESS_READ_ITER 200000

static tdb_epoch_t s_guard = 0;
static tdb_retire_list_t s_list = {NULL};
static _Atomic(int) s_readers_go = 0;

static void *stress_reader(void *arg)
{
    (void)arg;
    while (atomic_load(&s_readers_go) == 0) cpu_pause();
    for (long i = 0; i < STRESS_READ_ITER; i++)
    {
        tdb_epoch_enter(&s_guard);
        /* a real reader would traverse the guarded structure here */
        cpu_pause();
        tdb_epoch_exit(&s_guard);
    }
    return NULL;
}

/* many readers bracket a shared guard while a writer retires items and sweeps; every item must be
 * reclaimed exactly once and nothing may be freed while a reader is in flight (ASan catches a UAF)
 */
void test_stress_epoch_retire(void)
{
    atomic_store(&g_reclaimed, 0);
    atomic_store(&s_readers_go, 0);
    s_guard = 0;
    s_list.head = NULL;

    pthread_t readers[STRESS_READERS];
    for (int i = 0; i < STRESS_READERS; i++) pthread_create(&readers[i], NULL, stress_reader, NULL);
    atomic_store(&s_readers_go, 1);

    for (int i = 0; i < STRESS_ITEMS; i++)
    {
        tdb_retire(&s_list, malloc(16), &s_guard, reclaim_free_int, NULL);
        if ((i & 0x3F) == 0) tdb_retire_sweep(&s_list);
    }

    for (int i = 0; i < STRESS_READERS; i++) pthread_join(readers[i], NULL);

    /* readers are gone, force out whatever is left */
    tdb_retire_drain(&s_list, NULL, NULL);
    ASSERT_EQ(atomic_load(&g_reclaimed), STRESS_ITEMS);
}

/* an object at baseline is repeatedly evicted and restored while readers try_ref it; because it is
 * never actually freed, try_ref must always succeed -- it waits the evicting window out, never a
 * miss */
static tdb_refcount_t s_rc = 2;
static _Atomic(int) s_evictor_go = 1;
static _Atomic(long) s_false_miss = 0;

static void *stress_trylock_reader(void *arg)
{
    (void)arg;
    for (long i = 0; i < STRESS_READ_ITER; i++)
    {
        if (tdb_try_ref(&s_rc))
            tdb_unref(&s_rc);
        else
            atomic_fetch_add(&s_false_miss, 1);
    }
    return NULL;
}

static void *stress_evictor(void *arg)
{
    (void)arg;
    while (atomic_load(&s_evictor_go))
    {
        if (tdb_refcount_begin_evict(&s_rc, 2))
        {
            cpu_pause();
            tdb_refcount_end_evict(&s_rc, 2);
        }
        cpu_yield();
    }
    return NULL;
}

void test_stress_evict_never_false_miss(void)
{
    s_rc = 2;
    atomic_store(&s_evictor_go, 1);
    atomic_store(&s_false_miss, 0);

    pthread_t readers[STRESS_READERS], evictor;
    pthread_create(&evictor, NULL, stress_evictor, NULL);
    for (int i = 0; i < STRESS_READERS; i++)
        pthread_create(&readers[i], NULL, stress_trylock_reader, NULL);

    for (int i = 0; i < STRESS_READERS; i++) pthread_join(readers[i], NULL);
    atomic_store(&s_evictor_go, 0);
    pthread_join(evictor, NULL);

    ASSERT_EQ(atomic_load(&s_false_miss), 0);
    ASSERT_EQ(atomic_load(&s_rc), 2); /* restored to baseline */
}

/* the pattern the block cache uses: stable entry structs in a fixed array (never freed), a
 * per-entry refcount whose baseline is the cache's own reference, and payloads reclaimed on the
 * last unref -- no evicting window. a reader pins with try_ref and touches the payload only while
 * pinned; an evictor drops the baseline. whoever drops the count to zero reclaims the payload,
 * exactly once, and no reader ever touches a freed payload. ASan is the use-after-free /
 * double-free / leak oracle. */
#define CACHE_SLOTS 64

typedef struct
{
    tdb_refcount_t rc;
    _Atomic(int *) payload;
} pin_entry_t;

static pin_entry_t s_entries[CACHE_SLOTS];
static _Atomic(long) s_pin_reclaimed = 0;
static _Atomic(int) s_pin_go = 0;

/* reclaim the payload once, on whichever thread drops the last reference */
static void pin_reclaim(pin_entry_t *e)
{
    int *p = atomic_load_explicit(&e->payload, memory_order_acquire);
    atomic_store_explicit(&e->payload, NULL, memory_order_release);
    free(p);
    atomic_fetch_add(&s_pin_reclaimed, 1);
}

static void *pin_reader(void *arg)
{
    (void)arg;
    while (atomic_load(&s_pin_go) == 0) cpu_pause();
    for (long i = 0; i < STRESS_READ_ITER; i++)
    {
        pin_entry_t *e = &s_entries[i % CACHE_SLOTS];
        if (tdb_try_ref(&e->rc))
        {
            /* under the pin the payload cannot be reclaimed, so this read is always valid */
            int *p = atomic_load_explicit(&e->payload, memory_order_acquire);
            if (p)
            {
                volatile int v = *p;
                (void)v;
            }
            if (tdb_unref(&e->rc)) pin_reclaim(e);
        }
    }
    return NULL;
}

static void *pin_evictor(void *arg)
{
    (void)arg;
    while (atomic_load(&s_pin_go) == 0) cpu_pause();
    for (int i = 0; i < CACHE_SLOTS; i++)
    {
        pin_entry_t *e = &s_entries[i];
        if (tdb_unref(&e->rc)) pin_reclaim(e); /* drop the cache's baseline ref */
        cpu_yield();
    }
    return NULL;
}

void test_stress_pin_reclaim_eviction(void)
{
    atomic_store(&s_pin_reclaimed, 0);
    atomic_store(&s_pin_go, 0);
    for (int i = 0; i < CACHE_SLOTS; i++)
    {
        int *p = malloc(sizeof(int));
        *p = i;
        atomic_store_explicit(&s_entries[i].payload, p, memory_order_relaxed);
        atomic_init(&s_entries[i].rc, 1); /* baseline: the cache's own reference */
    }

    pthread_t readers[STRESS_READERS], evictor;
    for (int i = 0; i < STRESS_READERS; i++) pthread_create(&readers[i], NULL, pin_reader, NULL);
    pthread_create(&evictor, NULL, pin_evictor, NULL);
    atomic_store(&s_pin_go, 1);

    for (int i = 0; i < STRESS_READERS; i++) pthread_join(readers[i], NULL);
    pthread_join(evictor, NULL);

    /* every entry's payload reclaimed exactly once, and every refcount drained to empty */
    ASSERT_EQ(atomic_load(&s_pin_reclaimed), (long)CACHE_SLOTS);
    for (int i = 0; i < CACHE_SLOTS; i++) ASSERT_EQ(atomic_load(&s_entries[i].rc), 0);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_epoch_enter_exit, tests_passed);
    RUN_TEST(test_refcount_basic, tests_passed);
    RUN_TEST(test_refcount_evict_window, tests_passed);
    RUN_TEST(test_retire_inline_and_deferred, tests_passed);
    RUN_TEST(test_retire_drain_all, tests_passed);
    RUN_TEST(test_retire_drain_match, tests_passed);
    RUN_TEST(test_stress_epoch_retire, tests_passed);
    RUN_TEST(test_stress_evict_never_false_miss, tests_passed);
    RUN_TEST(test_stress_pin_reclaim_eviction, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
