/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/base/arena.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* a small chunk size so multi-chunk growth and oversized allocations are easy to trigger */
#define TEST_ARENA_CHUNK 4096

/* reserved bytes are what the process holds, allocated bytes are what the caller asked for, and the
 * gap between them is the chunk rounding.
 *
 * this matters because a consumer with a memory budget has to charge the first figure. the block
 * cache holds one arena per decoded node, each rounded up to a whole chunk, so charging the
 * allocated figure let it hold several times the budget it was given -- and the overshoot was
 * invisible, because nothing reported the rounding */
void test_arena_reserved_counts_whole_chunks_not_bytes_used(void)
{
    arena_pool_t *pool = arena_pool_create(TEST_ARENA_CHUNK, 1024 * 1024);
    ASSERT_TRUE(pool != NULL);
    arena_t *arena = arena_create(pool);
    ASSERT_TRUE(arena != NULL);

    ASSERT_EQ(arena_bytes_allocated(arena), 0u);
    ASSERT_EQ(arena_bytes_reserved(arena), 0u);

    /* one small object still takes a whole chunk, which is the whole point */
    ASSERT_TRUE(arena_alloc(arena, 32, 0) != NULL);
    ASSERT_EQ(arena_bytes_allocated(arena), 32u);
    ASSERT_TRUE(arena_bytes_reserved(arena) >= TEST_ARENA_CHUNK);

    /* further allocations inside the same chunk raise the used figure without reserving more */
    const size_t reserved_after_first = arena_bytes_reserved(arena);
    ASSERT_TRUE(arena_alloc(arena, 64, 0) != NULL);
    ASSERT_EQ(arena_bytes_allocated(arena), 96u);
    ASSERT_EQ(arena_bytes_reserved(arena), reserved_after_first);

    /* an allocation past the chunk size gets a block of its own, so reserved tracks it too */
    ASSERT_TRUE(arena_alloc(arena, TEST_ARENA_CHUNK * 4, 0) != NULL);
    ASSERT_TRUE(arena_bytes_reserved(arena) >= reserved_after_first + TEST_ARENA_CHUNK * 4);
    ASSERT_TRUE(arena_bytes_reserved(arena) >= arena_bytes_allocated(arena));

    /* a reset hands the chunks back, so neither figure carries over */
    arena_reset(arena);
    ASSERT_EQ(arena_bytes_allocated(arena), 0u);
    ASSERT_EQ(arena_bytes_reserved(arena), 0u);

    arena_destroy(arena);
    arena_pool_destroy(pool);
}

/* every allocation is writable, distinct, and non-overlapping across chunk boundaries */
void test_arena_basic_bump(void)
{
    arena_pool_t *pool = arena_pool_create(TEST_ARENA_CHUNK, 1024 * 1024);
    ASSERT_TRUE(pool != NULL);
    arena_t *arena = arena_create(pool);
    ASSERT_TRUE(arena != NULL);

    const int count = 300;
    const size_t sz = 32;
    uint8_t *ptrs[300];
    for (int i = 0; i < count; i++)
    {
        ptrs[i] = arena_alloc(arena, sz, 0);
        ASSERT_TRUE(ptrs[i] != NULL);
        memset(ptrs[i], (uint8_t)(i & 0xFF),
               sz); /* write the whole region -- ASan catches overrun */
    }
    /* each region kept its own bytes, so nothing overlapped */
    for (int i = 0; i < count; i++)
        for (size_t j = 0; j < sz; j++) ASSERT_EQ(ptrs[i][j], (uint8_t)(i & 0xFF));

    ASSERT_EQ(arena_bytes_allocated(arena), (size_t)count * sz);

    arena_destroy(arena);
    arena_pool_destroy(pool);
}

/* a requested alignment is honored */
void test_arena_alignment(void)
{
    arena_pool_t *pool = arena_pool_create(TEST_ARENA_CHUNK, 1024 * 1024);
    arena_t *arena = arena_create(pool);

    const size_t aligns[] = {1, 8, 16, 64, 128};
    for (size_t a = 0; a < sizeof(aligns) / sizeof(aligns[0]); a++)
    {
        for (int i = 0; i < 20; i++)
        {
            void *p = arena_alloc(arena, 24, aligns[a]);
            ASSERT_TRUE(p != NULL);
            ASSERT_EQ((uintptr_t)p % aligns[a], 0u);
        }
    }

    arena_destroy(arena);
    arena_pool_destroy(pool);
}

/* an allocation larger than a chunk is served by a dedicated block and is fully writable */
void test_arena_oversized(void)
{
    arena_pool_t *pool = arena_pool_create(TEST_ARENA_CHUNK, 1024 * 1024);
    arena_t *arena = arena_create(pool);

    const size_t big = TEST_ARENA_CHUNK * 3 + 17;
    uint8_t *p = arena_alloc(arena, big, 0);
    ASSERT_TRUE(p != NULL);
    memset(p, 0x5A, big);
    for (size_t i = 0; i < big; i++) ASSERT_EQ(p[i], 0x5A);

    /* a normal allocation after the oversized one still works */
    uint8_t *q = arena_alloc(arena, 64, 0);
    ASSERT_TRUE(q != NULL);
    ASSERT_TRUE(q != p);

    arena_destroy(arena);
    arena_pool_destroy(pool);
}

/* reset releases everything and the arena is immediately reusable */
void test_arena_reset(void)
{
    arena_pool_t *pool = arena_pool_create(TEST_ARENA_CHUNK, 1024 * 1024);
    arena_t *arena = arena_create(pool);

    for (int i = 0; i < 500; i++) ASSERT_TRUE(arena_alloc(arena, 40, 0) != NULL);
    ASSERT_TRUE(arena_bytes_allocated(arena) > 0);

    arena_reset(arena);
    ASSERT_EQ(arena_bytes_allocated(arena), 0u);

    /* usable again with no allocation of its own */
    uint8_t *p = arena_alloc(arena, 40, 0);
    ASSERT_TRUE(p != NULL);
    memset(p, 1, 40);
    ASSERT_EQ(arena_bytes_allocated(arena), 40u);

    arena_destroy(arena);
    arena_pool_destroy(pool);
}

/* an arena with no pool allocates and frees its chunks directly */
void test_arena_no_pool(void)
{
    arena_t *arena = arena_create(NULL);
    ASSERT_TRUE(arena != NULL);

    for (int i = 0; i < 1000; i++)
    {
        uint8_t *p = arena_alloc(arena, 50, 0);
        ASSERT_TRUE(p != NULL);
        memset(p, (uint8_t)i, 50);
    }
    arena_destroy(arena);
}

/* ===== concurrency: many arenas over one shared pool ===== */

#define STRESS_THREADS 6
#define STRESS_ROUNDS  400
#define STRESS_ALLOCS  200

static arena_pool_t *s_pool = NULL;
static _Atomic(int) s_go = 0;

static void *stress_worker(void *arg)
{
    const uint8_t tag = (uint8_t)(uintptr_t)arg;
    while (atomic_load(&s_go) == 0) cpu_pause();
    for (int r = 0; r < STRESS_ROUNDS; r++)
    {
        arena_t *arena = arena_create(s_pool);
        if (!arena) continue;
        for (int i = 0; i < STRESS_ALLOCS; i++)
        {
            const size_t sz = 16 + (size_t)((i * 7 + tag) % 128);
            uint8_t *p = arena_alloc(arena, sz, 0);
            if (p)
            {
                memset(p, tag, sz);
                /* the region stays private to this arena until reset/destroy */
                ASSERT_EQ(p[0], tag);
                ASSERT_EQ(p[sz - 1], tag);
            }
        }
        if ((r & 1) == 0) arena_reset(arena);
        arena_destroy(arena);
    }
    return NULL;
}

/* threads churn arenas over a shared pool: recycling races cleanly (TSan) and leaks nothing (ASan)
 */
void test_arena_pool_concurrent(void)
{
    atomic_store(&s_go, 0);
    s_pool = arena_pool_create(TEST_ARENA_CHUNK, 256 * 1024); /* small cache so give/take churns */
    ASSERT_TRUE(s_pool != NULL);

    pthread_t th[STRESS_THREADS];
    for (int i = 0; i < STRESS_THREADS; i++)
        pthread_create(&th[i], NULL, stress_worker, (void *)(uintptr_t)(i + 1));
    atomic_store(&s_go, 1);
    for (int i = 0; i < STRESS_THREADS; i++) pthread_join(th[i], NULL);

    arena_pool_destroy(s_pool);
    s_pool = NULL;
}

/* ===== concurrency: many threads alloc from one concurrent arena ===== */

#define CONC_THREADS 6
#define CONC_ALLOCS  50000

static arena_t *s_conc_arena = NULL;
static _Atomic(int) s_conc_go = 0;
static _Atomic(long) s_conc_count = 0;

static void *conc_worker(void *arg)
{
    const uint8_t tag = (uint8_t)(uintptr_t)arg;
    while (atomic_load(&s_conc_go) == 0) cpu_pause();
    for (int i = 0; i < CONC_ALLOCS; i++)
    {
        const size_t sz = 8 + (size_t)((i + tag) % 200);
        uint8_t *p = arena_alloc(s_conc_arena, sz, 0);
        if (p)
        {
            /* the region is this thread's alone until the arena is destroyed */
            memset(p, tag, sz);
            ASSERT_EQ(p[0], tag);
            ASSERT_EQ(p[sz - 1], tag);
            atomic_fetch_add(&s_conc_count, 1);
        }
    }
    return NULL;
}

/* concurrent allocation from a single arena: per-thread slots keep regions private, the shared
 * chunk list and pool recycle race cleanly (TSan), and every chunk is freed once at destroy (ASan)
 */
void test_arena_concurrent_single(void)
{
    atomic_store(&s_conc_go, 0);
    atomic_store(&s_conc_count, 0);
    arena_pool_t *pool = arena_pool_create(TEST_ARENA_CHUNK, 1024 * 1024);
    s_conc_arena = arena_create_concurrent(pool);
    ASSERT_TRUE(s_conc_arena != NULL);

    pthread_t th[CONC_THREADS];
    for (int i = 0; i < CONC_THREADS; i++)
        pthread_create(&th[i], NULL, conc_worker, (void *)(uintptr_t)(i + 1));
    atomic_store(&s_conc_go, 1);
    for (int i = 0; i < CONC_THREADS; i++) pthread_join(th[i], NULL);

    ASSERT_EQ(atomic_load(&s_conc_count), (long)CONC_THREADS * CONC_ALLOCS);
    ASSERT_TRUE(arena_bytes_allocated(s_conc_arena) > 0);

    arena_destroy(s_conc_arena);
    s_conc_arena = NULL;
    arena_pool_destroy(pool);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_arena_basic_bump, tests_passed);
    RUN_TEST(test_arena_alignment, tests_passed);
    RUN_TEST(test_arena_oversized, tests_passed);
    RUN_TEST(test_arena_reset, tests_passed);
    RUN_TEST(test_arena_reserved_counts_whole_chunks_not_bytes_used, tests_passed);
    RUN_TEST(test_arena_no_pool, tests_passed);
    RUN_TEST(test_arena_pool_concurrent, tests_passed);
    RUN_TEST(test_arena_concurrent_single, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
