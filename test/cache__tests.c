/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "../src/cache/cache.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* the file id every test uses; the offset distinguishes keys */
#define TEST_CACHE_FILE_ID 0x1234ull

/* a budget well past any per-shard frame ceiling, the cost charged per entry, and how far under the
 * budget a full cache may settle before something other than the budget is the binding limit */
#define TEST_CACHE_BUDGET_BYTES       (64u * 1024 * 1024)
#define TEST_CACHE_ENTRY_COST         4096
#define TEST_CACHE_FILL_SLACK_DIVISOR 20

/* keys per file id and file ids used when loading the bucket table, chosen so the keys spread over
 * both key words rather than one, and so the table sits around half full where probe chains are
 * long enough for a lookup to walk buckets it must reject */
#define TEST_CACHE_LOADED_FILES         64
#define TEST_CACHE_LOADED_KEYS_PER_FILE 128

/* a generic reclaim that frees a malloc'd payload and counts, so a leak or double free shows as a
 * wrong count under a normal run and as an error under ASan */
static _Atomic(long) g_reclaimed = 0;
static void reclaim_free(void *payload, void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&g_reclaimed, 1);
    free(payload);
}

/* allocate a counted payload holding its own offset for verification */
static _Atomic(long) g_allocated = 0;
static uint64_t *make_payload(uint64_t v)
{
    uint64_t *p = malloc(sizeof(*p));
    *p = v;
    atomic_fetch_add(&g_allocated, 1);
    return p;
}

/* a put stores a payload, a get returns it, and an absent key misses */
void test_cache_put_get_miss(void)
{
    atomic_store(&g_reclaimed, 0);
    atomic_store(&g_allocated, 0);
    cache_t *cache = cache_create(NULL);
    ASSERT_TRUE(cache != NULL);

    uint64_t *p = make_payload(42);
    ASSERT_EQ(cache_put(cache, TEST_CACHE_FILE_ID, 1, p, sizeof(*p), sizeof(*p), reclaim_free, NULL,
                        NULL),
              1);

    void *got = NULL;
    size_t got_len = 0;
    cache_entry_t *pin = NULL;
    ASSERT_EQ(cache_get(cache, TEST_CACHE_FILE_ID, 1, &got, &got_len, &pin), 1);
    ASSERT_EQ(got_len, sizeof(uint64_t));
    ASSERT_EQ(*(uint64_t *)got, 42u);
    cache_release(pin);

    ASSERT_EQ(cache_get(cache, TEST_CACHE_FILE_ID, 999, &got, &got_len, &pin), 0);

    cache_destroy(cache);
    ASSERT_EQ(atomic_load(&g_allocated), atomic_load(&g_reclaimed));
}

/* putting the same key twice keeps the first payload and reclaims the caller's duplicate */
void test_cache_idempotent_put(void)
{
    atomic_store(&g_reclaimed, 0);
    atomic_store(&g_allocated, 0);
    cache_t *cache = cache_create(NULL);

    uint64_t *first = make_payload(1);
    uint64_t *second = make_payload(2);
    ASSERT_EQ(cache_put(cache, TEST_CACHE_FILE_ID, 7, first, 8, 8, reclaim_free, NULL, NULL), 1);
    ASSERT_EQ(cache_put(cache, TEST_CACHE_FILE_ID, 7, second, 8, 8, reclaim_free, NULL, NULL), 1);
    /* the duplicate was reclaimed at once, the first is still cached */
    ASSERT_EQ(atomic_load(&g_reclaimed), 1);

    void *got = NULL;
    cache_entry_t *pin = NULL;
    ASSERT_EQ(cache_get(cache, TEST_CACHE_FILE_ID, 7, &got, NULL, &pin), 1);
    ASSERT_EQ(*(uint64_t *)got, 1u); /* the first payload survived */
    cache_release(pin);

    cache_destroy(cache);
    ASSERT_EQ(atomic_load(&g_allocated), atomic_load(&g_reclaimed));
}

/* two entries in one cache reclaim through their own reclaim functions -- the mixed-payload
 * guarantee */
static _Atomic(int) g_node_reclaimed = 0;
static _Atomic(int) g_block_reclaimed = 0;
static void reclaim_node(void *payload, void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&g_node_reclaimed, 1);
    free(payload);
}
static void reclaim_block(void *payload, void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&g_block_reclaimed, 1);
    free(payload);
}
void test_cache_mixed_payload_reclaim(void)
{
    atomic_store(&g_node_reclaimed, 0);
    atomic_store(&g_block_reclaimed, 0);
    cache_t *cache = cache_create(NULL);

    ASSERT_EQ(cache_put(cache, TEST_CACHE_FILE_ID, 1, malloc(8), 8, 8, reclaim_node, NULL, NULL),
              1);
    ASSERT_EQ(cache_put(cache, TEST_CACHE_FILE_ID, 2, malloc(8), 8, 8, reclaim_block, NULL, NULL),
              1);

    cache_destroy(cache);
    ASSERT_EQ(atomic_load(&g_node_reclaimed), 1);
    ASSERT_EQ(atomic_load(&g_block_reclaimed), 1);
}

/* under a byte budget the cache evicts to stay within it and reclaims every evicted payload */
void test_cache_eviction_budget(void)
{
    atomic_store(&g_reclaimed, 0);
    atomic_store(&g_allocated, 0);

    cache_config_t cfg = {0};
    cfg.capacity_bytes = 4096;
    cfg.shard_count = 1;
    cfg.slots_per_shard = 64;
    cache_t *cache = cache_create(&cfg);

    const size_t entry_cost = 256;
    for (uint64_t i = 0; i < 200; i++)
    {
        uint64_t *p = make_payload(i);
        (void)cache_put(cache, TEST_CACHE_FILE_ID, i, p, sizeof(*p), entry_cost, reclaim_free, NULL,
                        NULL);
    }

    cache_stats_t stats;
    cache_get_stats(cache, &stats);
    ASSERT_TRUE(stats.bytes_used <= cfg.capacity_bytes);
    ASSERT_TRUE(stats.evictions > 0);

    cache_destroy(cache);
    /* every payload was reclaimed exactly once, whether by eviction or teardown */
    ASSERT_EQ(atomic_load(&g_allocated), atomic_load(&g_reclaimed));
}

/* every key in a loaded bucket table gets back its own payload, so a lookup that walks a chain of
 * buckets belonging to other keys rejects each one rather than returning the frame it points at */
void test_cache_loaded_table_returns_each_key_its_own_payload(void)
{
    atomic_store(&g_reclaimed, 0);
    atomic_store(&g_allocated, 0);

    cache_config_t cfg = {0};
    cfg.capacity_bytes = TEST_CACHE_BUDGET_BYTES;
    cfg.shard_count = 1;
    cache_t *cache = cache_create(&cfg);
    ASSERT_TRUE(cache != NULL);

    /* the payload is a hash of the key, so a lookup that returns another key's frame is caught by
     * its contents and not only by its absence */
    for (uint64_t f = 0; f < TEST_CACHE_LOADED_FILES; f++)
    {
        for (uint64_t k = 0; k < TEST_CACHE_LOADED_KEYS_PER_FILE; k++)
        {
            uint64_t *p = make_payload(f * TEST_CACHE_LOADED_KEYS_PER_FILE + k);
            ASSERT_EQ(cache_put(cache, f, k, p, sizeof(*p), sizeof(*p), reclaim_free, NULL, NULL),
                      1);
        }
    }

    for (uint64_t f = 0; f < TEST_CACHE_LOADED_FILES; f++)
    {
        for (uint64_t k = 0; k < TEST_CACHE_LOADED_KEYS_PER_FILE; k++)
        {
            void *payload = NULL;
            size_t len = 0;
            cache_entry_t *pin = NULL;
            ASSERT_EQ(cache_get(cache, f, k, &payload, &len, &pin), 1);
            ASSERT_EQ(*(uint64_t *)payload, f * TEST_CACHE_LOADED_KEYS_PER_FILE + k);
            ASSERT_EQ(len, sizeof(uint64_t));
            cache_release(pin);
        }
    }

    /* a key that was never inserted still misses, so the chain walk is not matching too loosely */
    void *payload = NULL;
    size_t len = 0;
    cache_entry_t *pin = NULL;
    ASSERT_EQ(cache_get(cache, TEST_CACHE_LOADED_FILES, 0, &payload, &len, &pin), 0);

    cache_destroy(cache);
    ASSERT_EQ(atomic_load(&g_allocated), atomic_load(&g_reclaimed));
}

/* a cache holds what it was configured to hold. the frame count is derived from the byte budget, so
 * a ceiling on frames that binds before the budget does silently shrinks the cache -- the budget
 * still reports as configured while a fraction of it is reachable, which reads as a miss-rate
 * problem rather than a sizing one */
void test_cache_reaches_its_configured_capacity(void)
{
    atomic_store(&g_reclaimed, 0);
    atomic_store(&g_allocated, 0);

    /* large enough that a per-shard frame ceiling would bind before the byte budget, which is the
     * shape the defaults have to survive */
    cache_config_t cfg = {0};
    cfg.capacity_bytes = TEST_CACHE_BUDGET_BYTES;
    cfg.shard_count = 1;
    cache_t *cache = cache_create(&cfg);
    ASSERT_TRUE(cache != NULL);

    /* insert more distinct keys than the budget can hold, so it fills and then evicts */
    const uint64_t attempts = (TEST_CACHE_BUDGET_BYTES / TEST_CACHE_ENTRY_COST) * 2;
    for (uint64_t i = 0; i < attempts; i++)
    {
        uint64_t *p = make_payload(i);
        (void)cache_put(cache, TEST_CACHE_FILE_ID, i, p, sizeof(*p), TEST_CACHE_ENTRY_COST,
                        reclaim_free, NULL, NULL);
    }

    cache_stats_t stats;
    cache_get_stats(cache, &stats);

    /* never over the budget, and close enough under it that nothing else is binding first */
    ASSERT_TRUE(stats.bytes_used <= cfg.capacity_bytes);
    ASSERT_TRUE(stats.bytes_used >=
                cfg.capacity_bytes - (cfg.capacity_bytes / TEST_CACHE_FILL_SLACK_DIVISOR));

    cache_destroy(cache);
    ASSERT_EQ(atomic_load(&g_allocated), atomic_load(&g_reclaimed));
}

/* an entry evicted while a reader holds its pin stays valid until the pin is released, and is
 * reclaimed exactly on that release */
static _Atomic(int) g_pinned_reclaimed = 0;
static void reclaim_pinned(void *payload, void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&g_pinned_reclaimed, 1);
    free(payload);
}
void test_cache_pin_survives_eviction(void)
{
    atomic_store(&g_pinned_reclaimed, 0);

    /* a single-frame shard so the pinned entry is the forced eviction victim */
    cache_config_t cfg = {0};
    cfg.capacity_bytes = 100;
    cfg.shard_count = 1;
    cfg.slots_per_shard = 1;
    cache_t *cache = cache_create(&cfg);

    uint64_t *a = malloc(sizeof(*a));
    *a = 0xABCD;
    ASSERT_EQ(
        cache_put(cache, TEST_CACHE_FILE_ID, 1, a, sizeof(*a), 100, reclaim_pinned, NULL, NULL), 1);

    void *got = NULL;
    cache_entry_t *pin = NULL;
    ASSERT_EQ(cache_get(cache, TEST_CACHE_FILE_ID, 1, &got, NULL, &pin), 1);

    /* a second entry cannot fit; its put evicts the pinned one, which becomes DYING, not reclaimed
     */
    uint64_t *b = malloc(sizeof(*b));
    *b = 0x1111;
    (void)cache_put(cache, TEST_CACHE_FILE_ID, 2, b, sizeof(*b), 100, reclaim_pinned, NULL, NULL);
    ASSERT_EQ(atomic_load(&g_pinned_reclaimed),
              1); /* only b was reclaimed (put could not cache it) */

    /* the pinned payload is still valid to read, then reclaimed exactly on release */
    ASSERT_EQ(*(uint64_t *)got, 0xABCDu);
    cache_release(pin);
    ASSERT_EQ(atomic_load(&g_pinned_reclaimed), 2);

    cache_destroy(cache);
}

/* ===== concurrency stress ===== */

#define STRESS_READERS   4
#define STRESS_KEYSPACE  256
#define STRESS_WRITES    40000
#define STRESS_READ_ITER 300000

static cache_t *s_cache = NULL;
static _Atomic(int) s_go = 0;
static _Atomic(int) s_writer_done = 0;

static void *stress_reader(void *arg)
{
    (void)arg;
    unsigned seed = 12345;
    while (atomic_load(&s_go) == 0) cpu_pause();
    for (long i = 0; i < STRESS_READ_ITER; i++)
    {
        seed = seed * 1103515245u + 12345u;
        const uint64_t off = seed % STRESS_KEYSPACE;
        void *got = NULL;
        cache_entry_t *pin = NULL;
        if (cache_get(s_cache, TEST_CACHE_FILE_ID, off, &got, NULL, &pin))
        {
            /* touch the payload under the pin -- must be alive; ASan is the UAF oracle */
            volatile uint64_t v = *(uint64_t *)got;
            (void)v;
            cache_release(pin);
        }
    }
    return NULL;
}

static void *stress_writer(void *arg)
{
    (void)arg;
    while (atomic_load(&s_go) == 0) cpu_pause();
    for (long i = 0; i < STRESS_WRITES; i++)
    {
        const uint64_t off = (uint64_t)i % STRESS_KEYSPACE;
        uint64_t *p = make_payload(off);
        (void)cache_put(s_cache, TEST_CACHE_FILE_ID, off, p, sizeof(*p), 256, reclaim_free, NULL,
                        NULL);
    }
    atomic_store(&s_writer_done, 1);
    return NULL;
}

/* concurrent gets, puts, and evictions across threads: every payload is reclaimed exactly once, no
 * reader touches a freed payload (ASan), and the accesses race cleanly (TSan) */
void test_cache_stress_concurrent(void)
{
    atomic_store(&g_reclaimed, 0);
    atomic_store(&g_allocated, 0);
    atomic_store(&s_go, 0);
    atomic_store(&s_writer_done, 0);

    cache_config_t cfg = {0};
    cfg.capacity_bytes = 64 * 256; /* room for ~64 of the 256 keys, so eviction churns */
    cfg.shard_count = 4;
    cfg.slots_per_shard = 32;
    s_cache = cache_create(&cfg);

    pthread_t readers[STRESS_READERS], writer;
    for (int i = 0; i < STRESS_READERS; i++) pthread_create(&readers[i], NULL, stress_reader, NULL);
    pthread_create(&writer, NULL, stress_writer, NULL);
    atomic_store(&s_go, 1);

    pthread_join(writer, NULL);
    for (int i = 0; i < STRESS_READERS; i++) pthread_join(readers[i], NULL);

    cache_destroy(s_cache); /* reclaims whatever is still cached */
    s_cache = NULL;

    /* every allocated payload was reclaimed exactly once */
    ASSERT_EQ(atomic_load(&g_allocated), atomic_load(&g_reclaimed));
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_cache_put_get_miss, tests_passed);
    RUN_TEST(test_cache_idempotent_put, tests_passed);
    RUN_TEST(test_cache_mixed_payload_reclaim, tests_passed);
    RUN_TEST(test_cache_eviction_budget, tests_passed);
    RUN_TEST(test_cache_reaches_its_configured_capacity, tests_passed);
    RUN_TEST(test_cache_loaded_table_returns_each_key_its_own_payload, tests_passed);
    RUN_TEST(test_cache_pin_survives_eviction, tests_passed);
    RUN_TEST(test_cache_stress_concurrent, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
