/**
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "../src/lru.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* global counters */
static _Atomic(int) eviction_count = 0;
static char last_evicted_key[256] = {0};
static pthread_mutex_t evict_lock = PTHREAD_MUTEX_INITIALIZER;

static void test_evict_callback(const char *key, void *value, void *user_data)
{
    atomic_fetch_add(&eviction_count, 1);
    pthread_mutex_lock(&evict_lock);
    strncpy(last_evicted_key, key, sizeof(last_evicted_key) - 1);
    pthread_mutex_unlock(&evict_lock);
    (void)value;
    (void)user_data;
}

static void free_evict_callback(const char *key, void *value, void *user_data)
{
    (void)key;
    (void)user_data;
    if (value) free(value);
}

static void test_lru_cache_new_free(void)
{
    lru_cache_t *cache = lru_cache_new(10);
    ASSERT_TRUE(cache != NULL);
    ASSERT_EQ(lru_cache_capacity(cache), 10);
    ASSERT_EQ(lru_cache_size(cache), 0);
    lru_cache_free(cache);
}

static void test_lru_cache_put_get(void)
{
    lru_cache_t *cache = lru_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int value1 = 100;
    int value2 = 200;
    int value3 = 300;

    ASSERT_EQ(lru_cache_put(cache, "key1", &value1, NULL, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key2", &value2, NULL, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key3", &value3, NULL, NULL), 0);

    ASSERT_EQ(lru_cache_size(cache), 3);

    int *retrieved1 = (int *)lru_cache_get(cache, "key1");
    ASSERT_TRUE(retrieved1 != NULL);
    ASSERT_EQ(*retrieved1, 100);

    int *retrieved2 = (int *)lru_cache_get(cache, "key2");
    ASSERT_TRUE(retrieved2 != NULL);
    ASSERT_EQ(*retrieved2, 200);

    int *retrieved3 = (int *)lru_cache_get(cache, "key3");
    ASSERT_TRUE(retrieved3 != NULL);
    ASSERT_EQ(*retrieved3, 300);

    void *not_found = lru_cache_get(cache, "nonexistent");
    ASSERT_TRUE(not_found == NULL);

    lru_cache_free(cache);
}

static void test_lru_cache_eviction(void)
{
    atomic_store(&eviction_count, 0);
    pthread_mutex_lock(&evict_lock);
    memset(last_evicted_key, 0, sizeof(last_evicted_key));
    pthread_mutex_unlock(&evict_lock);

    lru_cache_t *cache = lru_cache_new(3);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3, v4 = 4;

    ASSERT_EQ(lru_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    ASSERT_EQ(lru_cache_size(cache), 3);
    ASSERT_EQ(atomic_load(&eviction_count), 0);

    /* adding 4th item should evict one entry */
    ASSERT_EQ(lru_cache_put(cache, "key4", &v4, test_evict_callback, NULL), 0);

    ASSERT_EQ(lru_cache_size(cache), 3);
    ASSERT_EQ(atomic_load(&eviction_count), 1);

    /* key4 should exist */
    ASSERT_TRUE(lru_cache_get(cache, "key4") != NULL);

    lru_cache_free(cache);
}

static void test_lru_cache_get_updates_order(void)
{
    atomic_store(&eviction_count, 0);
    pthread_mutex_lock(&evict_lock);
    memset(last_evicted_key, 0, sizeof(last_evicted_key));
    pthread_mutex_unlock(&evict_lock);

    lru_cache_t *cache = lru_cache_new(3);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3, v4 = 4;

    ASSERT_EQ(lru_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    /* access key1 multiple times - this should increase its access count */
    /* making it less likely to be evicted (LRU behavior) */
    for (int i = 0; i < 5; i++)
    {
        ASSERT_TRUE(lru_cache_get(cache, "key1") != NULL);
    }

    /* add key4 - with LRU, key1 should NOT be evicted since it was recently accessed */
    ASSERT_EQ(lru_cache_put(cache, "key4", &v4, test_evict_callback, NULL), 0);

    ASSERT_EQ(atomic_load(&eviction_count), 1);

    /* key1 should still exist because it was recently accessed */
    ASSERT_TRUE(lru_cache_get(cache, "key1") != NULL);

    /* key4 should exist */
    ASSERT_TRUE(lru_cache_get(cache, "key4") != NULL);

    lru_cache_free(cache);
}

static void test_lru_cache_update(void)
{
    lru_cache_t *cache = lru_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int v1 = 100;
    int v2 = 200;

    ASSERT_EQ(lru_cache_put(cache, "key1", &v1, NULL, NULL), 0);
    ASSERT_EQ(lru_cache_size(cache), 1);

    int *retrieved = (int *)lru_cache_get(cache, "key1");
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(*retrieved, 100);

    /* update should return 1 */
    ASSERT_EQ(lru_cache_put(cache, "key1", &v2, NULL, NULL), 1);
    ASSERT_EQ(lru_cache_size(cache), 1); /* size should not change */

    retrieved = (int *)lru_cache_get(cache, "key1");
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(*retrieved, 200);

    lru_cache_free(cache);
}

static void test_lru_cache_update_refreshes_access(void)
{
    atomic_store(&eviction_count, 0);
    pthread_mutex_lock(&evict_lock);
    memset(last_evicted_key, 0, sizeof(last_evicted_key));
    pthread_mutex_unlock(&evict_lock);

    lru_cache_t *cache = lru_cache_new(3);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3, v4 = 4;
    int v1_updated = 100;

    ASSERT_EQ(lru_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    /* update key1 - this should refresh its access count (LRU behavior) */
    ASSERT_EQ(lru_cache_put(cache, "key1", &v1_updated, test_evict_callback, NULL), 1);

    /* eviction callback was called once to clean up old value */
    ASSERT_EQ(atomic_load(&eviction_count), 1);

    /* adding key4 should evict key2 or key3, NOT key1 (since key1 was just updated) */
    ASSERT_EQ(lru_cache_put(cache, "key4", &v4, test_evict_callback, NULL), 0);

    /* eviction callback called again when an entry is evicted from cache */
    ASSERT_EQ(atomic_load(&eviction_count), 2);

    /* key1 should still exist because it was just updated */
    ASSERT_TRUE(lru_cache_get(cache, "key1") != NULL);

    /* verify the updated value */
    int *retrieved = (int *)lru_cache_get(cache, "key1");
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(*retrieved, 100);

    /* key4 should exist */
    ASSERT_TRUE(lru_cache_get(cache, "key4") != NULL);

    lru_cache_free(cache);
}

static void test_lru_cache_remove(void)
{
    atomic_store(&eviction_count, 0);

    lru_cache_t *cache = lru_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3;

    ASSERT_EQ(lru_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    ASSERT_EQ(lru_cache_size(cache), 3);

    ASSERT_EQ(lru_cache_remove(cache, "key2"), 0);
    ASSERT_EQ(lru_cache_size(cache), 2);
    ASSERT_EQ(atomic_load(&eviction_count), 1); /* callback should be called */

    /* key2 should be gone */
    ASSERT_TRUE(lru_cache_get(cache, "key2") == NULL);

    /* key1 and key3 should still exist */
    ASSERT_TRUE(lru_cache_get(cache, "key1") != NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key3") != NULL);

    /* removing non-existent key should fail */
    ASSERT_EQ(lru_cache_remove(cache, "nonexistent"), -1);

    lru_cache_free(cache);
}

static void test_lru_cache_clear(void)
{
    atomic_store(&eviction_count, 0);

    lru_cache_t *cache = lru_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3;

    ASSERT_EQ(lru_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    ASSERT_EQ(lru_cache_size(cache), 3);

    lru_cache_clear(cache);

    ASSERT_EQ(lru_cache_size(cache), 0);
    ASSERT_EQ(atomic_load(&eviction_count), 3); /* all callbacks should be called */

    /* all keys should be gone */
    ASSERT_TRUE(lru_cache_get(cache, "key1") == NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key2") == NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key3") == NULL);

    lru_cache_free(cache);
}

static void test_lru_cache_with_malloc(void)
{
    lru_cache_t *cache = lru_cache_new(3);
    ASSERT_TRUE(cache != NULL);

    int *v1 = (int *)malloc(sizeof(int));
    int *v2 = (int *)malloc(sizeof(int));
    int *v3 = (int *)malloc(sizeof(int));
    int *v4 = (int *)malloc(sizeof(int));

    *v1 = 100;
    *v2 = 200;
    *v3 = 300;
    *v4 = 400;

    ASSERT_EQ(lru_cache_put(cache, "key1", v1, free_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key2", v2, free_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key3", v3, free_evict_callback, NULL), 0);

    /* this should evict one entry and free its value */
    ASSERT_EQ(lru_cache_put(cache, "key4", v4, free_evict_callback, NULL), 0);

    ASSERT_EQ(lru_cache_size(cache), 3);

    lru_cache_free(cache); /* should free remaining allocated memory */
}

typedef struct
{
    lru_cache_t *cache;
    int thread_id;
    int num_ops;
} thread_arg_t;

static void *concurrent_put_thread(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < targ->num_ops; i++)
    {
        char key[64];
        snprintf(key, sizeof(key), "thread%d_key%d", targ->thread_id, i);

        int *value = (int *)malloc(sizeof(int));
        if (value == NULL) continue; /* skip if allocation fails */

        *value = targ->thread_id * 1000 + i;

        /* lru_cache_put takes ownership of the value and will call free_evict_callback
         * on failure to prevent leaks, so we don't need to free manually on error */
        int result = lru_cache_put(targ->cache, key, value, free_evict_callback, NULL);
        (void)result; /* result: 0=inserted, 1=updated, -1=failed (callback already called) */
    }

    return NULL;
}

static void *concurrent_get_thread(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < targ->num_ops; i++)
    {
        char key[64];
        snprintf(key, sizeof(key), "thread%d_key%d", targ->thread_id % 2, i % 50);

        void *value = lru_cache_get(targ->cache, key);
        (void)value; /* may be NULL, that's ok */
    }

    return NULL;
}

static void test_lru_cache_concurrent(void)
{
    lru_cache_t *cache = lru_cache_new(100);
    ASSERT_TRUE(cache != NULL);

#define NUM_THREADS    4
#define OPS_PER_THREAD 100

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS / 2; i++)
    {
        args[i].cache = cache;
        args[i].thread_id = i;
        args[i].num_ops = OPS_PER_THREAD;
        pthread_create(&threads[i], NULL, concurrent_put_thread, &args[i]);
    }

    for (int i = NUM_THREADS / 2; i < NUM_THREADS; i++)
    {
        args[i].cache = cache;
        args[i].thread_id = i;
        args[i].num_ops = OPS_PER_THREAD;
        pthread_create(&threads[i], NULL, concurrent_get_thread, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    /* cache should have at most 100 entries */
    ASSERT_TRUE(lru_cache_size(cache) <= 100);

    lru_cache_free(cache);

#undef NUM_THREADS
#undef OPS_PER_THREAD
}

static void test_lru_cache_edge_cases(void)
{
    lru_cache_t *cache1 = lru_cache_new(1);
    ASSERT_TRUE(cache1 != NULL);

    int v1 = 1, v2 = 2;
    ASSERT_EQ(lru_cache_put(cache1, "key1", &v1, NULL, NULL), 0);
    ASSERT_EQ(lru_cache_size(cache1), 1);

    ASSERT_EQ(lru_cache_put(cache1, "key2", &v2, NULL, NULL), 0);
    ASSERT_EQ(lru_cache_size(cache1), 1);

    ASSERT_TRUE(lru_cache_get(cache1, "key1") == NULL);
    ASSERT_TRUE(lru_cache_get(cache1, "key2") != NULL);

    lru_cache_free(cache1);

    /* NULL key/cache handling */
    lru_cache_t *cache2 = lru_cache_new(5);
    ASSERT_EQ(lru_cache_put(NULL, "key", &v1, NULL, NULL), -1);
    ASSERT_EQ(lru_cache_put(cache2, NULL, &v1, NULL, NULL), -1);
    ASSERT_TRUE(lru_cache_get(NULL, "key") == NULL);
    ASSERT_TRUE(lru_cache_get(cache2, NULL) == NULL);
    ASSERT_EQ(lru_cache_remove(NULL, "key"), -1);
    ASSERT_EQ(lru_cache_remove(cache2, NULL), -1);

    lru_cache_free(cache2);
}

static int foreach_callback(const char *key, void *value, void *user_data)
{
    int *count = (int *)user_data;
    (*count)++;
    (void)key;
    (void)value;
    return 0; /* continue iteration */
}

static int foreach_stop_callback(const char *key, void *value, void *user_data)
{
    int *count = (int *)user_data;
    (*count)++;
    (void)key;
    (void)value;
    /* stop after 2 iterations */
    return (*count >= 2) ? 1 : 0;
}

static void test_lru_cache_foreach(void)
{
    lru_cache_t *cache = lru_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3;

    ASSERT_EQ(lru_cache_put(cache, "key1", &v1, NULL, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key2", &v2, NULL, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key3", &v3, NULL, NULL), 0);

    int count = 0;
    size_t visited = lru_cache_foreach(cache, foreach_callback, &count);
    ASSERT_EQ(visited, 3);
    ASSERT_EQ(count, 3);

    count = 0;
    visited = lru_cache_foreach(cache, foreach_stop_callback, &count);
    ASSERT_EQ(visited, 2);
    ASSERT_EQ(count, 2);

    visited = lru_cache_foreach(cache, NULL, NULL);
    ASSERT_EQ(visited, 0);

    lru_cache_free(cache);
}

void test_lru_cache_destroy_vs_free()
{
    /* test destroy (no callbacks) vs free (with callbacks) */
    atomic_store(&eviction_count, 0);

    lru_cache_t *cache1 = lru_cache_new(3);
    int v1 = 1, v2 = 2;
    lru_cache_put(cache1, "key1", &v1, test_evict_callback, NULL);
    lru_cache_put(cache1, "key2", &v2, test_evict_callback, NULL);

    /* destroy should not call callbacks */
    lru_cache_destroy(cache1);
    ASSERT_EQ(atomic_load(&eviction_count), 0);

    /* free should call callbacks */
    atomic_store(&eviction_count, 0);
    lru_cache_t *cache2 = lru_cache_new(3);
    lru_cache_put(cache2, "key1", &v1, test_evict_callback, NULL);
    lru_cache_put(cache2, "key2", &v2, test_evict_callback, NULL);
    lru_cache_free(cache2);
    ASSERT_EQ(atomic_load(&eviction_count), 2);
}

void test_lru_cache_zero_capacity()
{
    lru_cache_t *cache = lru_cache_new(0);
    ASSERT_TRUE(cache == NULL); /* should return NULL for zero capacity */
}

void test_lru_cache_long_keys()
{
    lru_cache_t *cache = lru_cache_new(5);

    /* fairly long key (1KB) */
    char long_key[1024];
    memset(long_key, 'A', sizeof(long_key) - 1);
    long_key[sizeof(long_key) - 1] = '\0';

    int v = 123;
    ASSERT_EQ(lru_cache_put(cache, long_key, &v, NULL, NULL), 0);
    ASSERT_TRUE(lru_cache_get(cache, long_key) == &v);

    lru_cache_free(cache);
}

void test_lru_cache_empty_key()
{
    lru_cache_t *cache = lru_cache_new(5);

    int v = 1;
    ASSERT_EQ(lru_cache_put(cache, "", &v, NULL, NULL), 0);
    ASSERT_TRUE(lru_cache_get(cache, "") == &v);

    lru_cache_free(cache);
}

void test_lru_cache_hash_collisions()
{
    lru_cache_t *cache = lru_cache_new(100);

    /* add many keys to test hash collision handling */
    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        int *v = malloc(sizeof(int));
        *v = i;
        ASSERT_EQ(lru_cache_put(cache, key, v, free_evict_callback, NULL), 0);
    }

    /* verify all are retrievable */
    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        int *v = (int *)lru_cache_get(cache, key);
        ASSERT_TRUE(v != NULL);
        ASSERT_EQ(*v, i);
    }

    lru_cache_free(cache);
}

void test_lru_cache_free_null()
{
    lru_cache_free(NULL);
    lru_cache_destroy(NULL);
    lru_cache_clear(NULL);
}

/* test for race condition where multiple threads try to add same key */
typedef struct
{
    lru_cache_t *cache;
    const char *key;
    _Atomic(int) *refcount;
    int thread_id;
} race_test_arg_t;

static void race_evict_callback(const char *key, void *value, void *user_data)
{
    (void)key;
    (void)value;
    race_test_arg_t *arg = (race_test_arg_t *)user_data;
    if (arg && arg->refcount)
    {
        atomic_fetch_sub(arg->refcount, 1);
    }
}

static void *race_condition_thread(void *arg)
{
    race_test_arg_t *targ = (race_test_arg_t *)arg;

    /* check if already in cache */
    void *cached = lru_cache_get(targ->cache, targ->key);
    if (!cached)
    {
        /* simulate taking a reference */
        atomic_fetch_add(targ->refcount, 1);

        /* try to add to cache */
        int result = lru_cache_put(targ->cache, targ->key, targ, race_evict_callback, targ);

        if (result == 1)
        {
            /* entry already existed (race detected), release our extra ref */
            atomic_fetch_sub(targ->refcount, 1);
        }
        else if (result == -1)
        {
            /* put failed, release our ref */
            atomic_fetch_sub(targ->refcount, 1);
        }
    }

    return NULL;
}

void test_lru_cache_race_condition()
{
    printf(BOLDWHITE "\nTest: Race Condition - Multiple Threads Adding Same Key\n" RESET);

    lru_cache_t *cache = lru_cache_new(100);
    ASSERT_TRUE(cache != NULL);

    _Atomic(int) refcount = 0;

    const char *shared_key = "shared_sstable_key";

#define RACE_THREADS 10
    pthread_t threads[RACE_THREADS];
    race_test_arg_t args[RACE_THREADS];

    /* spawn multiple threads trying to add the same key */
    for (int i = 0; i < RACE_THREADS; i++)
    {
        args[i].cache = cache;
        args[i].key = shared_key;
        args[i].refcount = &refcount;
        args[i].thread_id = i;
        pthread_create(&threads[i], NULL, race_condition_thread, &args[i]);
    }

    for (int i = 0; i < RACE_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    /* refcount should be 1 (only the cache holds a reference) */
    int final_refcount = atomic_load(&refcount);
    printf("  Final refcount: %d (expected: 1)\n", final_refcount);
    ASSERT_EQ(final_refcount, 1);

    /* clear cache, which should call evict callback and decrement refcount to 0 */
    lru_cache_clear(cache);
    final_refcount = atomic_load(&refcount);
    printf("  Refcount after cache clear: %d (expected: 0)\n", final_refcount);
    ASSERT_EQ(final_refcount, 0);

    lru_cache_free(cache);

#undef RACE_THREADS
}

void test_lru_cache_put_return_values()
{
    lru_cache_t *cache = lru_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int v1 = 100;
    int v2 = 200;

    /* first put should return 0 (new insertion) */
    int result = lru_cache_put(cache, "key1", &v1, NULL, NULL);
    ASSERT_EQ(result, 0);

    /* second put with same key should return 1 (update) */
    result = lru_cache_put(cache, "key1", &v2, NULL, NULL);
    ASSERT_EQ(result, 1);

    /* verify value was updated */
    int *retrieved = (int *)lru_cache_get(cache, "key1");
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(*retrieved, 200);

    /* size should still be 1 */
    ASSERT_EQ(lru_cache_size(cache), 1);

    lru_cache_free(cache);
}

void test_lru_cache_access_pattern()
{
    printf(BOLDWHITE "\nTest: LRU Access Pattern - Frequently Accessed Items Stay\n" RESET);

    lru_cache_t *cache = lru_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int values[10];
    for (int i = 0; i < 10; i++)
    {
        values[i] = i * 100;
    }

    for (int i = 0; i < 5; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%d", i);
        ASSERT_EQ(lru_cache_put(cache, key, &values[i], NULL, NULL), 0);
    }

    /* access key0 many times to make it "hot" */
    for (int i = 0; i < 10; i++)
    {
        ASSERT_TRUE(lru_cache_get(cache, "key0") != NULL);
    }

    /* insert 5 more items, which should evict some of the original items */
    for (int i = 5; i < 10; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%d", i);
        ASSERT_EQ(lru_cache_put(cache, key, &values[i], NULL, NULL), 0);
    }

    /* key0 should still be in cache because it was frequently accessed */
    void *key0_value = lru_cache_get(cache, "key0");
    printf("  key0 still in cache: %s\n", key0_value != NULL ? "YES" : "NO");
    ASSERT_TRUE(key0_value != NULL);

    lru_cache_free(cache);
}

static void *int_copy_fn(void *value)
{
    if (value == NULL) return NULL;
    int *copy = malloc(sizeof(int));
    if (copy) *copy = *(int *)value;
    return copy;
}

void test_lru_cache_get_copy()
{
    lru_cache_t *cache = lru_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int v1 = 42;
    ASSERT_EQ(lru_cache_put(cache, "key1", &v1, NULL, NULL), 0);

    /* get a copy of the value */
    int *copy = (int *)lru_cache_get_copy(cache, "key1", int_copy_fn);
    ASSERT_TRUE(copy != NULL);
    ASSERT_EQ(*copy, 42);

    /* modify original, copy should be unchanged */
    v1 = 100;
    ASSERT_EQ(*copy, 42);

    free(copy);

    /* test with non-existent key */
    copy = (int *)lru_cache_get_copy(cache, "nonexistent", int_copy_fn);
    ASSERT_TRUE(copy == NULL);

    lru_cache_free(cache);
}

#define BENCH_ITERATIONS 1000000
#define BENCH_CACHE_SIZE 10000
#define BENCH_THREADS    8

typedef struct
{
    lru_cache_t *cache;
    int thread_id;
    int iterations;
    double elapsed_time;
} bench_thread_context_t;

static void benchmark_lru_sequential(void)
{
    printf(BOLDWHITE "\nBenchmark 1: Sequential Write/Read Performance\n" RESET);

    lru_cache_t *cache = lru_cache_new(BENCH_CACHE_SIZE);
    ASSERT_TRUE(cache != NULL);

    int *values = malloc(BENCH_ITERATIONS * sizeof(int));
    for (int i = 0; i < BENCH_ITERATIONS; i++)
    {
        values[i] = i;
    }

    /* sequential writes */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < BENCH_ITERATIONS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        lru_cache_put(cache, key, &values[i], NULL, NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double write_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("  Sequential writes: %.2f M ops/sec (%.3f seconds)\n",
           BENCH_ITERATIONS / write_time / 1e6, write_time);

    /* sequential reads (cache hits for last BENCH_CACHE_SIZE entries) */
    clock_gettime(CLOCK_MONOTONIC, &start);

    int hits = 0;
    for (int i = 0; i < BENCH_ITERATIONS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        void *val = lru_cache_get(cache, key);
        if (val != NULL) hits++;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double read_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("  Sequential reads: %.2f M ops/sec (%.3f seconds)\n",
           BENCH_ITERATIONS / read_time / 1e6, read_time);
    printf("  Cache hit rate: %.1f%% (%d/%d)\n", (double)hits / BENCH_ITERATIONS * 100, hits,
           BENCH_ITERATIONS);

    free(values);
    lru_cache_free(cache);
}

static void benchmark_lru_random_access(void)
{
    printf(BOLDWHITE "\nBenchmark 2: Random Access Performance\n" RESET);

    lru_cache_t *cache = lru_cache_new(BENCH_CACHE_SIZE);
    ASSERT_TRUE(cache != NULL);

    int *values = malloc(BENCH_CACHE_SIZE * sizeof(int));

    /* populate cache */
    for (int i = 0; i < BENCH_CACHE_SIZE; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        values[i] = i;
        lru_cache_put(cache, key, &values[i], NULL, NULL);
    }

    /* random reads */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < BENCH_ITERATIONS; i++)
    {
        int idx = rand() % BENCH_CACHE_SIZE;
        char key[32];
        snprintf(key, sizeof(key), "key_%d", idx);
        void *val = lru_cache_get(cache, key);
        (void)val;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("  Random reads: %.2f M ops/sec (%.3f seconds)\n", BENCH_ITERATIONS / time / 1e6, time);
    printf("  Cache hit rate: 100%% (all keys in cache)\n");

    free(values);
    lru_cache_free(cache);
}

static void *concurrent_read_worker(void *arg)
{
    bench_thread_context_t *ctx = (bench_thread_context_t *)arg;
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < ctx->iterations; i++)
    {
        int idx = (ctx->thread_id * 1000 + i) % BENCH_CACHE_SIZE;
        char key[32];
        snprintf(key, sizeof(key), "key_%d", idx);
        void *val = lru_cache_get(ctx->cache, key);
        (void)val;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    ctx->elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    return NULL;
}

static void benchmark_lru_concurrent_reads(void)
{
    printf(BOLDWHITE "\nBenchmark 3: Concurrent Read Performance (Lock-Free)\n" RESET);

    lru_cache_t *cache = lru_cache_new(BENCH_CACHE_SIZE);
    ASSERT_TRUE(cache != NULL);

    int *values = malloc(BENCH_CACHE_SIZE * sizeof(int));

    /* populate cache */
    for (int i = 0; i < BENCH_CACHE_SIZE; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        values[i] = i;
        lru_cache_put(cache, key, &values[i], NULL, NULL);
    }

    pthread_t threads[BENCH_THREADS];
    bench_thread_context_t contexts[BENCH_THREADS];
    int iterations_per_thread = BENCH_ITERATIONS / BENCH_THREADS;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < BENCH_THREADS; i++)
    {
        contexts[i].cache = cache;
        contexts[i].thread_id = i;
        contexts[i].iterations = iterations_per_thread;
        contexts[i].elapsed_time = 0;
        pthread_create(&threads[i], NULL, concurrent_read_worker, &contexts[i]);
    }

    for (int i = 0; i < BENCH_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double wall_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    double total_thread_time = 0;
    for (int i = 0; i < BENCH_THREADS; i++)
    {
        total_thread_time += contexts[i].elapsed_time;
    }
    double avg_thread_time = total_thread_time / BENCH_THREADS;

    printf("  Threads: %d\n", BENCH_THREADS);
    printf("  Wall time: %.3f seconds\n", wall_time);
    printf("  Aggregate throughput: %.2f M ops/sec\n", BENCH_ITERATIONS / wall_time / 1e6);
    printf("  Average thread time: %.3f seconds\n", avg_thread_time);
    printf("  Speedup vs sequential: %.2fx\n", avg_thread_time / wall_time * BENCH_THREADS);
    printf("  Per-thread throughput: %.2f M ops/sec\n",
           iterations_per_thread / avg_thread_time / 1e6);

    free(values);
    lru_cache_free(cache);
}

static void *mixed_workload_worker(void *arg)
{
    bench_thread_context_t *ctx = (bench_thread_context_t *)arg;
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < ctx->iterations; i++)
    {
        int idx = (ctx->thread_id * 1000 + i) % BENCH_CACHE_SIZE;
        char key[32];
        snprintf(key, sizeof(key), "key_%d", idx);

        /* 80% reads, 20% writes */
        if (i % 5 == 0)
        {
            static int dummy = 0;
            lru_cache_put(ctx->cache, key, &dummy, NULL, NULL);
        }
        else
        {
            void *val = lru_cache_get(ctx->cache, key);
            (void)val;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    ctx->elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    return NULL;
}

static void benchmark_lru_mixed_workload(void)
{
    printf(BOLDWHITE "\nBenchmark 4: Mixed Workload (80%% Read, 20%% Write) - Lock-Free\n" RESET);

    lru_cache_t *cache = lru_cache_new(BENCH_CACHE_SIZE);
    ASSERT_TRUE(cache != NULL);

    int *values = malloc(BENCH_CACHE_SIZE * sizeof(int));

    /* populate cache */
    for (int i = 0; i < BENCH_CACHE_SIZE; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        values[i] = i;
        lru_cache_put(cache, key, &values[i], NULL, NULL);
    }

    pthread_t threads[BENCH_THREADS];
    bench_thread_context_t contexts[BENCH_THREADS];
    int iterations_per_thread = BENCH_ITERATIONS / BENCH_THREADS;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* spawn worker threads */
    for (int i = 0; i < BENCH_THREADS; i++)
    {
        contexts[i].cache = cache;
        contexts[i].thread_id = i;
        contexts[i].iterations = iterations_per_thread;
        contexts[i].elapsed_time = 0;
        pthread_create(&threads[i], NULL, mixed_workload_worker, &contexts[i]);
    }

    for (int i = 0; i < BENCH_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double wall_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    double total_thread_time = 0;
    for (int i = 0; i < BENCH_THREADS; i++)
    {
        total_thread_time += contexts[i].elapsed_time;
    }
    double avg_thread_time = total_thread_time / BENCH_THREADS;

    printf("  Threads: %d\n", BENCH_THREADS);
    printf("  Wall time: %.3f seconds\n", wall_time);
    printf("  Aggregate throughput: %.2f M ops/sec\n", BENCH_ITERATIONS / wall_time / 1e6);
    printf("  Average thread time: %.3f seconds\n", avg_thread_time);
    printf("  Speedup vs sequential: %.2fx\n", avg_thread_time / wall_time * BENCH_THREADS);

    free(values);
    lru_cache_free(cache);
}

int main(void)
{
    RUN_TEST(test_lru_cache_new_free, tests_passed);
    RUN_TEST(test_lru_cache_put_get, tests_passed);
    RUN_TEST(test_lru_cache_eviction, tests_passed);
    RUN_TEST(test_lru_cache_get_updates_order, tests_passed);
    RUN_TEST(test_lru_cache_update, tests_passed);
    RUN_TEST(test_lru_cache_update_refreshes_access, tests_passed);
    RUN_TEST(test_lru_cache_remove, tests_passed);
    RUN_TEST(test_lru_cache_clear, tests_passed);
    RUN_TEST(test_lru_cache_with_malloc, tests_passed);
    RUN_TEST(test_lru_cache_foreach, tests_passed);
    RUN_TEST(test_lru_cache_concurrent, tests_passed);
    RUN_TEST(test_lru_cache_edge_cases, tests_passed);
    RUN_TEST(test_lru_cache_destroy_vs_free, tests_passed);
    RUN_TEST(test_lru_cache_zero_capacity, tests_passed);
    RUN_TEST(test_lru_cache_long_keys, tests_passed);
    RUN_TEST(test_lru_cache_empty_key, tests_passed);
    RUN_TEST(test_lru_cache_hash_collisions, tests_passed);
    RUN_TEST(test_lru_cache_free_null, tests_passed);
    RUN_TEST(test_lru_cache_race_condition, tests_passed);
    RUN_TEST(test_lru_cache_put_return_values, tests_passed);
    RUN_TEST(test_lru_cache_access_pattern, tests_passed);
    RUN_TEST(test_lru_cache_get_copy, tests_passed);

    benchmark_lru_sequential();
    benchmark_lru_random_access();
    benchmark_lru_concurrent_reads();
    benchmark_lru_mixed_workload();

    PRINT_TEST_RESULTS(tests_passed, tests_failed);

    return 0;
}