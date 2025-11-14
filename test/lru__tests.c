/*
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
static int eviction_count = 0;
static char last_evicted_key[256] = {0};

/* simple eviction callback for testing */
static void test_evict_callback(const char *key, void *value, void *user_data)
{
    eviction_count++;
    strncpy(last_evicted_key, key, sizeof(last_evicted_key) - 1);
    (void)value;
    (void)user_data;
}

/* eviction callback that frees allocated memory */
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
    eviction_count = 0;
    memset(last_evicted_key, 0, sizeof(last_evicted_key));

    lru_cache_t *cache = lru_cache_new(3);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3, v4 = 4;

    ASSERT_EQ(lru_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    ASSERT_EQ(lru_cache_size(cache), 3);
    ASSERT_EQ(eviction_count, 0);

    /* adding 4th item should evict key1 (least recently used) */
    ASSERT_EQ(lru_cache_put(cache, "key4", &v4, test_evict_callback, NULL), 0);

    ASSERT_EQ(lru_cache_size(cache), 3);
    ASSERT_EQ(eviction_count, 1);
    ASSERT_TRUE(strcmp(last_evicted_key, "key1") == 0);

    /* key1 should be gone */
    ASSERT_TRUE(lru_cache_get(cache, "key1") == NULL);

    /* key2, key3, key4 should still exist */
    ASSERT_TRUE(lru_cache_get(cache, "key2") != NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key3") != NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key4") != NULL);

    lru_cache_free(cache);
}

static void test_lru_cache_get_updates_order(void)
{
    eviction_count = 0;
    memset(last_evicted_key, 0, sizeof(last_evicted_key));

    lru_cache_t *cache = lru_cache_new(3);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3, v4 = 4;

    ASSERT_EQ(lru_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    /* access key1, making it most recently used */
    ASSERT_TRUE(lru_cache_get(cache, "key1") != NULL);

    /* now key2 is least recently used */
    ASSERT_EQ(lru_cache_put(cache, "key4", &v4, test_evict_callback, NULL), 0);

    ASSERT_EQ(eviction_count, 1);
    ASSERT_TRUE(strcmp(last_evicted_key, "key2") == 0);

    /* key1 should still exist */
    ASSERT_TRUE(lru_cache_get(cache, "key1") != NULL);

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

    /* update the value */
    ASSERT_EQ(lru_cache_put(cache, "key1", &v2, NULL, NULL), 0);
    ASSERT_EQ(lru_cache_size(cache), 1); /* size should not change */

    retrieved = (int *)lru_cache_get(cache, "key1");
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(*retrieved, 200);

    lru_cache_free(cache);
}

static void test_lru_cache_remove(void)
{
    eviction_count = 0;

    lru_cache_t *cache = lru_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3;

    ASSERT_EQ(lru_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    ASSERT_EQ(lru_cache_size(cache), 3);

    ASSERT_EQ(lru_cache_remove(cache, "key2"), 0);
    ASSERT_EQ(lru_cache_size(cache), 2);
    ASSERT_EQ(eviction_count, 1); /* callback should be called */

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
    eviction_count = 0;

    lru_cache_t *cache = lru_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3;

    ASSERT_EQ(lru_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(lru_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    ASSERT_EQ(lru_cache_size(cache), 3);

    lru_cache_clear(cache);

    ASSERT_EQ(lru_cache_size(cache), 0);
    ASSERT_EQ(eviction_count, 3); /* all callbacks should be called */

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

    /* this should evict key1 and free v1 */
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
        *value = targ->thread_id * 1000 + i;

        lru_cache_put(targ->cache, key, value, free_evict_callback, NULL);
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
    eviction_count = 0;

    lru_cache_t *cache1 = lru_cache_new(3);
    int v1 = 1, v2 = 2;
    lru_cache_put(cache1, "key1", &v1, test_evict_callback, NULL);
    lru_cache_put(cache1, "key2", &v2, test_evict_callback, NULL);

    /* destroy should NOT call callbacks */
    lru_cache_destroy(cache1);
    ASSERT_EQ(eviction_count, 0);

    /* free SHOULD call callbacks */
    eviction_count = 0;
    lru_cache_t *cache2 = lru_cache_new(3);
    lru_cache_put(cache2, "key1", &v1, test_evict_callback, NULL);
    lru_cache_put(cache2, "key2", &v2, test_evict_callback, NULL);
    lru_cache_free(cache2);
    ASSERT_EQ(eviction_count, 2);

    printf(GREEN "test_lru_cache_destroy_vs_free passed\n" RESET);
}

void test_lru_cache_zero_capacity()
{
    lru_cache_t *cache = lru_cache_new(0);
    if (cache)
    {
        ASSERT_EQ(lru_cache_capacity(cache), 0);
        int v = 1;
        /* should fail to add */
        ASSERT_EQ(lru_cache_put(cache, "key", &v, NULL, NULL), -1);
        lru_cache_free(cache);
    }
    printf(GREEN "test_lru_cache_zero_capacity passed\n" RESET);
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
    printf(GREEN "test_lru_cache_long_keys passed\n" RESET);
}

void test_lru_cache_empty_key()
{
    lru_cache_t *cache = lru_cache_new(5);

    int v = 1;
    ASSERT_EQ(lru_cache_put(cache, "", &v, NULL, NULL), 0);
    ASSERT_TRUE(lru_cache_get(cache, "") == &v);

    lru_cache_free(cache);
    printf(GREEN "test_lru_cache_empty_key passed\n" RESET);
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
    printf(GREEN "test_lru_cache_hash_collisions passed\n" RESET);
}

void test_lru_cache_free_null()
{
    lru_cache_free(NULL);
    lru_cache_destroy(NULL);
    lru_cache_clear(NULL);
    printf(GREEN "test_lru_cache_free_null passed\n" RESET);
}

int main(void)
{
    RUN_TEST(test_lru_cache_new_free, tests_passed);
    RUN_TEST(test_lru_cache_put_get, tests_passed);
    RUN_TEST(test_lru_cache_eviction, tests_passed);
    RUN_TEST(test_lru_cache_get_updates_order, tests_passed);
    RUN_TEST(test_lru_cache_update, tests_passed);
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
    PRINT_TEST_RESULTS(tests_passed, tests_failed);

    return 0;
}
