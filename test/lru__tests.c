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

typedef struct
{
    int value;
    int freed;
} test_data_t;

static void test_evict_callback(const char *key, void *value, void *user_data)
{
    (void)key;
    (void)value;
    int *evict_count = (int *)user_data;
    if (evict_count) (*evict_count)++;
}

void test_lru_cache_new(void)
{
    lru_cache_t *cache = lru_cache_new(10, 5, 3, 0);
    ASSERT_TRUE(cache != NULL);
    ASSERT_EQ(lru_cache_size(cache), 0);
    ASSERT_EQ(lru_cache_capacity(cache), 15);
    lru_cache_free(cache);

    cache = lru_cache_new(0, 5, 3, 0);
    ASSERT_TRUE(cache == NULL);
}

void test_lru_cache_put_get(void)
{
    lru_cache_t *cache = lru_cache_new(5, 0, 3, 0);
    ASSERT_TRUE(cache != NULL);

    int data1 = 100;
    int data2 = 200;
    int data3 = 300;

    ASSERT_EQ(lru_cache_put(cache, "key1", &data1, NULL, NULL), 0);
    ASSERT_EQ(lru_cache_size(cache), 1);

    ASSERT_EQ(lru_cache_put(cache, "key2", &data2, NULL, NULL), 0);
    ASSERT_EQ(lru_cache_size(cache), 2);

    ASSERT_EQ(lru_cache_put(cache, "key3", &data3, NULL, NULL), 0);
    ASSERT_EQ(lru_cache_size(cache), 3);

    int *result1 = (int *)lru_cache_get(cache, "key1");
    ASSERT_TRUE(result1 != NULL);
    ASSERT_EQ(*result1, 100);

    int *result2 = (int *)lru_cache_get(cache, "key2");
    ASSERT_TRUE(result2 != NULL);
    ASSERT_EQ(*result2, 200);

    int *result3 = (int *)lru_cache_get(cache, "key3");
    ASSERT_TRUE(result3 != NULL);
    ASSERT_EQ(*result3, 300);

    ASSERT_TRUE(lru_cache_get(cache, "nonexistent") == NULL);

    lru_cache_free(cache);
}

void test_lru_cache_update(void)
{
    lru_cache_t *cache = lru_cache_new(5, 0, 3, 0);
    ASSERT_TRUE(cache != NULL);

    int data1 = 100;
    int data2 = 200;
    int evict_count = 0;

    ASSERT_EQ(lru_cache_put(cache, "key1", &data1, test_evict_callback, &evict_count), 0);

    ASSERT_EQ(lru_cache_put(cache, "key1", &data2, test_evict_callback, &evict_count), 1);
    ASSERT_EQ(evict_count, 1);
    ASSERT_EQ(lru_cache_size(cache), 1);

    int *result = (int *)lru_cache_get(cache, "key1");
    ASSERT_TRUE(result != NULL);
    ASSERT_EQ(*result, 200);

    lru_cache_free(cache);
}

void test_lru_eviction(void)
{
    lru_cache_t *cache = lru_cache_new(3, 0, 10, 0);
    ASSERT_TRUE(cache != NULL);

    int data[5] = {1, 2, 3, 4, 5};
    int evict_count = 0;

    lru_cache_put(cache, "key1", &data[0], test_evict_callback, &evict_count);
    lru_cache_put(cache, "key2", &data[1], test_evict_callback, &evict_count);
    lru_cache_put(cache, "key3", &data[2], test_evict_callback, &evict_count);
    ASSERT_EQ(lru_cache_size(cache), 3);
    ASSERT_EQ(evict_count, 0);

    lru_cache_put(cache, "key4", &data[3], test_evict_callback, &evict_count);
    ASSERT_EQ(lru_cache_size(cache), 3);
    ASSERT_EQ(evict_count, 1);

    ASSERT_TRUE(lru_cache_get(cache, "key1") == NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key2") != NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key3") != NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key4") != NULL);

    lru_cache_put(cache, "key5", &data[4], test_evict_callback, &evict_count);
    ASSERT_EQ(evict_count, 2);
    ASSERT_TRUE(lru_cache_get(cache, "key2") == NULL);

    lru_cache_free(cache);
}

void test_lru_to_lfu_promotion(void)
{
    lru_cache_t *cache = lru_cache_new(3, 2, 3, 0);
    ASSERT_TRUE(cache != NULL);

    int data1 = 100;
    lru_cache_put(cache, "hot_key", &data1, NULL, NULL);

    size_t lru_size, lfu_size;
    uint64_t hits, misses;

    lru_cache_stats(cache, &lru_size, &lfu_size, &hits, &misses);
    ASSERT_EQ(lru_size, 1);
    ASSERT_EQ(lfu_size, 0);

    lru_cache_get(cache, "hot_key"); /* access_count = 2 */
    lru_cache_get(cache, "hot_key"); /* access_count = 3, should promote */

    lru_cache_stats(cache, &lru_size, &lfu_size, &hits, &misses);
    ASSERT_EQ(lru_size, 0);
    ASSERT_EQ(lfu_size, 1);

    int *result = (int *)lru_cache_get(cache, "hot_key");
    ASSERT_TRUE(result != NULL);
    ASSERT_EQ(*result, 100);

    lru_cache_free(cache);
}

void test_lfu_eviction(void)
{
    lru_cache_t *cache = lru_cache_new(5, 2, 2, 0);
    ASSERT_TRUE(cache != NULL);

    int data[5] = {1, 2, 3, 4, 5};
    int evict_count = 0;

    lru_cache_put(cache, "key1", &data[0], test_evict_callback, &evict_count);
    lru_cache_get(cache, "key1"); /* promote to LFU */

    lru_cache_put(cache, "key2", &data[1], test_evict_callback, &evict_count);
    lru_cache_get(cache, "key2"); /* promote to LFU */

    size_t lru_size, lfu_size;
    lru_cache_stats(cache, &lru_size, &lfu_size, NULL, NULL);
    ASSERT_EQ(lfu_size, 2);

    lru_cache_put(cache, "key3", &data[2], test_evict_callback, &evict_count);
    lru_cache_get(cache, "key3"); /* promote to LFU */

    lru_cache_stats(cache, &lru_size, &lfu_size, NULL, NULL);
    ASSERT_EQ(lfu_size, 2);
    ASSERT_EQ(evict_count, 1);

    lru_cache_free(cache);
}

void test_lru_cache_remove(void)
{
    lru_cache_t *cache = lru_cache_new(5, 0, 3, 0);
    ASSERT_TRUE(cache != NULL);

    int data1 = 100;
    int data2 = 200;
    int evict_count = 0;

    lru_cache_put(cache, "key1", &data1, test_evict_callback, &evict_count);
    lru_cache_put(cache, "key2", &data2, test_evict_callback, &evict_count);
    ASSERT_EQ(lru_cache_size(cache), 2);

    ASSERT_EQ(lru_cache_remove(cache, "key1"), 0);
    ASSERT_EQ(lru_cache_size(cache), 1);
    ASSERT_EQ(evict_count, 1);
    ASSERT_TRUE(lru_cache_get(cache, "key1") == NULL);

    ASSERT_EQ(lru_cache_remove(cache, "nonexistent"), -1);
    ASSERT_EQ(lru_cache_size(cache), 1);

    lru_cache_free(cache);
}

void test_lru_cache_clear(void)
{
    lru_cache_t *cache = lru_cache_new(5, 3, 2, 0);
    ASSERT_TRUE(cache != NULL);

    int data[5] = {1, 2, 3, 4, 5};
    int evict_count = 0;

    lru_cache_put(cache, "key1", &data[0], test_evict_callback, &evict_count);
    lru_cache_put(cache, "key2", &data[1], test_evict_callback, &evict_count);
    lru_cache_put(cache, "key3", &data[2], test_evict_callback, &evict_count);

    lru_cache_get(cache, "key1");
    lru_cache_get(cache, "key1");

    ASSERT_TRUE(lru_cache_size(cache) > 0);

    lru_cache_clear(cache);
    ASSERT_EQ(lru_cache_size(cache), 0);

    size_t lru_size, lfu_size;
    lru_cache_stats(cache, &lru_size, &lfu_size, NULL, NULL);
    ASSERT_EQ(lru_size, 0);
    ASSERT_EQ(lfu_size, 0);

    ASSERT_TRUE(lru_cache_get(cache, "key1") == NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key2") == NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key3") == NULL);

    lru_cache_free(cache);
}

void test_lru_cache_stats(void)
{
    lru_cache_t *cache = lru_cache_new(5, 3, 2, 0);
    ASSERT_TRUE(cache != NULL);

    size_t lru_size, lfu_size;
    uint64_t hits, misses;

    lru_cache_stats(cache, &lru_size, &lfu_size, &hits, &misses);
    ASSERT_EQ(lru_size, 0);
    ASSERT_EQ(lfu_size, 0);
    ASSERT_EQ(hits, 0);
    ASSERT_EQ(misses, 0);

    int data1 = 100;
    lru_cache_put(cache, "key1", &data1, NULL, NULL);

    lru_cache_get(cache, "key1");
    lru_cache_stats(cache, &lru_size, &lfu_size, &hits, &misses);
    ASSERT_EQ(hits, 1);
    ASSERT_EQ(misses, 0);

    lru_cache_get(cache, "nonexistent");
    lru_cache_stats(cache, &lru_size, &lfu_size, &hits, &misses);
    ASSERT_EQ(hits, 1);
    ASSERT_EQ(misses, 1);

    lru_cache_free(cache);
}

void test_lru_cache_ttl(void)
{
    lru_cache_t *cache = lru_cache_new(5, 3, 2, 2);
    ASSERT_TRUE(cache != NULL);

    int data1 = 100;
    lru_cache_put(cache, "key1", &data1, NULL, NULL);

    lru_cache_get(cache, "key1");
    lru_cache_get(cache, "key1");

    size_t lru_size, lfu_size;
    lru_cache_stats(cache, &lru_size, &lfu_size, NULL, NULL);
    ASSERT_EQ(lfu_size, 1);

    ASSERT_TRUE(lru_cache_get(cache, "key1") != NULL);

    sleep(3);

    int data2 = 200;
    lru_cache_put(cache, "key2", &data2, NULL, NULL);
    lru_cache_get(cache, "key2");

    ASSERT_TRUE(lru_cache_get(cache, "key1") == NULL);

    lru_cache_free(cache);
}

static void *test_copy_fn(void *value)
{
    int *original = (int *)value;
    int *copy = malloc(sizeof(int));
    if (copy) *copy = *original;
    return copy;
}

void test_lru_cache_get_copy(void)
{
    lru_cache_t *cache = lru_cache_new(5, 0, 3, 0);
    ASSERT_TRUE(cache != NULL);

    int data1 = 100;
    lru_cache_put(cache, "key1", &data1, NULL, NULL);

    int *copy = (int *)lru_cache_get_copy(cache, "key1", test_copy_fn);
    ASSERT_TRUE(copy != NULL);
    ASSERT_EQ(*copy, 100);
    ASSERT_TRUE(copy != &data1);
    free(copy);

    copy = (int *)lru_cache_get_copy(cache, "nonexistent", test_copy_fn);
    ASSERT_TRUE(copy == NULL);

    lru_cache_free(cache);
}

typedef struct
{
    int count;
    int sum;
} foreach_ctx_t;

static int test_count_callback(const char *key, void *value, void *user_data)
{
    (void)key;
    foreach_ctx_t *ctx = (foreach_ctx_t *)user_data;
    ctx->count++;
    ctx->sum += *(int *)value;
    return 0;
}

void test_lru_cache_foreach(void)
{
    lru_cache_t *cache = lru_cache_new(5, 3, 2, 0);
    ASSERT_TRUE(cache != NULL);

    int data[5] = {10, 20, 30, 40, 50};

    lru_cache_put(cache, "key1", &data[0], NULL, NULL);
    lru_cache_put(cache, "key2", &data[1], NULL, NULL);
    lru_cache_put(cache, "key3", &data[2], NULL, NULL);

    lru_cache_get(cache, "key1");
    lru_cache_get(cache, "key1");

    foreach_ctx_t ctx = {0, 0};
    size_t visited = lru_cache_foreach(cache, test_count_callback, &ctx);
    ASSERT_EQ(visited, 3);
    ASSERT_EQ(ctx.count, 3);
    ASSERT_EQ(ctx.sum, 60); /* 10 + 20 + 30 */

    lru_cache_free(cache);
}

static int test_stop_callback(const char *key, void *value, void *user_data)
{
    (void)key;
    (void)value;
    int *count = (int *)user_data;
    (*count)++;
    return (*count >= 2) ? 1 : 0;
}

void test_lru_cache_foreach_early_stop(void)
{
    lru_cache_t *cache = lru_cache_new(5, 0, 3, 0);
    ASSERT_TRUE(cache != NULL);

    int data[5] = {1, 2, 3, 4, 5};
    lru_cache_put(cache, "key1", &data[0], NULL, NULL);
    lru_cache_put(cache, "key2", &data[1], NULL, NULL);
    lru_cache_put(cache, "key3", &data[2], NULL, NULL);

    int count = 0;
    size_t visited = lru_cache_foreach(cache, test_stop_callback, &count);
    ASSERT_EQ(visited, 2);
    ASSERT_EQ(count, 2);

    lru_cache_free(cache);
}

void test_lru_cache_null_handling(void)
{
    ASSERT_EQ(lru_cache_put(NULL, "key", NULL, NULL, NULL), -1);
    ASSERT_TRUE(lru_cache_get(NULL, "key") == NULL);
    ASSERT_TRUE(lru_cache_get_copy(NULL, "key", NULL) == NULL);
    ASSERT_EQ(lru_cache_remove(NULL, "key"), -1);
    ASSERT_EQ(lru_cache_size(NULL), 0);
    ASSERT_EQ(lru_cache_capacity(NULL), 0);
    ASSERT_EQ(lru_cache_foreach(NULL, NULL, NULL), 0);
    lru_cache_clear(NULL);
    lru_cache_free(NULL);
    lru_cache_destroy(NULL);
    lru_cache_stats(NULL, NULL, NULL, NULL, NULL);

    lru_cache_t *cache = lru_cache_new(5, 0, 3, 0);
    ASSERT_TRUE(cache != NULL);
    ASSERT_EQ(lru_cache_put(cache, NULL, NULL, NULL, NULL), -1);
    ASSERT_TRUE(lru_cache_get(cache, NULL) == NULL);
    ASSERT_EQ(lru_cache_remove(cache, NULL), -1);
    lru_cache_free(cache);
}

void test_lru_cache_destroy_no_callbacks(void)
{
    lru_cache_t *cache = lru_cache_new(5, 0, 3, 0);
    ASSERT_TRUE(cache != NULL);

    int data[3] = {1, 2, 3};
    int evict_count = 0;

    lru_cache_put(cache, "key1", &data[0], test_evict_callback, &evict_count);
    lru_cache_put(cache, "key2", &data[1], test_evict_callback, &evict_count);
    lru_cache_put(cache, "key3", &data[2], test_evict_callback, &evict_count);

    lru_cache_destroy(cache);

    ASSERT_EQ(evict_count, 0);
}

void test_lru_cache_large_volume(void)
{
    lru_cache_t *cache = lru_cache_new(1000, 500, 5, 0);
    ASSERT_TRUE(cache != NULL);

    int *data = malloc(2000 * sizeof(int));
    ASSERT_TRUE(data != NULL);

    for (int i = 0; i < 2000; i++)
    {
        data[i] = i;
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        lru_cache_put(cache, key, &data[i], NULL, NULL);
    }

    /* should be at LRU capacity (entries not promoted without multiple accesses) */
    ASSERT_EQ(lru_cache_size(cache), 1000);

    /* recent entries should be present */
    for (int i = 1000; i < 2000; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        int *result = (int *)lru_cache_get(cache, key);
        ASSERT_TRUE(result != NULL);
        ASSERT_EQ(*result, i);
    }

    free(data);
    lru_cache_free(cache);
}

void test_lru_cache_string_keys(void)
{
    lru_cache_t *cache = lru_cache_new(5, 0, 3, 0);
    ASSERT_TRUE(cache != NULL);

    char *str1 = "value1";
    char *str2 = "value2";
    char *str3 = "value3";

    lru_cache_put(cache, "first", str1, NULL, NULL);
    lru_cache_put(cache, "second", str2, NULL, NULL);
    lru_cache_put(cache, "third", str3, NULL, NULL);

    char *result1 = (char *)lru_cache_get(cache, "first");
    ASSERT_TRUE(result1 != NULL);
    ASSERT_TRUE(strcmp(result1, "value1") == 0);

    char *result2 = (char *)lru_cache_get(cache, "second");
    ASSERT_TRUE(result2 != NULL);
    ASSERT_TRUE(strcmp(result2, "value2") == 0);

    lru_cache_free(cache);
}

void test_lru_cache_access_pattern(void)
{
    lru_cache_t *cache = lru_cache_new(3, 0, 10, 0);
    ASSERT_TRUE(cache != NULL);

    int data[4] = {1, 2, 3, 4};

    lru_cache_put(cache, "key1", &data[0], NULL, NULL);
    lru_cache_put(cache, "key2", &data[1], NULL, NULL);
    lru_cache_put(cache, "key3", &data[2], NULL, NULL);

    /* access key1 multiple times to trigger adaptive reordering
     * (reordering happens every 16 accesses for performance) */
    for (int i = 0; i < 16; i++)
    {
        lru_cache_get(cache, "key1");
    }

    /* now key1 should be at front, so key2 (LRU) should be evicted */
    lru_cache_put(cache, "key4", &data[3], NULL, NULL);

    ASSERT_TRUE(lru_cache_get(cache, "key1") != NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key2") == NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key3") != NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key4") != NULL);

    lru_cache_free(cache);
}

void test_lru_cache_promotion_threshold(void)
{
    lru_cache_t *cache = lru_cache_new(5, 3, 5, 0);
    ASSERT_TRUE(cache != NULL);

    int data1 = 100;
    lru_cache_put(cache, "key1", &data1, NULL, NULL);

    size_t lru_size, lfu_size;

    for (int i = 0; i < 3; i++)
    {
        lru_cache_get(cache, "key1");
    }

    lru_cache_stats(cache, &lru_size, &lfu_size, NULL, NULL);
    ASSERT_EQ(lru_size, 1);
    ASSERT_EQ(lfu_size, 0);

    lru_cache_get(cache, "key1");

    lru_cache_stats(cache, &lru_size, &lfu_size, NULL, NULL);
    ASSERT_EQ(lru_size, 0);
    ASSERT_EQ(lfu_size, 1);

    lru_cache_free(cache);
}

void test_lru_cache_no_lfu(void)
{
    lru_cache_t *cache = lru_cache_new(5, 0, 2, 0);
    ASSERT_TRUE(cache != NULL);

    int data1 = 100;
    lru_cache_put(cache, "key1", &data1, NULL, NULL);

    lru_cache_get(cache, "key1");
    lru_cache_get(cache, "key1");
    lru_cache_get(cache, "key1");

    size_t lru_size, lfu_size;
    lru_cache_stats(cache, &lru_size, &lfu_size, NULL, NULL);
    ASSERT_EQ(lru_size, 1);
    ASSERT_EQ(lfu_size, 0);

    lru_cache_free(cache);
}

void test_lru_cache_empty_key(void)
{
    lru_cache_t *cache = lru_cache_new(5, 0, 3, 0);
    ASSERT_TRUE(cache != NULL);

    int data1 = 100;

    ASSERT_EQ(lru_cache_put(cache, "", &data1, NULL, NULL), 0);
    int *result = (int *)lru_cache_get(cache, "");
    ASSERT_TRUE(result != NULL);
    ASSERT_EQ(*result, 100);

    lru_cache_free(cache);
}

void test_lru_cache_collision_keys(void)
{
    lru_cache_t *cache = lru_cache_new(10, 0, 3, 0);
    ASSERT_TRUE(cache != NULL);

    int data[10];
    for (int i = 0; i < 10; i++)
    {
        data[i] = i * 10;
        char key[32];
        snprintf(key, sizeof(key), "key%d", i);
        lru_cache_put(cache, key, &data[i], NULL, NULL);
    }

    for (int i = 0; i < 10; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%d", i);
        int *result = (int *)lru_cache_get(cache, key);
        ASSERT_TRUE(result != NULL);
        ASSERT_EQ(*result, i * 10);
    }

    lru_cache_free(cache);
}

void test_lru_cache_mixed_operations(void)
{
    lru_cache_t *cache = lru_cache_new(5, 3, 2, 0);
    ASSERT_TRUE(cache != NULL);

    int data[10];
    for (int i = 0; i < 10; i++) data[i] = i;

    lru_cache_put(cache, "key1", &data[1], NULL, NULL);
    lru_cache_put(cache, "key2", &data[2], NULL, NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key1") != NULL);
    lru_cache_put(cache, "key3", &data[3], NULL, NULL);
    lru_cache_remove(cache, "key2");
    ASSERT_TRUE(lru_cache_get(cache, "key2") == NULL);
    lru_cache_put(cache, "key4", &data[4], NULL, NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key1") != NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key3") != NULL);
    ASSERT_TRUE(lru_cache_get(cache, "key4") != NULL);

    lru_cache_free(cache);
}

void benchmark_lru_cache_insertions(void)
{
    lru_cache_t *cache = lru_cache_new(10000, 5000, 5, 0);
    ASSERT_TRUE(cache != NULL);

    int *data = malloc(100000 * sizeof(int));
    ASSERT_TRUE(data != NULL);

    for (int i = 0; i < 100000; i++) data[i] = i;

    clock_t start = clock();
    for (int i = 0; i < 100000; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        lru_cache_put(cache, key, &data[i], NULL, NULL);
    }
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "Inserting 100,000 entries took %f seconds\n" RESET, time_spent);
    printf(BOLDWHITE "Final cache size: %zu\n" RESET, lru_cache_size(cache));

    free(data);
    lru_cache_free(cache);
}

void benchmark_lru_cache_lookups(void)
{
    lru_cache_t *cache = lru_cache_new(50000, 0, 10, 0);
    ASSERT_TRUE(cache != NULL);

    int *data = malloc(50000 * sizeof(int));
    ASSERT_TRUE(data != NULL);

    for (int i = 0; i < 50000; i++)
    {
        data[i] = i;
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        lru_cache_put(cache, key, &data[i], NULL, NULL);
    }

    /* Benchmark lookups */
    clock_t start = clock();
    for (int i = 0; i < 100000; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i % 50000);
        lru_cache_get(cache, key);
    }
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "100,000 lookups took %f seconds\n" RESET, time_spent);

    size_t lru_size, lfu_size;
    uint64_t hits, misses;
    lru_cache_stats(cache, &lru_size, &lfu_size, &hits, &misses);
    printf(BOLDWHITE "Hits: %" PRIu64 ", Misses: %" PRIu64 ", Hit rate: %.2f%%\n" RESET, hits,
           misses, (double)hits / (hits + misses) * 100.0);

    free(data);
    lru_cache_free(cache);
}

void benchmark_lru_lfu_promotion(void)
{
    lru_cache_t *cache = lru_cache_new(10000, 5000, 3, 0);
    ASSERT_TRUE(cache != NULL);

    int *data = malloc(20000 * sizeof(int));
    ASSERT_TRUE(data != NULL);

    for (int i = 0; i < 20000; i++) data[i] = i;

    for (int i = 0; i < 20000; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        lru_cache_put(cache, key, &data[i], NULL, NULL);
    }

    /* access hot entries to trigger promotions */
    clock_t start = clock();
    for (int j = 0; j < 5; j++)
    {
        for (int i = 10000; i < 15000; i++) /* access subset multiple times */
        {
            char key[32];
            snprintf(key, sizeof(key), "key_%d", i);
            lru_cache_get(cache, key);
        }
    }
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "Promotion benchmark took %f seconds\n" RESET, time_spent);

    size_t lru_size, lfu_size;
    uint64_t hits, misses;
    lru_cache_stats(cache, &lru_size, &lfu_size, &hits, &misses);
    printf(BOLDWHITE "LRU size: %zu, LFU size: %zu\n" RESET, lru_size, lfu_size);
    printf(BOLDWHITE "Hits: %" PRIu64 ", Misses: %" PRIu64 "\n" RESET, hits, misses);

    free(data);
    lru_cache_free(cache);
}

int main(void)
{
    RUN_TEST(test_lru_cache_new, tests_passed);
    RUN_TEST(test_lru_cache_put_get, tests_passed);
    RUN_TEST(test_lru_cache_update, tests_passed);
    RUN_TEST(test_lru_eviction, tests_passed);
    RUN_TEST(test_lru_to_lfu_promotion, tests_passed);
    RUN_TEST(test_lfu_eviction, tests_passed);
    RUN_TEST(test_lru_cache_remove, tests_passed);
    RUN_TEST(test_lru_cache_clear, tests_passed);
    RUN_TEST(test_lru_cache_stats, tests_passed);
    RUN_TEST(test_lru_cache_ttl, tests_passed);
    RUN_TEST(test_lru_cache_get_copy, tests_passed);
    RUN_TEST(test_lru_cache_foreach, tests_passed);
    RUN_TEST(test_lru_cache_foreach_early_stop, tests_passed);
    RUN_TEST(test_lru_cache_null_handling, tests_passed);
    RUN_TEST(test_lru_cache_destroy_no_callbacks, tests_passed);
    RUN_TEST(test_lru_cache_large_volume, tests_passed);
    RUN_TEST(test_lru_cache_string_keys, tests_passed);
    RUN_TEST(test_lru_cache_access_pattern, tests_passed);
    RUN_TEST(test_lru_cache_promotion_threshold, tests_passed);
    RUN_TEST(test_lru_cache_no_lfu, tests_passed);
    RUN_TEST(test_lru_cache_empty_key, tests_passed);
    RUN_TEST(test_lru_cache_collision_keys, tests_passed);
    RUN_TEST(test_lru_cache_mixed_operations, tests_passed);
    RUN_TEST(benchmark_lru_cache_insertions, tests_passed);
    RUN_TEST(benchmark_lru_cache_lookups, tests_passed);
    RUN_TEST(benchmark_lru_lfu_promotion, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
