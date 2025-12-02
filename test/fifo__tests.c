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
#include "../src/fifo.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* global counters */
static int eviction_count = 0;
static char last_evicted_key[256] = {0};

static void test_evict_callback(const char *key, void *value, void *user_data)
{
    eviction_count++;
    strncpy(last_evicted_key, key, sizeof(last_evicted_key) - 1);
    (void)value;
    (void)user_data;
}

static void free_evict_callback(const char *key, void *value, void *user_data)
{
    (void)key;
    (void)user_data;
    if (value) free(value);
}

static void test_fifo_cache_new_free(void)
{
    fifo_cache_t *cache = fifo_cache_new(10);
    ASSERT_TRUE(cache != NULL);
    ASSERT_EQ(fifo_cache_capacity(cache), 10);
    ASSERT_EQ(fifo_cache_size(cache), 0);
    fifo_cache_free(cache);
}

static void test_fifo_cache_put_get(void)
{
    fifo_cache_t *cache = fifo_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int value1 = 100;
    int value2 = 200;
    int value3 = 300;

    ASSERT_EQ(fifo_cache_put(cache, "key1", &value1, NULL, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key2", &value2, NULL, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key3", &value3, NULL, NULL), 0);

    ASSERT_EQ(fifo_cache_size(cache), 3);

    int *retrieved1 = (int *)fifo_cache_get(cache, "key1");
    ASSERT_TRUE(retrieved1 != NULL);
    ASSERT_EQ(*retrieved1, 100);

    int *retrieved2 = (int *)fifo_cache_get(cache, "key2");
    ASSERT_TRUE(retrieved2 != NULL);
    ASSERT_EQ(*retrieved2, 200);

    int *retrieved3 = (int *)fifo_cache_get(cache, "key3");
    ASSERT_TRUE(retrieved3 != NULL);
    ASSERT_EQ(*retrieved3, 300);

    void *not_found = fifo_cache_get(cache, "nonexistent");
    ASSERT_TRUE(not_found == NULL);

    fifo_cache_free(cache);
}

static void test_fifo_cache_eviction(void)
{
    eviction_count = 0;
    memset(last_evicted_key, 0, sizeof(last_evicted_key));

    fifo_cache_t *cache = fifo_cache_new(3);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3, v4 = 4;

    ASSERT_EQ(fifo_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    ASSERT_EQ(fifo_cache_size(cache), 3);
    ASSERT_EQ(eviction_count, 0);

    /* adding 4th item should evict key1 (least recently used) */
    ASSERT_EQ(fifo_cache_put(cache, "key4", &v4, test_evict_callback, NULL), 0);

    ASSERT_EQ(fifo_cache_size(cache), 3);
    ASSERT_EQ(eviction_count, 1);
    ASSERT_TRUE(strcmp(last_evicted_key, "key1") == 0);

    /* key1 should be gone */
    ASSERT_TRUE(fifo_cache_get(cache, "key1") == NULL);

    /* key2, key3, key4 should still exist */
    ASSERT_TRUE(fifo_cache_get(cache, "key2") != NULL);
    ASSERT_TRUE(fifo_cache_get(cache, "key3") != NULL);
    ASSERT_TRUE(fifo_cache_get(cache, "key4") != NULL);

    fifo_cache_free(cache);
}

static void test_fifo_cache_get_updates_order(void)
{
    eviction_count = 0;
    memset(last_evicted_key, 0, sizeof(last_evicted_key));

    fifo_cache_t *cache = fifo_cache_new(3);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3, v4 = 4;

    ASSERT_EQ(fifo_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    /* access key1 (with FIFO, this doesn't affect eviction order) */
    ASSERT_TRUE(fifo_cache_get(cache, "key1") != NULL);

    /* FIFO eviction key1 is oldest, so it gets evicted */
    ASSERT_EQ(fifo_cache_put(cache, "key4", &v4, test_evict_callback, NULL), 0);

    ASSERT_EQ(eviction_count, 1);
    ASSERT_TRUE(strcmp(last_evicted_key, "key1") == 0);

    /* key1 should be gone, key2 and key3 should still exist */
    ASSERT_TRUE(fifo_cache_get(cache, "key1") == NULL);
    ASSERT_TRUE(fifo_cache_get(cache, "key2") != NULL);
    ASSERT_TRUE(fifo_cache_get(cache, "key3") != NULL);

    fifo_cache_free(cache);
}

static void test_fifo_cache_update(void)
{
    fifo_cache_t *cache = fifo_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int v1 = 100;
    int v2 = 200;

    ASSERT_EQ(fifo_cache_put(cache, "key1", &v1, NULL, NULL), 0);
    ASSERT_EQ(fifo_cache_size(cache), 1);

    int *retrieved = (int *)fifo_cache_get(cache, "key1");
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(*retrieved, 100);

    ASSERT_EQ(fifo_cache_put(cache, "key1", &v2, NULL, NULL), 0);
    ASSERT_EQ(fifo_cache_size(cache), 1); /* size should not change */

    retrieved = (int *)fifo_cache_get(cache, "key1");
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(*retrieved, 200);

    fifo_cache_free(cache);
}

static void test_fifo_cache_remove(void)
{
    eviction_count = 0;

    fifo_cache_t *cache = fifo_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3;

    ASSERT_EQ(fifo_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    ASSERT_EQ(fifo_cache_size(cache), 3);

    ASSERT_EQ(fifo_cache_remove(cache, "key2"), 0);
    ASSERT_EQ(fifo_cache_size(cache), 2);
    ASSERT_EQ(eviction_count, 1); /* callback should be called */

    /* key2 should be gone */
    ASSERT_TRUE(fifo_cache_get(cache, "key2") == NULL);

    /* key1 and key3 should still exist */
    ASSERT_TRUE(fifo_cache_get(cache, "key1") != NULL);
    ASSERT_TRUE(fifo_cache_get(cache, "key3") != NULL);

    /* removing non-existent key should fail */
    ASSERT_EQ(fifo_cache_remove(cache, "nonexistent"), -1);

    fifo_cache_free(cache);
}

static void test_fifo_cache_clear(void)
{
    eviction_count = 0;

    fifo_cache_t *cache = fifo_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3;

    ASSERT_EQ(fifo_cache_put(cache, "key1", &v1, test_evict_callback, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key2", &v2, test_evict_callback, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key3", &v3, test_evict_callback, NULL), 0);

    ASSERT_EQ(fifo_cache_size(cache), 3);

    fifo_cache_clear(cache);

    ASSERT_EQ(fifo_cache_size(cache), 0);
    ASSERT_EQ(eviction_count, 3); /* all callbacks should be called */

    /* all keys should be gone */
    ASSERT_TRUE(fifo_cache_get(cache, "key1") == NULL);
    ASSERT_TRUE(fifo_cache_get(cache, "key2") == NULL);
    ASSERT_TRUE(fifo_cache_get(cache, "key3") == NULL);

    fifo_cache_free(cache);
}

static void test_fifo_cache_with_malloc(void)
{
    fifo_cache_t *cache = fifo_cache_new(3);
    ASSERT_TRUE(cache != NULL);

    int *v1 = (int *)malloc(sizeof(int));
    int *v2 = (int *)malloc(sizeof(int));
    int *v3 = (int *)malloc(sizeof(int));
    int *v4 = (int *)malloc(sizeof(int));

    *v1 = 100;
    *v2 = 200;
    *v3 = 300;
    *v4 = 400;

    ASSERT_EQ(fifo_cache_put(cache, "key1", v1, free_evict_callback, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key2", v2, free_evict_callback, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key3", v3, free_evict_callback, NULL), 0);

    /* this should evict key1 and free v1 */
    ASSERT_EQ(fifo_cache_put(cache, "key4", v4, free_evict_callback, NULL), 0);

    ASSERT_EQ(fifo_cache_size(cache), 3);

    fifo_cache_free(cache); /* should free remaining allocated memory */
}

typedef struct
{
    fifo_cache_t *cache;
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

        fifo_cache_put(targ->cache, key, value, free_evict_callback, NULL);
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

        void *value = fifo_cache_get(targ->cache, key);
        (void)value; /* may be NULL, that's ok */
    }

    return NULL;
}

static void test_fifo_cache_concurrent(void)
{
    fifo_cache_t *cache = fifo_cache_new(100);
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
    ASSERT_TRUE(fifo_cache_size(cache) <= 100);

    fifo_cache_free(cache);

#undef NUM_THREADS
#undef OPS_PER_THREAD
}

static void test_fifo_cache_edge_cases(void)
{
    fifo_cache_t *cache1 = fifo_cache_new(1);
    ASSERT_TRUE(cache1 != NULL);

    int v1 = 1, v2 = 2;
    ASSERT_EQ(fifo_cache_put(cache1, "key1", &v1, NULL, NULL), 0);
    ASSERT_EQ(fifo_cache_size(cache1), 1);

    ASSERT_EQ(fifo_cache_put(cache1, "key2", &v2, NULL, NULL), 0);
    ASSERT_EQ(fifo_cache_size(cache1), 1);

    ASSERT_TRUE(fifo_cache_get(cache1, "key1") == NULL);
    ASSERT_TRUE(fifo_cache_get(cache1, "key2") != NULL);

    fifo_cache_free(cache1);

    /* NULL key/cache handling */
    fifo_cache_t *cache2 = fifo_cache_new(5);
    ASSERT_EQ(fifo_cache_put(NULL, "key", &v1, NULL, NULL), -1);
    ASSERT_EQ(fifo_cache_put(cache2, NULL, &v1, NULL, NULL), -1);
    ASSERT_TRUE(fifo_cache_get(NULL, "key") == NULL);
    ASSERT_TRUE(fifo_cache_get(cache2, NULL) == NULL);
    ASSERT_EQ(fifo_cache_remove(NULL, "key"), -1);
    ASSERT_EQ(fifo_cache_remove(cache2, NULL), -1);

    fifo_cache_free(cache2);
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

static void test_fifo_cache_foreach(void)
{
    fifo_cache_t *cache = fifo_cache_new(5);
    ASSERT_TRUE(cache != NULL);

    int v1 = 1, v2 = 2, v3 = 3;

    ASSERT_EQ(fifo_cache_put(cache, "key1", &v1, NULL, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key2", &v2, NULL, NULL), 0);
    ASSERT_EQ(fifo_cache_put(cache, "key3", &v3, NULL, NULL), 0);

    int count = 0;
    size_t visited = fifo_cache_foreach(cache, foreach_callback, &count);
    ASSERT_EQ(visited, 3);
    ASSERT_EQ(count, 3);

    count = 0;
    visited = fifo_cache_foreach(cache, foreach_stop_callback, &count);
    ASSERT_EQ(visited, 2);
    ASSERT_EQ(count, 2);

    visited = fifo_cache_foreach(cache, NULL, NULL);
    ASSERT_EQ(visited, 0);

    fifo_cache_free(cache);
}

void test_fifo_cache_destroy_vs_free()
{
    /* test destroy (no callbacks) vs free (with callbacks) */
    eviction_count = 0;

    fifo_cache_t *cache1 = fifo_cache_new(3);
    int v1 = 1, v2 = 2;
    fifo_cache_put(cache1, "key1", &v1, test_evict_callback, NULL);
    fifo_cache_put(cache1, "key2", &v2, test_evict_callback, NULL);

    /* destroy should not call callbacks */
    fifo_cache_destroy(cache1);
    ASSERT_EQ(eviction_count, 0);

    /* free should call callbacks */
    eviction_count = 0;
    fifo_cache_t *cache2 = fifo_cache_new(3);
    fifo_cache_put(cache2, "key1", &v1, test_evict_callback, NULL);
    fifo_cache_put(cache2, "key2", &v2, test_evict_callback, NULL);
    fifo_cache_free(cache2);
    ASSERT_EQ(eviction_count, 2);
}

void test_fifo_cache_zero_capacity()
{
    fifo_cache_t *cache = fifo_cache_new(0);
    if (cache)
    {
        ASSERT_EQ(fifo_cache_capacity(cache), 0);
        int v = 1;
        /* should fail to add */
        ASSERT_EQ(fifo_cache_put(cache, "key", &v, NULL, NULL), -1);
        fifo_cache_free(cache);
    }
}

void test_fifo_cache_long_keys()
{
    fifo_cache_t *cache = fifo_cache_new(5);

    /* fairly long key (1KB) */
    char long_key[1024];
    memset(long_key, 'A', sizeof(long_key) - 1);
    long_key[sizeof(long_key) - 1] = '\0';

    int v = 123;
    ASSERT_EQ(fifo_cache_put(cache, long_key, &v, NULL, NULL), 0);
    ASSERT_TRUE(fifo_cache_get(cache, long_key) == &v);

    fifo_cache_free(cache);
}

void test_fifo_cache_empty_key()
{
    fifo_cache_t *cache = fifo_cache_new(5);

    int v = 1;
    ASSERT_EQ(fifo_cache_put(cache, "", &v, NULL, NULL), 0);
    ASSERT_TRUE(fifo_cache_get(cache, "") == &v);

    fifo_cache_free(cache);
}

void test_fifo_cache_hash_collisions()
{
    fifo_cache_t *cache = fifo_cache_new(100);

    /* add many keys to test hash collision handling */
    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        int *v = malloc(sizeof(int));
        *v = i;
        ASSERT_EQ(fifo_cache_put(cache, key, v, free_evict_callback, NULL), 0);
    }

    /* verify all are retrievable */
    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        int *v = (int *)fifo_cache_get(cache, key);
        ASSERT_TRUE(v != NULL);
        ASSERT_EQ(*v, i);
    }

    fifo_cache_free(cache);
}

void test_fifo_cache_free_null()
{
    fifo_cache_free(NULL);
    fifo_cache_destroy(NULL);
    fifo_cache_clear(NULL);
}

#define BENCH_ITERATIONS 1000000
#define BENCH_CACHE_SIZE 10000
#define BENCH_THREADS    8

typedef struct
{
    fifo_cache_t *cache;
    int thread_id;
    int iterations;
    double elapsed_time;
} bench_thread_context_t;

static void benchmark_fifo_sequential(void)
{
    printf(BOLDWHITE "\nBenchmark 1: Sequential Write/Read Performance\n" RESET);

    fifo_cache_t *cache = fifo_cache_new(BENCH_CACHE_SIZE);
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
        fifo_cache_put(cache, key, &values[i], NULL, NULL);
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
        void *val = fifo_cache_get(cache, key);
        if (val != NULL) hits++;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double read_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("  Sequential reads: %.2f M ops/sec (%.3f seconds)\n",
           BENCH_ITERATIONS / read_time / 1e6, read_time);
    printf("  Cache hit rate: %.1f%% (%d/%d)\n", (double)hits / BENCH_ITERATIONS * 100, hits,
           BENCH_ITERATIONS);

    free(values);
    fifo_cache_free(cache);
}

static void benchmark_fifo_random_access(void)
{
    printf(BOLDWHITE "\nBenchmark 2: Random Access Performance\n" RESET);

    fifo_cache_t *cache = fifo_cache_new(BENCH_CACHE_SIZE);
    ASSERT_TRUE(cache != NULL);

    int *values = malloc(BENCH_CACHE_SIZE * sizeof(int));

    /* populate cache */
    for (int i = 0; i < BENCH_CACHE_SIZE; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        values[i] = i;
        fifo_cache_put(cache, key, &values[i], NULL, NULL);
    }

    /* random reads */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < BENCH_ITERATIONS; i++)
    {
        int idx = rand() % BENCH_CACHE_SIZE;
        char key[32];
        snprintf(key, sizeof(key), "key_%d", idx);
        void *val = fifo_cache_get(cache, key);
        (void)val;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("  Random reads: %.2f M ops/sec (%.3f seconds)\n", BENCH_ITERATIONS / time / 1e6, time);
    printf("  Cache hit rate: 100%% (all keys in cache)\n");

    free(values);
    fifo_cache_free(cache);
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
        void *val = fifo_cache_get(ctx->cache, key);
        (void)val;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    ctx->elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    return NULL;
}

static void benchmark_fifo_concurrent_reads(void)
{
    printf(BOLDWHITE "\nBenchmark 3: Concurrent Read Performance (Lock-Free)\n" RESET);

    fifo_cache_t *cache = fifo_cache_new(BENCH_CACHE_SIZE);
    ASSERT_TRUE(cache != NULL);

    int *values = malloc(BENCH_CACHE_SIZE * sizeof(int));

    /* populate cache */
    for (int i = 0; i < BENCH_CACHE_SIZE; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        values[i] = i;
        fifo_cache_put(cache, key, &values[i], NULL, NULL);
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
    fifo_cache_free(cache);
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
            fifo_cache_put(ctx->cache, key, &dummy, NULL, NULL);
        }
        else
        {
            void *val = fifo_cache_get(ctx->cache, key);
            (void)val;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    ctx->elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    return NULL;
}

static void benchmark_fifo_mixed_workload(void)
{
    printf(BOLDWHITE "\nBenchmark 4: Mixed Workload (80%% Read, 20%% Write)\n" RESET);

    fifo_cache_t *cache = fifo_cache_new(BENCH_CACHE_SIZE);
    ASSERT_TRUE(cache != NULL);

    int *values = malloc(BENCH_CACHE_SIZE * sizeof(int));

    /* populate cache */
    for (int i = 0; i < BENCH_CACHE_SIZE; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        values[i] = i;
        fifo_cache_put(cache, key, &values[i], NULL, NULL);
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
    fifo_cache_free(cache);
}

int main(void)
{
    RUN_TEST(test_fifo_cache_new_free, tests_passed);
    RUN_TEST(test_fifo_cache_put_get, tests_passed);
    RUN_TEST(test_fifo_cache_eviction, tests_passed);
    RUN_TEST(test_fifo_cache_get_updates_order, tests_passed);
    RUN_TEST(test_fifo_cache_update, tests_passed);
    RUN_TEST(test_fifo_cache_remove, tests_passed);
    RUN_TEST(test_fifo_cache_clear, tests_passed);
    RUN_TEST(test_fifo_cache_with_malloc, tests_passed);
    RUN_TEST(test_fifo_cache_foreach, tests_passed);
    RUN_TEST(test_fifo_cache_concurrent, tests_passed);
    RUN_TEST(test_fifo_cache_edge_cases, tests_passed);
    RUN_TEST(test_fifo_cache_destroy_vs_free, tests_passed);
    RUN_TEST(test_fifo_cache_zero_capacity, tests_passed);
    RUN_TEST(test_fifo_cache_long_keys, tests_passed);
    RUN_TEST(test_fifo_cache_empty_key, tests_passed);
    RUN_TEST(test_fifo_cache_hash_collisions, tests_passed);
    RUN_TEST(test_fifo_cache_free_null, tests_passed);

    benchmark_fifo_sequential();
    benchmark_fifo_random_access();
    benchmark_fifo_concurrent_reads();
    benchmark_fifo_mixed_workload();

    PRINT_TEST_RESULTS(tests_passed, tests_failed);

    return 0;
}
