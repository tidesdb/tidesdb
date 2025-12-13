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
#include <math.h>

#include "../src/clock_cache.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* Test: Create and destroy cache */
void test_cache_create_destroy(void)
{
    cache_config_t config = {.max_bytes = 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);
    // ASSERT_EQ(cache->max_bytes, 1024 * 1024);

    clock_cache_destroy(cache);
}

/* Test: Basic put and get operations */
void test_cache_put_get(void)
{
    cache_config_t config = {.max_bytes = 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const char *key1 = "test_key_1";
    const uint8_t payload1[] = "Hello, World!";
    size_t payload1_len = sizeof(payload1);

    ASSERT_EQ(clock_cache_put(cache, key1, strlen(key1), payload1, payload1_len), 0);

    size_t retrieved_len = 0;
    uint8_t *retrieved = clock_cache_get(cache, key1, strlen(key1), &retrieved_len);
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(retrieved_len, payload1_len);
    ASSERT_TRUE(memcmp(retrieved, payload1, payload1_len) == 0);
    free(retrieved);

    retrieved = clock_cache_get(cache, "nonexistent", 11, &retrieved_len);
    ASSERT_TRUE(retrieved == NULL);

    clock_cache_destroy(cache);
}

/* Test: Update existing entry */
void test_cache_update(void)
{
    cache_config_t config = {.max_bytes = 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const char *key = "update_key";
    const uint8_t payload1[] = "original";
    const uint8_t payload2[] = "updated value";

    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload1, sizeof(payload1)), 0);
    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload2, sizeof(payload2)), 0);

    size_t retrieved_len = 0;
    uint8_t *retrieved = clock_cache_get(cache, key, strlen(key), &retrieved_len);
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(retrieved_len, sizeof(payload2));
    ASSERT_TRUE(memcmp(retrieved, payload2, sizeof(payload2)) == 0);
    free(retrieved);

    clock_cache_destroy(cache);
}

/* Test: Delete operation */
void test_cache_delete(void)
{
    cache_config_t config = {.max_bytes = 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const char *key = "delete_key";
    const uint8_t payload[] = "to be deleted";

    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, sizeof(payload)), 0);
    ASSERT_EQ(clock_cache_exists(cache, key, strlen(key)), 1);

    ASSERT_EQ(clock_cache_delete(cache, key, strlen(key)), 0);
    ASSERT_EQ(clock_cache_exists(cache, key, strlen(key)), 0);

    ASSERT_EQ(clock_cache_delete(cache, "nonexistent", 11), -1);

    clock_cache_destroy(cache);
}

/* Test: Exists operation */
void test_cache_exists(void)
{
    cache_config_t config = {.max_bytes = 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const char *key = "exists_key";
    const uint8_t payload[] = "exists";

    ASSERT_EQ(clock_cache_exists(cache, key, strlen(key)), 0);
    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, sizeof(payload)), 0);
    ASSERT_EQ(clock_cache_exists(cache, key, strlen(key)), 1);

    clock_cache_destroy(cache);
}

/* Test: Clear cache */
void test_cache_clear(void)
{
    cache_config_t config = {.max_bytes = 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    for (int i = 0; i < 10; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        uint8_t payload[32];
        snprintf((char *)payload, sizeof(payload), "value_%d", i);
        ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1),
                  0);
    }

    size_t total_entries, total_bytes;
    clock_cache_stats(cache, &total_entries, &total_bytes);
    ASSERT_TRUE(total_entries > 0);
    ASSERT_TRUE(total_bytes > 0);

    clock_cache_clear(cache);
    clock_cache_stats(cache, &total_entries, &total_bytes);
    ASSERT_EQ(total_entries, 0);
    ASSERT_EQ(total_bytes, 0);

    clock_cache_destroy(cache);
}

/* Test: FIFO eviction */
void test_cache_fifo_eviction(void)
{
    cache_config_t config = {.max_bytes = 200};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const char *key1 = "key1";
    const char *key2 = "key2";
    const char *key3 = "key3";
    const uint8_t payload[] = "some data here";

    ASSERT_EQ(clock_cache_put(cache, key1, strlen(key1), payload, sizeof(payload)), 0);
    ASSERT_EQ(clock_cache_put(cache, key2, strlen(key2), payload, sizeof(payload)), 0);

    for (int i = 0; i < 5; i++)
    {
        size_t len;
        uint8_t *data = clock_cache_get(cache, key1, strlen(key1), &len);
        ASSERT_TRUE(data != NULL);
        free(data);
    }

    ASSERT_EQ(clock_cache_put(cache, key3, strlen(key3), payload, sizeof(payload)), 0);
    ASSERT_EQ(clock_cache_exists(cache, key1, strlen(key1)), 1);

    clock_cache_destroy(cache);
}

void test_cache_expansion(void)
{
    cache_config_t config = {.max_bytes = 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "expand_key_%d", i);
        uint8_t payload[64];
        snprintf((char *)payload, sizeof(payload), "expand_value_%d", i);
        ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1),
                  0);
    }

    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "expand_key_%d", i);
        ASSERT_EQ(clock_cache_exists(cache, key, strlen(key)), 1);
    }

    clock_cache_destroy(cache);
}

/* Test: Cache statistics */
void test_cache_stats(void)
{
    cache_config_t config = {.max_bytes = 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    size_t total_entries, total_bytes;
    clock_cache_stats(cache, &total_entries, &total_bytes);
    ASSERT_EQ(total_entries, 0);
    ASSERT_EQ(total_bytes, 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "stats_key_%d", i);
        uint8_t payload[64];
        snprintf((char *)payload, sizeof(payload), "stats_value_%d", i);
        size_t payload_len = strlen((char *)payload) + 1;
        ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, payload_len), 0);
    }

    clock_cache_stats(cache, &total_entries, &total_bytes);
    ASSERT_EQ(total_entries, 10);
    ASSERT_TRUE(total_bytes > 0);

    clock_cache_destroy(cache);
}

/* Test: Null parameter handling */
void test_cache_null_handling(void)
{
    cache_config_t config = {.max_bytes = 1024};

    ASSERT_TRUE(clock_cache_create(NULL) == NULL);

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const uint8_t payload[] = "test";
    size_t len;

    ASSERT_EQ(clock_cache_put(NULL, "key", 3, payload, sizeof(payload)), -1);
    ASSERT_EQ(clock_cache_put(cache, NULL, 3, payload, sizeof(payload)), -1);
    ASSERT_EQ(clock_cache_put(cache, "key", 3, NULL, sizeof(payload)), -1);

    ASSERT_TRUE(clock_cache_get(NULL, "key", 3, &len) == NULL);
    ASSERT_TRUE(clock_cache_get(cache, NULL, 3, &len) == NULL);
    ASSERT_TRUE(clock_cache_get(cache, "key", 3, NULL) == NULL);

    ASSERT_EQ(clock_cache_delete(NULL, "key", 3), -1);
    ASSERT_EQ(clock_cache_delete(cache, NULL, 3), -1);

    ASSERT_EQ(clock_cache_exists(NULL, "key", 3), 0);
    ASSERT_EQ(clock_cache_exists(cache, NULL, 3), 0);

    clock_cache_clear(NULL);
    clock_cache_destroy(NULL);
    clock_cache_destroy(cache);
}

/* Concurrent test helper */
typedef struct
{
    clock_cache_t *cache;
    int thread_id;
    int num_ops;
} thread_args_t;

void *concurrent_put_thread(void *arg)
{
    thread_args_t *args = (thread_args_t *)arg;
    for (int i = 0; i < args->num_ops; i++)
    {
        char key[64];
        snprintf(key, sizeof(key), "thread_%d_key_%d", args->thread_id, i);
        uint8_t payload[128];
        snprintf((char *)payload, sizeof(payload), "thread_%d_value_%d", args->thread_id, i);
        clock_cache_put(args->cache, key, strlen(key), payload, strlen((char *)payload) + 1);
    }
    return NULL;
}

void *concurrent_get_thread(void *arg)
{
    thread_args_t *args = (thread_args_t *)arg;
    for (int i = 0; i < args->num_ops; i++)
    {
        char key[64];
        snprintf(key, sizeof(key), "thread_%d_key_%d", args->thread_id % 4, i % 100);
        size_t len;
        uint8_t *data = clock_cache_get(args->cache, key, strlen(key), &len);
        if (data) free(data);
    }
    return NULL;
}

void *concurrent_mixed_thread(void *arg)
{
    thread_args_t *args = (thread_args_t *)arg;
    for (int i = 0; i < args->num_ops; i++)
    {
        char key[64];
        snprintf(key, sizeof(key), "mixed_%d_key_%d", args->thread_id, i);
        uint8_t payload[64];
        snprintf((char *)payload, sizeof(payload), "mixed_value_%d", i);

        clock_cache_put(args->cache, key, strlen(key), payload, strlen((char *)payload) + 1);

        size_t len;
        uint8_t *data = clock_cache_get(args->cache, key, strlen(key), &len);
        if (data) free(data);

        if (i % 10 == 0) clock_cache_delete(args->cache, key, strlen(key));
    }
    return NULL;
}

/* Benchmark: Sequential insertions */
void benchmark_cache_insertions(void)
{
    cache_config_t config = {.max_bytes = 100 * 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    clock_t start = clock();
    for (int i = 0; i < 100000; i++)
    {
        char key[64];
        snprintf(key, sizeof(key), "bench_key_%d", i);
        uint8_t payload[128];
        snprintf((char *)payload, sizeof(payload), "bench_value_%d", i);
        clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1);
    }
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "Inserting 100,000 entries took %f seconds\n" RESET, time_spent);

    size_t total_entries, total_bytes;
    clock_cache_stats(cache, &total_entries, &total_bytes);
    printf(BOLDWHITE "Final cache: %zu entries, %zu bytes\n" RESET, total_entries, total_bytes);

    clock_cache_destroy(cache);
}

/* Benchmark: Sequential lookups */
void benchmark_cache_lookups(void)
{
    cache_config_t config = {.max_bytes = 100 * 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    for (int i = 0; i < 50000; i++)
    {
        char key[64];
        snprintf(key, sizeof(key), "lookup_key_%d", i);
        uint8_t payload[128];
        snprintf((char *)payload, sizeof(payload), "lookup_value_%d", i);
        clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1);
    }

    clock_t start = clock();
    int hits = 0;
    for (int i = 0; i < 100000; i++)
    {
        char key[64];
        snprintf(key, sizeof(key), "lookup_key_%d", i % 50000);
        size_t len;
        uint8_t *data = clock_cache_get(cache, key, strlen(key), &len);
        if (data)
        {
            hits++;
            free(data);
        }
    }
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "100,000 lookups took %f seconds\n" RESET, time_spent);
    printf(BOLDWHITE "Hit rate: %.2f%%\n" RESET, (double)hits / 100000.0 * 100.0);

    clock_cache_destroy(cache);
}

/* Benchmark: Concurrent puts */
void benchmark_concurrent_puts(void)
{
    cache_config_t config = {.max_bytes = 100 * 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const int num_threads = 8;
    const int ops_per_thread = 10000;
    pthread_t threads[num_threads];
    thread_args_t args[num_threads];

    clock_t start = clock();
    for (int i = 0; i < num_threads; i++)
    {
        args[i].cache = cache;
        args[i].thread_id = i;
        args[i].num_ops = ops_per_thread;
        pthread_create(&threads[i], NULL, concurrent_put_thread, &args[i]);
    }

    for (int i = 0; i < num_threads; i++) pthread_join(threads[i], NULL);
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "%d threads inserting %d entries each took %f seconds\n" RESET, num_threads,
           ops_per_thread, time_spent);

    size_t total_entries, total_bytes;
    clock_cache_stats(cache, &total_entries, &total_bytes);
    printf(BOLDWHITE "Final cache: %zu entries, %zu bytes\n" RESET, total_entries, total_bytes);

    clock_cache_destroy(cache);
}

/* Benchmark: Concurrent gets */
void benchmark_concurrent_gets(void)
{
    cache_config_t config = {.max_bytes = 100 * 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    for (int i = 0; i < 10000; i++)
    {
        char key[64];
        snprintf(key, sizeof(key), "thread_0_key_%d", i);
        uint8_t payload[128];
        snprintf((char *)payload, sizeof(payload), "thread_0_value_%d", i);
        clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1);
    }

    const int num_threads = 8;
    const int ops_per_thread = 50000;
    pthread_t threads[num_threads];
    thread_args_t args[num_threads];

    clock_t start = clock();
    for (int i = 0; i < num_threads; i++)
    {
        args[i].cache = cache;
        args[i].thread_id = i;
        args[i].num_ops = ops_per_thread;
        pthread_create(&threads[i], NULL, concurrent_get_thread, &args[i]);
    }

    for (int i = 0; i < num_threads; i++) pthread_join(threads[i], NULL);
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "%d threads performing %d gets each took %f seconds\n" RESET, num_threads,
           ops_per_thread, time_spent);

    clock_cache_destroy(cache);
}

/* Benchmark: Concurrent mixed operations */
void benchmark_concurrent_mixed(void)
{
    cache_config_t config = {.max_bytes = 100 * 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const int num_threads = 8;
    const int ops_per_thread = 5000;
    pthread_t threads[num_threads];
    thread_args_t args[num_threads];

    clock_t start = clock();
    for (int i = 0; i < num_threads; i++)
    {
        args[i].cache = cache;
        args[i].thread_id = i;
        args[i].num_ops = ops_per_thread;
        pthread_create(&threads[i], NULL, concurrent_mixed_thread, &args[i]);
    }

    for (int i = 0; i < num_threads; i++) pthread_join(threads[i], NULL);
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "%d threads performing %d mixed ops each took %f seconds\n" RESET, num_threads,
           ops_per_thread, time_spent);

    size_t total_entries, total_bytes;
    clock_cache_stats(cache, &total_entries, &total_bytes);
    printf(BOLDWHITE "Final cache: %zu entries, %zu bytes\n" RESET, total_entries, total_bytes);

    clock_cache_destroy(cache);
}

/* Benchmark: Linear scaling - puts */
void benchmark_scaling_puts(void)
{
    cache_config_t config = {.max_bytes = 200 * 1024 * 1024};

    const int thread_counts[] = {1, 2, 4, 8, 16};
    const int num_configs = 5;
    const int ops_per_thread = 20000;

    printf(BOLDWHITE "\n=== Linear Scaling Benchmark: Concurrent Puts ===\n" RESET);
    printf(BOLDWHITE "Operations per thread: %d\n" RESET, ops_per_thread);
    printf(BOLDWHITE "%-10s %-15s %-15s %-15s\n" RESET, "Threads", "Time (s)", "Ops/sec",
           "Speedup");

    double baseline_time = 0.0;

    for (int i = 0; i < num_configs; i++)
    {
        clock_cache_t *cache = clock_cache_create(&config);
        ASSERT_TRUE(cache != NULL);

        int num_threads = thread_counts[i];
        pthread_t threads[16];
        thread_args_t args[16];

        clock_t start = clock();

        for (int t = 0; t < num_threads; t++)
        {
            args[t].cache = cache;
            args[t].thread_id = t;
            args[t].num_ops = ops_per_thread;
            pthread_create(&threads[t], NULL, concurrent_put_thread, &args[t]);
        }

        for (int t = 0; t < num_threads; t++) pthread_join(threads[t], NULL);

        clock_t end = clock();
        double time_spent = (double)(end - start) / CLOCKS_PER_SEC;

        if (i == 0) baseline_time = time_spent;

        int total_ops = num_threads * ops_per_thread;
        double ops_per_sec = total_ops / time_spent;
        double speedup = baseline_time / time_spent;

        printf(CYAN "%-10d %-15.4f %-15.0f %-15.2fx\n" RESET, num_threads, time_spent, ops_per_sec,
               speedup);

        clock_cache_destroy(cache);
    }
}

/* Benchmark: Linear scaling - gets */
void benchmark_scaling_gets(void)
{
    cache_config_t config = {.max_bytes = 200 * 1024 * 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    /* Populate cache with shared data */
    for (int i = 0; i < 10000; i++)
    {
        char key[64];
        snprintf(key, sizeof(key), "shared_key_%d", i);
        uint8_t payload[128];
        snprintf((char *)payload, sizeof(payload), "shared_value_%d", i);
        clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1);
    }

    const int thread_counts[] = {1, 2, 4, 8, 16};
    const int num_configs = 5;
    const int ops_per_thread = 50000;

    printf(BOLDWHITE "\n=== Linear Scaling Benchmark: Concurrent Gets ===\n" RESET);
    printf(BOLDWHITE "Operations per thread: %d\n" RESET, ops_per_thread);
    printf(BOLDWHITE "%-10s %-15s %-15s %-15s\n" RESET, "Threads", "Time (s)", "Ops/sec",
           "Speedup");

    double baseline_time = 0.0;

    for (int i = 0; i < num_configs; i++)
    {
        int num_threads = thread_counts[i];
        pthread_t threads[16];
        thread_args_t args[16];

        clock_t start = clock();

        for (int t = 0; t < num_threads; t++)
        {
            args[t].cache = cache;
            args[t].thread_id = t;
            args[t].num_ops = ops_per_thread;
            pthread_create(&threads[t], NULL, concurrent_get_thread, &args[t]);
        }

        for (int t = 0; t < num_threads; t++) pthread_join(threads[t], NULL);

        clock_t end = clock();
        double time_spent = (double)(end - start) / CLOCKS_PER_SEC;

        if (i == 0) baseline_time = time_spent;

        int total_ops = num_threads * ops_per_thread;
        double ops_per_sec = total_ops / time_spent;
        double speedup = baseline_time / time_spent;

        printf(CYAN "%-10d %-15.4f %-15.0f %-15.2fx\n" RESET, num_threads, time_spent, ops_per_sec,
               speedup);
    }

    clock_cache_destroy(cache);
}

/* Benchmark: Linear scaling - mixed operations */
void benchmark_scaling_mixed(void)
{
    cache_config_t config = {.max_bytes = 200 * 1024 * 1024};

    const int thread_counts[] = {1, 2, 4, 8, 16};
    const int num_configs = 5;
    const int ops_per_thread = 10000;

    printf(BOLDWHITE "\n=== Linear Scaling Benchmark: Mixed Operations ===\n" RESET);
    printf(BOLDWHITE "Operations per thread: %d (put/get/delete mix)\n" RESET, ops_per_thread);
    printf(BOLDWHITE "%-10s %-15s %-15s %-15s\n" RESET, "Threads", "Time (s)", "Ops/sec",
           "Speedup");

    double baseline_time = 0.0;

    for (int i = 0; i < num_configs; i++)
    {
        clock_cache_t *cache = clock_cache_create(&config);
        ASSERT_TRUE(cache != NULL);

        int num_threads = thread_counts[i];
        pthread_t threads[16];
        thread_args_t args[16];

        clock_t start = clock();

        for (int t = 0; t < num_threads; t++)
        {
            args[t].cache = cache;
            args[t].thread_id = t;
            args[t].num_ops = ops_per_thread;
            pthread_create(&threads[t], NULL, concurrent_mixed_thread, &args[t]);
        }

        for (int t = 0; t < num_threads; t++) pthread_join(threads[t], NULL);

        clock_t end = clock();
        double time_spent = (double)(end - start) / CLOCKS_PER_SEC;

        if (i == 0) baseline_time = time_spent;

        int total_ops = num_threads * ops_per_thread;
        double ops_per_sec = total_ops / time_spent;
        double speedup = baseline_time / time_spent;

        printf(CYAN "%-10d %-15.4f %-15.0f %-15.2fx\n" RESET, num_threads, time_spent, ops_per_sec,
               speedup);

        clock_cache_destroy(cache);
    }
}

/* Benchmark: Memory allocation overhead */
void benchmark_malloc_overhead(void)
{
    printf(BOLDWHITE "\n=== Memory Allocation Overhead Test ===\n" RESET);

    const int num_allocs = 100000;
    void **ptrs = malloc(num_allocs * sizeof(void *));

    /* Benchmark malloc/free */
    clock_t start = clock();
    for (int i = 0; i < num_allocs; i++)
    {
        ptrs[i] = malloc(128);
    }
    for (int i = 0; i < num_allocs; i++)
    {
        free(ptrs[i]);
    }
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "100,000 malloc+free took %f seconds (%.0f ops/sec)\n" RESET, time_spent,
           num_allocs / time_spent);

    free(ptrs);
}

/* Benchmark: CAS contention test */
void benchmark_cas_contention(void)
{
    printf(BOLDWHITE "\n=== CAS Contention Test ===\n" RESET);

    _Atomic uint64_t counter = 0;
    const int ops_per_thread = 100000;

    typedef struct
    {
        _Atomic uint64_t *counter;
        int ops;
    } cas_args_t;

    void *cas_thread(void *arg)
    {
        cas_args_t *args = (cas_args_t *)arg;
        for (int i = 0; i < args->ops; i++)
        {
            atomic_fetch_add_explicit(args->counter, 1, memory_order_relaxed);
        }
        return NULL;
    }

    const int thread_counts[] = {1, 2, 4, 8, 16};
    printf(BOLDWHITE "%-10s %-15s %-15s\n" RESET, "Threads", "Time (s)", "Ops/sec");

    for (int t = 0; t < 5; t++)
    {
        int num_threads = thread_counts[t];
        atomic_store(&counter, 0);

        pthread_t threads[16];
        cas_args_t args = {&counter, ops_per_thread};

        clock_t start = clock();
        for (int i = 0; i < num_threads; i++)
        {
            pthread_create(&threads[i], NULL, cas_thread, &args);
        }
        for (int i = 0; i < num_threads; i++)
        {
            pthread_join(threads[i], NULL);
        }
        clock_t end = clock();

        double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
        int total_ops = num_threads * ops_per_thread;
        printf(CYAN "%-10d %-15.4f %-15.0f\n" RESET, num_threads, time_spent,
               total_ops / time_spent);
    }
}

/* ============================================================================
 * ZIPFIAN DISTRIBUTION BENCHMARK
 * Tests cache performance with realistic hot-key workloads
 * ============================================================================ */

/* Zipfian distribution generator (approximation)
 * Generates keys following power-law distribution where ~20% of keys get ~80% of accesses */
typedef struct
{
    uint32_t num_keys;
    double theta; /* skew parameter: 0.99 = highly skewed (hot keys) */
    double *probabilities;
    double *cumulative;
} zipfian_t;

static zipfian_t *zipfian_create(uint32_t num_keys, double theta)
{
    zipfian_t *z = malloc(sizeof(zipfian_t));
    if (!z) return NULL;

    z->num_keys = num_keys;
    z->theta = theta;
    z->probabilities = malloc(num_keys * sizeof(double));
    z->cumulative = malloc(num_keys * sizeof(double));

    if (!z->probabilities || !z->cumulative)
    {
        free(z->probabilities);
        free(z->cumulative);
        free(z);
        return NULL;
    }

    /* Calculate Zipfian probabilities */
    double sum = 0.0;
    for (uint32_t i = 0; i < num_keys; i++)
    {
        z->probabilities[i] = 1.0 / pow((double)(i + 1), theta);
        sum += z->probabilities[i];
    }

    /* Normalize and create cumulative distribution */
    z->cumulative[0] = z->probabilities[0] / sum;
    for (uint32_t i = 1; i < num_keys; i++)
    {
        z->probabilities[i] /= sum;
        z->cumulative[i] = z->cumulative[i - 1] + z->probabilities[i];
    }

    return z;
}

static void zipfian_destroy(zipfian_t *z)
{
    if (!z) return;
    free(z->probabilities);
    free(z->cumulative);
    free(z);
}

static uint32_t zipfian_next(zipfian_t *z)
{
    double r = (double)rand() / RAND_MAX;

    /* Binary search in cumulative distribution */
    uint32_t left = 0, right = z->num_keys - 1;
    while (left < right)
    {
        uint32_t mid = (left + right) / 2;
        if (r <= z->cumulative[mid])
            right = mid;
        else
            left = mid + 1;
    }
    return left;
}

/* Thread data for Zipfian benchmark */
typedef struct
{
    clock_cache_t *cache;
    zipfian_t *zipf;
    int ops_per_thread;
    int thread_id;
    uint64_t hits;
    uint64_t misses;
} zipfian_thread_data_t;

static void *zipfian_benchmark_thread(void *arg)
{
    zipfian_thread_data_t *data = (zipfian_thread_data_t *)arg;

    for (int i = 0; i < data->ops_per_thread; i++)
    {
        /* Get Zipfian-distributed key */
        uint32_t key_idx = zipfian_next(data->zipf);
        char key[32];
        snprintf(key, sizeof(key), "zipf_key_%u", key_idx);

        /* Try to get from cache */
        size_t len;
        uint8_t *value = clock_cache_get(data->cache, key, strlen(key), &len);

        if (value)
        {
            data->hits++;
            free(value);
        }
        else
        {
            data->misses++;
            /* Simulate fetching from "database" and caching */
            uint8_t payload[100];
            snprintf((char *)payload, sizeof(payload), "value_for_key_%u", key_idx);
            clock_cache_put(data->cache, key, strlen(key), payload, strlen((char *)payload) + 1);
        }
    }

    return NULL;
}

void benchmark_zipfian_scaling(void)
{
    printf("\n" YELLOW "=== Zipfian Distribution Benchmark (Hot Keys) ===\n" RESET);
    printf(CYAN "Cache: 64 MB, Keys: 10000, Theta: 0.99 (highly skewed)\n" RESET);
    printf(CYAN "Expected: ~80%% of accesses hit ~20%% of keys (cache should help!)\n\n" RESET);

    cache_config_t config = {
        .max_bytes = 64 * 1024 * 1024, /* 64 MB */
        .num_buckets = 0               /* auto-calculate */
    };

    clock_cache_t *cache = clock_cache_create(&config);
    if (!cache)
    {
        printf(RED "Failed to create cache\n" RESET);
        return;
    }

    /* Create Zipfian distribution (theta=0.99 = very skewed) */
    zipfian_t *zipf = zipfian_create(10000, 0.99);
    if (!zipf)
    {
        clock_cache_destroy(cache);
        return;
    }

    printf(CYAN "%-10s %-15s %-15s %-15s %-15s\n" RESET, "Threads", "Time (s)", "Ops/sec",
           "Cache Hits", "Hit Rate");
    printf("─────────────────────────────────────────────────────────────────────\n");

    int thread_counts[] = {1, 2, 4, 8, 16};
    int ops_per_thread = 100000;

    for (int t = 0; t < 5; t++)
    {
        int num_threads = thread_counts[t];

        /* Clear cache between runs */
        clock_cache_clear(cache);

        pthread_t threads[16];
        zipfian_thread_data_t thread_data[16];

        clock_t start = clock();

        for (int i = 0; i < num_threads; i++)
        {
            thread_data[i].cache = cache;
            thread_data[i].zipf = zipf;
            thread_data[i].ops_per_thread = ops_per_thread;
            thread_data[i].thread_id = i;
            thread_data[i].hits = 0;
            thread_data[i].misses = 0;
            pthread_create(&threads[i], NULL, zipfian_benchmark_thread, &thread_data[i]);
        }

        for (int i = 0; i < num_threads; i++)
        {
            pthread_join(threads[i], NULL);
        }

        clock_t end = clock();

        /* Calculate total hits and misses */
        uint64_t total_hits = 0, total_misses = 0;
        for (int i = 0; i < num_threads; i++)
        {
            total_hits += thread_data[i].hits;
            total_misses += thread_data[i].misses;
        }

        double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
        int total_ops = num_threads * ops_per_thread;
        double hit_rate = (double)total_hits / (total_hits + total_misses) * 100.0;

        printf(CYAN "%-10d %-15.4f %-15.0f %-15" PRIu64 " %-15.2f%%\n" RESET, num_threads,
               time_spent, total_ops / time_spent, total_hits, hit_rate);
    }

    /* Print pool statistics if available */
    if (cache->entry_pool)
    {
        size_t pool_hits, pool_misses, pool_allocated, pool_max;
        float pool_hit_rate;
        clock_cache_stats_pool(cache, &pool_hits, &pool_misses, &pool_allocated, &pool_max,
                               &pool_hit_rate);

        printf("\n" YELLOW "Memory Pool Statistics:\n" RESET);
        printf(CYAN "  Pool Hits:      %zu\n" RESET, pool_hits);
        printf(CYAN "  Pool Misses:    %zu\n" RESET, pool_misses);
        printf(CYAN "  Pool Hit Rate:  %.2f%%\n" RESET, pool_hit_rate * 100.0);
        printf(CYAN "  Pool Allocated: %zu / %zu\n" RESET, pool_allocated, pool_max);
    }

    /* Print hash table statistics */
    size_t entries, bytes;
    uint32_t buckets;
    float load_factor;
    clock_cache_stats_detailed(cache, &entries, &bytes, &buckets, &load_factor);

    printf("\n" YELLOW "Hash Table Statistics:\n" RESET);
    printf(CYAN "  Entries:      %zu\n" RESET, entries);
    printf(CYAN "  Buckets:      %u\n" RESET, buckets);
    printf(CYAN "  Load Factor:  %.4f\n" RESET, load_factor);
    printf(CYAN "  Bytes Used:   %zu (%.2f MB)\n" RESET, bytes, bytes / (1024.0 * 1024.0));

    zipfian_destroy(zipf);
    clock_cache_destroy(cache);
}

int main(void)
{
    srand((unsigned int)time(NULL));

    RUN_TEST(test_cache_create_destroy, tests_passed);
    RUN_TEST(test_cache_put_get, tests_passed);
    RUN_TEST(test_cache_update, tests_passed);
    RUN_TEST(test_cache_delete, tests_passed);
    RUN_TEST(test_cache_exists, tests_passed);
    RUN_TEST(test_cache_clear, tests_passed);
    RUN_TEST(test_cache_fifo_eviction, tests_passed);
    RUN_TEST(test_cache_expansion, tests_passed);
    RUN_TEST(test_cache_stats, tests_passed);
    RUN_TEST(test_cache_null_handling, tests_passed);
    RUN_TEST(benchmark_cache_insertions, tests_passed);
    RUN_TEST(benchmark_cache_lookups, tests_passed);
    RUN_TEST(benchmark_concurrent_puts, tests_passed);
    RUN_TEST(benchmark_concurrent_gets, tests_passed);
    RUN_TEST(benchmark_concurrent_mixed, tests_passed);
    RUN_TEST(benchmark_scaling_puts, tests_passed);
    RUN_TEST(benchmark_scaling_gets, tests_passed);
    RUN_TEST(benchmark_scaling_mixed, tests_passed);
    RUN_TEST(benchmark_malloc_overhead, tests_passed);
    RUN_TEST(benchmark_cas_contention, tests_passed);
    RUN_TEST(benchmark_zipfian_scaling, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
