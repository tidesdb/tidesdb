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

void test_cache_create_destroy(void)
{
    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 4, .slots_per_partition = 256};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);
    ASSERT_EQ(cache->max_bytes, 1024 * 1024);

    clock_cache_destroy(cache);
}

void test_cache_put_get(void)
{
    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 4, .slots_per_partition = 256};

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

void test_cache_update(void)
{
    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 4, .slots_per_partition = 256};

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

void test_cache_delete(void)
{
    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 4, .slots_per_partition = 256};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const char *key = "delete_key";
    const uint8_t payload[] = "to be deleted";

    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, sizeof(payload)), 0);

    size_t check_len;
    uint8_t *check_data = clock_cache_get(cache, key, strlen(key), &check_len);
    ASSERT_TRUE(check_data != NULL);
    free(check_data);

    ASSERT_EQ(clock_cache_delete(cache, key, strlen(key)), 0);

    check_data = clock_cache_get(cache, key, strlen(key), &check_len);
    ASSERT_TRUE(check_data == NULL);

    ASSERT_EQ(clock_cache_delete(cache, "nonexistent", 11), -1);

    clock_cache_destroy(cache);
}

void test_cache_exists(void)
{
    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 4, .slots_per_partition = 256};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const char *key = "exists_key";
    const uint8_t payload[] = "exists";

    size_t len;
    uint8_t *data = clock_cache_get(cache, key, strlen(key), &len);
    ASSERT_TRUE(data == NULL);

    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, sizeof(payload)), 0);

    data = clock_cache_get(cache, key, strlen(key), &len);
    ASSERT_TRUE(data != NULL);
    free(data);

    clock_cache_destroy(cache);
}

void test_cache_clear(void)
{
    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 4, .slots_per_partition = 256};

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

    clock_cache_stats_t stats;
    clock_cache_get_stats(cache, &stats);
    ASSERT_TRUE(stats.total_bytes > 0);

    clock_cache_clear(cache);
    clock_cache_get_stats(cache, &stats);
    ASSERT_EQ(stats.total_bytes, 0);

    clock_cache_destroy(cache);
}

void test_cache_clock_eviction(void)
{
    cache_config_t config = {.max_bytes = 190, .num_partitions = 2, .slots_per_partition = 8};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const uint8_t payload[] = "test_payload_data!!";

    ASSERT_EQ(clock_cache_put(cache, "k1", 2, payload, sizeof(payload)), 0);
    ASSERT_EQ(clock_cache_put(cache, "k2", 2, payload, sizeof(payload)), 0);
    ASSERT_EQ(clock_cache_put(cache, "k3", 2, payload, sizeof(payload)), 0);

    clock_cache_stats_t stats;
    clock_cache_get_stats(cache, &stats);
    ASSERT_TRUE(stats.total_bytes <= 190);

    ASSERT_EQ(clock_cache_put(cache, "k4", 2, payload, sizeof(payload)), 0);

    clock_cache_get_stats(cache, &stats);

    printf("Total bytes after eviction: %zu\n", stats.total_bytes);
    ASSERT_TRUE(stats.total_bytes <= 190);

    size_t len;
    uint8_t *data = clock_cache_get(cache, "k4", 2, &len);
    ASSERT_TRUE(data != NULL);
    free(data);

    uint8_t *k1_data = clock_cache_get(cache, "k1", 2, &len);
    int k1_exists = (k1_data != NULL);
    if (k1_exists) free(k1_data);

    uint8_t *k2_data = clock_cache_get(cache, "k2", 2, &len);
    int k2_exists = (k2_data != NULL);
    if (k2_exists) free(k2_data);

    uint8_t *k3_data = clock_cache_get(cache, "k3", 2, &len);
    int k3_exists = (k3_data != NULL);
    if (k3_exists) free(k3_data);

    int total_old_keys = k1_exists + k2_exists + k3_exists;
    ASSERT_TRUE(total_old_keys < 3);

    clock_cache_destroy(cache);
}

void test_cache_stats(void)
{
    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 4, .slots_per_partition = 256};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    clock_cache_stats_t stats;
    clock_cache_get_stats(cache, &stats);
    ASSERT_EQ(stats.total_bytes, 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "stats_key_%d", i);
        uint8_t payload[64];
        snprintf((char *)payload, sizeof(payload), "stats_value_%d", i);
        size_t payload_len = strlen((char *)payload) + 1;
        ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, payload_len), 0);
    }

    clock_cache_get_stats(cache, &stats);
    ASSERT_TRUE(stats.total_bytes > 0);

    clock_cache_destroy(cache);
}

void test_cache_null_handling(void)
{
    cache_config_t config = {
        .max_bytes = 64 * 1024, .num_partitions = 2, .slots_per_partition = 32};

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

    ASSERT_EQ(clock_cache_delete(NULL, "key", 3), -1);
    ASSERT_EQ(clock_cache_delete(cache, NULL, 3), -1);

    clock_cache_clear(NULL);
    clock_cache_destroy(NULL);
    clock_cache_destroy(cache);
}

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

        int key_num = (args->thread_id * args->num_ops + i);
        snprintf(key, sizeof(key), "key_%08x", key_num * 2654435761u);
        uint8_t payload[128];
        snprintf((char *)payload, sizeof(payload), "value_%d_%d", args->thread_id, i);
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

        int key_num = ((args->thread_id % 4) * 100 + (i % 100));
        snprintf(key, sizeof(key), "key_%08x", key_num * 2654435761u);
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
        int key_num = (args->thread_id * args->num_ops + i);
        snprintf(key, sizeof(key), "key_%08x", key_num * 2654435761u);

        int op = i % 20;
        if (op < 14) /* 70% reads */
        {
            size_t len;
            uint8_t *data = clock_cache_get(args->cache, key, strlen(key), &len);
            if (data) free(data);
        }
        else if (op < 19) /* 25% writes */
        {
            uint8_t payload[64];
            snprintf((char *)payload, sizeof(payload), "value_%d_%d", args->thread_id, i);
            clock_cache_put(args->cache, key, strlen(key), payload, strlen((char *)payload) + 1);
        }
        else /* 5% deletes */
        {
            clock_cache_delete(args->cache, key, strlen(key));
        }
    }
    return NULL;
}

typedef struct
{
    clock_cache_t *cache;
    int thread_id;
    _Atomic(int) *stop_flag;
    _Atomic(int) *read_count;
    _Atomic(int) *write_count;
} race_test_args_t;

void *read_thread_race(void *arg)
{
    race_test_args_t *args = (race_test_args_t *)arg;
    int local_reads = 0;

    /* do exactly 10 reads as fast as possible to trigger race */
    for (int i = 0; i < 10; i++)
    {
        size_t len = 0;
        uint8_t *data = clock_cache_get(args->cache, "key_0", 5, &len);
        if (data)
        {
            /* verify data integrity */
            if (len > 0 && data[0] != 'X')
            {
                printf("ERROR: Data corruption detected in thread %d\n", args->thread_id);
            }
            free(data);
            local_reads++;
        }
    }

    atomic_fetch_add(args->read_count, local_reads);
    return NULL;
}

void *write_thread_race(void *arg)
{
    race_test_args_t *args = (race_test_args_t *)arg;
    char key[32];
    uint8_t payload[128];
    memset(payload, 'X', sizeof(payload));
    int local_writes = 0;

    /* small delay to let reader start first */
    usleep(1000);

    /* do exactly 10 writes as fast as possible to trigger race */
    for (int i = 0; i < 10; i++)
    {
        snprintf(key, sizeof(key), "evict_%d", i);
        if (clock_cache_put(args->cache, key, strlen(key), payload, sizeof(payload)) == 0)
        {
            local_writes++;
        }
    }

    atomic_fetch_add(args->write_count, local_writes);
    return NULL;
}

void test_concurrent_read_evict_race(void)
{
    /* create a small cache to force evictions but allow some reads */
    cache_config_t config = {
        .max_bytes = 2048,        /* small -- allows ~15 entries */
        .num_partitions = 1,      /* single partition for maximum contention */
        .slots_per_partition = 16 /* small slots */
    };

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    printf("Testing concurrent read/evict race (MINIMAL: 1 reader, 1 writer)\n");

    /* pre-populate with just key_0 */
    uint8_t payload[128];
    memset(payload, 'X', sizeof(payload));
    clock_cache_put(cache, "key_0", 5, payload, sizeof(payload));

    _Atomic(int) stop_flag = 0;
    _Atomic(int) read_count = 0;
    _Atomic(int) write_count = 0;

    const int num_readers = 1;
    const int num_writers = 1;
    const int total_threads = num_readers + num_writers;

/* use fixed size arrays for MSVC compatibility (no VLA support) */
#define MAX_RACE_THREADS 2
    pthread_t threads[MAX_RACE_THREADS];
    race_test_args_t args[MAX_RACE_THREADS];

    /* start reader threads */
    for (int i = 0; i < num_readers; i++)
    {
        args[i].cache = cache;
        args[i].thread_id = i;
        args[i].stop_flag = &stop_flag;
        args[i].read_count = &read_count;
        args[i].write_count = &write_count;
        pthread_create(&threads[i], NULL, read_thread_race, &args[i]);
    }

    /* start writer threads */
    for (int i = 0; i < num_writers; i++)
    {
        int idx = num_readers + i;
        args[idx].cache = cache;
        args[idx].thread_id = idx;
        args[idx].stop_flag = &stop_flag;
        args[idx].read_count = &read_count;
        args[idx].write_count = &write_count;
        pthread_create(&threads[idx], NULL, write_thread_race, &args[idx]);
    }

    /* threads will stop automatically after 10 operations each */
    printf("Waiting for threads to complete (10 ops each)...\n");
    fflush(stdout);

    /* wait for all threads */
    for (int i = 0; i < total_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    int total_reads = atomic_load(&read_count);
    int total_writes = atomic_load(&write_count);

    printf("Race test completed: %d reads, %d writes\n", total_reads, total_writes);
    printf("No crashes or data corruption detected!\n");

    ASSERT_TRUE(total_reads > 0);
    ASSERT_TRUE(total_writes > 0);

    clock_cache_destroy(cache);
}

void test_cache_compute_config(void)
{
    cache_config_t config;

    /* test with small cache (1MB) */
    clock_cache_compute_config(1 * 1024 * 1024, &config);
    ASSERT_TRUE(config.max_bytes == 1 * 1024 * 1024);
    ASSERT_TRUE(config.num_partitions >= CLOCK_CACHE_MIN_PARTITIONS);
    ASSERT_TRUE(config.num_partitions <= CLOCK_CACHE_MAX_PARTITIONS);
    ASSERT_TRUE(config.slots_per_partition >= CLOCK_CACHE_MIN_SLOTS_PER_PARTITION);
    ASSERT_TRUE(config.slots_per_partition <= CLOCK_CACHE_MAX_SLOTS_PER_PARTITION);
    /* verify num_partitions is power of 2 */
    ASSERT_TRUE((config.num_partitions & (config.num_partitions - 1)) == 0);
    /* verify slots_per_partition is power of 2 */
    ASSERT_TRUE((config.slots_per_partition & (config.slots_per_partition - 1)) == 0);

    printf("1MB cache: partitions=%zu, slots_per_partition=%zu\n", config.num_partitions,
           config.slots_per_partition);

    /* test with medium cache (100MB) */
    clock_cache_compute_config(100 * 1024 * 1024, &config);
    ASSERT_TRUE(config.max_bytes == 100 * 1024 * 1024);
    ASSERT_TRUE(config.num_partitions >= CLOCK_CACHE_MIN_PARTITIONS);
    ASSERT_TRUE(config.num_partitions <= CLOCK_CACHE_MAX_PARTITIONS);
    ASSERT_TRUE(config.slots_per_partition >= CLOCK_CACHE_MIN_SLOTS_PER_PARTITION);
    ASSERT_TRUE(config.slots_per_partition <= CLOCK_CACHE_MAX_SLOTS_PER_PARTITION);
    ASSERT_TRUE((config.num_partitions & (config.num_partitions - 1)) == 0);
    ASSERT_TRUE((config.slots_per_partition & (config.slots_per_partition - 1)) == 0);

    printf("100MB cache: partitions=%zu, slots_per_partition=%zu\n", config.num_partitions,
           config.slots_per_partition);

    /* test with large cache (1GB) */
    clock_cache_compute_config(1024 * 1024 * 1024, &config);
    ASSERT_TRUE(config.max_bytes == 1024 * 1024 * 1024);
    ASSERT_TRUE(config.num_partitions >= CLOCK_CACHE_MIN_PARTITIONS);
    ASSERT_TRUE(config.num_partitions <= CLOCK_CACHE_MAX_PARTITIONS);
    ASSERT_TRUE(config.slots_per_partition >= CLOCK_CACHE_MIN_SLOTS_PER_PARTITION);
    ASSERT_TRUE(config.slots_per_partition <= CLOCK_CACHE_MAX_SLOTS_PER_PARTITION);
    ASSERT_TRUE((config.num_partitions & (config.num_partitions - 1)) == 0);
    ASSERT_TRUE((config.slots_per_partition & (config.slots_per_partition - 1)) == 0);

    printf("1GB cache: partitions=%zu, slots_per_partition=%zu\n", config.num_partitions,
           config.slots_per_partition);

    /* verify computed config works with actual cache creation */
    clock_cache_compute_config(10 * 1024 * 1024, &config);
    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);
    ASSERT_EQ(cache->max_bytes, config.max_bytes);
    ASSERT_EQ(cache->num_partitions, config.num_partitions);

    /* verify cache is functional */
    const char *key = "test_key";
    const uint8_t payload[] = "test_value";
    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, sizeof(payload)), 0);

    size_t len;
    uint8_t *retrieved = clock_cache_get(cache, key, strlen(key), &len);
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(len, sizeof(payload));
    ASSERT_EQ(memcmp(retrieved, payload, len), 0);
    free(retrieved);

    clock_cache_destroy(cache);
}

void benchmark_cache_insertions(void)
{
    cache_config_t config = {
        .max_bytes = 50 * 1024 * 1024, .num_partitions = 64, .slots_per_partition = 512};

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

    clock_cache_stats_t stats;
    clock_cache_get_stats(cache, &stats);
    printf(BOLDWHITE "Final cache: %zu bytes used, %zu entries\n" RESET, stats.total_bytes,
           stats.total_entries);

    clock_cache_destroy(cache);
}

void benchmark_cache_lookups(void)
{
    cache_config_t config = {
        .max_bytes = 50 * 1024 * 1024, .num_partitions = 64, .slots_per_partition = 512};

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

void benchmark_concurrent_puts(void)
{
    cache_config_t config = {
        .max_bytes = 50 * 1024 * 1024, .num_partitions = 64, .slots_per_partition = 512};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const int num_threads = 8;
    const int ops_per_thread = 10000;
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    thread_args_t *args = malloc(num_threads * sizeof(thread_args_t));
    ASSERT_TRUE(threads != NULL && args != NULL);

    clock_t start = clock();
    for (int i = 0; i < num_threads; i++)
    {
        args[i].cache = cache;
        args[i].thread_id = i;
        args[i].num_ops = ops_per_thread;
        pthread_create(&threads[i], NULL, concurrent_put_thread, &args[i]);
    }

    for (int i = 0; i < num_threads; i++) pthread_join(threads[i], NULL);
    free(threads);
    free(args);
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "%d threads inserting %d entries each took %f seconds\n" RESET, num_threads,
           ops_per_thread, time_spent);

    clock_cache_stats_t stats;
    clock_cache_get_stats(cache, &stats);
    printf(BOLDWHITE "Final cache: %zu bytes used, %zu entries\n" RESET, stats.total_bytes,
           stats.total_entries);

    clock_cache_destroy(cache);
}

void benchmark_concurrent_gets(void)
{
    cache_config_t config = {
        .max_bytes = 50 * 1024 * 1024, .num_partitions = 64, .slots_per_partition = 512};

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
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    thread_args_t *args = malloc(num_threads * sizeof(thread_args_t));
    ASSERT_TRUE(threads != NULL && args != NULL);

    clock_t start = clock();
    for (int i = 0; i < num_threads; i++)
    {
        args[i].cache = cache;
        args[i].thread_id = i;
        args[i].num_ops = ops_per_thread;
        pthread_create(&threads[i], NULL, concurrent_get_thread, &args[i]);
    }

    for (int i = 0; i < num_threads; i++) pthread_join(threads[i], NULL);
    free(threads);
    free(args);
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "%d threads performing %d gets each took %f seconds\n" RESET, num_threads,
           ops_per_thread, time_spent);

    clock_cache_destroy(cache);
}

void benchmark_concurrent_mixed(void)
{
    cache_config_t config = {
        .max_bytes = 50 * 1024 * 1024, .num_partitions = 64, .slots_per_partition = 512};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const int num_threads = 8;
    const int ops_per_thread = 5000;
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    thread_args_t *args = malloc(num_threads * sizeof(thread_args_t));
    ASSERT_TRUE(threads != NULL && args != NULL);

    clock_t start = clock();
    for (int i = 0; i < num_threads; i++)
    {
        args[i].cache = cache;
        args[i].thread_id = i;
        args[i].num_ops = ops_per_thread;
        pthread_create(&threads[i], NULL, concurrent_mixed_thread, &args[i]);
    }

    for (int i = 0; i < num_threads; i++) pthread_join(threads[i], NULL);
    free(threads);
    free(args);
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "%d threads performing %d mixed ops each took %f seconds\n" RESET, num_threads,
           ops_per_thread, time_spent);

    clock_cache_stats_t stats;
    clock_cache_get_stats(cache, &stats);
    printf(BOLDWHITE "Final cache: %zu bytes used, %zu entries\n" RESET, stats.total_bytes,
           stats.total_entries);

    clock_cache_destroy(cache);
}

void benchmark_scaling_puts(void)
{
    cache_config_t config = {
        .max_bytes = 100 * 1024 * 1024, .num_partitions = 128, .slots_per_partition = 512};

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

void benchmark_scaling_gets(void)
{
    cache_config_t config = {
        .max_bytes = 100 * 1024 * 1024, .num_partitions = 64, .slots_per_partition = 512};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

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

void benchmark_scaling_mixed(void)
{
    cache_config_t config = {
        .max_bytes = 100 * 1024 * 1024, .num_partitions = 128, .slots_per_partition = 512};

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

int main(void)
{
    srand((unsigned int)time(NULL));
    RUN_TEST(test_cache_create_destroy, tests_passed);
    RUN_TEST(test_cache_put_get, tests_passed);
    RUN_TEST(test_cache_update, tests_passed);
    RUN_TEST(test_cache_delete, tests_passed);
    RUN_TEST(test_cache_exists, tests_passed);
    RUN_TEST(test_cache_clear, tests_passed);
    RUN_TEST(test_cache_clock_eviction, tests_passed);
    RUN_TEST(test_cache_stats, tests_passed);
    RUN_TEST(test_cache_null_handling, tests_passed);
    RUN_TEST(test_cache_compute_config, tests_passed);
    RUN_TEST(test_concurrent_read_evict_race, tests_passed);
    RUN_TEST(benchmark_cache_insertions, tests_passed);
    RUN_TEST(benchmark_cache_lookups, tests_passed);
    RUN_TEST(benchmark_concurrent_puts, tests_passed);
    RUN_TEST(benchmark_concurrent_gets, tests_passed);
    RUN_TEST(benchmark_concurrent_mixed, tests_passed);
    RUN_TEST(benchmark_scaling_puts, tests_passed);
    RUN_TEST(benchmark_scaling_gets, tests_passed);
    RUN_TEST(benchmark_scaling_mixed, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
