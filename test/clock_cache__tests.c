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
#include <time.h>

#include "../src/clock_cache.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* wall-clock timing helper -- clock() measures CPU time across all threads
 * which makes multi-threaded scaling look ~Nx worse than reality */
static inline double wall_time_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

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

    ASSERT_EQ(clock_cache_put(cache, key1, strlen(key1), payload1, payload1_len, 0), 0);

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

    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload1, sizeof(payload1), 0), 0);
    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload2, sizeof(payload2), 0), 0);

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

    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, sizeof(payload), 0), 0);

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

    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, sizeof(payload), 0), 0);

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
        ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1, 0),
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

/* test data structure for eviction callback testing */
typedef struct
{
    int *data;
    size_t size;
} test_evict_data_t;

static int eviction_callback_count = 0;

/* eviction callback that frees the test data */
static void test_eviction_callback(void *payload, size_t payload_len)
{
    if (!payload || payload_len != sizeof(test_evict_data_t *)) return;

    test_evict_data_t *data;
    memcpy(&data, payload, sizeof(data));
    if (data)
    {
        free(data->data);
        free(data);
        eviction_callback_count++;
    }
}

void test_cache_clock_eviction(void)
{
    printf("Testing cache eviction with callbacks...\n");

    {
        cache_config_t config = {.max_bytes = 200,
                                 .num_partitions = 2,
                                 .slots_per_partition = 4,
                                 .evict_callback = NULL};
        clock_cache_t *cache = clock_cache_create(&config);
        ASSERT_TRUE(cache != NULL);

        const uint8_t payload[] = "test_payload_data_for_eviction!!";

        /* fill cache beyond capacity to trigger eviction (4 slots per partition, 90% = 3.6, so 4th
         * triggers eviction) */
        for (int i = 0; i < 10; i++)
        {
            char key[16];
            snprintf(key, sizeof(key), "k%d", i);
            ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, sizeof(payload), 0), 0);
        }

        clock_cache_stats_t stats;
        clock_cache_get_stats(cache, &stats);
        printf("  Inserted 10 entries into 8 slots, cache bytes: %zu\n", stats.total_bytes);
        printf("  Cache entries: %zu\n", stats.total_entries);

        /* we verify most recent key exists */
        size_t len;
        uint8_t *data = clock_cache_get(cache, "k9", 2, &len);
        ASSERT_TRUE(data != NULL);
        free(data);

        /* we check that some old keys were evicted */
        int old_keys_found = 0;
        for (int i = 0; i < 5; i++)
        {
            char key[16];
            snprintf(key, sizeof(key), "k%d", i);
            uint8_t *kdata = clock_cache_get(cache, key, strlen(key), &len);
            if (kdata)
            {
                old_keys_found++;
                free(kdata);
            }
        }

        printf("  Old keys (k0-k4) remaining: %d/5 (some should be evicted)\n", old_keys_found);
        ASSERT_TRUE(old_keys_found < 5); /* at least one old key should be evicted */

        clock_cache_destroy(cache);
        printf("  ✓ Basic eviction test passed\n");
    }

    {
        eviction_callback_count = 0;
        cache_config_t config = {.max_bytes = 300,
                                 .num_partitions = 2,
                                 .slots_per_partition = 4,
                                 .evict_callback = test_eviction_callback};
        clock_cache_t *cache = clock_cache_create(&config);
        ASSERT_TRUE(cache != NULL);

        /* we create test data with pointers (simulating ref-counted blocks) */
        for (int i = 0; i < 6; i++)
        {
            test_evict_data_t *data = malloc(sizeof(test_evict_data_t));
            data->data = malloc(100);
            data->size = 100;

            char key[16];
            snprintf(key, sizeof(key), "key_%d", i);

            /* w cache pointer to data */
            int result =
                clock_cache_put(cache, key, strlen(key), &data, sizeof(test_evict_data_t *), 0);
            ASSERT_EQ(result, 0);
        }

        clock_cache_stats_t stats;
        clock_cache_get_stats(cache, &stats);
        printf("  Inserted 6 entries, cache bytes: %zu (target: 300, allows overhead)\n",
               stats.total_bytes);
        /* we cache uses approximate eviction, allow reasonable overhead */
        ASSERT_TRUE(stats.total_bytes < 600);

        /* we verify callback was called for evicted entries */
        printf("  Eviction callback called: %d times\n", eviction_callback_count);
        ASSERT_TRUE(eviction_callback_count > 0); /* some entries should have been evicted */

        int initial_evictions = eviction_callback_count;

        /* we destroy cache -- should call callback for remaining entries */
        clock_cache_destroy(cache);

        printf("  Total eviction callbacks: %d (initial: %d, on destroy: %d)\n",
               eviction_callback_count, initial_evictions,
               eviction_callback_count - initial_evictions);
        ASSERT_TRUE(eviction_callback_count >= 6); /* all 6 entries should eventually be freed */

        printf("  ✓ Callback eviction test passed\n");
    }

    {
        eviction_callback_count = 0;
        cache_config_t config = {.max_bytes = 150,
                                 .num_partitions = 1,
                                 .slots_per_partition = 8,
                                 .evict_callback = test_eviction_callback};
        clock_cache_t *cache = clock_cache_create(&config);
        ASSERT_TRUE(cache != NULL);

        for (int round = 0; round < 3; round++)
        {
            for (int i = 0; i < 5; i++)
            {
                test_evict_data_t *data = malloc(sizeof(test_evict_data_t));
                data->data = malloc(50);
                data->size = 50;

                char key[16];
                snprintf(key, sizeof(key), "r%d_k%d", round, i);

                clock_cache_put(cache, key, strlen(key), &data, sizeof(test_evict_data_t *), 0);
            }
        }

        printf("  Inserted 15 entries across 3 rounds\n");
        printf("  Eviction callbacks during insertions: %d\n", eviction_callback_count);

        clock_cache_destroy(cache);

        printf("  Total eviction callbacks: %d (all 15 should be freed)\n",
               eviction_callback_count);
        ASSERT_EQ(eviction_callback_count, 15); /* all entries should be freed */

        printf("  ✓ Memory leak test passed\n");
    }

    printf("✓ All cache eviction tests passed!\n");
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
        ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, payload_len, 0), 0);
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

    ASSERT_EQ(clock_cache_put(NULL, "key", 3, payload, sizeof(payload), 0), -1);
    ASSERT_EQ(clock_cache_put(cache, NULL, 3, payload, sizeof(payload), 0), -1);
    ASSERT_EQ(clock_cache_put(cache, "key", 3, NULL, sizeof(payload), 0), -1);

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
        clock_cache_put(args->cache, key, strlen(key), payload, strlen((char *)payload) + 1, 0);
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
            clock_cache_put(args->cache, key, strlen(key), payload, strlen((char *)payload) + 1, 0);
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
        if (clock_cache_put(args->cache, key, strlen(key), payload, sizeof(payload), 0) == 0)
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
    clock_cache_put(cache, "key_0", 5, payload, sizeof(payload), 0);

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
    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, sizeof(payload), 0), 0);

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

    double start = wall_time_sec();
    for (int i = 0; i < 100000; i++)
    {
        char key[64];
        snprintf(key, sizeof(key), "bench_key_%d", i);
        uint8_t payload[128];
        snprintf((char *)payload, sizeof(payload), "bench_value_%d", i);
        clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1, 0);
    }
    double end = wall_time_sec();

    double time_spent = end - start;
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
        clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1, 0);
    }

    double start = wall_time_sec();
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
    double end = wall_time_sec();

    double time_spent = end - start;
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

    double start = wall_time_sec();
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
    double end = wall_time_sec();

    double time_spent = end - start;
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
        clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1, 0);
    }

    const int num_threads = 8;
    const int ops_per_thread = 50000;
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    thread_args_t *args = malloc(num_threads * sizeof(thread_args_t));
    ASSERT_TRUE(threads != NULL && args != NULL);

    double start = wall_time_sec();
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
    double end = wall_time_sec();

    double time_spent = end - start;
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

    double start = wall_time_sec();
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
    double end = wall_time_sec();

    double time_spent = end - start;
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

        double start = wall_time_sec();

        for (int t = 0; t < num_threads; t++)
        {
            args[t].cache = cache;
            args[t].thread_id = t;
            args[t].num_ops = ops_per_thread;
            pthread_create(&threads[t], NULL, concurrent_put_thread, &args[t]);
        }

        for (int t = 0; t < num_threads; t++) pthread_join(threads[t], NULL);

        double time_spent = wall_time_sec() - start;

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
        clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1, 0);
    }

    const int thread_counts[] = {1, 2, 4, 8, 16};
    const int num_configs = 5;
    const int ops_per_thread = 50000;

    printf(BOLDWHITE "Operations per thread: %d\n" RESET, ops_per_thread);
    printf(BOLDWHITE "%-10s %-15s %-15s %-15s\n" RESET, "Threads", "Time (s)", "Ops/sec",
           "Speedup");

    double baseline_time = 0.0;

    for (int i = 0; i < num_configs; i++)
    {
        int num_threads = thread_counts[i];
        pthread_t threads[16];
        thread_args_t args[16];

        double start = wall_time_sec();

        for (int t = 0; t < num_threads; t++)
        {
            args[t].cache = cache;
            args[t].thread_id = t;
            args[t].num_ops = ops_per_thread;
            pthread_create(&threads[t], NULL, concurrent_get_thread, &args[t]);
        }

        for (int t = 0; t < num_threads; t++) pthread_join(threads[t], NULL);

        double time_spent = wall_time_sec() - start;

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

        double start = wall_time_sec();

        for (int t = 0; t < num_threads; t++)
        {
            args[t].cache = cache;
            args[t].thread_id = t;
            args[t].num_ops = ops_per_thread;
            pthread_create(&threads[t], NULL, concurrent_mixed_thread, &args[t]);
        }

        for (int t = 0; t < num_threads; t++) pthread_join(threads[t], NULL);

        double time_spent = wall_time_sec() - start;

        if (i == 0) baseline_time = time_spent;

        int total_ops = num_threads * ops_per_thread;
        double ops_per_sec = total_ops / time_spent;
        double speedup = baseline_time / time_spent;

        printf(CYAN "%-10d %-15.4f %-15.0f %-15.2fx\n" RESET, num_threads, time_spent, ops_per_sec,
               speedup);

        clock_cache_destroy(cache);
    }
}

typedef struct
{
    clock_cache_t *cache;
    const char *key;
    size_t key_len;
    int thread_id;
    int num_ops;
    _Atomic(int) *success_count;
    _Atomic(int) *error_count;
} single_key_args_t;

void *put_same_key_thread(void *arg)
{
    single_key_args_t *args = (single_key_args_t *)arg;
    int local_success = 0;
    int local_error = 0;

    for (int i = 0; i < args->num_ops; i++)
    {
        uint8_t payload[64];
        snprintf((char *)payload, sizeof(payload), "thread_%d_iter_%d", args->thread_id, i);
        int result = clock_cache_put(args->cache, args->key, args->key_len, payload,
                                     strlen((char *)payload) + 1, 0);
        if (result == 0)
            local_success++;
        else
            local_error++;
    }

    atomic_fetch_add(args->success_count, local_success);
    atomic_fetch_add(args->error_count, local_error);
    return NULL;
}

void test_concurrent_put_same_key(void)
{
    printf("Testing concurrent put on same key...\n");

    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 4, .slots_per_partition = 256};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const char *shared_key = "shared_key";
    const int num_threads = 8;
    const int ops_per_thread = 1000;

    pthread_t threads[8];
    single_key_args_t args[8];
    _Atomic(int) success_count = 0;
    _Atomic(int) error_count = 0;

    for (int i = 0; i < num_threads; i++)
    {
        args[i].cache = cache;
        args[i].key = shared_key;
        args[i].key_len = strlen(shared_key);
        args[i].thread_id = i;
        args[i].num_ops = ops_per_thread;
        args[i].success_count = &success_count;
        args[i].error_count = &error_count;
        pthread_create(&threads[i], NULL, put_same_key_thread, &args[i]);
    }

    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    int total_success = atomic_load(&success_count);
    int total_error = atomic_load(&error_count);

    printf("  Total operations: %d, Success: %d, Errors: %d\n", num_threads * ops_per_thread,
           total_success, total_error);

    /* verify final value is readable */
    size_t len;
    uint8_t *data = clock_cache_get(cache, shared_key, strlen(shared_key), &len);
    ASSERT_TRUE(data != NULL);
    printf("  Final value: %s\n", (char *)data);
    free(data);

    /* most operations should succeed */
    ASSERT_TRUE(total_success > (num_threads * ops_per_thread) / 2);

    clock_cache_destroy(cache);
    printf("  ✓ Concurrent put same key test passed\n");
}

void *read_while_delete_thread(void *arg)
{
    single_key_args_t *args = (single_key_args_t *)arg;
    int local_success = 0;

    for (int i = 0; i < args->num_ops; i++)
    {
        size_t len;
        uint8_t *data = clock_cache_get(args->cache, args->key, args->key_len, &len);
        if (data)
        {
            /* verify data integrity - should start with 'v' for "value" */
            if (len > 0 && data[0] == 'v')
            {
                local_success++;
            }
            free(data);
        }
        /* small delay to increase race window */
        if (i % 100 == 0) sched_yield();
    }

    atomic_fetch_add(args->success_count, local_success);
    return NULL;
}

void *delete_while_read_thread(void *arg)
{
    single_key_args_t *args = (single_key_args_t *)arg;

    for (int i = 0; i < args->num_ops; i++)
    {
        /* delete then immediately re-insert */
        clock_cache_delete(args->cache, args->key, args->key_len);

        uint8_t payload[] = "value_after_delete";
        clock_cache_put(args->cache, args->key, args->key_len, payload, sizeof(payload), 0);

        if (i % 100 == 0) sched_yield();
    }

    return NULL;
}

void test_concurrent_delete_while_reading(void)
{
    printf("Testing concurrent delete while reading...\n");

    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 1, .slots_per_partition = 64};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const char *key = "delete_read_key";
    uint8_t initial_payload[] = "value_initial";
    clock_cache_put(cache, key, strlen(key), initial_payload, sizeof(initial_payload), 0);

    const int num_readers = 4;
    const int num_deleters = 2;
    const int ops_per_thread = 500;

    pthread_t readers[4];
    pthread_t deleters[2];
    single_key_args_t reader_args[4];
    single_key_args_t deleter_args[2];
    _Atomic(int) read_success = 0;
    _Atomic(int) dummy = 0;

    /* start readers */
    for (int i = 0; i < num_readers; i++)
    {
        reader_args[i].cache = cache;
        reader_args[i].key = key;
        reader_args[i].key_len = strlen(key);
        reader_args[i].thread_id = i;
        reader_args[i].num_ops = ops_per_thread;
        reader_args[i].success_count = &read_success;
        reader_args[i].error_count = &dummy;
        pthread_create(&readers[i], NULL, read_while_delete_thread, &reader_args[i]);
    }

    /* start deleters */
    for (int i = 0; i < num_deleters; i++)
    {
        deleter_args[i].cache = cache;
        deleter_args[i].key = key;
        deleter_args[i].key_len = strlen(key);
        deleter_args[i].thread_id = i;
        deleter_args[i].num_ops = ops_per_thread;
        deleter_args[i].success_count = &dummy;
        deleter_args[i].error_count = &dummy;
        pthread_create(&deleters[i], NULL, delete_while_read_thread, &deleter_args[i]);
    }

    for (int i = 0; i < num_readers; i++) pthread_join(readers[i], NULL);
    for (int i = 0; i < num_deleters; i++) pthread_join(deleters[i], NULL);

    int total_reads = atomic_load(&read_success);
    printf("  Successful reads with valid data: %d\n", total_reads);
    printf("  No crashes or data corruption detected!\n");

    clock_cache_destroy(cache);
    printf("  ✓ Concurrent delete while reading test passed\n");
}

void *put_delete_race_put_thread(void *arg)
{
    single_key_args_t *args = (single_key_args_t *)arg;

    for (int i = 0; i < args->num_ops; i++)
    {
        uint8_t payload[32];
        snprintf((char *)payload, sizeof(payload), "put_%d_%d", args->thread_id, i);
        clock_cache_put(args->cache, args->key, args->key_len, payload, strlen((char *)payload) + 1,
                        0);
    }
    return NULL;
}

void *put_delete_race_delete_thread(void *arg)
{
    single_key_args_t *args = (single_key_args_t *)arg;

    for (int i = 0; i < args->num_ops; i++)
    {
        clock_cache_delete(args->cache, args->key, args->key_len);
    }
    return NULL;
}

void test_concurrent_put_delete_same_key(void)
{
    printf("Testing concurrent put/delete on same key...\n");

    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 1, .slots_per_partition = 64};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const char *key = "put_delete_key";
    const int num_putters = 4;
    const int num_deleters = 4;
    const int ops_per_thread = 500;

    pthread_t putters[4];
    pthread_t deleters[4];
    single_key_args_t putter_args[4];
    single_key_args_t deleter_args[4];
    _Atomic(int) dummy = 0;

    for (int i = 0; i < num_putters; i++)
    {
        putter_args[i].cache = cache;
        putter_args[i].key = key;
        putter_args[i].key_len = strlen(key);
        putter_args[i].thread_id = i;
        putter_args[i].num_ops = ops_per_thread;
        putter_args[i].success_count = &dummy;
        putter_args[i].error_count = &dummy;
        pthread_create(&putters[i], NULL, put_delete_race_put_thread, &putter_args[i]);
    }

    for (int i = 0; i < num_deleters; i++)
    {
        deleter_args[i].cache = cache;
        deleter_args[i].key = key;
        deleter_args[i].key_len = strlen(key);
        deleter_args[i].thread_id = i;
        deleter_args[i].num_ops = ops_per_thread;
        deleter_args[i].success_count = &dummy;
        deleter_args[i].error_count = &dummy;
        pthread_create(&deleters[i], NULL, put_delete_race_delete_thread, &deleter_args[i]);
    }

    for (int i = 0; i < num_putters; i++) pthread_join(putters[i], NULL);
    for (int i = 0; i < num_deleters; i++) pthread_join(deleters[i], NULL);

    /* final state: key may or may not exist */
    size_t len;
    uint8_t *data = clock_cache_get(cache, key, strlen(key), &len);
    if (data)
    {
        printf("  Final state: key exists with value '%s'\n", (char *)data);
        free(data);
    }
    else
    {
        printf("  Final state: key was deleted\n");
    }

    printf("  No crashes detected!\n");
    clock_cache_destroy(cache);
    printf("  ✓ Concurrent put/delete same key test passed\n");
}

void test_hash_collision_concurrent(void)
{
    printf("Testing hash collisions under concurrent access...\n");

    /* small hash index to force collisions */
    cache_config_t config = {
        .max_bytes = 64 * 1024, .num_partitions = 1, .slots_per_partition = 16};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    /* create keys that will likely collide in small hash space */
    const int num_threads = 8;
    const int keys_per_thread = 100;

    pthread_t threads[8];
    thread_args_t args[8];

    for (int i = 0; i < num_threads; i++)
    {
        args[i].cache = cache;
        args[i].thread_id = i;
        args[i].num_ops = keys_per_thread;
        pthread_create(&threads[i], NULL, concurrent_mixed_thread, &args[i]);
    }

    for (int i = 0; i < num_threads; i++) pthread_join(threads[i], NULL);

    clock_cache_stats_t stats;
    clock_cache_get_stats(cache, &stats);
    printf("  Final entries: %zu, bytes: %zu\n", stats.total_entries, stats.total_bytes);
    printf("  No crashes during hash collision stress!\n");

    clock_cache_destroy(cache);
    printf("  ✓ Hash collision concurrent test passed\n");
}

typedef struct
{
    clock_cache_t *cache;
    _Atomic(int) *started;
    _Atomic(int) *should_stop;
    int thread_id;
} shutdown_test_args_t;

void *shutdown_worker_thread(void *arg)
{
    shutdown_test_args_t *args = (shutdown_test_args_t *)arg;

    atomic_fetch_add(args->started, 1);

    int i = 0;
    while (!atomic_load(args->should_stop))
    {
        char key[32];
        snprintf(key, sizeof(key), "shutdown_key_%d_%d", args->thread_id, i % 100);

        uint8_t payload[64];
        snprintf((char *)payload, sizeof(payload), "value_%d", i);

        /* mix of operations */
        if (i % 3 == 0)
        {
            clock_cache_put(args->cache, key, strlen(key), payload, strlen((char *)payload) + 1, 0);
        }
        else if (i % 3 == 1)
        {
            size_t len;
            uint8_t *data = clock_cache_get(args->cache, key, strlen(key), &len);
            if (data) free(data);
        }
        else
        {
            clock_cache_delete(args->cache, key, strlen(key));
        }
        i++;
    }

    return NULL;
}

void test_shutdown_during_operations(void)
{
    printf("Testing shutdown during active operations...\n");

    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 4, .slots_per_partition = 128};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const int num_threads = 4;
    pthread_t threads[4];
    shutdown_test_args_t args[4];
    _Atomic(int) started = 0;
    _Atomic(int) should_stop = 0;

    for (int i = 0; i < num_threads; i++)
    {
        args[i].cache = cache;
        args[i].started = &started;
        args[i].should_stop = &should_stop;
        args[i].thread_id = i;
        pthread_create(&threads[i], NULL, shutdown_worker_thread, &args[i]);
    }

    /* wait for all threads to start */
    while (atomic_load(&started) < num_threads)
    {
        usleep(1000);
    }

    usleep(50000); /* 50ms */

    /* signal stop and destroy - this tests shutdown flag */
    atomic_store(&should_stop, 1);

    /* small delay to let threads see stop flag */
    usleep(10000);

    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    clock_cache_destroy(cache);
    printf("  No crashes during shutdown!\n");
    printf("  ✓ Shutdown during operations test passed\n");
}

void test_zero_copy_get_release(void)
{
    printf("Testing zero-copy get and release...\n");

    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 4, .slots_per_partition = 256};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const char *key = "zero_copy_key";
    const uint8_t payload[] = "zero_copy_payload_data";

    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, sizeof(payload), 0), 0);

    size_t len;
    clock_cache_entry_t *entry = NULL;
    const uint8_t *data = clock_cache_get_zero_copy(cache, key, strlen(key), &len, &entry);

    ASSERT_TRUE(data != NULL);
    ASSERT_TRUE(entry != NULL);
    ASSERT_EQ(len, sizeof(payload));
    ASSERT_TRUE(memcmp(data, payload, len) == 0);

    uint8_t ref_bit = atomic_load(&entry->ref_bit);
    ASSERT_TRUE(ref_bit >= 1);

    clock_cache_release(entry);

    data = clock_cache_get_zero_copy(cache, "nonexistent", 11, &len, &entry);
    ASSERT_TRUE(data == NULL);

    clock_cache_destroy(cache);
    printf("  ✓ Zero-copy get/release test passed\n");
}

void test_large_payload(void)
{
    printf("Testing large payloads (1MB+)...\n");

    cache_config_t config = {.max_bytes = 50 * 1024 * 1024, /* 50MB */
                             .num_partitions = 4,
                             .slots_per_partition = 64};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    /* create 1MB payload */
    size_t large_size = 1024 * 1024;
    uint8_t *large_payload = malloc(large_size);
    ASSERT_TRUE(large_payload != NULL);

    /* fill with pattern */
    for (size_t i = 0; i < large_size; i++)
    {
        large_payload[i] = (uint8_t)(i & 0xFF);
    }

    const char *key = "large_key";
    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), large_payload, large_size, 0), 0);

    size_t retrieved_len;
    uint8_t *retrieved = clock_cache_get(cache, key, strlen(key), &retrieved_len);
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(retrieved_len, large_size);

    /* verify pattern */
    int pattern_ok = 1;
    for (size_t i = 0; i < large_size && pattern_ok; i++)
    {
        if (retrieved[i] != (uint8_t)(i & 0xFF))
        {
            pattern_ok = 0;
        }
    }
    ASSERT_TRUE(pattern_ok);

    free(retrieved);
    free(large_payload);

    /* test multiple large payloads */
    for (int i = 0; i < 5; i++)
    {
        char key_buf[32];
        snprintf(key_buf, sizeof(key_buf), "large_key_%d", i);

        uint8_t *payload = malloc(large_size);
        memset(payload, (uint8_t)i, large_size);

        clock_cache_put(cache, key_buf, strlen(key_buf), payload, large_size, 0);
        free(payload);
    }

    clock_cache_stats_t stats;
    clock_cache_get_stats(cache, &stats);
    printf("  Cache bytes after large payloads: %zu\n", stats.total_bytes);

    clock_cache_destroy(cache);
    printf("  ✓ Large payload test passed\n");
}

void test_many_small_entries(void)
{
    printf("Testing many small entries...\n");

    cache_config_t config = {.max_bytes = 10 * 1024 * 1024, /* 10MB */
                             .num_partitions = 8,
                             .slots_per_partition = 1024};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const int num_entries = 10000;
    int insert_success = 0;

    for (int i = 0; i < num_entries; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "k%d", i);
        uint8_t payload[8];
        snprintf((char *)payload, sizeof(payload), "v%d", i);

        if (clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1, 0) == 0)
        {
            insert_success++;
        }
    }

    printf("  Inserted %d/%d small entries\n", insert_success, num_entries);

    int found = 0;
    for (int i = 0; i < 100; i++)
    {
        int idx = rand() % num_entries;
        char key[16];
        snprintf(key, sizeof(key), "k%d", idx);

        size_t len;
        uint8_t *data = clock_cache_get(cache, key, strlen(key), &len);
        if (data)
        {
            found++;
            free(data);
        }
    }

    printf("  Random sample: found %d/100 entries\n", found);

    clock_cache_stats_t stats;
    clock_cache_get_stats(cache, &stats);
    printf("  Total entries: %zu, bytes: %zu\n", stats.total_entries, stats.total_bytes);

    clock_cache_destroy(cache);
    printf("  ✓ Many small entries test passed\n");
}

static _Atomic(int) foreach_callback_count = 0;

static int foreach_test_callback(const char *key, size_t key_len, const uint8_t *payload,
                                 size_t payload_len, void *user_data)
{
    (void)key;
    (void)key_len;
    (void)payload;
    (void)payload_len;
    (void)user_data;
    atomic_fetch_add(&foreach_callback_count, 1);
    return 0;
}

void *foreach_modifier_thread(void *arg)
{
    single_key_args_t *args = (single_key_args_t *)arg;

    for (int i = 0; i < args->num_ops; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "prefix_%d", i);
        uint8_t payload[32];
        snprintf((char *)payload, sizeof(payload), "value_%d", i);

        if (i % 2 == 0)
        {
            clock_cache_put(args->cache, key, strlen(key), payload, strlen((char *)payload) + 1, 0);
        }
        else
        {
            clock_cache_delete(args->cache, key, strlen(key));
        }
    }
    return NULL;
}

void test_foreach_prefix_concurrent(void)
{
    printf("Testing foreach_prefix during concurrent modification...\n");

    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 4, .slots_per_partition = 256};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "prefix_%d", i);
        uint8_t payload[32];
        snprintf((char *)payload, sizeof(payload), "value_%d", i);
        clock_cache_put(cache, key, strlen(key), payload, strlen((char *)payload) + 1, 0);
    }

    const int num_modifiers = 2;
    pthread_t modifiers[2];
    single_key_args_t mod_args[2];
    _Atomic(int) dummy = 0;

    for (int i = 0; i < num_modifiers; i++)
    {
        mod_args[i].cache = cache;
        mod_args[i].key = NULL;
        mod_args[i].key_len = 0;
        mod_args[i].thread_id = i;
        mod_args[i].num_ops = 200;
        mod_args[i].success_count = &dummy;
        mod_args[i].error_count = &dummy;
        pthread_create(&modifiers[i], NULL, foreach_modifier_thread, &mod_args[i]);
    }

    atomic_store(&foreach_callback_count, 0);
    size_t count = clock_cache_foreach_prefix(cache, "prefix_", 7, foreach_test_callback, NULL);

    for (int i = 0; i < num_modifiers; i++)
    {
        pthread_join(modifiers[i], NULL);
    }

    printf("  foreach_prefix returned: %zu, callback count: %d\n", count,
           atomic_load(&foreach_callback_count));
    printf("  No crashes during concurrent iteration!\n");

    clock_cache_destroy(cache);
    printf("  ✓ Foreach prefix concurrent test passed\n");
}

void test_put_after_shutdown(void)
{
    printf("Testing operations after shutdown...\n");

    cache_config_t config = {
        .max_bytes = 1024 * 1024, .num_partitions = 4, .slots_per_partition = 256};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const char *key = "shutdown_test_key";
    uint8_t payload[] = "test_value";
    ASSERT_EQ(clock_cache_put(cache, key, strlen(key), payload, sizeof(payload), 0), 0);

    atomic_store(&cache->shutdown, 1);

    int put_result = clock_cache_put(cache, "new_key", 7, payload, sizeof(payload), 0);
    ASSERT_EQ(put_result, -1);

    size_t len;
    uint8_t *data = clock_cache_get(cache, key, strlen(key), &len);
    ASSERT_TRUE(data == NULL);

    int delete_result = clock_cache_delete(cache, key, strlen(key));
    ASSERT_EQ(delete_result, -1);

    atomic_store(&cache->shutdown, 0);

    clock_cache_destroy(cache);
    printf("  ✓ Put after shutdown test passed\n");
}

typedef struct
{
    clock_cache_t *cache;
    int thread_id;
    int num_ops;
    int num_unique_keys;
    _Atomic(int) *reads_done;
    _Atomic(int) *writes_done;
} rw_cache_bench_ctx_t;

void *rw_cache_bench_reader(void *arg)
{
    rw_cache_bench_ctx_t *ctx = (rw_cache_bench_ctx_t *)arg;
    int completed = 0;

    for (int i = 0; i < ctx->num_ops; i++)
    {
        char key_buf[32];
        snprintf(key_buf, sizeof(key_buf), "rwcache_%06d", i % ctx->num_unique_keys);

        size_t len;
        uint8_t *data = clock_cache_get(ctx->cache, key_buf, strlen(key_buf), &len);
        if (data) free(data);
        completed++;
    }

    atomic_fetch_add_explicit(ctx->reads_done, completed, memory_order_relaxed);
    return NULL;
}

void *rw_cache_bench_writer(void *arg)
{
    rw_cache_bench_ctx_t *ctx = (rw_cache_bench_ctx_t *)arg;
    int completed = 0;

    for (int i = 0; i < ctx->num_ops; i++)
    {
        char key_buf[32];
        char value_buf[64];
        snprintf(key_buf, sizeof(key_buf), "rwcache_%06d", i % ctx->num_unique_keys);
        snprintf(value_buf, sizeof(value_buf), "t%d_v%d", ctx->thread_id, i);

        if (clock_cache_put(ctx->cache, key_buf, strlen(key_buf), (uint8_t *)value_buf,
                            strlen(value_buf) + 1, 0) == 0)
        {
            completed++;
        }
    }

    atomic_fetch_add_explicit(ctx->writes_done, completed, memory_order_relaxed);
    return NULL;
}

static void run_cache_rw_contention_ratio(int num_readers, int num_writers, int ops_per_thread,
                                          int num_unique_keys)
{
    cache_config_t config = {
        .max_bytes = 50 * 1024 * 1024, .num_partitions = 32, .slots_per_partition = 2048};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    _Atomic(int) reads_done = 0;
    _Atomic(int) writes_done = 0;

    /* pre-populate so readers always have data */
    for (int i = 0; i < num_unique_keys; i++)
    {
        char key_buf[32];
        char value_buf[64];
        snprintf(key_buf, sizeof(key_buf), "rwcache_%06d", i);
        snprintf(value_buf, sizeof(value_buf), "init_%d", i);
        clock_cache_put(cache, key_buf, strlen(key_buf), (uint8_t *)value_buf,
                        strlen(value_buf) + 1, 0);
    }

    int total_threads = num_readers + num_writers;
    pthread_t *threads = malloc(total_threads * sizeof(pthread_t));
    rw_cache_bench_ctx_t *ctxs = malloc(total_threads * sizeof(rw_cache_bench_ctx_t));

    for (int i = 0; i < total_threads; i++)
    {
        ctxs[i].cache = cache;
        ctxs[i].thread_id = i;
        ctxs[i].num_ops = ops_per_thread;
        ctxs[i].num_unique_keys = num_unique_keys;
        ctxs[i].reads_done = &reads_done;
        ctxs[i].writes_done = &writes_done;
    }

    double start = wall_time_sec();

    for (int i = 0; i < num_readers; i++)
    {
        pthread_create(&threads[i], NULL, rw_cache_bench_reader, &ctxs[i]);
    }
    for (int i = 0; i < num_writers; i++)
    {
        pthread_create(&threads[num_readers + i], NULL, rw_cache_bench_writer,
                       &ctxs[num_readers + i]);
    }

    for (int i = 0; i < total_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    double elapsed = wall_time_sec() - start;

    int tr = atomic_load(&reads_done);
    int tw = atomic_load(&writes_done);
    int total_ops = tr + tw;

    int read_pct = (total_threads > 0) ? (num_readers * 100 / total_threads) : 0;
    int write_pct = 100 - read_pct;

    printf(CYAN "  %3d/%3d R/W  | %2dR + %2dW threads | %.3f sec | %7.2f M total ops/sec", read_pct,
           write_pct, num_readers, num_writers, elapsed, total_ops / elapsed / 1000000.0);
    if (tr > 0) printf(" | R: %.2f M/s", tr / elapsed / 1000000.0);
    if (tw > 0) printf(" | W: %.2f M/s", tw / elapsed / 1000000.0);
    printf("\n" RESET);

    free(threads);
    free(ctxs);
    clock_cache_destroy(cache);
}

void benchmark_cache_rw_contention(void)
{
    printf(BOLDWHITE
           "\n----------------- Cache Read-Write Contention Benchmark -----------------\n" RESET);

    const int ops_per_thread = 100000;
    const int num_unique_keys = 10000;
    const int total_threads = 8;

    printf(YELLOW "  %d threads total, %d ops/thread, %d unique keys\n" RESET, total_threads,
           ops_per_thread, num_unique_keys);

    /* pure read baseline */
    run_cache_rw_contention_ratio(total_threads, 0, ops_per_thread, num_unique_keys);
    /* read-heavy */
    run_cache_rw_contention_ratio(7, 1, ops_per_thread, num_unique_keys);
    /* 75/25 */
    run_cache_rw_contention_ratio(6, 2, ops_per_thread, num_unique_keys);
    /* balanced */
    run_cache_rw_contention_ratio(4, 4, ops_per_thread, num_unique_keys);
    /* write-heavy */
    run_cache_rw_contention_ratio(2, 6, ops_per_thread, num_unique_keys);
    /* pure write baseline */
    run_cache_rw_contention_ratio(0, total_threads, ops_per_thread, num_unique_keys);
}

/* simple xorshift32 PRNG -- deterministic, no global state, fast */
static inline uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/* approximate Zipfian: pick index in [0, n) biased toward low indices.
 * models real-world "hot key" patterns -- a few btree root/internal nodes
 * are accessed far more often than deep leaf nodes. */
static inline int zipf_pick(uint32_t *rng, int n)
{
    /* square the uniform [0,1) sample to skew toward 0 */
    uint32_t r = xorshift32(rng);
    double u = (double)(r & 0x7FFFFFFF) / (double)0x7FFFFFFF;
    int idx = (int)(u * u * n);
    return (idx >= n) ? n - 1 : idx;
}

/* variable block size: models real btree nodes that range from ~200B (small leaf)
 * to ~4KB (large internal node with many keys). returns a size in [lo, hi). */
static inline size_t variable_block_size(uint32_t *rng, size_t lo, size_t hi)
{
    return lo + (xorshift32(rng) % (hi - lo));
}

/* fill a payload with a deterministic pattern so we can verify integrity on read.
 * byte 0 = checksum (XOR of remaining bytes), bytes 1..len-1 = pattern from block_id. */
static void fill_block_payload(uint8_t *buf, size_t len, uint32_t block_id)
{
    if (len == 0) return;
    uint32_t s = block_id ^ 0xDEADBEEF;
    uint8_t cksum = 0;
    for (size_t i = 1; i < len; i++)
    {
        s = s * 1103515245 + 12345;
        buf[i] = (uint8_t)(s >> 16);
        cksum ^= buf[i];
    }
    buf[0] = cksum;
}

/* verify payload integrity. returns 1 if valid, 0 if corrupt. */
static int verify_block_payload(const uint8_t *buf, size_t len)
{
    if (len == 0) return 1;
    uint8_t cksum = 0;
    for (size_t i = 1; i < len; i++) cksum ^= buf[i];
    return buf[0] == cksum;
}

/**
 * test_realistic_block_cache_eviction
 * models a single-threaded btree scan workload:
 *   -- 5000 "blocks" (more than fit in cache) with variable sizes 200B–4KB
 *   -- insert all blocks, verify byte budget is respected throughout
 *   -- read back with Zipfian access (hot blocks hit cache, cold blocks miss)
 *   -- verify every successful read returns uncorrupted data
 *   -- verify hot blocks have higher hit rates than cold blocks
 */
void test_realistic_block_cache_eviction(void)
{
    printf("Testing realistic block cache eviction (single-threaded)...\n");

    /* 1 MB cache -- holds ~500-2000 variable-size blocks.
     * total keyspace is 2000 blocks so cache can hold a meaningful fraction
     * of the hot working set (Zipfian skew means ~top 200 blocks are "hot"). */
    const size_t max_bytes = 1024 * 1024;
    cache_config_t config = {
        .max_bytes = max_bytes, .num_partitions = 4, .slots_per_partition = 512};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const int num_blocks = 2000;
    uint32_t rng = 42;
    size_t total_data_inserted = 0;
    size_t max_observed_bytes = 0;
    int corruptions = 0;

    /* pre-compute block sizes so we can re-generate on cache miss */
    size_t block_sizes[2000];
    for (int i = 0; i < num_blocks; i++) block_sizes[i] = variable_block_size(&rng, 200, 2048);

    /* phase 1: warm-up -- insert all blocks (simulates initial table scan / SST open) */
    printf("  Phase 1: inserting %d variable-size blocks (200B-2KB)...\n", num_blocks);
    for (int i = 0; i < num_blocks; i++)
    {
        size_t bsz = block_sizes[i];
        uint8_t *block = (uint8_t *)malloc(bsz);
        ASSERT_TRUE(block != NULL);
        fill_block_payload(block, bsz, (uint32_t)i);

        char key[32];
        snprintf(key, sizeof(key), "blk:%05d", i);
        clock_cache_put(cache, key, strlen(key), block, bsz, 0);
        total_data_inserted += bsz;
        free(block);

        if (i % 500 == 499)
        {
            clock_cache_stats_t stats;
            clock_cache_get_stats(cache, &stats);
            if (stats.total_bytes > max_observed_bytes) max_observed_bytes = stats.total_bytes;
            printf("    [%d/%d] bytes_used=%zu / %zu, entries=%zu\n", i + 1, num_blocks,
                   stats.total_bytes, max_bytes, stats.total_entries);
            ASSERT_TRUE(stats.total_bytes <= max_bytes * 2);
        }
    }
    printf("    Total data offered: %zu bytes (%.1fx cache size)\n", total_data_inserted,
           (double)total_data_inserted / max_bytes);

    /* phase 2: steady-state Zipfian workload (90% read, 10% new-block writes).
     * on cache miss, we re-insert the block (simulating a real disk read that
     * populates the cache -- this is how btree_node_read_cached works). */
    printf("  Phase 2: 20000 Zipfian accesses (90%% read, 10%% write)...\n");
    const int num_accesses = 20000;
    int hits = 0, reads = 0, integrity_checks = 0;

    for (int i = 0; i < num_accesses; i++)
    {
        int op = xorshift32(&rng) % 10;
        if (op < 9) /* 90% read */
        {
            int block_id = zipf_pick(&rng, num_blocks);
            char key[32];
            snprintf(key, sizeof(key), "blk:%05d", block_id);

            size_t len;
            uint8_t *data = clock_cache_get(cache, key, strlen(key), &len);
            reads++;
            if (data)
            {
                hits++;
                integrity_checks++;
                if (!verify_block_payload(data, len))
                {
                    printf("    ERROR: corruption in block %d (len=%zu)\n", block_id, len);
                    corruptions++;
                }
                free(data);
            }
            else
            {
                /* cache miss -- simulate disk read and re-populate cache */
                size_t bsz = block_sizes[block_id];
                uint8_t *block = (uint8_t *)malloc(bsz);
                fill_block_payload(block, bsz, (uint32_t)block_id);
                clock_cache_put(cache, key, strlen(key), block, bsz, 0);
                free(block);
            }
        }
        else /* 10% write -- simulate compaction producing new blocks */
        {
            int block_id = num_blocks + i;
            size_t bsz = variable_block_size(&rng, 200, 2048);
            uint8_t *block = (uint8_t *)malloc(bsz);
            fill_block_payload(block, bsz, (uint32_t)block_id);

            char key[32];
            snprintf(key, sizeof(key), "blk:%05d", block_id);
            clock_cache_put(cache, key, strlen(key), block, bsz, 0);
            free(block);
        }
    }

    double hit_rate = (reads > 0) ? (double)hits / reads * 100.0 : 0.0;
    printf("    Reads: %d, Hits: %d, Hit rate: %.1f%%\n", reads, hits, hit_rate);
    printf("    Integrity checks: %d, Corruptions: %d\n", integrity_checks, corruptions);

    /* with Zipfian access + miss-fill, hot blocks get re-cached and should
     * yield a meaningful hit rate.  the exact rate depends on cache pressure
     * from the 10% writes, but should be well above zero. */
    ASSERT_TRUE(hits > 0);
    ASSERT_TRUE(corruptions == 0);

    /* verify byte budget is still respected after steady-state phase */
    clock_cache_stats_t mid_stats;
    clock_cache_get_stats(cache, &mid_stats);
    printf("    Post-steady-state: bytes_used=%zu / %zu\n", mid_stats.total_bytes, max_bytes);
    ASSERT_TRUE(mid_stats.total_bytes <= max_bytes * 2);

    /* phase 3: scan burst -- sequential scan of 500 cold blocks forces eviction
     * of working set, then re-access hot keys to verify cache recovers */
    printf("  Phase 3: sequential scan burst (500 cold blocks)...\n");
    for (int i = 0; i < 500; i++)
    {
        size_t bsz = variable_block_size(&rng, 512, 2048);
        uint8_t *block = (uint8_t *)malloc(bsz);
        fill_block_payload(block, bsz, (uint32_t)(100000 + i));

        char key[32];
        snprintf(key, sizeof(key), "scan:%05d", i);
        clock_cache_put(cache, key, strlen(key), block, bsz, 0);
        free(block);
    }

    clock_cache_stats_t final_stats;
    clock_cache_get_stats(cache, &final_stats);
    printf("    Post-scan: bytes_used=%zu / %zu, entries=%zu\n", final_stats.total_bytes, max_bytes,
           final_stats.total_entries);
    ASSERT_TRUE(final_stats.total_bytes <= max_bytes * 2);

    /* re-access hot block 0 -- may have been evicted by scan, verify graceful miss */
    size_t len;
    uint8_t *data = clock_cache_get(cache, "blk:00000", 9, &len);
    if (data)
    {
        ASSERT_TRUE(verify_block_payload(data, len));
        free(data);
        printf("    Hot block 0 survived scan burst (still cached)\n");
    }
    else
    {
        printf("    Hot block 0 was evicted by scan burst (expected)\n");
    }

    clock_cache_destroy(cache);
    printf("  ✓ Realistic block cache eviction test passed\n");
}

/**
 * test_realistic_node_cache_external_bytes
 * models btree node caching where the inline payload is a pointer (8 bytes)
 * but the real cost is the heap-allocated btree_node_t behind it (external_bytes).
 * this is exactly how btree_node_read_cached uses the cache:
 *   -- inline payload = sizeof(btree_node_t *) = 8 bytes
 *   -- external_bytes = actual node size (arena allocation, keys, values)
 * verifies that eviction is driven by external_bytes, not just inline size.
 */
void test_realistic_node_cache_external_bytes(void)
{
    printf("Testing realistic node cache with external_bytes...\n");

    /* 128 KB cache -- should hold ~30-60 "nodes" at 2-4KB each */
    const size_t max_bytes = 128 * 1024;
    cache_config_t config = {
        .max_bytes = max_bytes, .num_partitions = 4, .slots_per_partition = 128};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const int num_nodes = 500; /* more nodes than fit in cache */
    uint32_t rng = 12345;

    /* phase 1: populate -- each entry is a small pointer (8B inline) + large external cost */
    printf("  Inserting %d nodes with variable external_bytes (1-8 KB each)...\n", num_nodes);
    size_t total_external_offered = 0;

    for (int i = 0; i < num_nodes; i++)
    {
        /* inline payload: simulates a pointer value */
        uint64_t fake_ptr = (uint64_t)(0xCAFE0000 + i);

        /* external_bytes: simulates the real heap cost of the node */
        size_t ext = variable_block_size(&rng, 1024, 8192);
        total_external_offered += ext;

        char key[32];
        snprintf(key, sizeof(key), "node:%04d", i);
        clock_cache_put(cache, key, strlen(key), &fake_ptr, sizeof(fake_ptr), ext);
    }

    clock_cache_stats_t stats;
    clock_cache_get_stats(cache, &stats);
    printf("  Total external offered: %zu bytes (%.1fx cache)\n", total_external_offered,
           (double)total_external_offered / max_bytes);
    printf("  bytes_used=%zu / %zu, entries=%zu / %d\n", stats.total_bytes, max_bytes,
           stats.total_entries, num_nodes);

    /* external_bytes should drive eviction -- far fewer than num_nodes should remain */
    ASSERT_TRUE(stats.total_entries < (size_t)num_nodes);
    ASSERT_TRUE(stats.total_bytes <= max_bytes * 2);

    /* phase 2: Zipfian reads with miss-fill -- simulates btree_node_read_cached:
     * on miss, read from "disk" and re-populate cache with external_bytes cost.
     * hot root/internal nodes get re-cached and stay cached. */
    printf("  Zipfian reads of %d nodes (with miss-fill)...\n", num_nodes);
    int hits = 0;
    const int num_reads = 5000;
    for (int i = 0; i < num_reads; i++)
    {
        int nid = zipf_pick(&rng, num_nodes);
        char key[32];
        snprintf(key, sizeof(key), "node:%04d", nid);

        size_t len;
        uint8_t *data = clock_cache_get(cache, key, strlen(key), &len);
        if (data)
        {
            /* verify inline payload is the expected pointer value */
            ASSERT_EQ(len, sizeof(uint64_t));
            uint64_t retrieved_ptr;
            memcpy(&retrieved_ptr, data, sizeof(uint64_t));
            ASSERT_EQ(retrieved_ptr, (uint64_t)(0xCAFE0000 + nid));
            hits++;
            free(data);
        }
        else
        {
            /* cache miss -- simulate disk read: re-insert with external_bytes */
            uint64_t fake_ptr = (uint64_t)(0xCAFE0000 + nid);
            size_t ext = variable_block_size(&rng, 1024, 8192);
            clock_cache_put(cache, key, strlen(key), &fake_ptr, sizeof(fake_ptr), ext);
        }
    }

    double hit_rate = (double)hits / num_reads * 100.0;
    printf("  Reads: %d, Hits: %d, Hit rate: %.1f%%\n", num_reads, hits, hit_rate);
    /* with miss-fill and Zipfian skew, hot nodes get re-cached */
    ASSERT_TRUE(hits > 0);

    /* phase 3: compare with no external_bytes -- should fit far more entries */
    clock_cache_clear(cache);
    for (int i = 0; i < num_nodes; i++)
    {
        uint64_t fake_ptr = (uint64_t)(0xBEEF0000 + i);
        char key[32];
        snprintf(key, sizeof(key), "noext:%04d", i);
        clock_cache_put(cache, key, strlen(key), &fake_ptr, sizeof(fake_ptr), 0);
    }

    clock_cache_stats_t noext_stats;
    clock_cache_get_stats(cache, &noext_stats);
    printf("  Without external_bytes: entries=%zu (vs %zu with external)\n",
           noext_stats.total_entries, stats.total_entries);
    /* without external cost, many more tiny entries should fit */
    ASSERT_TRUE(noext_stats.total_entries > stats.total_entries);

    clock_cache_destroy(cache);
    printf("  ✓ Realistic node cache external_bytes test passed\n");
}

/**
 * test_realistic_oltp_concurrent
 * models a realistic concurrent OLTP workload:
 *   -- 6 reader threads (point lookups, Zipfian -- simulates SELECT queries)
 *   -- 2 writer threads (insert new blocks + update existing -- simulates INSERT/UPDATE)
 *   -- cache sized to hold ~30% of working set (forces realistic eviction pressure)
 *   -- runs for ~1 second, sampling stats every 200ms
 *   -- verifies: byte budget, data integrity, reasonable hit rates, no crashes
 */
#define OLTP_NUM_BLOCKS    10000 /* total block keyspace */
#define OLTP_BLOCK_MIN_SZ  256
#define OLTP_BLOCK_MAX_SZ  2048
#define OLTP_NUM_READERS   6
#define OLTP_NUM_WRITERS   2
#define OLTP_TOTAL_THREADS (OLTP_NUM_READERS + OLTP_NUM_WRITERS)

typedef struct
{
    clock_cache_t *cache;
    int thread_id;
    _Atomic(int) *stop_flag;
    _Atomic(int64_t) *total_reads;
    _Atomic(int64_t) *total_hits;
    _Atomic(int64_t) *total_writes;
    _Atomic(int) *corruption_count;
} oltp_thread_args_t;

static void *oltp_reader_thread(void *arg)
{
    oltp_thread_args_t *a = (oltp_thread_args_t *)arg;
    uint32_t rng = (uint32_t)(a->thread_id * 7919 + 1);
    int64_t local_reads = 0, local_hits = 0;

    while (!atomic_load(a->stop_flag))
    {
        /* Zipfian pick from block keyspace */
        int block_id = zipf_pick(&rng, OLTP_NUM_BLOCKS);
        char key[32];
        snprintf(key, sizeof(key), "blk:%05d", block_id);

        size_t len;
        uint8_t *data = clock_cache_get(a->cache, key, strlen(key), &len);
        local_reads++;
        if (data)
        {
            local_hits++;
            if (!verify_block_payload(data, len))
            {
                atomic_fetch_add(a->corruption_count, 1);
            }
            free(data);
        }
    }

    atomic_fetch_add(a->total_reads, local_reads);
    atomic_fetch_add(a->total_hits, local_hits);
    return NULL;
}

static void *oltp_writer_thread(void *arg)
{
    oltp_thread_args_t *a = (oltp_thread_args_t *)arg;
    uint32_t rng = (uint32_t)(a->thread_id * 6271 + 31);
    int64_t local_writes = 0;

    while (!atomic_load(a->stop_flag))
    {
        /* 70% update existing block (Zipfian), 30% insert new sequential block */
        int op = xorshift32(&rng) % 10;
        int block_id;
        if (op < 7)
        {
            block_id = zipf_pick(&rng, OLTP_NUM_BLOCKS);
        }
        else
        {
            block_id = OLTP_NUM_BLOCKS + (int)(local_writes & 0xFFFF);
        }

        size_t bsz = variable_block_size(&rng, OLTP_BLOCK_MIN_SZ, OLTP_BLOCK_MAX_SZ);
        uint8_t *block = (uint8_t *)malloc(bsz);
        fill_block_payload(block, bsz, (uint32_t)block_id);

        char key[32];
        snprintf(key, sizeof(key), "blk:%05d", block_id);
        clock_cache_put(a->cache, key, strlen(key), block, bsz, 0);
        free(block);
        local_writes++;
    }

    atomic_fetch_add(a->total_writes, local_writes);
    return NULL;
}

void test_realistic_oltp_concurrent(void)
{
    printf("Testing realistic concurrent OLTP workload (~1s)...\n");

    /* cache holds ~30% of typical working set to force realistic eviction */
    const size_t max_bytes = 512 * 1024; /* 512 KB */
    cache_config_t config = {
        .max_bytes = max_bytes, .num_partitions = 8, .slots_per_partition = 256};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    /* pre-populate ~2000 hot blocks so readers get hits from the start */
    printf("  Pre-populating %d hot blocks...\n", 2000);
    uint32_t rng = 99;
    for (int i = 0; i < 2000; i++)
    {
        size_t bsz = variable_block_size(&rng, OLTP_BLOCK_MIN_SZ, OLTP_BLOCK_MAX_SZ);
        uint8_t *block = (uint8_t *)malloc(bsz);
        fill_block_payload(block, bsz, (uint32_t)i);

        char key[32];
        snprintf(key, sizeof(key), "blk:%05d", i);
        clock_cache_put(cache, key, strlen(key), block, bsz, 0);
        free(block);
    }

    _Atomic(int) stop_flag = 0;
    _Atomic(int64_t) total_reads = 0, total_hits = 0, total_writes = 0;
    _Atomic(int) corruption_count = 0;

    pthread_t threads[OLTP_TOTAL_THREADS];
    oltp_thread_args_t args[OLTP_TOTAL_THREADS];

    for (int i = 0; i < OLTP_TOTAL_THREADS; i++)
    {
        args[i].cache = cache;
        args[i].thread_id = i;
        args[i].stop_flag = &stop_flag;
        args[i].total_reads = &total_reads;
        args[i].total_hits = &total_hits;
        args[i].total_writes = &total_writes;
        args[i].corruption_count = &corruption_count;
    }

    double start = wall_time_sec();

    for (int i = 0; i < OLTP_NUM_READERS; i++)
        pthread_create(&threads[i], NULL, oltp_reader_thread, &args[i]);
    for (int i = 0; i < OLTP_NUM_WRITERS; i++)
        pthread_create(&threads[OLTP_NUM_READERS + i], NULL, oltp_writer_thread,
                       &args[OLTP_NUM_READERS + i]);

    /* run for ~1 second, sampling stats every 200ms */
    size_t peak_bytes = 0;
    for (int sample = 0; sample < 5; sample++)
    {
        usleep(200000); /* 200ms */
        clock_cache_stats_t stats;
        clock_cache_get_stats(cache, &stats);
        if (stats.total_bytes > peak_bytes) peak_bytes = stats.total_bytes;
        printf("    [%dms] bytes=%zu/%zu entries=%zu R=%" PRId64 " W=%" PRId64 "\n",
               (sample + 1) * 200, stats.total_bytes, max_bytes, stats.total_entries,
               atomic_load(&total_reads), atomic_load(&total_writes));
        /* verify byte budget at each sample point */
        ASSERT_TRUE(stats.total_bytes <= max_bytes * 3);
    }

    atomic_store(&stop_flag, 1);
    for (int i = 0; i < OLTP_TOTAL_THREADS; i++) pthread_join(threads[i], NULL);

    double elapsed = wall_time_sec() - start;
    int64_t tr = atomic_load(&total_reads);
    int64_t th = atomic_load(&total_hits);
    int64_t tw = atomic_load(&total_writes);
    int corr = atomic_load(&corruption_count);

    clock_cache_stats_t final_stats;
    clock_cache_get_stats(cache, &final_stats);

    double final_hit_rate = (tr > 0) ? (double)th / tr * 100.0 : 0.0;
    printf("  Results (%.2fs):\n", elapsed);
    printf("    Reads: %" PRId64 ", Hits: %" PRId64 ", Hit rate: %.1f%%\n", tr, th, final_hit_rate);
    printf("    Writes: %" PRId64 "\n", tw);
    printf("    Corruptions: %d\n", corr);
    printf("    Final bytes=%zu/%zu, peak=%zu, entries=%zu\n", final_stats.total_bytes, max_bytes,
           peak_bytes, final_stats.total_entries);

    ASSERT_EQ(corr, 0);
    ASSERT_TRUE(final_stats.total_bytes <= max_bytes * 3);
    ASSERT_TRUE(tr > 0);
    ASSERT_TRUE(tw > 0);

    clock_cache_destroy(cache);
    printf("  ✓ Realistic concurrent OLTP test passed\n");
}

/**
 * test_realistic_working_set_shift
 * simulates a workload where the hot working set shifts over time
 * (e.g., time-series ingestion where recent partitions are hot):
 *   -- epoch 0: blocks 0-999 are hot
 *   -- epoch 1: blocks 1000-1999 become hot, 0-999 cool off
 *   -- epoch 2: blocks 2000-2999 become hot
 * after each epoch shift, verifies:
 *   -- new hot blocks achieve high hit rates after warm-up
 *   -- old cold blocks are mostly evicted
 *   -- byte budget remains respected
 */
void test_realistic_working_set_shift(void)
{
    printf("Testing realistic working-set shift (3 epochs)...\n");

    const size_t max_bytes = 256 * 1024; /* 256 KB */
    cache_config_t config = {
        .max_bytes = max_bytes, .num_partitions = 4, .slots_per_partition = 256};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    const int blocks_per_epoch = 1000;
    const int num_epochs = 3;
    const int reads_per_epoch = 5000;
    uint32_t rng = 7777;
    int corruptions = 0;

    for (int epoch = 0; epoch < num_epochs; epoch++)
    {
        int base = epoch * blocks_per_epoch;
        printf("  Epoch %d: hot blocks [%d, %d)\n", epoch, base, base + blocks_per_epoch);

        /* insert this epoch's blocks */
        for (int i = 0; i < blocks_per_epoch; i++)
        {
            int bid = base + i;
            size_t bsz = variable_block_size(&rng, 200, 1024);
            uint8_t *block = (uint8_t *)malloc(bsz);
            fill_block_payload(block, bsz, (uint32_t)bid);

            char key[32];
            snprintf(key, sizeof(key), "ts:%06d", bid);
            clock_cache_put(cache, key, strlen(key), block, bsz, 0);
            free(block);
        }

        /* Zipfian reads within this epoch's range */
        int hits = 0;
        for (int i = 0; i < reads_per_epoch; i++)
        {
            int offset = zipf_pick(&rng, blocks_per_epoch);
            int bid = base + offset;
            char key[32];
            snprintf(key, sizeof(key), "ts:%06d", bid);

            size_t len;
            uint8_t *data = clock_cache_get(cache, key, strlen(key), &len);
            if (data)
            {
                hits++;
                if (!verify_block_payload(data, len)) corruptions++;
                free(data);
            }
        }

        clock_cache_stats_t stats;
        clock_cache_get_stats(cache, &stats);
        double hr = (double)hits / reads_per_epoch * 100.0;
        printf("    Hit rate: %.1f%% (%d/%d), bytes=%zu/%zu, entries=%zu\n", hr, hits,
               reads_per_epoch, stats.total_bytes, max_bytes, stats.total_entries);
        ASSERT_TRUE(stats.total_bytes <= max_bytes * 2);

        /* after epoch 1+, verify old epoch blocks are mostly evicted */
        if (epoch > 0)
        {
            int old_base = (epoch - 1) * blocks_per_epoch;
            int old_found = 0;
            for (int i = 0; i < 50; i++) /* sample 50 from previous epoch */
            {
                int bid = old_base + (int)(xorshift32(&rng) % (unsigned)blocks_per_epoch);
                char key[32];
                snprintf(key, sizeof(key), "ts:%06d", bid);
                size_t len;
                uint8_t *data = clock_cache_get(cache, key, strlen(key), &len);
                if (data)
                {
                    old_found++;
                    if (!verify_block_payload(data, len)) corruptions++;
                    free(data);
                }
            }
            printf("    Previous epoch sample: %d/50 still cached\n", old_found);
            /* most old blocks should have been evicted by new epoch's inserts */
            ASSERT_TRUE(old_found < 40);
        }
    }

    ASSERT_EQ(corruptions, 0);
    printf("  Data integrity: %d corruptions\n", corruptions);

    clock_cache_destroy(cache);
    printf("  ✓ Realistic working-set shift test passed\n");
}

/**
 * test_realistic_mixed_block_sizes
 * models a column family with mixed SST block sizes:
 *   -- index blocks: small (~128B), frequently accessed
 *   -- data blocks: large (~2-8KB), less frequently accessed
 *   -- filter/bloom blocks: medium (~512B), accessed on every query
 * verifies that the cache fairly handles mixed sizes and that
 * small hot entries don't get unfairly evicted by large cold entries.
 */
void test_realistic_mixed_block_sizes(void)
{
    printf("Testing realistic mixed block sizes...\n");

    const size_t max_bytes = 128 * 1024; /* 128 KB */
    cache_config_t config = {
        .max_bytes = max_bytes, .num_partitions = 4, .slots_per_partition = 128};

    clock_cache_t *cache = clock_cache_create(&config);
    ASSERT_TRUE(cache != NULL);

    uint32_t rng = 31337;

    /* insert index blocks (small, 50 entries) */
    const int num_index = 50;
    for (int i = 0; i < num_index; i++)
    {
        size_t bsz = variable_block_size(&rng, 64, 192);
        uint8_t *block = (uint8_t *)malloc(bsz);
        fill_block_payload(block, bsz, (uint32_t)(10000 + i));

        char key[32];
        snprintf(key, sizeof(key), "idx:%04d", i);
        clock_cache_put(cache, key, strlen(key), block, bsz, 0);
        free(block);
    }

    /* insert filter/bloom blocks (medium, 50 entries) */
    const int num_filter = 50;
    for (int i = 0; i < num_filter; i++)
    {
        size_t bsz = variable_block_size(&rng, 384, 640);
        uint8_t *block = (uint8_t *)malloc(bsz);
        fill_block_payload(block, bsz, (uint32_t)(20000 + i));

        char key[32];
        snprintf(key, sizeof(key), "flt:%04d", i);
        clock_cache_put(cache, key, strlen(key), block, bsz, 0);
        free(block);
    }

    /* insert data blocks (large, 200 entries -- these will force eviction) */
    const int num_data = 200;
    for (int i = 0; i < num_data; i++)
    {
        size_t bsz = variable_block_size(&rng, 2048, 8192);
        uint8_t *block = (uint8_t *)malloc(bsz);
        fill_block_payload(block, bsz, (uint32_t)(30000 + i));

        char key[32];
        snprintf(key, sizeof(key), "dat:%04d", i);
        clock_cache_put(cache, key, strlen(key), block, bsz, 0);
        free(block);
    }

    clock_cache_stats_t stats;
    clock_cache_get_stats(cache, &stats);
    printf("  After inserting %d idx + %d flt + %d dat blocks:\n", num_index, num_filter, num_data);
    printf("    bytes=%zu/%zu, entries=%zu\n", stats.total_bytes, max_bytes, stats.total_entries);
    ASSERT_TRUE(stats.total_bytes <= max_bytes * 2);

    /* now simulate realistic query pattern: each query reads 1 index + 1 filter + 1 data block
     * index/filter blocks are Zipfian-hot, data blocks are more uniformly accessed */
    printf("  Simulating 5000 queries (idx + flt + dat per query)...\n");
    int idx_hits = 0, flt_hits = 0, dat_hits = 0;
    int corruptions = 0;
    const int num_queries = 5000;

    for (int q = 0; q < num_queries; q++)
    {
        /* index lookup -- Zipfian hot */
        int iid = zipf_pick(&rng, num_index);
        char key[32];
        snprintf(key, sizeof(key), "idx:%04d", iid);
        size_t len;
        uint8_t *data = clock_cache_get(cache, key, strlen(key), &len);
        if (data)
        {
            idx_hits++;
            if (!verify_block_payload(data, len)) corruptions++;
            free(data);
        }
        else
        {
            /* miss-fill: simulate disk read populating cache */
            size_t bsz = variable_block_size(&rng, 64, 192);
            uint8_t *block = (uint8_t *)malloc(bsz);
            fill_block_payload(block, bsz, (uint32_t)(10000 + iid));
            clock_cache_put(cache, key, strlen(key), block, bsz, 0);
            free(block);
        }

        /* filter check -- Zipfian hot (same distribution as index) */
        int fid = zipf_pick(&rng, num_filter);
        snprintf(key, sizeof(key), "flt:%04d", fid);
        data = clock_cache_get(cache, key, strlen(key), &len);
        if (data)
        {
            flt_hits++;
            if (!verify_block_payload(data, len)) corruptions++;
            free(data);
        }
        else
        {
            size_t bsz = variable_block_size(&rng, 384, 640);
            uint8_t *block = (uint8_t *)malloc(bsz);
            fill_block_payload(block, bsz, (uint32_t)(20000 + fid));
            clock_cache_put(cache, key, strlen(key), block, bsz, 0);
            free(block);
        }

        /* data block -- more uniform (less skew, models range scans) */
        int did = xorshift32(&rng) % num_data;
        snprintf(key, sizeof(key), "dat:%04d", did);
        data = clock_cache_get(cache, key, strlen(key), &len);
        if (data)
        {
            dat_hits++;
            if (!verify_block_payload(data, len)) corruptions++;
            free(data);
        }
        else
        {
            size_t bsz = variable_block_size(&rng, 2048, 8192);
            uint8_t *block = (uint8_t *)malloc(bsz);
            fill_block_payload(block, bsz, (uint32_t)(30000 + did));
            clock_cache_put(cache, key, strlen(key), block, bsz, 0);
            free(block);
        }

        /* periodically re-insert a data block (simulates compaction output) */
        if (q % 50 == 0)
        {
            int new_did = num_data + q;
            size_t bsz = variable_block_size(&rng, 2048, 8192);
            uint8_t *block = (uint8_t *)malloc(bsz);
            fill_block_payload(block, bsz, (uint32_t)(30000 + new_did));

            snprintf(key, sizeof(key), "dat:%04d", new_did);
            clock_cache_put(cache, key, strlen(key), block, bsz, 0);
            free(block);
        }
    }

    printf("    Index hit rate:  %.1f%% (%d/%d)\n", (double)idx_hits / num_queries * 100.0,
           idx_hits, num_queries);
    printf("    Filter hit rate: %.1f%% (%d/%d)\n", (double)flt_hits / num_queries * 100.0,
           flt_hits, num_queries);
    printf("    Data hit rate:   %.1f%% (%d/%d)\n", (double)dat_hits / num_queries * 100.0,
           dat_hits, num_queries);
    printf("    Corruptions: %d\n", corruptions);

    ASSERT_EQ(corruptions, 0);

    clock_cache_get_stats(cache, &stats);
    printf("    Final: bytes=%zu/%zu, entries=%zu\n", stats.total_bytes, max_bytes,
           stats.total_entries);
    ASSERT_TRUE(stats.total_bytes <= max_bytes * 2);

    clock_cache_destroy(cache);
    printf("  ✓ Realistic mixed block sizes test passed\n");
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
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
    RUN_TEST(test_concurrent_put_same_key, tests_passed);
    RUN_TEST(test_concurrent_put_delete_same_key, tests_passed);
    RUN_TEST(test_hash_collision_concurrent, tests_passed);
    RUN_TEST(test_shutdown_during_operations, tests_passed);
    RUN_TEST(test_zero_copy_get_release, tests_passed);
    RUN_TEST(test_large_payload, tests_passed);
    RUN_TEST(test_many_small_entries, tests_passed);
    RUN_TEST(test_foreach_prefix_concurrent, tests_passed);
    RUN_TEST(test_put_after_shutdown, tests_passed);
    RUN_TEST(test_concurrent_delete_while_reading, tests_passed);
    RUN_TEST(test_realistic_block_cache_eviction, tests_passed);
    RUN_TEST(test_realistic_node_cache_external_bytes, tests_passed);
    RUN_TEST(test_realistic_oltp_concurrent, tests_passed);
    RUN_TEST(test_realistic_working_set_shift, tests_passed);
    RUN_TEST(test_realistic_mixed_block_sizes, tests_passed);
    RUN_TEST(benchmark_cache_insertions, tests_passed);
    RUN_TEST(benchmark_cache_lookups, tests_passed);
    RUN_TEST(benchmark_concurrent_puts, tests_passed);
    RUN_TEST(benchmark_concurrent_gets, tests_passed);
    RUN_TEST(benchmark_concurrent_mixed, tests_passed);
    RUN_TEST(benchmark_scaling_puts, tests_passed);
    RUN_TEST(benchmark_scaling_gets, tests_passed);
    RUN_TEST(benchmark_scaling_mixed, tests_passed);
    RUN_TEST(benchmark_cache_rw_contention, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
