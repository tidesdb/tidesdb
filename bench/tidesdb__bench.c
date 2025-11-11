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
#include "../src/tidesdb.h"
#include "../test/test_utils.h"

/*
 * thread_data_t
 * data structure for passing to threads
 * @param tdb pointer to tidesdb instance
 * @param keys array of keys
 * @param values array of values
 * @param key_sizes array of key sizes
 * @param value_sizes array of value sizes
 * @param start start index
 */
typedef struct
{
    tidesdb_t *tdb;
    uint8_t **keys;
    uint8_t **values;
    size_t *key_sizes;
    size_t *value_sizes;
    int start;
    int end;
    int thread_id;
} thread_data_t;

/*
 * generate_sequential_key
 * generates a sequential key based on index
 * format: key_<16-digit-padded-number>
 */
void generate_sequential_key(uint8_t *buffer, size_t size, int index)
{
    snprintf((char *)buffer, size, "key_%016d", index);
}

/*
 * generate_random_key
 * generates a random alphanumeric key
 */
void generate_random_key(uint8_t *buffer, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < size - 1; i++)
    {
        buffer[i] = (uint8_t)charset[rand() % (int)(sizeof(charset) - 1)];
    }
    buffer[size - 1] = '\0';
}

/*
 * zipfian_next
 * generates a zipfian-distributed number (80/20 rule)
 * 80% of accesses go to 20% of keys
 */
int zipfian_next(int max_value)
{
    double random = (double)rand() / RAND_MAX;

    /* simple zipfian approximation */
    if (random < 0.8)
    {
        /* 80% of accesses go to first 20% of keys */
        return rand() % (max_value / 5);
    }
    else
    {
        /* 20% of accesses go to remaining 80% of keys */
        return (max_value / 5) + (rand() % (max_value - max_value / 5));
    }
}

/*
 * generate_zipfian_key
 * generates a key following zipfian distribution
 */
void generate_zipfian_key(uint8_t *buffer, size_t size, int max_index)
{
    int index = zipfian_next(max_index);
    snprintf((char *)buffer, size, "key_%016d", index);
}

void generate_random_string(uint8_t *buffer, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < size - 1; i++)
    {
        buffer[i] = (uint8_t)charset[rand() % (int)(sizeof(charset) - 1)];
    }

    buffer[size - 1] = '\0';
}

double get_time_ms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((double)tv.tv_sec * 1000.0) + ((double)tv.tv_usec / 1000.0);
}

void *thread_put(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;

    for (int i = data->start; i < data->end; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(data->tdb, &txn) != 0)
        {
            printf(BOLDRED "Failed to begin transaction\n" RESET);
            continue;
        }

        if (tidesdb_txn_put(txn, BENCH_CF_NAME, data->keys[i], data->key_sizes[i], data->values[i],
                            data->value_sizes[i], -1) != 0)
        {
            printf(BOLDRED "Put operation failed\n" RESET);
            tidesdb_txn_free(txn);
            continue;
        }

        if (tidesdb_txn_commit(txn) != 0)
        {
            printf(BOLDRED "Failed to commit transaction\n" RESET);
        }
        tidesdb_txn_free(txn);
    }

    return NULL;
}

void *thread_get(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;

    for (int i = data->start; i < data->end; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin_read(data->tdb, &txn) != 0)
        {
            printf(BOLDRED "Failed to begin read transaction\n" RESET);
            continue;
        }

        uint8_t *value_out = NULL;
        size_t value_len = 0;

        if (tidesdb_txn_get(txn, BENCH_CF_NAME, data->keys[i], data->key_sizes[i], &value_out,
                            &value_len) == 0)
        {
            free(value_out);
        }

        tidesdb_txn_free(txn);
    }

    return NULL;
}

void *thread_delete(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;

    for (int i = data->start; i < data->end; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(data->tdb, &txn) != 0)
        {
            printf(BOLDRED "Failed to begin transaction\n" RESET);
            continue;
        }

        if (tidesdb_txn_delete(txn, BENCH_CF_NAME, data->keys[i], data->key_sizes[i]) != 0)
        {
            printf(BOLDRED "Delete operation failed\n" RESET);
            tidesdb_txn_free(txn);
            continue;
        }

        if (tidesdb_txn_commit(txn) != 0)
        {
            printf(BOLDRED "Failed to commit transaction\n" RESET);
        }
        tidesdb_txn_free(txn);
    }

    return NULL;
}

void *thread_iter_forward(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin_read(data->tdb, &txn) != 0)
    {
        printf(BOLDRED "Failed to begin read transaction\n" RESET);
        return NULL;
    }

    tidesdb_iter_t *iter = NULL;
    if (tidesdb_iter_new(txn, BENCH_CF_NAME, &iter) != 0)
    {
        printf(BOLDRED "Failed to create iterator\n" RESET);
        tidesdb_txn_free(txn);
        return NULL;
    }

    if (tidesdb_iter_seek_to_first(iter) == 0)
    {
        while (tidesdb_iter_valid(iter))
        {
            if (tidesdb_iter_next(iter) != 0) break;
        }
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);

    return NULL;
}

void *thread_iter_backward(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;

    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin_read(data->tdb, &txn) != 0)
    {
        printf(BOLDRED "Failed to begin read transaction\n" RESET);
        return NULL;
    }

    tidesdb_iter_t *iter = NULL;
    if (tidesdb_iter_new(txn, BENCH_CF_NAME, &iter) != 0)
    {
        printf(BOLDRED "Failed to create iterator\n" RESET);
        tidesdb_txn_free(txn);
        return NULL;
    }

    if (tidesdb_iter_seek_to_last(iter) == 0)
    {
        while (tidesdb_iter_valid(iter))
        {
            if (tidesdb_iter_prev(iter) != 0) break;
        }
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);

    return NULL;
}

void *thread_iter_seek(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;

    tidesdb_txn_t *txn = NULL;

    if (tidesdb_txn_begin_read(data->tdb, &txn) != 0)
    {
        printf(BOLDRED "[Thread %d] Failed to begin transaction\n" RESET, data->thread_id);
        return NULL;
    }

    /* seed random number generator with thread id for different sequences per thread */
    srand(time(NULL) + data->thread_id);

    int num_seeks = data->end - data->start;
    for (int i = 0; i < num_seeks; i++)
    {
        /* create a new iterator for each seek (more realistic benchmark) */
        tidesdb_iter_t *iter = NULL;
        if (tidesdb_iter_new(txn, BENCH_CF_NAME, &iter) != 0)
        {
            continue;
        }

        /* random seek to an existing key */
        int random_idx = data->start + (rand() % (data->end - data->start));
        tidesdb_iter_seek(iter, data->keys[random_idx], data->key_sizes[random_idx]);
        if (tidesdb_iter_valid(iter))
        {
            uint8_t *key = NULL, *value = NULL;
            size_t key_size = 0, value_size = 0;
            tidesdb_iter_key(iter, &key, &key_size);
            tidesdb_iter_value(iter, &value, &value_size);
        }

        tidesdb_iter_free(iter);
    }
    tidesdb_txn_free(txn);

    return NULL;
}

int main()
{
    remove_directory(BENCH_DB_PATH);
    tidesdb_t *tdb = NULL;
    double start_time, end_time;

    srand((unsigned int)time(NULL));

    /* print benchmark configuration */
    printf(BOLDCYAN "\n=== TidesDB Benchmark Configuration ===\n" RESET);
    printf("Operations: %d\n", BENCH_NUM_OPERATIONS);
    printf("Seek Operations: %d\n", BENCH_NUM_SEEK_OPS);
    printf("Key Size: %d bytes\n", BENCH_KEY_SIZE);
    printf("Value Size: %d bytes\n", BENCH_VALUE_SIZE);
    printf("Threads: %d\n", BENCH_NUM_THREADS);
    printf("Debug Logging: %s\n", BENCH_DEBUG ? "enabled" : "disabled");
    printf("Key Pattern: %s\n", BENCH_KEY_PATTERN);
    printf("Compression: %s\n", BENCH_ENABLE_COMPRESSION ? "enabled" : "disabled");
    printf("Bloom Filter: %s\n", BENCH_ENABLE_BLOOM_FILTER ? "enabled" : "disabled");
    printf("Block Indexes: %s\n", BENCH_ENABLE_BLOCK_INDEXES ? "enabled" : "disabled");
    printf("======================================\n\n" RESET);

    uint8_t **keys = malloc(BENCH_NUM_OPERATIONS * sizeof(uint8_t *));
    if (keys == NULL)
    {
        printf(BOLDRED "Failed to allocate memory for keys array\n" RESET);
        return 1;
    }

    uint8_t **values = malloc(BENCH_NUM_OPERATIONS * sizeof(uint8_t *));
    if (values == NULL)
    {
        printf(BOLDRED "Failed to allocate memory for values array\n" RESET);
        free(keys);
        return 1;
    }

    size_t *key_sizes = malloc(BENCH_NUM_OPERATIONS * sizeof(size_t));
    if (key_sizes == NULL)
    {
        printf(BOLDRED "Failed to allocate memory for key sizes array\n" RESET);
        free(keys);
        free(values);
        return 1;
    }

    size_t *value_sizes = malloc(BENCH_NUM_OPERATIONS * sizeof(size_t));
    if (value_sizes == NULL)
    {
        printf(BOLDRED "Failed to allocate memory for value sizes array\n" RESET);
        free(keys);
        free(values);
        free(key_sizes);
        return 1;
    }

    for (int i = 0; i < BENCH_NUM_OPERATIONS; i++)
    {
        keys[i] = malloc(BENCH_KEY_SIZE);
        if (keys[i] == NULL)
        {
            printf(BOLDRED "Failed to allocate memory for key %d\n" RESET, i);
            for (int j = 0; j < i; j++)
            {
                free(keys[j]);
                free(values[j]);
            }
            free(keys);
            free(values);
            free(key_sizes);
            free(value_sizes);
            return 1;
        }

        /* generate key based on selected pattern */
        if (strcmp(BENCH_KEY_PATTERN, "sequential") == 0)
        {
            generate_sequential_key(keys[i], BENCH_KEY_SIZE, i);
        }
        else if (strcmp(BENCH_KEY_PATTERN, "zipfian") == 0)
        {
            generate_zipfian_key(keys[i], BENCH_KEY_SIZE, BENCH_NUM_OPERATIONS);
        }
        else /* default to random */
        {
            generate_random_key(keys[i], BENCH_KEY_SIZE);
        }
        key_sizes[i] = strlen((char *)keys[i]);

        values[i] = malloc(BENCH_VALUE_SIZE);
        if (values[i] == NULL)
        {
            printf(BOLDRED "Failed to allocate memory for value %d\n" RESET, i);
            free(keys[i]);
            for (int j = 0; j < i; j++)
            {
                free(keys[j]);
                free(values[j]);
            }
            free(keys);
            free(values);
            free(key_sizes);
            free(value_sizes);
            return 1;
        }
        generate_random_string(values[i], BENCH_VALUE_SIZE);
        value_sizes[i] = BENCH_VALUE_SIZE - 1;
    }

    tidesdb_config_t config = {.db_path = BENCH_DB_PATH, .enable_debug_logging = BENCH_DEBUG};
    if (tidesdb_open(&config, &tdb) != 0)
    {
        printf(BOLDRED "Failed to open database\n" RESET);

        for (int i = 0; i < BENCH_NUM_OPERATIONS; i++)
        {
            free(keys[i]);
            free(values[i]);
        }
        free(keys);
        free(values);
        free(key_sizes);
        free(value_sizes);
        return 1;
    }

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.memtable_flush_size = BENCH_MEMTABLE_FLUSH_SIZE;
    cf_config.max_sstables_before_compaction = BENCH_MAX_SSTABLES_BEFORE_COMPACTION;
    cf_config.compaction_threads = BENCH_COMPACTION_THREADS;
    cf_config.sl_max_level = BENCH_SL_MAX_LEVEL;
    cf_config.sl_probability = BENCH_SL_PROBABILITY;
    cf_config.enable_compression = BENCH_ENABLE_COMPRESSION;
    cf_config.compression_algorithm = BENCH_COMPRESSION_ALGORITHM;
    cf_config.enable_bloom_filter = BENCH_ENABLE_BLOOM_FILTER;
    cf_config.bloom_filter_fp_rate = BENCH_BLOOM_FILTER_FP_RATE;
    cf_config.enable_background_compaction = BENCH_ENABLE_BACKGROUND_COMPACTION;
    cf_config.background_compaction_interval = BENCH_BACKGROUND_COMPACTION_INTERVAL;
    cf_config.enable_block_indexes = BENCH_ENABLE_BLOCK_INDEXES;
    cf_config.sync_mode = BENCH_SYNC_MODE;
    strncpy(cf_config.comparator_name, BENCH_COMPARATOR_NAME, TDB_MAX_COMPARATOR_NAME - 1);
    cf_config.comparator_name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';

    if (tidesdb_create_column_family(tdb, BENCH_CF_NAME, &cf_config) != 0)
    {
        printf(BOLDRED "Failed to create column family\n" RESET);

        for (int i = 0; i < BENCH_NUM_OPERATIONS; i++)
        {
            free(keys[i]);
            free(values[i]);
        }
        free(keys);
        free(values);
        free(key_sizes);
        free(value_sizes);
        tidesdb_close(tdb);
        return 1;
    }

    pthread_t threads[BENCH_NUM_THREADS];
    thread_data_t thread_data[BENCH_NUM_THREADS];

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        thread_data[i].tdb = tdb;
        thread_data[i].keys = keys;
        thread_data[i].values = values;
        thread_data[i].key_sizes = key_sizes;
        thread_data[i].value_sizes = value_sizes;
        thread_data[i].start = i * (BENCH_NUM_OPERATIONS / BENCH_NUM_THREADS);
        thread_data[i].end = (i + 1) * (BENCH_NUM_OPERATIONS / BENCH_NUM_THREADS);
    }

    printf(BOLDGREEN "\nBenchmarking Put operations...\n" RESET);
    start_time = get_time_ms();

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_put, &thread_data[i]);
    }

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }

    end_time = get_time_ms();
    printf(BOLDGREEN "Put: %d operations in %.2f ms (%.2f ops/sec)\n" RESET, BENCH_NUM_OPERATIONS,
           end_time - start_time, (BENCH_NUM_OPERATIONS / (end_time - start_time)) * 1000);

    printf(BOLDGREEN "\nBenchmarking Get operations...\n" RESET);
    start_time = get_time_ms();

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_get, &thread_data[i]);
    }

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }

    end_time = get_time_ms();
    printf(BOLDGREEN "Get: %d operations in %.2f ms (%.2f ops/sec)\n" RESET, BENCH_NUM_OPERATIONS,
           end_time - start_time, (BENCH_NUM_OPERATIONS / (end_time - start_time)) * 1000);

    printf(BOLDGREEN "\nBenchmarking Delete operations...\n" RESET);
    start_time = get_time_ms();

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_delete, &thread_data[i]);
    }

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }

    end_time = get_time_ms();
    printf(BOLDGREEN "Delete: %d operations in %.2f ms (%.2f ops/sec)\n" RESET,
           BENCH_NUM_OPERATIONS, end_time - start_time,
           (BENCH_NUM_OPERATIONS / (end_time - start_time)) * 1000);

    printf(BOLDGREEN "\nRe-populating data for iterator benchmarks...\n" RESET);
    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_put, &thread_data[i]);
    }
    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }

    printf(BOLDGREEN "\nBenchmarking Forward Iterator (full scan)...\n" RESET);
    start_time = get_time_ms();

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_iter_forward, &thread_data[i]);
    }

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }

    end_time = get_time_ms();
    printf(BOLDGREEN "Forward Iterator: %d threads in %.2f ms (%.2f ops/sec)\n" RESET,
           BENCH_NUM_THREADS, end_time - start_time,
           (BENCH_NUM_OPERATIONS / (end_time - start_time)) * 1000);

    printf(BOLDGREEN "\nBenchmarking Backward Iterator (full scan)...\n" RESET);
    start_time = get_time_ms();

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_iter_backward, &thread_data[i]);
    }

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }

    end_time = get_time_ms();
    printf(BOLDGREEN "Backward Iterator: %d threads in %.2f ms (%.2f ops/sec)\n" RESET,
           BENCH_NUM_THREADS, end_time - start_time,
           (BENCH_NUM_OPERATIONS / (end_time - start_time)) * 1000);

    printf(BOLDGREEN "\nBenchmarking Iterator Seek operations...\n" RESET);

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        thread_data[i].start = i * (BENCH_NUM_SEEK_OPS / BENCH_NUM_THREADS);
        thread_data[i].end = (i + 1) * (BENCH_NUM_SEEK_OPS / BENCH_NUM_THREADS);
        thread_data[i].thread_id = i;
    }

    start_time = get_time_ms();

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_iter_seek, &thread_data[i]);
    }

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }

    end_time = get_time_ms();
    printf(BOLDGREEN "Iterator Seek: %d operations in %.2f ms (%.2f ops/sec)\n" RESET,
           BENCH_NUM_SEEK_OPS, end_time - start_time,
           (BENCH_NUM_SEEK_OPS / (end_time - start_time)) * 1000);

    if (tidesdb_drop_column_family(tdb, BENCH_CF_NAME) != 0)
    {
        printf(BOLDRED "Failed to drop column family\n" RESET);
    }

    tidesdb_close(tdb);

    for (int i = 0; i < BENCH_NUM_OPERATIONS; i++)
    {
        free(keys[i]);
        free(values[i]);
    }
    free(keys);
    free(values);
    free(key_sizes);
    free(value_sizes);

    remove_directory(BENCH_DB_PATH);

    printf(MAGENTA "\nCleanup completed\n" RESET);
    return 0;
}