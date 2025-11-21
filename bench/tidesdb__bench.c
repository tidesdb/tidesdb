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
#include "../src/tidesdb.h"
#include "../test/test_utils.h"

/**
 * thread_data_t
 * data structure for passing to threads
 * @param tdb pointer to tidesdb instance
 * @param keys array of keys
 * @param values array of values
 * @param key_sizes array of key sizes
 * @param value_sizes array of value sizes
 * @param start start index
 * @param end end index
 * @param thread_id thread id
 */
typedef struct
{
    tidesdb_t *tdb;
    tidesdb_column_family_t *cf;
    uint8_t **keys;
    uint8_t **values;
    size_t *key_sizes;
    size_t *value_sizes;
    int start;
    int end;
    int thread_id;
} thread_data_t;

/**
 * generate_sequential_key
 * generates a sequential key based on index
 * format: key_<16-digit-padded-number>
 * @param buffer buffer to store key
 * @param size size of buffer
 * @param index index of key
 */
void generate_sequential_key(uint8_t *buffer, size_t size, int index)
{
    snprintf((char *)buffer, size, "key_%016d", index);
}

/**
 * generate_random_key
 * generates a random alphanumeric key
 * @param buffer buffer to store key
 * @param size size of buffer
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

/**
 * zipfian_next
 * generates a zipfian-distributed number (80/20 rule)
 * 80% of accesses go to 20% of keys
 * @param max_value maximum value
 * @return zipfian-distributed number
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
    /* 20% of accesses go to remaining 80% of keys */
    return (max_value / 5) + (rand() % (max_value - max_value / 5));
}

/**
 * generate_zipfian_key
 * generates a key following zipfian distribution
 * @param buffer buffer to store key
 * @param size size of buffer
 * @param max_index maximum index
 */
void generate_zipfian_key(uint8_t *buffer, size_t size, int max_index)
{
    int index = zipfian_next(max_index);
    snprintf((char *)buffer, size, "key_%016d", index);
}

/**
 * generate_random_string
 * generates a random string
 * @param buffer buffer to store string
 * @param size size of buffer
 */
void generate_random_string(uint8_t *buffer, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < size - 1; i++)
    {
        buffer[i] = (uint8_t)charset[rand() % (int)(sizeof(charset) - 1)];
    }

    buffer[size - 1] = '\0';
}

/**
 * get_time_ms
 * gets the current time in milliseconds
 * @return current time in milliseconds
 */
double get_time_ms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((double)tv.tv_sec * 1000.0) + ((double)tv.tv_usec / 1000.0);
}

/**
 * thread_put
 * puts data into the database
 * @param arg thread data
 * @return NULL
 */
void *thread_put(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    const int BATCH_SIZE = 1000;

    for (int i = data->start; i < data->end;)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(data->tdb, data->cf, &txn) != 0)
        {
            continue;
        }

        /* batch multiple operations in one transaction */
        int batch_end = i + BATCH_SIZE;
        if (batch_end > data->end) batch_end = data->end;

        for (int j = i; j < batch_end; j++)
        {
            if (tidesdb_txn_put(txn, data->keys[j], data->key_sizes[j], data->values[j],
                                data->value_sizes[j], 0) != 0)
            {
                printf(BOLDRED "Put operation failed\n" RESET);
                break;
            }
        }

        if (tidesdb_txn_commit(txn) != 0)
        {
            printf(BOLDRED "Failed to commit transaction\n" RESET);
        }

        tidesdb_txn_free(txn);
        i = batch_end;
    }

    return NULL;
}

/**
 * thread_get
 * gets data from the database
 * @param arg thread data
 * @return NULL
 */
void *thread_get(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    const int BATCH_SIZE = 1000;

    for (int i = data->start; i < data->end;)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(data->tdb, data->cf, &txn) != 0)
        {
            printf(BOLDRED "Failed to begin read transaction\n" RESET);
            continue;
        }

        /* batch multiple reads in one transaction */
        int batch_end = i + BATCH_SIZE;
        if (batch_end > data->end) batch_end = data->end;

        for (int j = i; j < batch_end; j++)
        {
            uint8_t *value_out = NULL;
            size_t value_len = 0;

            if (tidesdb_txn_get(txn, data->keys[j], data->key_sizes[j], &value_out, &value_len) ==
                0)
            {
                free(value_out);
            }
        }

        tidesdb_txn_free(txn);
        i = batch_end;
    }

    return NULL;
}

/**
 * thread_delete
 * deletes data from the database
 * @param arg thread data
 * @return NULL
 */
void *thread_delete(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    const int BATCH_SIZE = 1000;

    for (int i = data->start; i < data->end;)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(data->tdb, data->cf, &txn) != 0)
        {
            printf(BOLDRED "Failed to begin transaction\n" RESET);
            continue;
        }

        /* batch multiple deletes in one transaction */
        int batch_end = i + BATCH_SIZE;
        if (batch_end > data->end) batch_end = data->end;

        for (int j = i; j < batch_end; j++)
        {
            if (tidesdb_txn_delete(txn, data->keys[j], data->key_sizes[j]) != 0)
            {
                printf(BOLDRED "Delete operation failed\n" RESET);
                break;
            }
        }

        if (tidesdb_txn_commit(txn) != 0)
        {
            printf(BOLDRED "Failed to commit transaction\n" RESET);
        }
        tidesdb_txn_free(txn);
        i = batch_end;
    }

    return NULL;
}

/**
 * thread_iter_forward
 * iterates forward through the database
 * @param arg thread data
 * @return NULL
 */
void *thread_iter_forward(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin(data->tdb, data->cf, &txn) != 0)
    {
        printf(BOLDRED "Failed to begin read transaction\n" RESET);
        return NULL;
    }

    tidesdb_iter_t *iter = NULL;
    if (tidesdb_iter_new(txn, &iter) != 0)
    {
        printf(BOLDRED "Failed to create iterator\n" RESET);
        tidesdb_txn_free(txn);
        return NULL;
    }

    if (tidesdb_iter_seek_to_first(iter) == 0)
    {
        do
        {
            /* process current entry (in real code) */
        } while (tidesdb_iter_next(iter) == 0 && tidesdb_iter_valid(iter));
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);

    return NULL;
}

/**
 * thread_iter_backward
 * iterates backward through the database
 * @param arg thread data
 * @return NULL
 */
void *thread_iter_backward(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;

    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin(data->tdb, data->cf, &txn) != 0)
    {
        printf(BOLDRED "Failed to begin read transaction\n" RESET);
        return NULL;
    }

    tidesdb_iter_t *iter = NULL;
    if (tidesdb_iter_new(txn, &iter) != 0)
    {
        printf(BOLDRED "Failed to create iterator\n" RESET);
        tidesdb_txn_free(txn);
        return NULL;
    }

    if (tidesdb_iter_seek_to_last(iter) == 0)
    {
        do
        {
            /* process current entry (in real code) */
        } while (tidesdb_iter_prev(iter) == 0 && tidesdb_iter_valid(iter));
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);

    return NULL;
}

/**
 * thread_iter_seek
 * iterates to a specific key in the database
 * @param arg thread data
 * @return NULL
 */
void *thread_iter_seek(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;

    tidesdb_txn_t *txn = NULL;

    if (tidesdb_txn_begin(data->tdb, data->cf, &txn) != 0)
    {
        printf(BOLDRED "[Thread %d] Failed to begin transaction\n" RESET, data->thread_id);
        return NULL;
    }

    /* seed random number generator with thread id for different sequences per thread */
    srand(time(NULL) + data->thread_id);

    /* create iterator once and reuse for all seeks */
    tidesdb_iter_t *iter = NULL;
    if (tidesdb_iter_new(txn, &iter) != 0)
    {
        printf(BOLDRED "[Thread %d] Failed to create iterator\n" RESET, data->thread_id);
        tidesdb_txn_free(txn);
        return NULL;
    }

    /* perform BENCH_NUM_SEEK_OPS seeks to random keys from the dataset */
    int num_seeks = BENCH_NUM_SEEK_OPS / BENCH_NUM_THREADS;
    for (int i = 0; i < num_seeks; i++)
    {
        /* pick a random key from the dataset */
        int key_idx = rand() % BENCH_NUM_OPERATIONS;
        if (tidesdb_iter_seek(iter, data->keys[key_idx], data->key_sizes[key_idx]) == 0)
        {
            /* successfully positioned at key >= target */
        }
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);

    return NULL;
}

/**
 * thread_iter_seek_for_prev
 * iterates to a specific key in the database and seeks for the previous key
 * @param arg thread data
 * @return NULL
 */
void *thread_iter_seek_for_prev(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;

    tidesdb_txn_t *txn = NULL;

    if (tidesdb_txn_begin(data->tdb, data->cf, &txn) != 0)
    {
        printf(BOLDRED "[Thread %d] Failed to begin transaction\n" RESET, data->thread_id);
        return NULL;
    }

    /* seed random number generator with thread id for different sequences per thread */
    srand(time(NULL) + data->thread_id + 1000); /* different seed than regular seek */

    /* create iterator once and reuse for all seeks */
    tidesdb_iter_t *iter = NULL;
    if (tidesdb_iter_new(txn, &iter) != 0)
    {
        printf(BOLDRED "[Thread %d] Failed to create iterator\n" RESET, data->thread_id);
        tidesdb_txn_free(txn);
        return NULL;
    }

    /* perform BENCH_NUM_SEEK_OPS seeks to random keys from the dataset */
    int num_seeks = BENCH_NUM_SEEK_OPS / BENCH_NUM_THREADS;
    for (int i = 0; i < num_seeks; i++)
    {
        /* pick a random key from the dataset */
        int key_idx = rand() % BENCH_NUM_OPERATIONS;
        if (tidesdb_iter_seek_for_prev(iter, data->keys[key_idx], data->key_sizes[key_idx]) == 0)
        {
            /* successfully positioned at key <= target */
        }
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);

    return NULL;
}

int main()
{
    remove_directory(BENCH_DB_PATH);
    tidesdb_t *tdb = NULL;
    double start_time, end_time;

    srand((unsigned int)time(NULL));

    printf(BOLDCYAN "\n=== TidesDB Benchmark Configuration ===\n" RESET);
    printf(BOLDWHITE "Workload Settings:\n" RESET);
    printf("  Operations: %d\n", BENCH_NUM_OPERATIONS);
    printf("  Seek Operations: %d\n", BENCH_NUM_SEEK_OPS);
    printf("  Key Size: %d bytes\n", BENCH_KEY_SIZE);
    printf("  Value Size: %d bytes\n", BENCH_VALUE_SIZE);
    printf("  Threads: %d\n", BENCH_NUM_THREADS);
    printf("  Key Pattern: %s\n", BENCH_KEY_PATTERN);
#ifdef TDB_DEBUG
    printf("  DB Debug Logging: %s\n", "enabled");
#else
    printf("  DB Debug Logging: %s\n", "disabled");
#endif
    printf("  DB Flush Pool Threads: %d\n", BENCH_DB_FLUSH_POOL_THREADS);
    printf("  DB Compaction Pool Threads: %d\n", BENCH_DB_COMPACTION_POOL_THREADS);

    printf("\n" BOLDWHITE "Column Family Configuration:\n" RESET);
    printf("  Write Buffer Size: %zu bytes (%.2f MB)\n", (size_t)BENCH_WRITE_BUFFER_SIZE,
           (double)BENCH_WRITE_BUFFER_SIZE / (1024.0 * 1024.0));
    printf("  Level Size Ratio: %dx\n", BENCH_LEVEL_RATIO);
    printf("  Dividing Level Offset: %d\n", BENCH_DIVIDING_LEVEL_OFFSET);
    printf("  Max Levels: %d\n", BENCH_MAX_LEVELS);
    printf("  Skip List Max Level: %d\n", BENCH_SKIP_LIST_MAX_LEVEL);
    printf("  Skip List Probability: %.2f\n", BENCH_SKIP_LIST_PROBABILITY);
    printf("  Compression: %s\n", BENCH_ENABLE_COMPRESSION ? "enabled" : "disabled");
    printf("  Bloom Filter: %s\n", BENCH_ENABLE_BLOOM_FILTER ? "enabled" : "disabled");
    printf("  Bloom Filter FP Rate: %.4f\n", BENCH_BLOOM_FILTER_FP_RATE);
    printf("  Block Indexes: %s\n", BENCH_ENABLE_BLOCK_INDEXES ? "enabled" : "disabled");
    printf("  Background Compaction: %s\n",
           BENCH_ENABLE_BACKGROUND_COMPACTION ? "enabled" : "disabled");
    printf("  Background Compaction Interval: %d\n", BENCH_BACKGROUND_COMPACTION_INTERVAL);
    printf("  Block Manager Cache Size: %d\n", BENCH_COLUMN_FAMILY_BLOCK_CACHE);
    printf("  Comparator: %s\n", BENCH_COMPARATOR_NAME);
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

    tidesdb_config_t config = {.db_path = BENCH_DB_PATH,
                               .enable_debug_logging = BENCH_DB_DEBUG,
                               .num_flush_threads = BENCH_DB_FLUSH_POOL_THREADS,
                               .num_compaction_threads = BENCH_DB_COMPACTION_POOL_THREADS,
                               .max_open_sstables = 1000};
    int open_result = tidesdb_open(&config, &tdb);
    if (open_result != 0)
    {
        printf(BOLDRED "Failed to open database (error code: %d)\n" RESET, open_result);

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

    cf_config.write_buffer_size = BENCH_WRITE_BUFFER_SIZE;
    cf_config.level_size_ratio = BENCH_LEVEL_RATIO;
    cf_config.dividing_level_offset = BENCH_DIVIDING_LEVEL_OFFSET;
    cf_config.max_levels = BENCH_MAX_LEVELS;
    cf_config.skip_list_max_level = BENCH_SKIP_LIST_MAX_LEVEL;
    cf_config.skip_list_probability = BENCH_SKIP_LIST_PROBABILITY;
    cf_config.compression_algorithm = BENCH_COMPRESSION_ALGORITHM;
    cf_config.enable_bloom_filter = BENCH_ENABLE_BLOOM_FILTER;
    cf_config.bloom_fpr = BENCH_BLOOM_FILTER_FP_RATE;
    cf_config.enable_block_indexes = BENCH_ENABLE_BLOCK_INDEXES;
    cf_config.index_sample_ratio = BENCH_BLOCK_INDEX_SAMPLING_COUNT;
    cf_config.enable_background_compaction = BENCH_ENABLE_BACKGROUND_COMPACTION;
    cf_config.compaction_interval_ms = BENCH_BACKGROUND_COMPACTION_INTERVAL;
    cf_config.sync_mode = BENCH_SYNC_MODE;
    cf_config.block_manager_cache_size = BENCH_COLUMN_FAMILY_BLOCK_CACHE;
    cf_config.comparator = skip_list_comparator_memcmp;

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

    tidesdb_column_family_t *cf = tidesdb_get_column_family(tdb, BENCH_CF_NAME);
    if (cf == NULL)
    {
        printf(BOLDRED "Failed to get column family\n" RESET);

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
        thread_data[i].cf = cf;
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

    /* for seek benchmark, we want to perform BENCH_NUM_SEEK_OPS seeks
     * but select keys from the full dataset (BENCH_NUM_OPERATIONS)
     * so set start=0, end=BENCH_NUM_OPERATIONS for key selection range */
    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        thread_data[i].start = 0;
        thread_data[i].end = BENCH_NUM_OPERATIONS;
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

    printf(BOLDGREEN "\nBenchmarking Iterator Seek For Prev operations...\n" RESET);

    /* reuse same thread_data setup */
    start_time = get_time_ms();

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_iter_seek_for_prev, &thread_data[i]);
    }

    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }

    end_time = get_time_ms();
    printf(BOLDGREEN "Iterator Seek For Prev: %d operations in %.2f ms (%.2f ops/sec)\n" RESET,
           BENCH_NUM_SEEK_OPS, end_time - start_time,
           (BENCH_NUM_SEEK_OPS / (end_time - start_time)) * 1000);

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