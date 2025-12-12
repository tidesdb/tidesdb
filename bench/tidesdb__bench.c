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
    int count;            /* for storing iteration count */
    _Atomic(int) *errors; /* pointer to shared error counter */
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
    /* use a format that fits in the buffer size */
    snprintf((char *)buffer, size, "k%06d", index);
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
 * for benchmark purposes, we make this deterministic by using the operation
 * index directly rather than generating a random zipfian index. this ensures that
 * each operation index maps to a unique key, allowing proper verification.
 * the zipfian distribution is simulated by having operations access keys in a
 * pattern where early indices (hot keys) are accessed more frequently.
 * @param buffer buffer to store key
 * @param size size of buffer
 * @param operation_index the operation index (used to generate deterministic key)
 */
void generate_zipfian_key(uint8_t *buffer, size_t size, int operation_index)
{
    /** we use operation index directly to ensure deterministic key generation
     * format: k%010d fits in 16 bytes (k + 10 digits + null = 12 bytes) */
    snprintf((char *)buffer, size, "k%010d", operation_index);
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
 * generate_deterministic_value
 * generates a deterministic value based on index for verification
 * @param buffer buffer to store value
 * @param size size of buffer
 * @param index index to generate value for
 */
void generate_deterministic_value(uint8_t *buffer, size_t size, int index)
{
    /* create a deterministic pattern: "val_XXXX" where XXXX is the index */
    snprintf((char *)buffer, size, "val_%04d", index);
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
        if (tidesdb_txn_begin(data->tdb, &txn) != 0)
        {
            continue;
        }

        /* batch multiple operations in one transaction */
        int batch_end = i + BATCH_SIZE;
        if (batch_end > data->end) batch_end = data->end;

        for (int j = i; j < batch_end; j++)
        {
            if (tidesdb_txn_put(txn, data->cf, data->keys[j], data->key_sizes[j], data->values[j],
                                data->value_sizes[j], 0) != 0)
            {
                printf(BOLDRED "Put operation failed\n" RESET);
                break;
            }
        }

        if (tidesdb_txn_commit(txn) != 0)
        {
            tidesdb_txn_free(txn);
            continue;
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
        if (tidesdb_txn_begin(data->tdb, &txn) != 0)
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

            if (tidesdb_txn_get(txn, data->cf, data->keys[j], data->key_sizes[j], &value_out,
                                &value_len) == 0)
            {
                /* verify the value matches what we wrote */
                if (value_len != data->value_sizes[j] ||
                    memcmp(value_out, data->values[j], value_len) != 0)
                {
                    if (data->errors)
                    {
                        atomic_fetch_add(data->errors, 1);
                    }
                    printf(BOLDRED "[Thread %d] GET verification failed for key %d:\n" RESET,
                           data->thread_id, j);
                    printf("  Expected %zu bytes: ", data->value_sizes[j]);
                    for (size_t k = 0; k < data->value_sizes[j] && k < 20; k++)
                        printf("%02x ", data->values[j][k]);
                    printf("\n  Got %zu bytes:      ", value_len);
                    for (size_t k = 0; k < value_len && k < 20; k++) printf("%02x ", value_out[k]);
                    printf("\n");
                }
                free(value_out);
            }
            else
            {
                /* key not found */
                if (data->errors)
                {
                    atomic_fetch_add(data->errors, 1);
                }
                printf(BOLDRED "[Thread %d] GET failed: key %d not found\n" RESET, data->thread_id,
                       j);
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
        if (tidesdb_txn_begin(data->tdb, &txn) != 0)
        {
            printf(BOLDRED "Failed to begin transaction\n" RESET);
            continue;
        }

        /* batch multiple deletes in one transaction */
        int batch_end = i + BATCH_SIZE;
        if (batch_end > data->end) batch_end = data->end;

        for (int j = i; j < batch_end; j++)
        {
            if (tidesdb_txn_delete(txn, data->cf, data->keys[j], data->key_sizes[j]) != 0)
            {
                printf(BOLDRED "Delete operation failed\n" RESET);
                break;
            }
        }

        if (tidesdb_txn_commit(txn) != 0)
        {
            tidesdb_txn_free(txn);
            continue;
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
    if (tidesdb_txn_begin(data->tdb, &txn) != 0)
    {
        printf(BOLDRED "Failed to begin read transaction\n" RESET);
        return NULL;
    }

    tidesdb_iter_t *iter = NULL;
    if (tidesdb_iter_new(txn, data->cf, &iter) != 0)
    {
        printf(BOLDRED "Failed to create iterator\n" RESET);
        tidesdb_txn_free(txn);
        return NULL;
    }

    int count = 0;
    uint8_t *prev_key = NULL;
    size_t prev_key_size = 0;

    if (tidesdb_iter_seek_to_first(iter) == 0)
    {
        while (tidesdb_iter_valid(iter))
        {
            uint8_t *key = NULL, *value = NULL;
            size_t key_size = 0, value_size = 0;
            tidesdb_iter_key(iter, &key, &key_size);
            tidesdb_iter_value(iter, &value, &value_size);

            /* verify keys are in sorted order */
            if (prev_key != NULL)
            {
                if (memcmp(prev_key, key, prev_key_size < key_size ? prev_key_size : key_size) > 0)
                {
                    if (data->errors)
                    {
                        atomic_fetch_add(data->errors, 1);
                    }
                    printf(BOLDRED
                           "[Thread %d] Forward iterator: keys out of order at position %d\n" RESET,
                           data->thread_id, count);
                }
                free(prev_key);
            }

            /* save current key for next comparison */
            prev_key = malloc(key_size);
            if (prev_key)
            {
                memcpy(prev_key, key, key_size);
                prev_key_size = key_size;
            }

            count++;
            /* keys/values are internal pointers, no need to free */
            if (tidesdb_iter_next(iter) != 0) break;
        }
    }

    if (prev_key) free(prev_key);

    /* store count in count field for reporting */
    data->count = count;

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
    if (tidesdb_txn_begin(data->tdb, &txn) != 0)
    {
        printf(BOLDRED "Failed to begin read transaction\n" RESET);
        return NULL;
    }

    tidesdb_iter_t *iter = NULL;
    if (tidesdb_iter_new(txn, data->cf, &iter) != 0)
    {
        printf(BOLDRED "Failed to create iterator\n" RESET);
        tidesdb_txn_free(txn);
        return NULL;
    }

    int count = 0;
    uint8_t *prev_key = NULL;
    size_t prev_key_size = 0;

    if (tidesdb_iter_seek_to_last(iter) == 0)
    {
        while (tidesdb_iter_valid(iter))
        {
            uint8_t *key = NULL, *value = NULL;
            size_t key_size = 0, value_size = 0;
            tidesdb_iter_key(iter, &key, &key_size);
            tidesdb_iter_value(iter, &value, &value_size);

            /* verify keys are in reverse sorted order */
            if (prev_key != NULL)
            {
                if (memcmp(prev_key, key, prev_key_size < key_size ? prev_key_size : key_size) < 0)
                {
                    if (data->errors)
                    {
                        atomic_fetch_add(data->errors, 1);
                    }
                    printf(
                        BOLDRED
                        "[Thread %d] Backward iterator: keys out of order at position %d\n" RESET,
                        data->thread_id, count);
                }
                free(prev_key);
            }

            /* save current key for next comparison */
            prev_key = malloc(key_size);
            if (prev_key)
            {
                memcpy(prev_key, key, key_size);
                prev_key_size = key_size;
            }

            count++;
            /* keys/values are internal pointers, no need to free */
            if (tidesdb_iter_prev(iter) != 0) break;
        }
    }

    if (prev_key) free(prev_key);

    /* store count in count field for reporting */
    data->count = count;

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

    if (tidesdb_txn_begin(data->tdb, &txn) != 0)
    {
        printf(BOLDRED "[Thread %d] Failed to begin transaction\n" RESET, data->thread_id);
        return NULL;
    }

    /* seed random number generator with thread id for different sequences per thread */
    srand(time(NULL) + data->thread_id);

    /* create iterator once and reuse for all seeks */
    tidesdb_iter_t *iter = NULL;
    if (tidesdb_iter_new(txn, data->cf, &iter) != 0)
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

    if (tidesdb_txn_begin(data->tdb, &txn) != 0)
    {
        printf(BOLDRED "[Thread %d] Failed to begin transaction\n" RESET, data->thread_id);
        return NULL;
    }

    /* seed random number generator with thread id for different sequences per thread */
    srand(time(NULL) + data->thread_id + 1000); /* different seed than regular seek */

    /* create iterator once and reuse for all seeks */
    tidesdb_iter_t *iter = NULL;
    if (tidesdb_iter_new(txn, data->cf, &iter) != 0)
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

char *get_isolation_level_name(int isolation_level)
{
    switch (isolation_level)
    {
        case TDB_ISOLATION_READ_COMMITTED:
            return "READ_COMMITTED";
        case TDB_ISOLATION_READ_UNCOMMITTED:
            return "READ_UNCOMMITTED";
        case TDB_ISOLATION_REPEATABLE_READ:
            return "REPEATABLE_READ";
        case TDB_ISOLATION_SNAPSHOT:
            return "SNAPSHOT";
        case TDB_ISOLATION_SERIALIZABLE:
            return "SERIALIZABLE";
        default:
            return "UNKNOWN";
    }
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
    printf("  DB Block Cache Size: %d\n", BENCH_BLOCK_CACHE_SIZE);

    printf("\n" BOLDWHITE "Column Family Configuration:\n" RESET);
    printf("  Write Buffer Size: %zu bytes (%.2f MB)\n", (size_t)BENCH_WRITE_BUFFER_SIZE,
           (double)BENCH_WRITE_BUFFER_SIZE / (1024.0 * 1024.0));
    printf("  Level Size Ratio: %dx\n", BENCH_LEVEL_RATIO);
    printf("  Dividing Level Offset: %d\n", BENCH_DIVIDING_LEVEL_OFFSET);
    printf("  Min Levels: %d\n", BENCH_MIN_LEVELS);
    printf("  Skip List Max Level: %d\n", BENCH_SKIP_LIST_MAX_LEVEL);
    printf("  Skip List Probability: %.2f\n", BENCH_SKIP_LIST_PROBABILITY);
    printf("  Compression: %s\n", BENCH_ENABLE_COMPRESSION ? "enabled" : "disabled");
    printf("  Bloom Filter: %s\n", BENCH_ENABLE_BLOOM_FILTER ? "enabled" : "disabled");
    printf("  Bloom Filter FP Rate: %.4f\n", BENCH_BLOOM_FILTER_FP_RATE);
    printf("  Block Indexes: %s\n", BENCH_ENABLE_BLOCK_INDEXES ? "enabled" : "disabled");
    printf("  Comparator: %s\n", BENCH_COMPARATOR_NAME);
    printf("  Isolation Level: %s\n", get_isolation_level_name(BENCH_ISOLATION_LEVEL));
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

    /* error counter for verification */
    _Atomic(int) verification_errors = 0;

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
            /* use operation index to generate deterministic keys */
            generate_zipfian_key(keys[i], BENCH_KEY_SIZE, i);
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
        generate_deterministic_value(values[i], BENCH_VALUE_SIZE, i);
        value_sizes[i] = strlen((char *)values[i]);
    }

    tidesdb_config_t config = {.db_path = BENCH_DB_PATH,
                               .enable_debug_logging = BENCH_DB_DEBUG,
                               .num_flush_threads = BENCH_DB_FLUSH_POOL_THREADS,
                               .num_compaction_threads = BENCH_DB_COMPACTION_POOL_THREADS,
                               .block_cache_size = BENCH_BLOCK_CACHE_SIZE,
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
    cf_config.min_levels = BENCH_MIN_LEVELS;
    cf_config.skip_list_max_level = BENCH_SKIP_LIST_MAX_LEVEL;
    cf_config.skip_list_probability = BENCH_SKIP_LIST_PROBABILITY;
    cf_config.compression_algorithm = BENCH_COMPRESSION_ALGORITHM;
    cf_config.enable_bloom_filter = BENCH_ENABLE_BLOOM_FILTER;
    cf_config.bloom_fpr = BENCH_BLOOM_FILTER_FP_RATE;
    cf_config.enable_block_indexes = BENCH_ENABLE_BLOCK_INDEXES;
    cf_config.index_sample_ratio = BENCH_BLOCK_INDEX_SAMPLING_COUNT;
    cf_config.sync_mode = BENCH_SYNC_MODE;
    strncpy(cf_config.comparator_name, BENCH_COMPARATOR_NAME, TDB_MAX_COMPARATOR_NAME - 1);
    cf_config.comparator_name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';
    cf_config.default_isolation_level = BENCH_ISOLATION_LEVEL;

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
        /* ensure last thread handles any remaining operations */
        thread_data[i].end = (i == BENCH_NUM_THREADS - 1)
                                 ? BENCH_NUM_OPERATIONS
                                 : (i + 1) * (BENCH_NUM_OPERATIONS / BENCH_NUM_THREADS);
        thread_data[i].thread_id = i;
        thread_data[i].count = 0;
        thread_data[i].errors = &verification_errors;
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

    /* ensure all PUT operations are fully committed and visible before GET operations
     * add memory barrier and small delay to allow concurrent commits to complete */
    atomic_thread_fence(memory_order_seq_cst);
    usleep(50000); /* 50ms delay to allow all pending commits to fully complete */

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

    if (verification_errors == 0)
    {
        printf(BOLDGREEN "  ✓ All GET operations verified successfully\n" RESET);
    }
    else
    {
        printf(BOLDRED "  ✗ GET verification failed: %d errors\n" RESET, verification_errors);
    }
    verification_errors = 0; /* reset for next test */

    printf(BOLDGREEN "\nBenchmarking Iterator Seek operations...\n" RESET);

    /* reset thread data for seek operations - each thread accesses full dataset */
    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        thread_data[i].start = 0;
        thread_data[i].end = BENCH_NUM_OPERATIONS;
        thread_data[i].thread_id = i;
        thread_data[i].count = 0;
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

    /* each thread iterates ALL keys independently, so check one thread's count */
    int keys_per_thread = thread_data[0].count;

    printf(BOLDGREEN "Forward Iterator: %d threads in %.2f ms (%.2f ops/sec)\n" RESET,
           BENCH_NUM_THREADS, end_time - start_time,
           (BENCH_NUM_OPERATIONS / (end_time - start_time)) * 1000);

    if (keys_per_thread == BENCH_NUM_OPERATIONS)
    {
        printf(BOLDGREEN "  ✓ Each thread iterated all %d keys successfully\n" RESET,
               keys_per_thread);
    }
    else
    {
        printf(BOLDRED "  ✗ Iterator count mismatch: expected %d, got %d keys per thread\n" RESET,
               BENCH_NUM_OPERATIONS, keys_per_thread);
    }

    if (verification_errors > 0)
    {
        printf(BOLDRED "  ✗ Iterator verification failed: %d errors\n" RESET, verification_errors);
    }
    verification_errors = 0; /* reset for next test */

    printf(BOLDGREEN "\nBenchmarking Backward Iterator (full scan)...\n" RESET);

    /* reset count for backward iterator */
    for (int i = 0; i < BENCH_NUM_THREADS; i++)
    {
        thread_data[i].count = 0;
    }

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

    /* get the count from backward iterator */
    int backward_keys_per_thread = thread_data[0].count;

    printf(BOLDGREEN "Backward Iterator: %d threads in %.2f ms (%.2f ops/sec)\n" RESET,
           BENCH_NUM_THREADS, end_time - start_time,
           (BENCH_NUM_OPERATIONS / (end_time - start_time)) * 1000);

    if (backward_keys_per_thread == BENCH_NUM_OPERATIONS)
    {
        printf(BOLDGREEN "  ✓ Each thread iterated all %d keys successfully\n" RESET,
               backward_keys_per_thread);
    }
    else
    {
        printf(BOLDRED "  ✗ Iterator count mismatch: expected %d, got %d keys per thread\n" RESET,
               BENCH_NUM_OPERATIONS, backward_keys_per_thread);
    }

    if (verification_errors > 0)
    {
        printf(BOLDRED "  ✗ Iterator verification failed: %d errors\n" RESET, verification_errors);
    }
    verification_errors = 0; /* reset for next test */

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