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
#include "../test/test_macros.h"

#define NUM_OPERATIONS 1000000
#define KEY_SIZE       64
#define VALUE_SIZE     156
#define CF_NAME        "benchmark_cf"
#define NUM_THREADS    2
#define BENCH_DB_PATH  "benchmark_db"

/* helper to clean benchmark directory */
static inline void cleanup_benchmark_dir(void)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", BENCH_DB_PATH);
    system(cmd);
}

/*
 * thread_data_t struct is used to pass data to the thread functions
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
} thread_data_t;

void generate_random_string(uint8_t *buffer, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /*  we fill buffer with random characters from charset (leaving room for null terminator) */
    for (size_t i = 0; i < size - 1; i++)
    {
        buffer[i] = (uint8_t)charset[rand() % (int)(sizeof(charset) - 1)];
    }

    /* ensure null termination */
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

        if (tidesdb_txn_put(txn, CF_NAME, data->keys[i], data->key_sizes[i], data->values[i],
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

        if (tidesdb_txn_get(txn, CF_NAME, data->keys[i], data->key_sizes[i], &value_out,
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

        if (tidesdb_txn_delete(txn, CF_NAME, data->keys[i], data->key_sizes[i]) != 0)
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

int main()
{
    cleanup_benchmark_dir();
    tidesdb_t *tdb = NULL;
    double start_time, end_time;

    /* we seed random number generator */
    srand((unsigned int)time(NULL));

    /* we allocate arrays for keys and values */
    uint8_t **keys = malloc(NUM_OPERATIONS * sizeof(uint8_t *));
    if (keys == NULL)
    {
        printf(BOLDRED "Failed to allocate memory for keys array\n" RESET);
        return 1;
    }

    uint8_t **values = malloc(NUM_OPERATIONS * sizeof(uint8_t *));
    if (values == NULL)
    {
        printf(BOLDRED "Failed to allocate memory for values array\n" RESET);
        free(keys);
        return 1;
    }

    size_t *key_sizes = malloc(NUM_OPERATIONS * sizeof(size_t));
    if (key_sizes == NULL)
    {
        printf(BOLDRED "Failed to allocate memory for key sizes array\n" RESET);
        free(keys);
        free(values);
        return 1;
    }

    size_t *value_sizes = malloc(NUM_OPERATIONS * sizeof(size_t));
    if (value_sizes == NULL)
    {
        printf(BOLDRED "Failed to allocate memory for value sizes array\n" RESET);
        free(keys);
        free(values);
        free(key_sizes);
        return 1;
    }

    /* we generate random keys and values */
    for (int i = 0; i < NUM_OPERATIONS; i++)
    {
        /* we allocate and generate key */
        keys[i] = malloc(KEY_SIZE);
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
        generate_random_string(keys[i], KEY_SIZE);
        key_sizes[i] = KEY_SIZE - 1;

        /* we allocate and generate value */
        values[i] = malloc(VALUE_SIZE);
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
        generate_random_string(values[i], VALUE_SIZE);
        value_sizes[i] = VALUE_SIZE - 1;
    }

    tidesdb_config_t config = {.db_path = "benchmark_db", .enable_debug_logging = 0};
    if (tidesdb_open(&config, &tdb) != 0)
    {
        printf(BOLDRED "Failed to open database\n" RESET);

        for (int i = 0; i < NUM_OPERATIONS; i++)
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
    cf_config.memtable_flush_size = (1024 * 1024) * 64; /* 64MB */
    cf_config.max_sstables_before_compaction = 512;
    cf_config.compaction_threads = 4; /* Enable parallel compaction */
    cf_config.compressed = 1;
    cf_config.compress_algo = COMPRESS_LZ4;
    cf_config.enable_background_compaction = 1;

    if (tidesdb_create_column_family(tdb, CF_NAME, &cf_config) != 0)
    {
        printf(BOLDRED "Failed to create column family\n" RESET);

        /* we free allocated memory */
        for (int i = 0; i < NUM_OPERATIONS; i++)
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

    /* setup thread data */
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++)
    {
        thread_data[i].tdb = tdb;
        thread_data[i].keys = keys;
        thread_data[i].values = values;
        thread_data[i].key_sizes = key_sizes;
        thread_data[i].value_sizes = value_sizes;
        thread_data[i].start = i * (NUM_OPERATIONS / NUM_THREADS);
        thread_data[i].end = (i + 1) * (NUM_OPERATIONS / NUM_THREADS);
    }

    printf(BOLDGREEN "\nBenchmarking Put operations...\n" RESET);
    start_time = get_time_ms();

    for (int i = 0; i < NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_put, &thread_data[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }

    end_time = get_time_ms();
    printf(BOLDGREEN "Put: %d operations in %.2f ms (%.2f ops/sec)\n" RESET, NUM_OPERATIONS,
           end_time - start_time, (NUM_OPERATIONS / (end_time - start_time)) * 1000);

    printf(BOLDGREEN "\nBenchmarking Get operations...\n" RESET);
    start_time = get_time_ms();

    for (int i = 0; i < NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_get, &thread_data[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }

    end_time = get_time_ms();
    printf(BOLDGREEN "Get: %d operations in %.2f ms (%.2f ops/sec)\n" RESET, NUM_OPERATIONS,
           end_time - start_time, (NUM_OPERATIONS / (end_time - start_time)) * 1000);

    printf(BOLDGREEN "\nBenchmarking Delete operations...\n" RESET);
    start_time = get_time_ms();

    for (int i = 0; i < NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_delete, &thread_data[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }

    end_time = get_time_ms();
    printf(BOLDGREEN "Delete: %d operations in %.2f ms (%.2f ops/sec)\n" RESET, NUM_OPERATIONS,
           end_time - start_time, (NUM_OPERATIONS / (end_time - start_time)) * 1000);

    if (tidesdb_drop_column_family(tdb, CF_NAME) != 0)
    {
        printf(BOLDRED "Failed to drop column family\n" RESET);
    }

    tidesdb_close(tdb);

    /* we free allocated memory */
    for (int i = 0; i < NUM_OPERATIONS; i++)
    {
        free(keys[i]);
        free(values[i]);
    }
    free(keys);
    free(values);
    free(key_sizes);
    free(value_sizes);

    cleanup_benchmark_dir();

    printf(MAGENTA "\nCleanup completed\n" RESET);
    return 0;
}